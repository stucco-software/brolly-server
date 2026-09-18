//! The member dashboard: overview, profile, security, apps, export, delete.
//!
//! Plan §4.4 puts this in Phase 4. §4.1 describes the member as the audience
//! who "needs to understand what is theirs and how to leave with it", which is
//! why export and delete are surfaces here rather than a support request.
//!
//! Everything is server-rendered and works without JavaScript (§4.2), so these
//! drive real form posts rather than a JSON API.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_solid::storage;
use brolly_store::StoreManager;
use http_body_util::BodyExt;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

const BASE: &str = "brolly.test";
const ROOT: &str = "https://alice.brolly.test/~/";
const WEBID: &str = "https://alice.brolly.test/profile#me";
const PASSWORD: &str = "correct-horse-battery-staple";

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    stores: std::sync::Arc<StoreManager>,
    user: Uuid,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 4, 60).unwrap());

    let user = db::create_user(&db.pool, "alice", None, PASSWORD, "member")
        .await
        .unwrap();
    let pod = stores.pod(user.id).unwrap();
    storage::init_storage_root(&pod, ROOT).unwrap();

    let router = app(
        AppState {
            pool: db.pool.clone(),
            base_domain: BASE.into(),
            instance_name: BASE.to_string(),
            instance_description: "A private community server.".to_string(),
            source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
            terms_url: None,
            privacy_url: None,
            stores: std::sync::Arc::clone(&stores),
            provider_key: std::sync::Arc::new(
                brolly_solid::oidc::store::load_or_create_key(&db.pool)
                    .await
                    .expect("provider key"),
            ),
            instance_actor: std::sync::Arc::new(
                brolly_identity::instance::load_or_create(
                    &db.pool,
                    brolly_activitypub::keys::generate,
                )
                .await
                .expect("instance actor"),
            ),
            commits: tokio::sync::broadcast::channel(64).0,
            plc_client: None,
            clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),
        },
        "server/static",
    );

    Harness {
        db,
        _dir: dir,
        router,
        stores,
        user: user.id,
    }
}

struct Reply {
    status: StatusCode,
    body: String,
    location: Option<String>,
    content_type: Option<String>,
}

impl Harness {
    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                .to_string();
        Reply {
            status,
            body,
            location,
            content_type,
        }
    }

    async fn login(&self) -> String {
        let reply = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::HOST, BASE)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("username=alice&password={PASSWORD}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        reply
            .headers()
            .get(header::SET_COOKIE)
            .expect("a session cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::HOST, BASE);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn post(&self, path: &str, body: &str, cookie: Option<&str>) -> Reply {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send(request.body(Body::from(body.to_string())).unwrap())
            .await
    }
}

// --- access -----------------------------------------------------------------

#[tokio::test]
async fn every_dashboard_page_needs_a_session_and_comes_back_afterwards() {
    let h = harness().await;

    for path in [
        "/account",
        "/account/profile",
        "/account/security",
        "/account/apps",
        "/account/export",
        "/account/delete",
    ] {
        let reply = h.get(path, None).await;
        assert_eq!(
            reply.status,
            StatusCode::SEE_OTHER,
            "{path} was not guarded"
        );
        let location = reply.location.expect("a redirect");
        assert!(
            location.starts_with("/login?"),
            "{path} should send an anonymous visitor to log in, got {location}"
        );
        assert!(
            location
                .contains(&form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>()),
            "{path} must come back after login, got {location}"
        );
    }
}

// --- overview ---------------------------------------------------------------

#[tokio::test]
async fn the_overview_shows_the_member_what_is_theirs() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h.get("/account", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::OK);

    // §4.1: the member has to be able to see what is theirs and where it lives.
    assert!(reply.body.contains("alice"), "the account must be named");
    assert!(
        reply.body.contains(WEBID),
        "the WebID is the member's identity across all four protocols"
    );
    assert!(
        reply.body.contains(ROOT),
        "the storage root is what a Solid client needs to be pointed at"
    );
}

// --- profile ----------------------------------------------------------------

#[tokio::test]
async fn the_profile_form_writes_to_the_pod_and_not_to_postgres() {
    // D2/D5: display names live in the pod. The predecessor migrated them out
    // and then added a column back seven weeks later.
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h
        .post(
            "/account/profile",
            "display_name=Alice+Example&bio=Testing+in+production",
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);

    let pod = h.stores.pod(h.user).unwrap();
    let triples: Vec<String> = pod
        .quads_for_pattern(None, None, None, None)
        .filter_map(Result::ok)
        .map(|q| q.to_string())
        .collect();
    let all = triples.join("\n");
    assert!(
        all.contains("Alice Example"),
        "the display name must land in the pod: {all}"
    );
    assert!(
        all.contains(WEBID),
        "profile triples must be asserted onto the WebID (D8), not a fresh node"
    );

    let columns: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'",
    )
    .fetch_all(&h.db.pool)
    .await
    .unwrap();
    let names: Vec<&str> = columns.iter().map(|(c,)| c.as_str()).collect();
    assert!(
        !names
            .iter()
            .any(|c| c.contains("display") || c.contains("bio")),
        "profile content must not acquire a Postgres column: {names:?}"
    );

    // And it comes back when the form is reloaded, rather than silently
    // vanishing into the store.
    let reply = h.get("/account/profile", Some(&cookie)).await;
    assert!(reply.body.contains("Alice Example"));
}

#[tokio::test]
async fn editing_a_profile_twice_replaces_rather_than_accumulates() {
    let h = harness().await;
    let cookie = h.login().await;

    h.post("/account/profile", "display_name=First&bio=", Some(&cookie))
        .await;
    h.post(
        "/account/profile",
        "display_name=Second&bio=",
        Some(&cookie),
    )
    .await;

    let reply = h.get("/account/profile", Some(&cookie)).await;
    assert!(reply.body.contains("Second"));
    assert!(
        !reply.body.contains("First"),
        "a second edit must replace the name, not leave two foaf:name triples"
    );
}

// --- security ---------------------------------------------------------------

#[tokio::test]
async fn changing_a_password_requires_the_current_one() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h
        .post(
            "/account/security",
            "current_password=wrong&new_password=an-entirely-new-password",
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    // The old password must still work.
    assert!(
        db::authenticate(&h.db.pool, "alice", PASSWORD)
            .await
            .is_ok(),
        "a failed change must not have changed anything"
    );
}

#[tokio::test]
async fn a_new_password_must_be_long_enough() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h
        .post(
            "/account/security",
            &format!("current_password={PASSWORD}&new_password=short"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        db::authenticate(&h.db.pool, "alice", PASSWORD)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn changing_a_password_ends_every_other_session() {
    // Someone changing their password is often doing it because they think
    // another session is not theirs. Leaving those sessions live defeats it.
    let h = harness().await;
    let stolen = h.login().await;
    let mine = h.login().await;

    let reply = h
        .post(
            "/account/security",
            &format!("current_password={PASSWORD}&new_password=an-entirely-new-password"),
            Some(&mine),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);

    assert_eq!(
        h.get("/account", Some(&stolen)).await.status,
        StatusCode::SEE_OTHER,
        "the other session must be gone"
    );
    assert_eq!(
        h.get("/account", Some(&mine)).await.status,
        StatusCode::OK,
        "the session that made the change must survive, or the member is logged out mid-task"
    );
    assert!(
        db::authenticate(&h.db.pool, "alice", "an-entirely-new-password")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_security_page_lists_active_sessions() {
    let h = harness().await;
    let cookie = h.login().await;
    h.login().await;

    let reply = h.get("/account/security", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.body.contains("2") || reply.body.to_lowercase().contains("session"),
        "the member should be able to see how many sessions are open"
    );
}

// --- apps -------------------------------------------------------------------

/// A DPoP proof, as the app's own key would produce.
fn dpop_proof(key: &SigningKey, method: &str, url: &str) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(&sec1[1..33]),
            "y": B64.encode(&sec1[33..65]),
        },
    });
    let claims = serde_json::json!({
        "htm": method,
        "htu": url,
        "jti": Uuid::new_v4().to_string(),
        "iat": time::OffsetDateTime::now_utc().unix_timestamp(),
    });
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// Register a Solid client and take it all the way through the token exchange,
/// so the member has a grant the dashboard can list.
///
/// The exchange is the point: a code that is never redeemed grants nothing, so
/// stopping at consent would leave nothing to show or revoke.
async fn an_authorised_app(h: &Harness, cookie: &str, name: &str) -> String {
    let reply = h
        .send(
            Request::builder()
                .method("POST")
                .uri("/oauth/solid/register")
                .header(header::HOST, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "client_name": name,
                        "redirect_uris": ["https://app.example/cb"],
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    let client_id = serde_json::from_str::<serde_json::Value>(&reply.body).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let verifier = "a-high-entropy-cryptographic-random-string-of-length-64ish";
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", "https://app.example/cb")
        .append_pair("scope", "openid webid offline_access")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let consent = h
        .get(&format!("/oauth/solid/authorize?{query}"), Some(cookie))
        .await;
    let marker = r#"name="request" value=""#;
    let start = consent.body.find(marker).expect("consent form") + marker.len();
    let token = consent.body[start..].split('"').next().unwrap().to_string();

    let decision = h
        .post(
            "/oauth/solid/authorize",
            &format!(
                "request={}&decision=allow",
                form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>()
            ),
            Some(cookie),
        )
        .await;
    let location = decision.location.expect("a redirect carrying the code");
    let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("a code");

    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let token_url = format!("https://{BASE}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", "https://app.example/cb")
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", verifier)
        .finish();
    let exchanged = h
        .send(
            Request::builder()
                .method("POST")
                .uri("/oauth/solid/token")
                .header(header::HOST, BASE)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("DPoP", dpop_proof(&key, "POST", &token_url))
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(
        exchanged.status,
        StatusCode::OK,
        "token exchange: {}",
        exchanged.body
    );

    client_id
}

#[tokio::test]
async fn the_apps_page_lists_what_the_member_has_authorised() {
    let h = harness().await;
    let cookie = h.login().await;
    an_authorised_app(&h, &cookie, "Notes App").await;

    let reply = h.get("/account/apps", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.body.contains("Notes App"),
        "an authorised app must be listed by name: {}",
        reply.body
    );
}

#[tokio::test]
async fn revoking_an_app_stops_it_refreshing() {
    // The consent screen promises "you can revoke this at any time from your
    // account settings". This is that.
    let h = harness().await;
    let cookie = h.login().await;
    let client_id = an_authorised_app(&h, &cookie, "Notes App").await;

    let reply = h
        .post(
            "/account/apps",
            &format!(
                "client_id={}",
                form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>()
            ),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);

    let live: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM solid_refresh_tokens
         WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(&client_id)
    .fetch_one(&h.db.pool)
    .await
    .unwrap();
    assert_eq!(live.0, 0, "revocation must kill the refresh tokens");

    let reply = h.get("/account/apps", Some(&cookie)).await;
    assert!(!reply.body.contains("Notes App"), "and delist the app");
}

#[tokio::test]
async fn one_member_cannot_revoke_anothers_app() {
    let h = harness().await;
    let alice = h.login().await;
    let client_id = an_authorised_app(&h, &alice, "Notes App").await;

    db::create_user(&h.db.pool, "mallory", None, PASSWORD, "member")
        .await
        .unwrap();
    let reply = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::HOST, BASE)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("username=mallory&password={PASSWORD}")))
                .unwrap(),
        )
        .await
        .unwrap();
    let mallory = reply
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    h.post(
        "/account/apps",
        &format!(
            "client_id={}",
            form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>()
        ),
        Some(&mallory),
    )
    .await;

    let live: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM solid_refresh_tokens
         WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(&client_id)
    .fetch_one(&h.db.pool)
    .await
    .unwrap();
    assert_eq!(
        live.0, 1,
        "revocation must be scoped to the member's own grants"
    );
}

// --- export -----------------------------------------------------------------

#[tokio::test]
async fn export_hands_back_the_whole_pod() {
    // D7: "export is complete". N-Quads because it is the only syntax that
    // carries the named graphs, and the graphs are what make it re-importable.
    let h = harness().await;
    let cookie = h.login().await;
    h.post(
        "/account/profile",
        "display_name=Alice+Example&bio=",
        Some(&cookie),
    )
    .await;

    let reply = h.get("/account/export", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.content_type.as_deref(),
        Some("application/n-quads"),
        "a lossy export is not an export"
    );
    assert!(reply.body.contains("Alice Example"));
    assert!(
        reply.body.contains(ROOT),
        "the storage root and its containment must be in the export"
    );
}

// --- delete -----------------------------------------------------------------

#[tokio::test]
async fn deleting_an_account_requires_typing_the_username() {
    // The confirmation is not ceremony: this is the one irreversible button in
    // the product.
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h
        .post("/account/delete", "confirm=something-else", Some(&cookie))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        db::find_by_username(&h.db.pool, "alice")
            .await
            .unwrap()
            .is_some(),
        "the account must survive a failed confirmation"
    );
}

#[tokio::test]
async fn deleting_an_account_removes_the_user_and_the_pod() {
    let h = harness().await;
    let cookie = h.login().await;
    h.post(
        "/account/profile",
        "display_name=Alice+Example&bio=",
        Some(&cookie),
    )
    .await;

    let reply = h
        .post("/account/delete", "confirm=alice", Some(&cookie))
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);

    assert!(
        db::find_by_username(&h.db.pool, "alice")
            .await
            .unwrap()
            .is_none(),
        "the user row must be gone"
    );
    assert!(
        !h.stores.pod_exists(h.user),
        "the pod directory must be gone — content lives in exactly one place (D2)"
    );
    assert_eq!(
        h.get("/account", Some(&cookie)).await.status,
        StatusCode::SEE_OTHER,
        "the session must not outlive the account"
    );
}

/// The footer is the other page every user reaches, so §13 is discharged there
/// too — and it stops naming the product while it is at it.
#[tokio::test]
async fn the_authenticated_footer_carries_the_source_link() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h.get("/account", Some(&cookie)).await;
    assert!(reply.body.contains(brolly_server::SOURCE_URL_DEFAULT));
    assert!(
        !reply.body.contains("Brolly"),
        "the footer stops naming the product"
    );
}

/// Revoking is a security action, and the only feedback was that a row
/// vanished. Same parameter and same extractor as profile and security; only
/// the sentence differs.
#[tokio::test]
async fn revoking_an_app_says_so() {
    let h = harness().await;
    let cookie = h.login().await;
    let client_id = an_authorised_app(&h, &cookie, "Notes App").await;

    let reply = h
        .post(
            "/account/apps",
            &format!(
                "client_id={}",
                form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>()
            ),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/account/apps?saved=true"));

    let reply = h.get("/account/apps?saved=true", Some(&cookie)).await;
    assert!(
        reply.body.contains("Access withdrawn."),
        "got: {}",
        reply.body
    );
    assert!(
        reply.body.contains("role=\"status\""),
        "got: {}",
        reply.body
    );
}

/// ...and the notice is not permanent furniture.
#[tokio::test]
async fn the_apps_page_is_quiet_without_the_parameter() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h.get("/account/apps", Some(&cookie)).await;
    assert!(!reply.body.contains("Access withdrawn."));
}
