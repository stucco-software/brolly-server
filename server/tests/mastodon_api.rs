//! The Mastodon Client API over HTTP.
//!
//! The hygiene assertions here close the third verified P0 defect: unknown
//! `/api/v*` paths fell through to the Solid/LDP router and answered clients
//! with RDF or an HTML error page. A client cannot parse that, so it renders an
//! unexplained failure and the member sees a broken tab with no reason given.
//!
//! Everything under `/api/` answers JSON, including its 404s, and no write is
//! faked into looking successful.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use http_body_util::BodyExt;
use tower::ServiceExt;

const BASE: &str = "brolly.test";

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let router = app(
        AppState {
            pool: db.pool.clone(),
            base_domain: BASE.into(),
            instance_name: BASE.to_string(),
            instance_description: "A private community server.".to_string(),
            source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
            terms_url: None,
            privacy_url: None,
            max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
            stores: std::sync::Arc::new(
                brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap(),
            ),
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
            solid_clients: std::sync::Arc::new(
                brolly_server::client_metadata::StaticClientDocuments::default(),
            ),
            // The remote path's lookups (spec 6, H5): empty here, as a fetch
            // that finds nothing would be — these tests never leave the
            // instance.
            issuer_discovery: std::sync::Arc::new(
                brolly_server::client_metadata::StaticDocuments::default(),
            ),
            issuer_jwks: std::sync::Arc::new(
                brolly_server::client_metadata::StaticDocuments::default(),
            ),
            webid_documents: std::sync::Arc::new(
                brolly_server::client_metadata::StaticDocuments::default(),
            ),
        },
        "server/static",
    );
    Harness {
        db,
        _dir: dir,
        router,
    }
}

struct Reply {
    status: StatusCode,
    body: String,
    content_type: Option<String>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("expected JSON, got {}: {}", self.body, e))
    }
}

async fn request(h: &Harness, method: &str, uri: &str, token: Option<&str>) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, BASE);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = h
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    Reply {
        status,
        body,
        content_type,
    }
}

async fn get(h: &Harness, uri: &str, token: Option<&str>) -> Reply {
    request(h, "GET", uri, token).await
}

/// A member with a working bearer token.
async fn a_member_with_a_token(h: &Harness) -> (uuid::Uuid, String) {
    let user = db::create_user(&h.db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .expect("create user");
    let app = brolly_mastodon::oauth::register_app(
        &h.db.pool,
        "Phanpy",
        &["https://app.example/cb".into()],
        "read write follow",
        None,
    )
    .await
    .expect("register app");
    let token = brolly_mastodon::oauth::issue_token(
        &h.db.pool,
        &app.app.client_id,
        user.id,
        "read write follow",
    )
    .await
    .expect("issue token");
    (user.id, token)
}

// --- API hygiene: the third P0 defect -------------------------------------------

#[tokio::test]
async fn an_unknown_api_path_answers_json_not_html() {
    // The defect exactly: it used to fall through to the LDP router.
    let h = harness().await;
    let reply = get(&h, "/api/v1/zzz-not-a-real-endpoint", None).await;

    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(
        reply
            .content_type
            .as_deref()
            .is_some_and(|c| c.contains("json")),
        "content-type was {:?}, body {}",
        reply.content_type,
        reply.body
    );
    assert_eq!(reply.json()["error"], "Record not found");
}

#[tokio::test]
async fn an_unimplemented_write_answers_404_rather_than_faking_success() {
    // "No write endpoint fakes success." A 200 here would make a client believe
    // it had bookmarked something that was silently discarded.
    let h = harness().await;
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let reply = request(&h, method, "/api/v1/bookmarks/12345", None).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{method} was answered as if it worked"
        );
        assert_eq!(reply.json()["error"], "Record not found");
    }
}

#[tokio::test]
async fn a_pod_path_outside_api_still_reaches_the_pod() {
    // The catch-all must not swallow anything that is not /api/.
    let h = harness().await;
    let reply = get(&h, "/.well-known/nodeinfo", None).await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "the /api/ catch-all captured a non-API path"
    );
}

#[tokio::test]
async fn the_catch_all_does_not_shadow_a_real_endpoint() {
    // Axum matches literal segments before wildcards, but "cannot shadow" is
    // exactly the kind of claim that stops being true.
    let h = harness().await;
    let reply = get(&h, "/api/v1/instance", None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["uri"], BASE);
}

// --- instance --------------------------------------------------------------------

#[tokio::test]
async fn the_instance_advertises_what_it_cannot_do() {
    // Clients hide composer features the instance says are unavailable. A poll
    // limit we do not honour produces a poll button that drops the poll.
    let h = harness().await;
    let config = get(&h, "/api/v2/instance", None).await.json()["configuration"].clone();

    assert_eq!(config["polls"]["max_options"], 0);
    assert_eq!(config["media_attachments"]["video_size_limit"], 0);
    assert_eq!(config["statuses"]["max_characters"], 500);
}

#[tokio::test]
async fn the_instance_says_registration_is_closed() {
    let h = harness().await;
    assert_eq!(
        get(&h, "/api/v2/instance", None).await.json()["registrations"]["enabled"],
        false
    );
    assert_eq!(
        get(&h, "/api/v1/instance", None).await.json()["registrations"],
        false
    );
}

#[tokio::test]
async fn both_instance_versions_are_served() {
    // A client that gets a 404 on the legacy shape often refuses to continue.
    let h = harness().await;
    assert_eq!(
        get(&h, "/api/v1/instance", None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        get(&h, "/api/v2/instance", None).await.status,
        StatusCode::OK
    );
}

// --- authentication ---------------------------------------------------------------

#[tokio::test]
async fn verify_credentials_identifies_the_token_holder() {
    // The first authenticated call every client makes.
    let h = harness().await;
    let (_, token) = a_member_with_a_token(&h).await;

    let reply = get(&h, "/api/v1/accounts/verify_credentials", Some(&token)).await;
    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);

    let account = reply.json();
    assert_eq!(account["username"], "alice");
    assert!(
        account["source"].is_object(),
        "clients read `source` to populate the preferences panel"
    );
}

#[tokio::test]
async fn an_authenticated_endpoint_refuses_an_unknown_token() {
    let h = harness().await;
    let reply = get(
        &h,
        "/api/v1/accounts/verify_credentials",
        Some("not-a-real-token"),
    )
    .await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.json()["error"].as_str().is_some());
}

#[tokio::test]
async fn a_revoked_token_stops_authenticating() {
    let h = harness().await;
    let (_, token) = a_member_with_a_token(&h).await;
    assert_eq!(
        get(&h, "/api/v1/accounts/verify_credentials", Some(&token))
            .await
            .status,
        StatusCode::OK
    );

    brolly_mastodon::oauth::revoke_token(&h.db.pool, &token)
        .await
        .unwrap();

    assert_eq!(
        get(&h, "/api/v1/accounts/verify_credentials", Some(&token))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_suspended_member_cannot_use_their_token() {
    let h = harness().await;
    let (_, token) = a_member_with_a_token(&h).await;

    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&h.db.pool)
        .await
        .unwrap();

    assert_eq!(
        get(&h, "/api/v1/accounts/verify_credentials", Some(&token))
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "a suspended account must not keep working through an old token"
    );
}

// --- accounts and relationships ----------------------------------------------------

#[tokio::test]
async fn an_account_is_fetchable_by_its_opaque_id() {
    let h = harness().await;
    let (user_id, token) = a_member_with_a_token(&h).await;
    let id = brolly_mastodon::translate::encode_account_id(user_id);

    let reply = get(&h, &format!("/api/v1/accounts/{id}"), Some(&token)).await;
    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    assert_eq!(reply.json()["username"], "alice");
}

#[tokio::test]
async fn a_nonsense_account_id_is_a_json_404() {
    let h = harness().await;
    let (_, token) = a_member_with_a_token(&h).await;

    let reply = get(&h, "/api/v1/accounts/not-an-id", Some(&token)).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.json()["error"], "Record not found");
}

#[tokio::test]
async fn relationships_answers_in_bulk() {
    // The endpoint the predecessor was missing entirely. Clients call it on
    // every profile view and every timeline render that shows a follow button,
    // so a 404 leaves every button in the wrong state.
    let h = harness().await;
    let (user_id, token) = a_member_with_a_token(&h).await;
    let id = brolly_mastodon::translate::encode_account_id(user_id);

    let reply = get(
        &h,
        &format!("/api/v1/accounts/relationships?id[]={id}"),
        Some(&token),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    let relationships = reply.json();
    let list = relationships.as_array().expect("an array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], id);
    // Every field a client reads must be present, even when false — a missing
    // key and `false` render differently.
    for field in [
        "following",
        "followed_by",
        "blocking",
        "muting",
        "requested",
    ] {
        assert!(list[0][field].is_boolean(), "{field} is missing");
    }
}

// --- timelines ----------------------------------------------------------------------

#[tokio::test]
async fn the_home_timeline_requires_a_token() {
    let h = harness().await;
    assert_eq!(
        get(&h, "/api/v1/timelines/home", None).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_empty_home_timeline_is_an_empty_array() {
    // Not a 404, and not an error. A new member's timeline is legitimately
    // empty and the client should render "nothing here yet".
    let h = harness().await;
    let (_, token) = a_member_with_a_token(&h).await;

    let reply = get(&h, "/api/v1/timelines/home", Some(&token)).await;
    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    assert_eq!(reply.json(), serde_json::json!([]));
}

#[tokio::test]
async fn the_public_timeline_is_readable_without_a_token() {
    // It is the public timeline; requiring auth would make the instance
    // unbrowsable to anyone deciding whether to join.
    let h = harness().await;
    let reply = get(&h, "/api/v1/timelines/public", None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.json().is_array());
}

// --- stubs -----------------------------------------------------------------------------

#[tokio::test]
async fn every_polled_endpoint_answers_its_empty_shape() {
    // Clients poll all of these at startup. Each one that errors is a visible
    // broken tab.
    let h = harness().await;
    let (_, token) = a_member_with_a_token(&h).await;

    for (path, expected) in brolly_mastodon::instance::EMPTY_READS {
        let reply = get(&h, path, Some(&token)).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}: {}", reply.body);
        assert_eq!(
            reply.json(),
            serde_json::from_str::<serde_json::Value>(expected).unwrap(),
            "{path} returned the wrong empty shape"
        );
    }
}

#[tokio::test]
async fn custom_emojis_is_served_before_login() {
    // Clients fetch it pre-login; requiring auth makes the login screen itself
    // show an error.
    let h = harness().await;
    let reply = get(&h, "/api/v1/custom_emojis", None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), serde_json::json!([]));
}

#[tokio::test]
async fn the_authenticated_stubs_still_require_a_token() {
    let h = harness().await;
    assert_eq!(
        get(&h, "/api/v1/bookmarks", None).await.status,
        StatusCode::UNAUTHORIZED
    );
}

// --- host scoping ------------------------------------------------------------------------

#[tokio::test]
async fn the_client_api_is_apex_only() {
    let h = harness().await;
    let (_, token) = a_member_with_a_token(&h).await;

    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/accounts/verify_credentials")
                .header(header::HOST, format!("alice.{BASE}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
