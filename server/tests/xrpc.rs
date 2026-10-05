//! The XRPC surface over HTTP.
//!
//! The interesting assertion here is not that records write — the repo tests
//! cover that — but that a write lands in **both** the repo and the pod. The
//! repo is what the network syncs; the pod is what every other protocol reads.
//! A record in one and not the other is a member whose data exists for some
//! readers and not others, and nothing in either subsystem's own tests would
//! notice.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db;
use brolly_server::{AppState, app};
use http_body_util::BodyExt;
use p256::ecdsa::signature::Signer;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tower::ServiceExt;

const BASE: &str = "brolly.test";

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    stores: std::sync::Arc<brolly_store::StoreManager>,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(brolly_store::StoreManager::open(dir.path(), 8, 60).unwrap());
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
            // an_xrpc_write_proof_is_good_for_one_request pushes a PAR as this
            // client, so it's registered exactly as production would accept it.
            clients: std::sync::Arc::new(
                brolly_server::client_metadata::StaticClients::default()
                    .with(
                        OAUTH_CLIENT,
                        &serde_json::json!({
                            "client_id": OAUTH_CLIENT,
                            "redirect_uris": [OAUTH_REDIRECT],
                            "scope": OAUTH_SCOPE,
                            "grant_types": ["authorization_code", "refresh_token"],
                            "response_types": ["code"],
                            "token_endpoint_auth_method": "none",
                            "application_type": "web",
                            "dpop_bound_access_tokens": true,
                        })
                        .to_string(),
                    )
                    .expect("the XRPC test client's metadata validates"),
            ),
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
        stores,
    }
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
    content_type: Option<String>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "expected JSON, got {}: {e}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

async fn send(h: &Harness, request: Request<Body>) -> Reply {
    let response = h.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Reply {
        status,
        body,
        content_type,
    }
}

async fn get(h: &Harness, uri: &str) -> Reply {
    send(
        h,
        Request::builder()
            .uri(uri)
            .header(header::HOST, BASE)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn post_json(h: &Harness, uri: &str, body: serde_json::Value, cookie: Option<&str>) -> Reply {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::HOST, BASE)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(h, request.body(Body::from(body.to_string())).unwrap()).await
}

/// A member with a pod, a repo, a signing key and a session.
async fn a_member(h: &Harness, username: &str) -> (uuid::Uuid, String) {
    let user = db::create_user(
        &h.db.pool,
        username,
        None,
        "correct-horse-battery",
        "member",
    )
    .await
    .unwrap();
    let pod = h.stores.pod(user.id).unwrap();
    brolly_server::provision::pod(&pod, username, BASE).unwrap();

    // Signing key, then a genesis commit pointing at it.
    let (private, public) = brolly_atproto::keys::generate_pair().unwrap();
    db::store_key(
        &h.db.pool,
        user.id,
        brolly_atproto::keys::ATPROTO_SIGNING,
        &private,
        &public,
    )
    .await
    .unwrap();

    let key = brolly_atproto::keys::SigningKey::from_bytes(&private).unwrap();
    let blocks = brolly_atproto::blocks::PodBlocks::new(h.stores.repo_blocks(user.id).unwrap());
    let root = brolly_atproto::repo::create(blocks, &format!("did:web:{username}.{BASE}"), &key)
        .await
        .unwrap();
    brolly_atproto::state::create(&h.db.pool, user.id, &root.to_string())
        .await
        .unwrap();

    let session = db::create_session(&h.db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    (user.id, format!("brolly_session={session}"))
}

// --- the assertion that matters --------------------------------------------------

#[tokio::test]
async fn a_write_lands_in_both_the_repo_and_the_pod() {
    // The repo is what the network syncs; the pod is what every other protocol
    // reads. A record in one and not the other is data that exists for some
    // readers and not others.
    let h = harness().await;
    let (user_id, cookie) = a_member(&h, "alice").await;

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": format!("alice.{BASE}"),
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "in both places"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    // In the repo, over XRPC.
    let fetched = get(
        &h,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
    )
    .await;
    assert_eq!(fetched.status, StatusCode::OK, "{}", fetched.text());
    assert_eq!(fetched.json()["value"]["text"], "in both places");

    // And in the pod, faithfully.
    let pod = h.stores.pod(user_id).unwrap();
    let uri = created.json()["uri"].as_str().unwrap().to_string();
    let stored = brolly_atproto::ingest::read(&pod.read_store(), &uri).expect("the pod copy");
    assert_eq!(stored["text"], "in both places");
}

#[tokio::test]
async fn an_unmapped_lexicon_writes_through_xrpc_too() {
    let h = harness().await;
    let (user_id, cookie) = a_member(&h, "alice").await;

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "site.standard.doc",
            "rkey": "3kbbbbbbbbbbb",
            "record": {"$type": "site.standard.doc", "text": "unmapped", "n": {"deep": [1, 2]}},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let pod = h.stores.pod(user_id).unwrap();
    let uri = created.json()["uri"].as_str().unwrap().to_string();
    let stored = brolly_atproto::ingest::read(&pod.read_store(), &uri).unwrap();
    assert_eq!(stored["n"]["deep"], json!([1, 2]));
}

#[tokio::test]
async fn a_record_without_a_type_is_given_its_collection() {
    // Clients omit `$type` when it equals the collection. Rejecting would be
    // pedantic; guessing wrong would put the fields in another lexicon's space.
    let h = harness().await;
    let (user_id, cookie) = a_member(&h, "alice").await;

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kccccccccccc",
            "record": {"text": "no type given"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let pod = h.stores.pod(user_id).unwrap();
    let uri = created.json()["uri"].as_str().unwrap().to_string();
    assert_eq!(
        brolly_atproto::ingest::read(&pod.read_store(), &uri).unwrap()["$type"],
        "app.bsky.feed.post"
    );
}

// --- sync ---------------------------------------------------------------------------

#[tokio::test]
async fn get_repo_serves_a_car_an_independent_reader_accepts() {
    // The sync primitive and the member's data export are the same bytes, so
    // an export cannot drift from what the network sees.
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "exported"},
        }),
        Some(&cookie),
    )
    .await;

    let reply = get(
        &h,
        &format!("/xrpc/com.atproto.sync.getRepo?did=alice.{BASE}"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        reply.content_type.as_deref(),
        Some("application/vnd.ipld.car")
    );

    let mut cursor = std::io::Cursor::new(reply.body.as_slice());
    let (blocks, header) = rs_car_sync::car_read_all(&mut cursor, true)
        .expect("an independent reader must accept what sync serves");
    assert!(!blocks.is_empty());
    assert_eq!(header.roots.len(), 1);
}

// --- identity resolution ---------------------------------------------------------------

#[tokio::test]
async fn a_repo_resolves_by_handle_and_by_did_web() {
    let h = harness().await;
    a_member(&h, "alice").await;

    for repo in [
        format!("alice.{BASE}"),
        format!("did:web:alice.{BASE}"),
        "alice".to_string(),
    ] {
        let reply = get(
            &h,
            &format!("/xrpc/com.atproto.repo.describeRepo?repo={repo}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{repo}: {}", reply.text());
        assert_eq!(reply.json()["handle"], format!("alice.{BASE}"));
    }
}

#[tokio::test]
async fn an_unknown_repo_is_a_typed_xrpc_error() {
    let h = harness().await;
    let reply = get(
        &h,
        "/xrpc/com.atproto.repo.describeRepo?repo=nobody.brolly.test",
    )
    .await;

    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    // XRPC's shape, not ours: a client cannot tell an expected failure from a
    // broken server otherwise.
    assert!(reply.json()["error"].as_str().is_some());
    assert!(reply.json()["message"].as_str().is_some());
}

/// Disabling an account must stop it serving, on every protocol.
///
/// Before this, an admin could disable a member for moderation reasons, watch
/// their pod 404 and their actor stop resolving, and anyone on the internet
/// could still download their whole repository as a CAR.
#[tokio::test]
async fn a_disabled_member_serves_no_repo() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    // Give her a record, so getRecord has something to find and the test
    // cannot pass merely because the repo is empty.
    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "before"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&h.db.pool)
        .await
        .unwrap();

    // All three, because resolve_repo feeds all three — testing two would
    // leave the fix looking complete while one endpoint still served.
    for uri in [
        format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
        format!("/xrpc/com.atproto.repo.describeRepo?repo=alice.{BASE}"),
        format!("/xrpc/com.atproto.sync.getRepo?did=alice.{BASE}"),
    ] {
        let reply = get(&h, &uri).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{uri} still served a disabled member: {}",
            reply.text()
        );
    }
}

// --- authorization -------------------------------------------------------------------

#[tokio::test]
async fn writing_requires_authentication() {
    let h = harness().await;
    a_member(&h, "alice").await;

    let reply = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({"collection": "app.bsky.feed.post", "record": {"text": "anonymous"}}),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn one_member_cannot_write_to_anothers_repo() {
    let h = harness().await;
    a_member(&h, "alice").await;
    let (_, mallory) = a_member(&h, "mallory").await;

    let reply = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": format!("alice.{BASE}"),
            "collection": "app.bsky.feed.post",
            "record": {"text": "not mine"},
        }),
        Some(&mallory),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_deleted_record_is_gone_from_the_repo() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "delete me"},
        }),
        Some(&cookie),
    )
    .await;

    let deleted = post_json(
        &h,
        "/xrpc/com.atproto.repo.deleteRecord",
        json!({"collection": "app.bsky.feed.post", "rkey": "3kaaaaaaaaaaa"}),
        Some(&cookie),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text());

    let fetched = get(
        &h,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
    )
    .await;
    assert_eq!(fetched.status, StatusCode::NOT_FOUND);
}

// --- DPoP-bound callers ------------------------------------------------------------

// Chunk 5 (B) makes PAR look these up in the harness's `StaticClients`. It must
// register exactly this client, redirect and scope there. See the note below.
const OAUTH_CLIENT: &str = "https://app.example/client-metadata.json";
const OAUTH_REDIRECT: &str = "https://app.example/cb";
const OAUTH_SCOPE: &str = "atproto transition:generic";

/// A DPoP proof, as a real client produces one.
fn dpop_proof(key: &p256::ecdsa::SigningKey, method: &str, url: &str, ath: Option<&str>) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = json!({
        "alg": "ES256", "typ": "dpop+jwt",
        "jwk": {"kty": "EC", "crv": "P-256",
                "x": B64.encode(&sec1[1..33]), "y": B64.encode(&sec1[33..65])},
    });
    let mut claims = json!({
        "htm": method, "htu": url,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": time::OffsetDateTime::now_utc().unix_timestamp(),
    });
    if let Some(ath) = ath {
        claims["ath"] = json!(ath);
    }
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// Take `cookie`'s member through ATProto OAuth and return an access token
/// bound to `key`: PAR, consent, decision, token, each through the router.
async fn atproto_access_token(h: &Harness, cookie: &str, key: &p256::ecdsa::SigningKey) -> String {
    let verifier = "a-high-entropy-value-for-the-xrpc-dpop-replay-test-0123456789";
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));

    let par = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", OAUTH_CLIENT)
        .append_pair("redirect_uri", OAUTH_REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", OAUTH_SCOPE)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let pushed = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                dpop_proof(
                    key,
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/par"),
                    None,
                ),
            )
            .body(Body::from(par))
            .unwrap(),
    )
    .await;
    assert_eq!(pushed.status, StatusCode::CREATED, "par: {}", pushed.text());
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();

    let authorize = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", OAUTH_CLIENT)
        .append_pair("request_uri", &request_uri)
        .finish();
    let consent = send(
        h,
        Request::builder()
            .uri(format!("/oauth/atproto/authorize?{authorize}"))
            .header(header::HOST, BASE)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        consent.status,
        StatusCode::OK,
        "authorize: {}",
        consent.text()
    );
    let html = consent.text();
    let marker = r#"name="request" value=""#;
    let start = html.find(marker).expect("a consent form") + marker.len();
    let request_token = html[start..].split('"').next().unwrap().to_string();

    // Straight through the router: `send` does not keep `Location`.
    let decision = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/atproto/authorize")
                .header(header::HOST, BASE)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    form_urlencoded::Serializer::new(String::new())
                        .append_pair("request", &request_token)
                        .append_pair("decision", "allow")
                        .finish(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = decision
        .headers()
        .get(header::LOCATION)
        .expect("a redirect back to the client")
        .to_str()
        .unwrap()
        .to_string();
    let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("a code");

    let exchange = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", OAUTH_REDIRECT)
        .append_pair("client_id", OAUTH_CLIENT)
        .append_pair("code_verifier", verifier)
        .finish();
    let token = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/token")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                dpop_proof(
                    key,
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/token"),
                    None,
                ),
            )
            .body(Body::from(exchange))
            .unwrap(),
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "token: {}", token.text());
    token.json()["access_token"].as_str().unwrap().to_string()
}

/// `createRecord` authenticated by nothing but a DPoP-bound token.
///
/// The proof has to sign `POST https://<base>/xrpc/`, because that fixed target
/// is what `token_caller` checks today. Stage 2 changes it to the method's
/// real URL.
async fn create_with_token(h: &Harness, token: &str, proof: &str, rkey: &str) -> Reply {
    send(
        h,
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("DPoP {token}"))
            .header("DPoP", proof)
            .body(Body::from(
                json!({
                    "repo": format!("alice.{BASE}"),
                    "collection": "app.bsky.feed.post",
                    "rkey": rkey,
                    "record": {"$type": "app.bsky.feed.post", "text": "signed once"},
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn an_xrpc_write_proof_is_good_for_one_request() {
    // A write is the costliest thing to replay: each replay is another record.
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let key = p256::ecdsa::SigningKey::from_slice(&[21u8; 32]).unwrap();
    let token = atproto_access_token(&h, &cookie, &key).await;
    let target = format!("https://{BASE}/xrpc/");
    let ath = B64.encode(Sha256::digest(token.as_bytes()));

    let proof = dpop_proof(&key, "POST", &target, Some(&ath));
    let first = create_with_token(&h, &token, &proof, "3kaaaaaaaaaab").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());

    // A different record, so the only thing this request repeats is the proof.
    let replayed = create_with_token(&h, &token, &proof, "3kaaaaaaaaaac").await;
    assert_eq!(
        replayed.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        replayed.text()
    );
    assert_eq!(replayed.json()["error"], "AuthenticationRequired");

    let fresh = dpop_proof(&key, "POST", &target, Some(&ath));
    let third = create_with_token(&h, &token, &fresh, "3kaaaaaaaaaac").await;
    assert_eq!(third.status, StatusCode::OK, "{}", third.text());
}

// --- hygiene ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unimplemented_method_says_so_by_name() {
    // A client must be able to tell "this server does not do that" from "this
    // server is broken".
    let h = harness().await;
    let reply = get(&h, "/xrpc/com.atproto.repo.listMissingBlobs").await;

    assert_eq!(reply.status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(reply.json()["error"], "MethodNotImplemented");
    assert!(
        reply.json()["message"]
            .as_str()
            .unwrap_or_default()
            .contains("com.atproto.repo.listMissingBlobs"),
        "the error should name the method"
    );
}

#[tokio::test]
async fn the_catch_all_does_not_shadow_an_implemented_method() {
    let h = harness().await;
    let reply = get(&h, "/xrpc/com.atproto.server.describeServer").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["inviteCodeRequired"], true);
}

#[tokio::test]
async fn xrpc_is_apex_only() {
    // ADR 0009 reserves `/xrpc/` on member subdomains; the PLC document points
    // at the apex, so serving both would be two answers to one question.
    let h = harness().await;
    a_member(&h, "alice").await;

    let reply = send(
        &h,
        Request::builder()
            .uri("/xrpc/com.atproto.server.describeServer")
            .header(header::HOST, format!("alice.{BASE}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

// --- firehose -------------------------------------------------------------------------

#[tokio::test]
async fn a_write_is_announced_on_the_firehose() {
    // The commit stream is how a relay learns anything changed without polling
    // every repo. A write that does not appear here is invisible to the network.
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "announced"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let events = brolly_atproto::firehose::since(&h.db.pool, None, 10)
        .await
        .expect("firehose");
    assert_eq!(events.len(), 1, "the write was not announced");
    assert_eq!(events[0].action, brolly_atproto::firehose::Action::Create);
    assert_eq!(events[0].path, "app.bsky.feed.post/3kaaaaaaaaaaa");
    assert!(events[0].commit_cid.starts_with("bafy"));
}

#[tokio::test]
async fn a_delete_is_announced_too() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "gone soon"},
        }),
        Some(&cookie),
    )
    .await;
    post_json(
        &h,
        "/xrpc/com.atproto.repo.deleteRecord",
        json!({"collection": "app.bsky.feed.post", "rkey": "3kaaaaaaaaaaa"}),
        Some(&cookie),
    )
    .await;

    let events = brolly_atproto::firehose::since(&h.db.pool, None, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].action, brolly_atproto::firehose::Action::Delete);
    assert_eq!(
        events[1].record_cid, None,
        "a delete announces no record CID"
    );
}

#[tokio::test]
async fn the_announcement_chains_to_the_previous_commit() {
    // A consumer verifies `prev` against what it already has; an event that
    // does not name its predecessor cannot be checked.
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    for n in 1..=2 {
        post_json(
            &h,
            "/xrpc/com.atproto.repo.createRecord",
            json!({
                "collection": "app.bsky.feed.post",
                "rkey": format!("3k{n}"),
                "record": {"$type": "app.bsky.feed.post", "text": format!("post {n}")},
            }),
            Some(&cookie),
        )
        .await;
    }

    let events = brolly_atproto::firehose::since(&h.db.pool, None, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[1].prev_cid.as_deref(),
        Some(events[0].commit_cid.as_str()),
        "the second commit must name the first"
    );
    assert!(events[1].rev > events[0].rev, "revisions must advance");
}

#[tokio::test]
async fn the_firehose_endpoint_is_mounted() {
    // A plain GET is refused by the upgrade extractor, which is itself proof
    // the route exists — falling through to the catch-all would answer 501.
    let h = harness().await;
    let reply = get(&h, "/xrpc/com.atproto.sync.subscribeRepos").await;
    assert_ne!(
        reply.status,
        StatusCode::NOT_IMPLEMENTED,
        "subscribeRepos fell through to the unimplemented catch-all"
    );
}

/// Serve the router on a real port.
///
/// `oneshot` cannot complete a websocket upgrade — there is no hyper upgrade
/// state behind it — so the firehose is unverifiable through the harness the
/// other tests use. A real listener is the only way to assert it streams at
/// all, which is the entire point of the endpoint.
async fn serve(router: axum::Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

#[tokio::test]
async fn a_relay_receives_backfill_from_its_cursor() {
    // The property the durable log exists for: a consumer that was away comes
    // back with a cursor and receives exactly what it missed.
    use futures_util::StreamExt;

    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    for n in 1..=3 {
        post_json(
            &h,
            "/xrpc/com.atproto.repo.createRecord",
            json!({
                "collection": "app.bsky.feed.post",
                "rkey": format!("3k{n}"),
                "record": {"$type": "app.bsky.feed.post", "text": format!("post {n}")},
            }),
            Some(&cookie),
        )
        .await;
    }

    let addr = serve(h.router.clone()).await;
    let (mut socket, response) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=1"
    ))
    .await
    .expect("a relay must be able to open the stream");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Two events remain after cursor=1, and they arrive as binary frames.
    let mut received = 0;
    while received < 2 {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("the stream should not stall")
            .expect("the stream should not end")
            .expect("a readable frame");

        if let tokio_tungstenite::tungstenite::Message::Binary(frame) = message {
            assert!(!frame.is_empty(), "an empty frame carries nothing");
            received += 1;
        }
    }
    assert_eq!(received, 2, "backfill delivered the wrong number of events");
}

#[tokio::test]
async fn the_firehose_is_apex_only() {
    // Over a real socket, so the upgrade succeeds and the host check is what
    // answers. Through `oneshot` this is untestable — the upgrade extractor
    // rejects first and both hosts look identical.
    let h = harness().await;
    let addr = serve(h.router.clone()).await;

    let mut request = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert(header::HOST, format!("alice.{BASE}").parse().unwrap());

    assert!(
        tokio_tungstenite::connect_async(request).await.is_err(),
        "the firehose must not serve on a member subdomain"
    );
}

// --- provisioning ---------------------------------------------------------------------

/// Register through the front door, exactly as a person would.
async fn a_registered_member(h: &Harness, username: &str) -> String {
    let invite = db::create_invite(&h.db.pool, None, 1, None, None)
        .await
        .expect("invite");
    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::HOST, BASE)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "invite={invite}&username={username}&email=&password=correct-horse-battery"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "registration should succeed"
    );

    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("brolly_session"))
        .map(|c| c.split(';').next().unwrap().to_string())
        .expect("a session cookie")
}

#[tokio::test]
async fn registering_provisions_a_usable_atproto_identity() {
    // The gap this closes: registration created the pod and its ACL but not the
    // signing key, the DID or the genesis commit, so the *first XRPC write* was
    // what discovered there was no repository. Every piece existed; nothing
    // called them at signup.
    let h = harness().await;
    let cookie = a_registered_member(&h, "alice").await;

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "straight after signing up"},
        }),
        Some(&cookie),
    )
    .await;

    assert_eq!(
        created.status,
        StatusCode::OK,
        "a member who just registered must be able to write: {}",
        created.text()
    );
    // The AT-URI names the DID, not the handle (D11).
    let uri = created.json()["uri"].as_str().unwrap().to_string();
    assert!(uri.starts_with("at://did:plc:"), "got {uri}");
}

#[tokio::test]
async fn registration_mints_a_did_two_keys_and_a_repo() {
    // All three or none. A member with a key and no repo, or a DID and no key,
    // has an account that looks provisioned and cannot participate.
    let h = harness().await;
    a_registered_member(&h, "alice").await;

    let user = db::find_by_username(&h.db.pool, "alice")
        .await
        .unwrap()
        .unwrap();

    assert!(
        user.did_plc
            .as_deref()
            .is_some_and(|d| d.starts_with("did:plc:")),
        "no DID was minted: {:?}",
        user.did_plc
    );

    for purpose in [
        brolly_atproto::keys::ATPROTO_SIGNING,
        brolly_atproto::keys::ATPROTO_ROTATION,
    ] {
        assert!(
            db::load_key(&h.db.pool, user.id, purpose)
                .await
                .unwrap()
                .is_some(),
            "{purpose} was not stored"
        );
    }

    assert!(
        brolly_atproto::state::load(&h.db.pool, user.id)
            .await
            .unwrap()
            .is_some(),
        "no repository was created"
    );
}

#[tokio::test]
async fn the_rotation_key_is_not_the_signing_key() {
    // Storing one key under both purposes would make a compromise
    // unrecoverable while looking, from the schema, exactly like doing it
    // properly.
    let h = harness().await;
    a_registered_member(&h, "alice").await;
    let user = db::find_by_username(&h.db.pool, "alice")
        .await
        .unwrap()
        .unwrap();

    let (signing, _) = db::load_key(&h.db.pool, user.id, brolly_atproto::keys::ATPROTO_SIGNING)
        .await
        .unwrap()
        .unwrap();
    let (rotation, _) = db::load_key(&h.db.pool, user.id, brolly_atproto::keys::ATPROTO_ROTATION)
        .await
        .unwrap()
        .unwrap();

    assert_ne!(signing, rotation, "one key is serving both purposes");
}

#[tokio::test]
async fn an_unregistered_did_is_visible_for_retry_rather_than_lost() {
    // With no PLC client configured — the local-development and
    // first-boot-behind-a-firewall case — the member is fully provisioned and
    // the genesis operation waits in the queue. A member who cannot be
    // published yet is very different from one who was never given an identity
    // (ADR 0016).
    let h = harness().await;
    a_registered_member(&h, "alice").await;

    let pending = brolly_atproto::identity::unsubmitted(&h.db.pool)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1, "the genesis operation should be queued");
    assert!(!pending[0].submitted);
    assert!(pending[0].did.starts_with("did:plc:"));
}

#[tokio::test]
async fn two_members_get_distinct_identities() {
    let h = harness().await;
    a_registered_member(&h, "alice").await;
    a_registered_member(&h, "bob").await;

    let alice = db::find_by_username(&h.db.pool, "alice")
        .await
        .unwrap()
        .unwrap();
    let bob = db::find_by_username(&h.db.pool, "bob")
        .await
        .unwrap()
        .unwrap();

    assert_ne!(alice.did_plc, bob.did_plc, "two members share a DID");
    assert_ne!(
        brolly_atproto::state::load(&h.db.pool, alice.id)
            .await
            .unwrap()
            .unwrap()
            .root_cid,
        brolly_atproto::state::load(&h.db.pool, bob.id)
            .await
            .unwrap()
            .unwrap()
            .root_cid,
        "two members share a repository root"
    );
}

#[tokio::test]
async fn the_new_members_repo_resolves_by_did() {
    // The DID is what every AT-URI names, so resolving by it is the path that
    // actually gets exercised.
    let h = harness().await;
    a_registered_member(&h, "alice").await;
    let user = db::find_by_username(&h.db.pool, "alice")
        .await
        .unwrap()
        .unwrap();
    let did = user.did_plc.unwrap();

    let reply = get(
        &h,
        &format!("/xrpc/com.atproto.repo.describeRepo?repo={did}"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["did"], did);
    assert_eq!(reply.json()["handle"], format!("alice.{BASE}"));
}
