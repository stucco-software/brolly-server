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
use brolly_identity::db;
use brolly_server::{AppState, app};
use http_body_util::BodyExt;
use serde_json::json;
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
    let stored = brolly_atproto::ingest::read(&pod, &uri).expect("the pod copy");
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
    let stored = brolly_atproto::ingest::read(&pod, &uri).unwrap();
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
        brolly_atproto::ingest::read(&pod, &uri).unwrap()["$type"],
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
