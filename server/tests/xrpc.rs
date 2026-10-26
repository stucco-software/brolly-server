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
    /// The firehose channel's sender, kept so a test can subscribe a witness
    /// of its own beside the sockets (1, G).
    commits: tokio::sync::broadcast::Sender<brolly_atproto::firehose::Event>,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(brolly_store::StoreManager::open(dir.path(), 8, 60).unwrap());
    // The channel and the listener, composed exactly as `main` composes them
    // (1, G): the writers' sends are the fast path, the listener is what makes
    // delivery correct, and a harness that omits either is testing a topology
    // production never runs. The capacity is 64 rather than 1024 so that a
    // `ConsumerTooSlow` test can overflow the ring with one transaction
    // instead of a thousand writes — the bound's meaning is what is under
    // test, not its production size.
    let commits = tokio::sync::broadcast::channel::<brolly_atproto::firehose::Event>(64).0;
    tokio::spawn(brolly_atproto::firehose::listen(
        db.pool.clone(),
        commits.clone(),
    ));
    let router = app(
        AppState {
            pool: db.pool.clone(),
            base_domain: BASE.into(),
            instance_name: BASE.to_string(),
            instance_description: "A private community server.".to_string(),
            source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
            terms_url: None,
            privacy_url: None,
            public_registration: false,
            limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
            www_redirect: None,
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
            plc_client: None,
            commits: commits.clone(),
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
        commits,
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
/// The log's commits — `since`'s mixed-kind answer narrowed to the kind these
/// write-path tests exercise. The log holds three kinds now (1, E); a test
/// that recorded only commits reads only commits back.
async fn commits(pool: &sqlx::PgPool) -> Vec<brolly_atproto::firehose::CommitEvent> {
    brolly_atproto::firehose::since(pool, None, 10)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|event| match event {
            brolly_atproto::firehose::Event::Commit(commit) => Some(commit),
            _ => None,
        })
        .collect()
}

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
    let (root, genesis_rev) =
        brolly_atproto::repo::create(blocks, &format!("did:web:{username}.{BASE}"), &key)
            .await
            .unwrap();
    brolly_atproto::state::create(&h.db.pool, user.id, &root.to_string(), &genesis_rev)
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

// --- the write path is the lexicon's (1, B) ------------------------------------

#[tokio::test]
async fn create_record_on_an_occupied_path_refuses_invalid_swap() {
    // `createRecord` creates; a second create at the same path is the
    // lexicon's `InvalidSwap`, not a silent replace (1, B).
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let body = json!({
        "collection": "app.bsky.feed.post",
        "rkey": "3kaaaaaaaaaaa",
        "record": {"$type": "app.bsky.feed.post", "text": "first"},
    });
    let first = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        body.clone(),
        Some(&cookie),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());

    let second = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "second"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST, "{}", second.text());
    assert_eq!(second.json()["error"], "InvalidSwap");

    // The refusal announced nothing and replaced nothing.
    let events = commits(&h.db.pool).await;
    assert_eq!(events.len(), 1);
    let fetched = get(
        &h,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
    )
    .await;
    assert_eq!(fetched.json()["value"]["text"], "first");
}

#[tokio::test]
async fn a_rkey_less_create_mints_a_tid_rkey() {
    // The reference PDS mints TID rkeys; the mint_note_id placeholder this
    // replaced produced rkeys no ATProtocol consumer treats as TIDs (1, B).
    let h = harness().await;
    let (user_id, cookie) = a_member(&h, "alice").await;

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "record": {"$type": "app.bsky.feed.post", "text": "minted"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let uri = created.json()["uri"].as_str().unwrap().to_string();
    let rkey = uri.rsplit('/').next().unwrap().to_string();
    assert_eq!(rkey.len(), 13, "a TID rkey is 13 base32 characters: {rkey}");
    assert!(
        brolly_atproto::tid::Tid::new(rkey.clone()).is_ok(),
        "the minted rkey must be a TID: {rkey}"
    );
    let _ = user_id;
}

#[tokio::test]
async fn put_record_creates_and_replaces() {
    // `putRecord` is upsert: the same call creates the record and then
    // replaces it, and the log says which happened (1, B).
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let body = |text: &str| {
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": text},
        })
    };

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.putRecord",
        body("created"),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let cid = created.json()["cid"].as_str().unwrap().to_string();

    let replaced = post_json(
        &h,
        "/xrpc/com.atproto.repo.putRecord",
        body("replaced"),
        Some(&cookie),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.text());
    assert_ne!(
        replaced.json()["cid"].as_str().unwrap(),
        cid.as_str(),
        "a replace must write a new record"
    );

    let fetched = get(
        &h,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
    )
    .await;
    assert_eq!(fetched.json()["value"]["text"], "replaced");

    let events = commits(&h.db.pool).await;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].ops[0].action,
        brolly_atproto::firehose::Action::Create
    );
    assert_eq!(
        events[1].ops[0].action,
        brolly_atproto::firehose::Action::Update
    );
    assert_eq!(
        events[1].ops[0].prev_cid.as_deref(),
        events[0].ops[0].record_cid.as_deref(),
        "the update's prev is the record it replaced (1, D)"
    );
}

#[tokio::test]
async fn a_stale_swap_record_refuses_invalid_swap() {
    // The client named the exact record; a mismatch is the answer, not a
    // retry and not a silent overwrite (1, C).
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "first"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let swapped = post_json(
        &h,
        "/xrpc/com.atproto.repo.putRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "swapped"},
            "swapRecord": "bafyreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy",
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        swapped.status,
        StatusCode::BAD_REQUEST,
        "{}",
        swapped.text()
    );
    assert_eq!(swapped.json()["error"], "InvalidSwap");

    // `swapRecord: null` on an occupied path is the same answer.
    let null_swap = post_json(
        &h,
        "/xrpc/com.atproto.repo.putRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "swapped"},
            "swapRecord": null,
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(null_swap.status, StatusCode::BAD_REQUEST);
    assert_eq!(null_swap.json()["error"], "InvalidSwap");
}

#[tokio::test]
async fn a_stale_swap_commit_refuses_invalid_swap() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    let swapped = post_json(
        &h,
        "/xrpc/com.atproto.repo.putRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "swapped"},
            "swapCommit": "bafyreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy",
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        swapped.status,
        StatusCode::BAD_REQUEST,
        "{}",
        swapped.text()
    );
    assert_eq!(swapped.json()["error"], "InvalidSwap");
}

#[tokio::test]
async fn the_swap_routes_write_against_the_exact_head_and_record() {
    // `swapRecord` and `swapCommit` are the compare-and-set C needs, as
    // routes a synced client can call with everything it knows (1, B).
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "first"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let record_cid = created.json()["cid"].as_str().unwrap().to_string();
    let commit_cid = created.json()["commit"]["cid"]
        .as_str()
        .unwrap()
        .to_string();

    // Both exact: the write lands.
    let swapped = post_json(
        &h,
        "/xrpc/com.atproto.repo.swapRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "second"},
            "swapRecord": record_cid,
            "swapCommit": commit_cid,
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(swapped.status, StatusCode::OK, "{}", swapped.text());

    // A stale record CID: refused, no retry.
    let stale_record = post_json(
        &h,
        "/xrpc/com.atproto.repo.swapRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "third"},
            "swapRecord": record_cid,
            "swapCommit": swapped.json()["commit"]["cid"].as_str().unwrap(),
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(stale_record.status, StatusCode::BAD_REQUEST);
    assert_eq!(stale_record.json()["error"], "InvalidSwap");

    // swapCommit alone, against the exact head.
    let head = swapped.json()["commit"]["cid"]
        .as_str()
        .unwrap()
        .to_string();
    let committed = post_json(
        &h,
        "/xrpc/com.atproto.repo.swapCommit",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "third"},
            "commitCid": head,
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(committed.status, StatusCode::OK, "{}", committed.text());

    // And against a head that has moved.
    let stale_head = post_json(
        &h,
        "/xrpc/com.atproto.repo.swapCommit",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "fourth"},
            "commitCid": head,
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(stale_head.status, StatusCode::BAD_REQUEST);
    assert_eq!(stale_head.json()["error"], "InvalidSwap");

    // Both swap parameters are required on the swapRecord route.
    let missing = post_json(
        &h,
        "/xrpc/com.atproto.repo.swapRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "fifth"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert_eq!(missing.json()["error"], "InvalidRequest");
}

#[tokio::test]
async fn apply_writes_applies_a_batch_as_one_commit() {
    // One commit — one MST revision, one signature — and one event with one
    // op per write (1, B).
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    let applied = post_json(
        &h,
        "/xrpc/com.atproto.repo.applyWrites",
        json!({
            "writes": [
                {"$type": "com.atproto.repo.applyWrites#create",
                 "collection": "app.bsky.feed.post",
                 "rkey": "3kaaaaaaaaaaa",
                 "value": {"$type": "app.bsky.feed.post", "text": "a"}},
                {"$type": "com.atproto.repo.applyWrites#create",
                 "collection": "app.bsky.feed.post",
                 "value": {"$type": "app.bsky.feed.post", "text": "b"}},
                {"$type": "com.atproto.repo.applyWrites#update",
                 "collection": "app.bsky.feed.post",
                 "rkey": "3kaaaaaaaaaaa",
                 "value": {"$type": "app.bsky.feed.post", "text": "a2"}},
            ],
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(applied.status, StatusCode::OK, "{}", applied.text());
    assert_eq!(
        applied.json()["results"].as_array().unwrap().len(),
        3,
        "one result per write"
    );

    let events = commits(&h.db.pool).await;
    assert_eq!(events.len(), 1, "a batch is one event");
    assert_eq!(events[0].ops.len(), 3, "one op per write");
    let actions: Vec<_> = events[0].ops.iter().map(|op| op.action).collect();
    assert_eq!(
        actions,
        vec![
            brolly_atproto::firehose::Action::Create,
            brolly_atproto::firehose::Action::Create,
            brolly_atproto::firehose::Action::Update,
        ]
    );
    assert_eq!(
        events[0].ops[2].prev_cid, events[0].ops[0].record_cid,
        "the update's prev is the record this same batch wrote (1, D)"
    );

    // The whole batch reads back under one commit — the minted rkey from
    // the results, the fixed ones by name.
    let minted = applied.json()["results"][1]["uri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    for (rkey, text) in [("3kaaaaaaaaaaa", "a2"), (minted.as_str(), "b")] {
        let fetched = get(
            &h,
            &format!(
                "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey={rkey}"
            ),
        )
        .await;
        assert_eq!(fetched.status, StatusCode::OK, "{rkey}");
        assert_eq!(fetched.json()["value"]["text"], text);
    }
}

#[tokio::test]
async fn an_invalid_op_refuses_the_whole_batch() {
    // A batch is atomic: one invalid op — here, a create on a path another
    // op in the same batch just took — refuses everything, unsigned (1, B).
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    let refused = post_json(
        &h,
        "/xrpc/com.atproto.repo.applyWrites",
        json!({
            "writes": [
                {"$type": "com.atproto.repo.applyWrites#create",
                 "collection": "app.bsky.feed.post",
                 "rkey": "3kaaaaaaaaaaa",
                 "value": {"$type": "app.bsky.feed.post", "text": "would land"}},
                {"$type": "com.atproto.repo.applyWrites#create",
                 "collection": "app.bsky.feed.post",
                 "rkey": "3kaaaaaaaaaaa",
                 "value": {"$type": "app.bsky.feed.post", "text": "collision"}},
            ],
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{}",
        refused.text()
    );
    assert_eq!(refused.json()["error"], "InvalidSwap");

    // Nothing landed and nothing was announced.
    assert!(
        commits(&h.db.pool).await.is_empty(),
        "a refused batch must not be announced"
    );
    let fetched = get(
        &h,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
    )
    .await;
    assert_eq!(fetched.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_batch_over_two_hundred_writes_is_refused() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    let writes: Vec<serde_json::Value> = (0..201)
        .map(|n| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": format!("3kb{n:010}"),
                "value": {"$type": "app.bsky.feed.post", "text": "too many"},
            })
        })
        .collect();

    let refused = post_json(
        &h,
        "/xrpc/com.atproto.repo.applyWrites",
        json!({"writes": writes}),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{}",
        refused.text()
    );
    assert_eq!(refused.json()["error"], "InvalidRequest");
    assert!(
        commits(&h.db.pool).await.is_empty(),
        "a refused batch must not be announced"
    );
}

#[tokio::test]
async fn a_record_over_a_megabyte_is_refused() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    let refused = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "x".repeat(1_000_001)},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        refused.text()
    );
    assert_eq!(refused.json()["error"], "PayloadTooLarge");
    assert!(commits(&h.db.pool).await.is_empty());
}

#[tokio::test]
async fn two_concurrent_put_records_both_land() {
    // The spec's lost-update race, with the retry: two writes from the same
    // root, and both succeed — one of them by re-applying against the head
    // the other moved. The head's history stays linear — `since`/`prevData`
    // chain with no orphan — and no event is missing (1, C).
    let h = harness().await;
    let (user_id, cookie) = a_member(&h, "alice").await;

    let put = |rkey: &'static str, text: &'static str| {
        post_json(
            &h,
            "/xrpc/com.atproto.repo.putRecord",
            json!({
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "record": {"$type": "app.bsky.feed.post", "text": text},
            }),
            Some(&cookie),
        )
    };
    let (a, b) = tokio::join!(
        put("3kaaaaaaaaaaa", "from a"),
        put("3kbbbbbbbbbbb", "from b")
    );
    assert_eq!(a.status, StatusCode::OK, "a: {}", a.text());
    assert_eq!(b.status, StatusCode::OK, "b: {}", b.text());

    // Both records landed.
    for (rkey, text) in [("3kaaaaaaaaaaa", "from a"), ("3kbbbbbbbbbbb", "from b")] {
        let fetched = get(
            &h,
            &format!(
                "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey={rkey}"
            ),
        )
        .await;
        assert_eq!(fetched.status, StatusCode::OK, "{rkey}");
        assert_eq!(fetched.json()["value"]["text"], text);
    }

    // Both events landed, in order, and the chain between them is linear.
    let events = commits(&h.db.pool).await;
    assert_eq!(
        events.len(),
        2,
        "no event may go missing: {} events",
        events.len()
    );
    assert_eq!(events[0].ops.len(), 1);
    assert_eq!(events[1].ops.len(), 1);
    assert_eq!(
        events[1].prev_cid.as_deref(),
        Some(events[0].commit_cid.as_str()),
        "the second commit must name the first — no orphan between them"
    );
    assert_eq!(
        events[1].since_rev.as_ref(),
        Some(&events[0].rev),
        "since must chain to the previous commit's rev (1, C)"
    );

    // prevData chains to the previous commit's MST root, read back through
    // atrium from the first event's commit alone.
    let blocks = brolly_atproto::blocks::PodBlocks::new(h.stores.repo_blocks(user_id).unwrap());
    let first = atrium_repo::Repository::open(blocks, events[0].commit_cid.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        events[1].prev_data.as_deref(),
        Some(first.commit().data().to_string().as_str()),
        "prevData must be the first commit's MST root (1, C)"
    );

    // And the head is exactly the second event's commit — no third state.
    let head = brolly_atproto::state::load(&h.db.pool, user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.root_cid, events[1].commit_cid);
}

#[tokio::test]
async fn a_blob_ref_round_trips_through_the_handler() {
    // H at the endpoint: a `$blob` ref lands as a CID link in the record's
    // block — asserted against the block itself in the repo tests — and the
    // record reads back as the JSON that named it (1, H).
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "with an image",
                "image": {
                    "$type": "blob",
                    "ref": "bafkreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy",
                    "mimeType": "image/png",
                    "size": 1234,
                },
            },
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let fetched = get(
        &h,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
    )
    .await;
    assert_eq!(fetched.status, StatusCode::OK, "{}", fetched.text());
    assert_eq!(
        fetched.json()["value"]["image"]["ref"],
        "bafkreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy",
        "a blob ref must read back as the CID string that named it"
    );
    assert_eq!(fetched.json()["value"]["image"]["mimeType"], "image/png");
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

// --- legacy sessions and app passwords (stage 2, chunk 1) ----------------------------

const LOGIN_PASSWORD: &str = "correct-horse-battery";

/// A member as the session endpoints see them: an email (verified), a
/// `did:plc`, and `a_member`'s password. No pod, no repo, no keys — none of
/// the seven session endpoints touches a repository, so none of that
/// scaffolding is paid for here.
async fn a_login_member(h: &Harness, username: &str) -> db::User {
    let user = db::create_user(
        &h.db.pool,
        username,
        Some(&format!("{username}@example.com")),
        LOGIN_PASSWORD,
        "member",
    )
    .await
    .unwrap();
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user.id)
        .execute(&h.db.pool)
        .await
        .unwrap();
    let did = format!("did:plc:{username}did22222222222");
    db::set_did_plc(&h.db.pool, user.id, &did).await.unwrap();
    db::find_by_id(&h.db.pool, user.id).await.unwrap().unwrap()
}

async fn create_session(h: &Harness, identifier: &str, password: &str) -> Reply {
    post_json(
        h,
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": identifier, "password": password}),
        None,
    )
    .await
}

async fn get_with_token(h: &Harness, uri: &str, token: &str) -> Reply {
    send(
        h,
        Request::builder()
            .uri(uri)
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn post_with_token(h: &Harness, uri: &str, token: &str, body: serde_json::Value) -> Reply {
    send(
        h,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

/// An access token from a primary-password login — the credential the
/// privilege matrix allows to manage app passwords (2, B).
async fn primary_access(h: &Harness, username: &str) -> String {
    let login = create_session(h, &format!("{username}.{BASE}"), LOGIN_PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text());
    login.json()["accessJwt"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn create_session_accepts_every_identifier_form() {
    // 2, A: handle, `did:plc` (stored), `did:web` (derived), email — DID forms
    // first, so a `did:web` handle is never mistaken for a bare handle.
    let h = harness().await;
    let user = a_login_member(&h, "alice").await;
    let handle = format!("alice.{BASE}");
    let did = user.did_plc.clone().unwrap();

    for identifier in [
        handle.clone(),
        format!("did:web:{handle}"),
        did.clone(),
        "alice@example.com".to_string(),
    ] {
        let reply = create_session(&h, &identifier, LOGIN_PASSWORD).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{identifier}: {}",
            reply.text()
        );
        assert_eq!(reply.json()["handle"], handle);
        assert_eq!(reply.json()["did"], did);
        assert_eq!(reply.json()["active"], true);
        // The primary-password session sees the email fields (2, B).
        assert_eq!(reply.json()["email"], "alice@example.com");
        assert_eq!(reply.json()["emailConfirmed"], true);
    }
}

#[tokio::test]
async fn bad_credentials_answer_authentication_required() {
    let h = harness().await;
    a_login_member(&h, "alice").await;

    // A wrong password...
    let reply = create_session(&h, &format!("alice.{BASE}"), "wrong-horse").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "AuthenticationRequired");

    // ...and an unknown identifier, with the same answer and the same shape:
    // the login surface does not enumerate its members. (The Argon2 run that
    // keeps the two the same cost is `dummy_verify`, one verify either way.)
    let reply = create_session(&h, "nobody.brolly.test", LOGIN_PASSWORD).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn a_disabled_account_answers_account_takedown() {
    let h = harness().await;
    let user = a_login_member(&h, "alice").await;
    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user.id)
        .execute(&h.db.pool)
        .await
        .unwrap();

    // A wrong password still answers AuthenticationRequired: the takedown
    // answer must not be reachable without valid credentials.
    let reply = create_session(&h, &format!("alice.{BASE}"), "wrong-horse").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "AuthenticationRequired");

    // The lexicon's own error name (2, A): brolly's `disabled` is the spec's
    // `takendown`.
    let reply = create_session(&h, &format!("alice.{BASE}"), LOGIN_PASSWORD).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.text());
    assert_eq!(reply.json()["error"], "AccountTakedown");
}

#[tokio::test]
async fn the_session_endpoints_are_apex_only() {
    // ADR 0009 reserves `/xrpc/` on member subdomains, for the session
    // endpoints like the rest of the surface.
    let h = harness().await;
    a_login_member(&h, "alice").await;

    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession")
            .header(header::HOST, format!("alice.{BASE}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"identifier": "alice", "password": LOGIN_PASSWORD}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_legacy_session_writes_through_the_bearer_arm() {
    // The arm this chunk adds (2, D): the write endpoints resolve a Bearer
    // token against the legacy table, after the DPoP arm and before the
    // cookie fallback.
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let access = primary_access(&h, "alice").await;

    let created = post_with_token(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        &access,
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "with the legacy token"},
        }),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    // The read path agrees.
    let fetched = get(
        &h,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.feed.post&rkey=3kaaaaaaaaaaa"
        ),
    )
    .await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.json()["value"]["text"], "with the legacy token");
    let _ = cookie;
}

#[tokio::test]
async fn get_session_email_visibility_follows_the_privilege_matrix() {
    // 2, B: primary / privileged / unprivileged.
    let h = harness().await;
    a_login_member(&h, "alice").await;

    // Unauthenticated first: the matrix is about *visibility*, which needs an
    // authenticated session to mean anything.
    let reply = get(&h, "/xrpc/com.atproto.server.getSession").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    let access = primary_access(&h, "alice").await;

    // The primary session sees the email.
    let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &access).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["email"], "alice@example.com");
    assert_eq!(reply.json()["emailConfirmed"], true);

    for (name, privileged, visible) in [("plain", false, false), ("trusted", true, true)] {
        let created = post_with_token(
            &h,
            "/xrpc/com.atproto.server.createAppPassword",
            &access,
            json!({"name": name, "privileged": privileged}),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK, "{}", created.text());
        assert_eq!(created.json()["privileged"], privileged);
        let password = created.json()["password"].as_str().unwrap().to_string();

        let login = create_session(&h, &format!("alice.{BASE}"), &password).await;
        assert_eq!(login.status, StatusCode::OK, "{}", login.text());
        // The app-password login answers by the same rule it will be held to.
        assert_eq!(
            login.json().get("email").is_some(),
            visible,
            "createSession for {name}"
        );
        let refresh = login.json()["refreshJwt"].as_str().unwrap().to_string();
        let token = login.json()["accessJwt"].as_str().unwrap().to_string();

        let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &token).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.json().get("email").is_some(),
            visible,
            "getSession for {name}"
        );

        // Provenance survives rotation (2, A): the new pair carries the same
        // `app_password_id`, so the same visibility.
        let rotated = post_with_token(
            &h,
            "/xrpc/com.atproto.server.refreshSession",
            &refresh,
            json!({}),
        )
        .await;
        assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.text());
        let rotated_access = rotated.json()["accessJwt"].as_str().unwrap().to_string();
        let reply =
            get_with_token(&h, "/xrpc/com.atproto.server.getSession", &rotated_access).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.json().get("email").is_some(),
            visible,
            "getSession after refresh for {name}"
        );
    }
}

#[tokio::test]
async fn refresh_session_rotates_the_pair() {
    let h = harness().await;
    a_login_member(&h, "alice").await;
    let login = create_session(&h, &format!("alice.{BASE}"), LOGIN_PASSWORD).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text());
    let access = login.json()["accessJwt"].as_str().unwrap().to_string();
    let refresh = login.json()["refreshJwt"].as_str().unwrap().to_string();

    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.refreshSession",
        &refresh,
        json!({}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["handle"], format!("alice.{BASE}"));
    assert_eq!(reply.json()["active"], true);
    let new_access = reply.json()["accessJwt"].as_str().unwrap().to_string();
    let new_refresh = reply.json()["refreshJwt"].as_str().unwrap().to_string();
    assert_ne!(new_access, access);
    assert_ne!(new_refresh, refresh);

    // The new pair lives...
    let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &new_access).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    // ...and the old pair is dead, both halves (2, A: "revoke the old rows"):
    // the refresh by rotation, the access with the session.
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.refreshSession",
        &refresh,
        json!({}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "InvalidToken");
    let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &access).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_refresh_token_answers_by_its_own_condition() {
    let h = harness().await;
    a_login_member(&h, "alice").await;

    // Unknown → `InvalidToken`, the lexicon's own name (2, A).
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.refreshSession",
        "not-a-token",
        json!({}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "InvalidToken");

    // Expired → `ExpiredToken`, distinguished from invalid because a client's
    // recovery differs: re-login, not a retry.
    let login = create_session(&h, &format!("alice.{BASE}"), LOGIN_PASSWORD).await;
    let refresh = login.json()["refreshJwt"].as_str().unwrap().to_string();
    sqlx::query(
        "UPDATE atproto_legacy_tokens SET expires_at = now() - interval '1 second'
         WHERE token_hash = $1",
    )
    .bind(db::hash_secret(&refresh))
    .execute(&h.db.pool)
    .await
    .unwrap();
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.refreshSession",
        &refresh,
        json!({}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.text());
    assert_eq!(reply.json()["error"], "ExpiredToken");
}

#[tokio::test]
async fn delete_session_kills_both_halves_of_the_pair() {
    let h = harness().await;
    a_login_member(&h, "alice").await;
    let login = create_session(&h, &format!("alice.{BASE}"), LOGIN_PASSWORD).await;
    let access = login.json()["accessJwt"].as_str().unwrap().to_string();
    let refresh = login.json()["refreshJwt"].as_str().unwrap().to_string();

    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.deleteSession",
        &refresh,
        json!({}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    // The access token died with the session, not at expiry (2, A)...
    let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &access).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.text());
    // ...and the refresh with it.
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.refreshSession",
        &refresh,
        json!({}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "InvalidToken");
}

#[tokio::test]
async fn app_passwords_take_the_http_api_specs_own_format() {
    let h = harness().await;
    a_login_member(&h, "alice").await;
    let access = primary_access(&h, "alice").await;

    for _ in 0..8 {
        let created = post_with_token(
            &h,
            "/xrpc/com.atproto.server.createAppPassword",
            &access,
            json!({"name": format!("app-{}", uuid::Uuid::new_v4())}),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK, "{}", created.text());
        let body = created.json();
        let password = body["password"].as_str().unwrap();
        // ^[a-z0-9]{4}(-[a-z0-9]{4}){3}$, by hand: no regex crate in the tree.
        let groups: Vec<&str> = password.split('-').collect();
        assert_eq!(groups.len(), 4, "{password}");
        for group in &groups {
            assert_eq!(group.len(), 4, "{password}");
            assert!(
                group
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{password}"
            );
        }
        // The lexicon's `datetime` format.
        let created_at = body["createdAt"].as_str().unwrap();
        assert!(created_at.contains('T'), "{created_at}");
    }
}

#[tokio::test]
async fn the_plaintext_appears_once_and_the_list_omits_it() {
    let h = harness().await;
    a_login_member(&h, "alice").await;
    let access = primary_access(&h, "alice").await;

    let created = post_with_token(
        &h,
        "/xrpc/com.atproto.server.createAppPassword",
        &access,
        json!({"name": "my phone"}),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let password = created.json()["password"].as_str().unwrap().to_string();
    assert_eq!(created.json()["name"], "my phone");

    // The list carries the row without the password (2, B): the lexicon's
    // list schema omits the field, and the stored hash could not return one.
    let listed = get_with_token(&h, "/xrpc/com.atproto.server.listAppPasswords", &access).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text());
    let body = listed.json();
    let passwords = body["passwords"].as_array().unwrap();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0]["name"], "my phone");
    assert!(passwords[0].get("password").is_none());
    // And the whole body carries no trace of the plaintext.
    assert!(!listed.text().contains(&password));

    // A duplicate name is refused, not silently duplicated.
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.createAppPassword",
        &access,
        json!({"name": "my phone"}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.text());
}

#[tokio::test]
async fn an_app_password_session_cannot_manage_app_passwords() {
    // The privilege matrix (2, B): the HTTP API spec's own sentence — app
    // passwords do not make changes to authentication settings, which
    // includes app passwords themselves.
    let h = harness().await;
    a_login_member(&h, "alice").await;
    let access = primary_access(&h, "alice").await;

    let created = post_with_token(
        &h,
        "/xrpc/com.atproto.server.createAppPassword",
        &access,
        json!({"name": "the only one"}),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    let password = created.json()["password"].as_str().unwrap().to_string();

    let login = create_session(&h, &format!("alice.{BASE}"), &password).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text());
    let app_access = login.json()["accessJwt"].as_str().unwrap().to_string();

    // All three, because the rule is the surface's, not one endpoint's.
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.createAppPassword",
        &app_access,
        json!({"name": "another"}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
    let reply = get_with_token(&h, "/xrpc/com.atproto.server.listAppPasswords", &app_access).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.revokeAppPassword",
        &app_access,
        json!({"name": "the only one"}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // An OAuth token cannot manage them either (2, B): the profile's
    // `transition:generic` excludes account management. Presented as the
    // DPoP credential it is, so the 403 is a privilege answer, not a 401.
    let (_, cookie) = a_member(&h, "bob").await;
    let key = p256::ecdsa::SigningKey::from_slice(&[21u8; 32]).unwrap();
    let token = atproto_access_token(&h, &cookie, &key).await;
    let ath = B64.encode(Sha256::digest(token.as_bytes()));
    let reply = send(
        &h,
        Request::builder()
            .uri("/xrpc/com.atproto.server.listAppPasswords")
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("DPoP {token}"))
            .header(
                "DPoP",
                dpop_proof(&key, "POST", &format!("https://{BASE}/xrpc/"), Some(&ath)),
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
}

#[tokio::test]
async fn revoking_an_app_password_kills_its_sessions_immediately() {
    // The whole point of opaque rows (2, B): the reference's self-asserting
    // JWT sessions outlive revocation until their next refresh; rows with
    // `ON DELETE CASCADE` do not.
    let h = harness().await;
    a_login_member(&h, "alice").await;
    let access = primary_access(&h, "alice").await;

    let created = post_with_token(
        &h,
        "/xrpc/com.atproto.server.createAppPassword",
        &access,
        json!({"name": "phone"}),
    )
    .await;
    let password = created.json()["password"].as_str().unwrap().to_string();

    let login = create_session(&h, &format!("alice.{BASE}"), &password).await;
    let app_access = login.json()["accessJwt"].as_str().unwrap().to_string();
    let app_refresh = login.json()["refreshJwt"].as_str().unwrap().to_string();

    // Alive before...
    let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &app_access).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    // ...dead the moment the row dies, both halves, and the password with
    // them.
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.revokeAppPassword",
        &access,
        json!({"name": "phone"}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &app_access).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.text());
    let reply = post_with_token(
        &h,
        "/xrpc/com.atproto.server.refreshSession",
        &app_refresh,
        json!({}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "InvalidToken");

    let login = create_session(&h, &format!("alice.{BASE}"), &password).await;
    assert_eq!(login.status, StatusCode::UNAUTHORIZED, "{}", login.text());
    assert_eq!(login.json()["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn changing_a_password_ends_the_atproto_sessions() {
    // The wiring this chunk adds (2, G): a password change ends the ATProto
    // sessions too — both tables — not just the browser ones.
    let h = harness().await;
    let user = a_login_member(&h, "alice").await;

    // A legacy session...
    let login = create_session(&h, &format!("alice.{BASE}"), LOGIN_PASSWORD).await;
    let access = login.json()["accessJwt"].as_str().unwrap().to_string();

    // ...and an OAuth one, driven as a real client drives it (PAR, consent,
    // decision, token), through the browser session the dashboard uses.
    let session = db::create_session(&h.db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    let cookie = format!("brolly_session={session}");
    let key = p256::ecdsa::SigningKey::from_slice(&[21u8; 32]).unwrap();
    let oauth_token = atproto_access_token(&h, &cookie, &key).await;

    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/account/security")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie)
            .body(Body::from(
                form_urlencoded::Serializer::new(String::new())
                    .append_pair("current_password", LOGIN_PASSWORD)
                    .append_pair("new_password", "a-new-longer-password")
                    .finish(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text());

    // The legacy session is dead...
    let reply = get_with_token(&h, "/xrpc/com.atproto.server.getSession", &access).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.text());

    // ...and the OAuth one with it, which is the half that had no caller at
    // all before this (`oauth::revoke_all_for_user`).
    let target = format!("https://{BASE}/xrpc/");
    let ath = B64.encode(Sha256::digest(oauth_token.as_bytes()));
    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.repo.createRecord")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("DPoP {oauth_token}"))
            .header("DPoP", dpop_proof(&key, "POST", &target, Some(&ath)))
            .body(Body::from(
                json!({
                    "collection": "app.bsky.feed.post",
                    "rkey": "3kaaaaaaaaaaa",
                    "record": {"$type": "app.bsky.feed.post", "text": "after"},
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.text());
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

    let events = commits(&h.db.pool).await;
    assert_eq!(events.len(), 1, "the write was not announced");
    assert_eq!(
        events[0].ops.len(),
        1,
        "a single write is one event with one op"
    );
    assert_eq!(
        events[0].ops[0].action,
        brolly_atproto::firehose::Action::Create
    );
    assert_eq!(events[0].ops[0].path, "app.bsky.feed.post/3kaaaaaaaaaaa");
    assert!(events[0].commit_cid.starts_with("bafy"));
    assert!(
        events[0].ops[0].record_cid.is_some(),
        "a create announces the record it wrote"
    );
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

    let events = commits(&h.db.pool).await;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[1].ops[0].action,
        brolly_atproto::firehose::Action::Delete
    );
    assert_eq!(
        events[1].ops[0].record_cid, None,
        "a delete announces no record CID"
    );
    assert!(
        events[1].ops[0].prev_cid.is_some(),
        "a delete announces the record it removed (1, D)"
    );
}

#[tokio::test]
async fn the_announcement_chains_to_the_previous_commit() {
    // A consumer verifies `prev` against what it already has; an event that
    // does not name its predecessor cannot be checked.
    let h = harness().await;
    let (user_id, cookie) = a_member(&h, "alice").await;

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

    let events = commits(&h.db.pool).await;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[1].prev_cid.as_deref(),
        Some(events[0].commit_cid.as_str()),
        "the second commit must name the first"
    );
    // The revs are TIDs, and TID text orders like TID numbers (1, A).
    assert!(
        events[1].rev.as_str() > events[0].rev.as_str(),
        "revisions must advance"
    );
    // And the chain a syncing consumer actually walks: `since` names the
    // rev the commit is based on, `prevData` the MST root it replaced —
    // the previous commit's `data` field, read back here through atrium
    // from the previous commit alone (1, A).
    let blocks = brolly_atproto::blocks::PodBlocks::new(h.stores.repo_blocks(user_id).unwrap());
    let previous = atrium_repo::Repository::open(blocks, events[0].commit_cid.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        events[1].since_rev.as_ref(),
        Some(&events[0].rev),
        "since must name the previous commit's own rev"
    );
    assert_eq!(
        events[1].prev_data.as_deref(),
        Some(previous.commit().data().to_string().as_str()),
        "prevData must be the previous commit's MST root"
    );
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

/// A frame's header, decoded the way a relay reads it: dispatch on `t` before
/// the body is parsed (1, D). `t` is optional because error frames carry none
/// — the event-stream spec says the type fragment does not ride an error
/// header (1, F).
#[derive(serde::Deserialize)]
struct FrameHeader {
    op: i64,
    #[serde(default)]
    t: Option<String>,
}

/// Read one binary frame off the socket and decode it the way a foreign
/// consumer does: header first, then the body as atrium-api's own type for
/// the kind the header names (1, E).
async fn a_frame<T: serde::de::DeserializeOwned>(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> (String, T) {
    use futures_util::StreamExt;
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("the stream should not stall")
            .expect("the stream should not end")
            .expect("a readable frame");
        let tokio_tungstenite::tungstenite::Message::Binary(frame) = message else {
            continue;
        };
        let mut reader = std::io::Cursor::new(&frame);
        let header: FrameHeader =
            serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the header decodes");
        assert_eq!(header.op, 1, "an event frame is op 1");
        let body = serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the body decodes");
        return (header.t.expect("an event frame names its type"), body);
    }
}

/// One binary frame off the socket — `None` when the stream closes or stalls,
/// which is what every "and then the server closes" assertion needs to tell
/// from a frame (1, F).
async fn a_binary_frame(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<Vec<u8>> {
    use futures_util::StreamExt;
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("the stream should not stall");
        match message {
            // The server closed — the event-stream spec's "immediately" after
            // an error frame, or a shutdown.
            None => return None,
            Some(Err(_)) => return None,
            Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(frame))) => return Some(frame),
            Some(Ok(_)) => continue,
        }
    }
}

/// One frame, dispatched the way a relay reads it: on the header's `op` and
/// `t`, then decoded as atrium-api's own type for that kind (1, F). The kinds
/// the cursor rules speak in — an `#info` with no `seq`, an error with no `t`
/// `t` — are first-class here because they are what these tests assert on.
#[derive(Debug)]
enum AFrame {
    Commit(Box<atrium_api::com::atproto::sync::subscribe_repos::Commit>),
    Identity(atrium_api::com::atproto::sync::subscribe_repos::Identity),
    Account(atrium_api::com::atproto::sync::subscribe_repos::Account),
    Info(atrium_api::com::atproto::sync::subscribe_repos::Info),
    Error(atrium_api::com::atproto::sync::subscribe_repos::Error),
}

async fn the_next_frame(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> AFrame {
    fn decode<T: serde::de::DeserializeOwned>(reader: &mut std::io::Cursor<&Vec<u8>>) -> T {
        serde_ipld_dagcbor::de::from_reader_once(reader).expect("the body decodes")
    }
    let frame = a_binary_frame(socket)
        .await
        .expect("a readable frame — the stream closed early");
    let mut reader = std::io::Cursor::new(&frame);
    let header: FrameHeader =
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the header decodes");
    match (header.op, header.t.as_deref()) {
        (1, Some("#commit")) => AFrame::Commit(Box::new(decode(&mut reader))),
        (1, Some("#identity")) => AFrame::Identity(decode(&mut reader)),
        (1, Some("#account")) => AFrame::Account(decode(&mut reader)),
        (1, Some("#info")) => AFrame::Info(decode(&mut reader)),
        (-1, None) => AFrame::Error(decode(&mut reader)),
        other => panic!("a frame shape the relay does not know: {other:?}"),
    }
}

#[tokio::test]
async fn registration_logs_an_identity_event() {
    // The identity layer owns the transition, and the hook is there: the
    // genesis operation lands and its `#identity` event lands with it, in the
    // same transaction — the durable log, not the live channel, is what a
    // reconnecting relay reads (1, E).
    let h = harness().await;
    a_registered_member(&h, "alice").await;

    let user = db::find_by_username(&h.db.pool, "alice")
        .await
        .unwrap()
        .unwrap();
    let did = user.did_plc.expect("registration mints a DID");

    let events = brolly_atproto::firehose::since(&h.db.pool, None, 10)
        .await
        .unwrap();
    let identity = events
        .iter()
        .find_map(|event| match event {
            brolly_atproto::firehose::Event::Identity(identity) => Some(identity),
            _ => None,
        })
        .expect("registration logs an #identity event");
    assert_eq!(identity.did, did);
    assert_eq!(identity.handle.as_deref(), Some("alice.brolly.test"));

    // And the event frames as atrium's own type — the foreign decoder, on a
    // row the real registration path wrote. The header is consumed first, the
    // way a consumer dispatches before it parses the body (1, D).
    let frame = brolly_atproto::firehose::identity_frame(identity).unwrap();
    let mut reader = std::io::Cursor::new(&frame);
    let header: FrameHeader =
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the header decodes");
    assert_eq!(header.t.as_deref(), Some("#identity"));
    let decoded: atrium_api::com::atproto::sync::subscribe_repos::Identity =
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).unwrap();
    assert_eq!(decoded.did.as_str(), did);
    assert_eq!(
        decoded.handle.as_ref().map(|h| h.as_str()),
        Some("alice.brolly.test")
    );
}

#[tokio::test]
async fn deleting_an_account_announces_it_on_the_firehose() {
    // The whole arc on one sequence: signup logs `#identity`, a write logs
    // `#commit`, deletion logs `#account` — and a relay connecting from zero
    // receives them through the real socket, decoded by atrium's own types
    // (1, E).
    //
    // The `#commit` in between is *not* delivered: its member is gone by the
    // time this relay connects, and a diff for a deleted repo is not a diff a
    // consumer can apply. The `#account` event is the frame that says why.
    let h = harness().await;
    let cookie = a_registered_member(&h, "alice").await;
    let user = db::find_by_username(&h.db.pool, "alice")
        .await
        .unwrap()
        .unwrap();
    let did = user.did_plc.expect("registration mints a DID");

    let created = post_json(
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
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    // Delete through the front door — the confirm field is the one the form
    // asks for, the member's own username.
    let deleted = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/account/delete")
                .header(header::HOST, BASE)
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("confirm=alice"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);

    let addr = serve(h.router.clone()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=0"
    ))
    .await
    .expect("a relay must be able to open the stream");

    let (kind, identity): (
        String,
        atrium_api::com::atproto::sync::subscribe_repos::Identity,
    ) = a_frame(&mut socket).await;
    assert_eq!(kind, "#identity");
    assert_eq!(identity.did.as_str(), did);
    assert_eq!(
        identity.handle.as_ref().map(|h| h.as_str()),
        Some("alice.brolly.test")
    );

    // The commit for the deleted member is skipped — the member cannot be
    // resolved, and the frame would pretend a diff nothing could invert.
    let (kind, account): (
        String,
        atrium_api::com::atproto::sync::subscribe_repos::Account,
    ) = a_frame(&mut socket).await;
    assert_eq!(kind, "#account");
    assert_eq!(account.did.as_str(), did);
    assert!(!account.active, "a deleted account is not active");
    assert_eq!(account.status.as_deref(), Some("deleted"));

    // The cursor moved past the skipped commit: the account event's seq is the
    // commit's plus two, and nothing else is coming.
    assert_eq!(account.seq, 3, "identity, commit, account — in order");
}

/// A cursor for events that do not exist yet — the client bug the lexicon
/// names rather than absorbs (1, F).
#[tokio::test]
async fn a_cursor_ahead_of_the_head_is_refused() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "the head"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let addr = serve(h.router.clone()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=99"
    ))
    .await
    .expect("a relay must be able to open the stream");

    match the_next_frame(&mut socket).await {
        AFrame::Error(atrium_api::com::atproto::sync::subscribe_repos::Error::FutureCursor(_)) => {}
        other => panic!("a future cursor is a FutureCursor error, got {other:?}"),
    }
    // The close is the event-stream spec's "immediately" — not a retry, not
    // silence: the client is wrong and must be told so before it waits.
    assert!(
        a_binary_frame(&mut socket).await.is_none(),
        "the stream must close after an error frame"
    );
}

/// A cursor the log can no longer fully serve — advice first, then the oldest
/// row (1, E, 1, F). Retention is a non-goal, so the removed rows are a
/// fixture for the day it is not; the rule has to exist before the removal
/// does, or every consumer that trusts its cursor corrupts quietly.
#[tokio::test]
async fn an_outdated_cursor_is_advised_then_served_from_the_oldest_row() {
    use brolly_atproto::firehose;

    let h = harness().await;
    // Account events — self-contained on the wire, so removing the first two
    // takes no op rows with them (1, E).
    for n in 1..=3 {
        let mut tx = h.db.pool.begin().await.unwrap();
        firehose::record_account(
            &mut tx,
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            n != 3,
            (n != 3).then_some("deleted"),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // The retention fixture: rows 1 and 2 are gone, row 3 is the oldest.
    sqlx::query("DELETE FROM atproto_firehose WHERE seq <= 2")
        .execute(&h.db.pool)
        .await
        .unwrap();

    let addr = serve(h.router.clone()).await;

    // A cursor one below the oldest row is the normal resume position: it has
    // missed nothing, and advising it would be noise.
    let (mut resumed, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=2"
    ))
    .await
    .expect("a relay must be able to open the stream");
    match the_next_frame(&mut resumed).await {
        AFrame::Account(account) => assert_eq!(account.seq, 3),
        other => panic!("a cursor at the window's edge resumes directly, got {other:?}"),
    }

    // A cursor below that may have missed events it can never see: the advice
    // is an `#info` — not an error, the stream can still serve — and the
    // service resumes from the oldest row (1, F).
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=1"
    ))
    .await
    .expect("a relay must be able to open the stream");
    match the_next_frame(&mut socket).await {
        AFrame::Info(info) => assert_eq!(info.name, "OutdatedCursor"),
        other => panic!("an outdated cursor is advised first, got {other:?}"),
    }
    match the_next_frame(&mut socket).await {
        AFrame::Account(account) => assert_eq!(
            account.seq, 3,
            "the stream continues from the oldest retained row"
        ),
        other => panic!("the oldest row follows the advice, got {other:?}"),
    }
}

/// The race the attach-first order closes (1, F): in the old order — drain
/// the table, then subscribe — an event committed between the two was in
/// neither and was missed, exactly once per connection. The writer is pinned
/// behind a table lock until the subscriber's backfill has visibly delivered
/// the committed rows, so the raced event's commit lands inside the window
/// the old order lost — and must arrive exactly once, whichever side of the
/// boundary it lands on: in the last page, or in the ring, or in both.
#[tokio::test]
async fn an_event_committed_during_the_backfill_is_delivered_exactly_once() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    for n in 1..=2 {
        let created = post_json(
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
        assert_eq!(created.status, StatusCode::OK, "{}", created.text());
    }

    // The gate: `SHARE ROW EXCLUSIVE` blocks the INSERT the write's
    // announcement performs, and nothing a subscriber's backfill needs — a
    // plain SELECT never waits on it.
    let mut gate = h.db.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE atproto_firehose IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();

    // The raced write, pinned mid-announcement: its row exists only when the
    // gate opens.
    let router = h.router.clone();
    let cookie2 = cookie.clone();
    let raced = tokio::spawn(async move {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.createRecord")
                    .header(header::HOST, BASE)
                    .header(header::COOKIE, cookie2)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "collection": "app.bsky.feed.post",
                            "rkey": "3kggggggggggg",
                            "record": {"$type": "app.bsky.feed.post", "text": "the raced write"},
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    });

    let addr = serve(h.router.clone()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=0"
    ))
    .await
    .expect("a relay must be able to open the stream");

    // The backfill delivers the two committed rows. The second frame proves
    // the table was read past them; the raced write is still invisible — its
    // row is uncommitted behind the gate.
    let mut seqs = Vec::new();
    while seqs.len() < 2 {
        match the_next_frame(&mut socket).await {
            AFrame::Commit(commit) => seqs.push(commit.seq),
            other => panic!("the backfill delivers the committed rows, got {other:?}"),
        }
    }

    // Open the gate: the write commits — inside the window the old order
    // lost, between the subscriber's last page and its live tail.
    gate.rollback().await.unwrap();
    assert_eq!(raced.await.unwrap().status(), StatusCode::OK);

    // A marker write, uncontended, to close the assertion's window: once its
    // seq arrives, a duplicate of the raced event could only have been
    // delivered before it — and the seq list would show it.
    let marker = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3khhhhhhhhhhh",
            "record": {"$type": "app.bsky.feed.post", "text": "the marker"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(marker.status, StatusCode::OK, "{}", marker.text());

    while seqs.last().copied() != Some(4) {
        match the_next_frame(&mut socket).await {
            AFrame::Commit(commit) => seqs.push(commit.seq),
            other => panic!("the live tail delivers, got {other:?}"),
        }
    }
    assert_eq!(
        seqs,
        vec![1, 2, 3, 4],
        "the raced event is delivered exactly once, in order — from the table, the ring, or both"
    );
}

/// The event-stream spec's "no cursor" case: the current position, live only
/// (1, F). This stream used to treat an absent cursor as `0` — the whole
/// retained window — and the change is asserted here so it cannot drift back:
/// the pre-attach history must not be replayed at a subscriber that never
/// asked for it.
#[tokio::test]
async fn a_subscriber_without_a_cursor_receives_only_what_happens_next() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;

    // A witness on the channel before the setup write, so the test can tell
    // when the listener has caught up: the setup event is sent to the channel
    // twice — once by the writer's fast path, once by the listener's
    // rebroadcast — and until both have landed, a socket attaching now could
    // receive the second as a live frame (a new broadcast receiver sees only
    // sends after its subscribe, and the listener's send is still pending).
    // Waiting for both makes the live-only assertion about the *table*, which
    // is the assertion the case is for.
    let mut witness = h.commits.subscribe();
    let first = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "before the attach"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    let mut deliveries_of_seq_1 = 0;
    while deliveries_of_seq_1 < 2 {
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), witness.recv())
            .await
            .expect("the setup event must reach the channel")
            .expect("the channel outlives the harness");
        if event.seq() == 1 {
            deliveries_of_seq_1 += 1;
        }
    }

    // The same gate discipline as the backfill-race test: a live-only stream
    // sends nothing to prove its subscription with, so the first live write
    // is pinned behind the gate until the socket has attached — the rollback's
    // await is the yield that lets the stream task take its subscription
    // before the write's announcement can send past it.
    let mut gate = h.db.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE atproto_firehose IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();

    let router = h.router.clone();
    let cookie2 = cookie.clone();
    let live = tokio::spawn(async move {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.atproto.repo.createRecord")
                    .header(header::HOST, BASE)
                    .header(header::COOKIE, cookie2)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "collection": "app.bsky.feed.post",
                            "rkey": "3kbbbbbbbbbbb",
                            "record": {"$type": "app.bsky.feed.post", "text": "live"},
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    });

    let addr = serve(h.router.clone()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos"
    ))
    .await
    .expect("a relay must be able to open the stream");

    // Releasing the gate completes only after the stream task has had the
    // yield it needs to subscribe; the pinned write's announcement cannot
    // have preceded that.
    gate.rollback().await.unwrap();
    assert_eq!(live.await.unwrap().status(), StatusCode::OK);

    // The marker that closes the window, uncontended.
    let marker = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kccccccccccc",
            "record": {"$type": "app.bsky.feed.post", "text": "the marker"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(marker.status, StatusCode::OK, "{}", marker.text());

    let mut seqs = Vec::new();
    while seqs.last().copied() != Some(3) {
        match the_next_frame(&mut socket).await {
            AFrame::Commit(commit) => seqs.push(commit.seq),
            other => panic!("a live-only stream delivers what happens next, got {other:?}"),
        }
    }
    assert_eq!(
        seqs,
        vec![2, 3],
        "no cursor is live only: the pre-attach history (seq 1) is not replayed"
    );
}

/// The correctness mechanism of (1, G): the broadcast channel is
/// process-local, so an event written through another pool — a second
/// process's — reaches a live subscriber through the transactional notify and
/// the shared listener, not through the writer. The witness receiver is the
/// airtight half of the assertion: only the listener ever sends on the
/// channel for this event, because the second "process" never held the
/// sender. The socket is the end-to-end half.
#[tokio::test]
async fn a_second_processs_writes_reach_live_subscribers() {
    use brolly_atproto::firehose;

    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "the setup"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    // Pin the second process's write behind the gate until the socket has
    // attached — the same discipline as the backfill-race test.
    let mut gate = h.db.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE atproto_firehose IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();

    // The second process: its own pool, its own connection, an identity event
    // logged in its own transaction (1, E, 1, G).
    let url = h.db.url.clone();
    let second = tokio::spawn(async move {
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        let event = firehose::record_identity(
            &mut tx,
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            Some("second.brolly.test"),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        event
    });

    // The witness on the channel, subscribed before the gate can open.
    let mut witness = h.commits.subscribe();

    let addr = serve(h.router.clone()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=0"
    ))
    .await
    .expect("a relay must be able to open the stream");

    // The setup commit arrives, which proves the subscription was taken
    // before the table was read (1, F).
    match the_next_frame(&mut socket).await {
        AFrame::Commit(commit) => assert_eq!(commit.seq, 1),
        other => panic!("the backfill delivers the setup, got {other:?}"),
    }

    // Open the gate: the second process's write commits, its notify rides the
    // commit, and the listener — attached before any of this — picks it up.
    gate.rollback().await.unwrap();
    let event = second.await.unwrap();
    assert_eq!(event.seq, 2);

    // The airtight half: the witness receives the event, and the only sender
    // that could have put it on the channel is the shared listener. (The
    // setup commit's own broadcasts, however many the ring still holds, are
    // skipped by seq.)
    let heard = loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), witness.recv())
            .await
            .expect("the listener must rebroadcast a second process's event")
            .expect("the channel outlives the harness");
        if event.seq() > 1 {
            break event;
        }
    };
    assert_eq!(
        heard.seq(),
        2,
        "the listener rebroadcast the second process's event"
    );

    // The end-to-end half: a socket attached through the same channel
    // receives it exactly once — a marker write closes the window the way the
    // backfill-race test's does.
    let marker = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kbbbbbbbbbbb",
            "record": {"$type": "app.bsky.feed.post", "text": "the marker"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(marker.status, StatusCode::OK, "{}", marker.text());

    let mut seqs = vec![1];
    while seqs.last().copied() != Some(3) {
        match the_next_frame(&mut socket).await {
            AFrame::Commit(commit) => seqs.push(commit.seq),
            AFrame::Identity(identity) => seqs.push(identity.seq),
            other => panic!("the live tail delivers, got {other:?}"),
        }
    }
    assert_eq!(
        seqs,
        vec![1, 2, 3],
        "the second process's event is delivered exactly once"
    );
}

/// The bounded buffer's far side (1, F): the ring is the channel's capacity,
/// and the lexicon names what hitting it means — `ConsumerTooSlow`, an error
/// frame, and the close whose designed recovery is the cursor. The burst is
/// `capacity + 6` events committed in one second-process transaction, so the
/// listener's rebroadcast pass sends them all without an await point and the
/// subscriber's receiver is provably behind the bound when the pass ends.
#[tokio::test]
async fn a_subscriber_slower_than_the_buffer_is_named_and_closed() {
    use brolly_atproto::firehose;

    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "app.bsky.feed.post",
            "rkey": "3kaaaaaaaaaaa",
            "record": {"$type": "app.bsky.feed.post", "text": "the anchor"},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let addr = serve(h.router.clone()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=0"
    ))
    .await
    .expect("a relay must be able to open the stream");

    // The anchor's delivery proves the subscription was taken (1, F) — the
    // burst below must not race it.
    match the_next_frame(&mut socket).await {
        AFrame::Commit(commit) => assert_eq!(commit.seq, 1),
        other => panic!("the backfill delivers the anchor, got {other:?}"),
    }

    // The burst: capacity + 6 account events in one transaction. One commit
    // makes them all visible at once; the listener reads them in one pass and
    // rebroadcasts in one slice; the ring holds 64, so the receiver misses
    // the last six's predecessors and is told so.
    let url = h.db.url.clone();
    let burst = tokio::spawn(async move {
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        for _ in 0..70 {
            firehose::record_account(
                &mut tx,
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                false,
                Some("deleted"),
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    });
    burst.await.unwrap();

    match the_next_frame(&mut socket).await {
        AFrame::Error(atrium_api::com::atproto::sync::subscribe_repos::Error::ConsumerTooSlow(
            _,
        )) => {}
        other => panic!("a subscriber behind the buffer is told ConsumerTooSlow, got {other:?}"),
    }
    assert!(
        a_binary_frame(&mut socket).await.is_none(),
        "the stream must close after the error — the cursor is the recovery"
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
