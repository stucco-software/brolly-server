//! Profile flags, and locking that actually locks.
//!
//! The fourth verified P0 defect: `locked`, `bot` and `discoverable` were
//! accepted by `update_credentials` and ignored, and the Follow processor
//! auto-accepted unconditionally. So locking an account did nothing — and did
//! nothing *invisibly*, because the profile still rendered the padlock. A
//! member who locked their account believed they were approving followers while
//! everyone was being let straight in.
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
            commits: tokio::sync::broadcast::channel(64).0,
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
    body: String,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("expected JSON, got {}: {}", self.body, e))
    }
}

async fn send(h: &Harness, request: Request<Body>) -> Reply {
    let response = h.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    Reply { status, body }
}

fn builder(method: &str, uri: &str, token: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, BASE)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
}

async fn form(h: &Harness, method: &str, uri: &str, body: &str, token: &str) -> Reply {
    send(
        h,
        builder(method, uri, token)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
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
    .expect("create user");
    let pod = h.stores.pod(user.id).unwrap();
    brolly_server::provision::pod(&pod, username, BASE).unwrap();

    let app = brolly_mastodon::oauth::register_app(
        &h.db.pool,
        "Phanpy",
        &["https://app.example/cb".into()],
        "read write follow",
        None,
    )
    .await
    .unwrap();
    let token = brolly_mastodon::oauth::issue_token(
        &h.db.pool,
        &app.app.client_id,
        user.id,
        "read write follow",
    )
    .await
    .unwrap();
    (user.id, token)
}

/// Deliver a Follow from `follower` to `followee`, as the wire would.
async fn follow(h: &Harness, follower: &str, followee: &str) {
    let actor = brolly_identity::webid::actor(follower, BASE);
    let target = brolly_identity::webid::actor(followee, BASE);
    let activity = serde_json::json!({
        "type": "Follow",
        "id": format!("https://{follower}.{BASE}/~/follows/1"),
        "actor": actor,
        "object": target,
    });

    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/outbox")
                .header(header::HOST, format!("{follower}.{BASE}"))
                .header(header::CONTENT_TYPE, "application/activity+json")
                .header(
                    header::COOKIE,
                    format!("brolly_session={}", session_for(h, follower).await),
                )
                .body(Body::from(activity.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "the Follow should have been published"
    );
}

async fn session_for(h: &Harness, username: &str) -> String {
    let user = db::find_by_username(&h.db.pool, username)
        .await
        .unwrap()
        .unwrap();
    db::create_session(&h.db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap()
}

// --- the flags are stored and read back ---------------------------------------

#[tokio::test]
async fn locking_an_account_is_recorded_and_reported() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let updated = form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "locked=true",
        &token,
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "body: {}", updated.body);
    assert_eq!(updated.json()["locked"], true);

    // And it survives a re-read, rather than only being echoed back.
    let account = send(
        &h,
        builder("GET", "/api/v1/accounts/verify_credentials", &token)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(account.json()["locked"], true);
}

#[tokio::test]
async fn bot_and_discoverable_are_stored_too() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "bot=true&discoverable=false",
        &token,
    )
    .await;

    let account = send(
        &h,
        builder("GET", "/api/v1/accounts/verify_credentials", &token)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .json();
    assert_eq!(account["bot"], true);
    assert_eq!(account["discoverable"], false);
}

#[tokio::test]
async fn a_new_account_is_unlocked_and_discoverable() {
    // Both defaults are the permissive one, and they are opposite values —
    // which is exactly why they are asserted rather than assumed.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let account = send(
        &h,
        builder("GET", "/api/v1/accounts/verify_credentials", &token)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .json();
    assert_eq!(account["locked"], false);
    assert_eq!(account["discoverable"], true);
    assert_eq!(account["bot"], false);
}

#[tokio::test]
async fn updating_one_field_leaves_the_others_alone() {
    // A client sending only `locked` must not blank the display name it never
    // mentioned.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "display_name=Alice%20Example",
        &token,
    )
    .await;
    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "locked=true",
        &token,
    )
    .await;

    let account = send(
        &h,
        builder("GET", "/api/v1/accounts/verify_credentials", &token)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .json();
    assert_eq!(account["display_name"], "Alice Example");
    assert_eq!(account["locked"], true);
}

#[tokio::test]
async fn the_dashboard_profile_form_does_not_unlock_an_account() {
    // The dashboard edits name and bio and never mentions locking, but the
    // profile writer replaces every predicate it manages — so it has to
    // preserve what it does not edit.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;
    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "locked=true",
        &token,
    )
    .await;

    let session = session_for(&h, "alice").await;
    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/account/profile")
                .header(header::HOST, BASE)
                .header(header::COOKIE, format!("brolly_session={session}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("display_name=Alice&bio=hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let account = send(
        &h,
        builder("GET", "/api/v1/accounts/verify_credentials", &token)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .json();
    assert_eq!(
        account["locked"], true,
        "editing a bio silently unlocked the account"
    );
}

// --- locking actually locks -------------------------------------------------------

#[tokio::test]
async fn an_unlocked_account_accepts_a_follow_immediately() {
    let h = harness().await;
    let (alice_id, _) = a_member(&h, "alice").await;
    a_member(&h, "bob").await;

    follow(&h, "bob", "alice").await;

    let alice_pod = h.stores.pod(alice_id).unwrap();
    let actor = brolly_identity::webid::actor("alice", BASE);
    assert_eq!(
        brolly_activitypub::follows::followers(&alice_pod, &actor).len(),
        1
    );
    assert!(brolly_activitypub::follows::pending(&alice_pod, &actor).is_empty());
}

#[tokio::test]
async fn a_locked_account_holds_the_follow_for_approval() {
    // The defect. Before, `locked` was recorded and then ignored, so this
    // follower went straight into the followers collection.
    let h = harness().await;
    let (alice_id, alice_token) = a_member(&h, "alice").await;
    a_member(&h, "bob").await;

    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "locked=true",
        &alice_token,
    )
    .await;

    follow(&h, "bob", "alice").await;

    let alice_pod = h.stores.pod(alice_id).unwrap();
    let actor = brolly_identity::webid::actor("alice", BASE);
    assert!(
        brolly_activitypub::follows::followers(&alice_pod, &actor).is_empty(),
        "a locked account let a follower straight in"
    );
    assert_eq!(
        brolly_activitypub::follows::pending(&alice_pod, &actor).len(),
        1,
        "the follow should be waiting for approval"
    );
}

#[tokio::test]
async fn a_pending_request_is_listed_and_can_be_approved() {
    let h = harness().await;
    let (alice_id, alice_token) = a_member(&h, "alice").await;
    let (bob_id, _) = a_member(&h, "bob").await;

    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "locked=true",
        &alice_token,
    )
    .await;
    follow(&h, "bob", "alice").await;

    let listed = send(
        &h,
        builder("GET", "/api/v1/follow_requests", &alice_token)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "body: {}", listed.body);
    let requests = listed.json();
    assert_eq!(requests.as_array().unwrap().len(), 1);
    assert_eq!(requests[0]["username"], "bob");

    let bob_account_id = brolly_mastodon::translate::encode_account_id(bob_id);
    let approved = form(
        &h,
        "POST",
        &format!("/api/v1/follow_requests/{bob_account_id}/authorize"),
        "",
        &alice_token,
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "body: {}", approved.body);
    assert_eq!(approved.json()["followed_by"], true);

    let alice_pod = h.stores.pod(alice_id).unwrap();
    let actor = brolly_identity::webid::actor("alice", BASE);
    assert_eq!(
        brolly_activitypub::follows::followers(&alice_pod, &actor).len(),
        1,
        "approval should produce a follower"
    );
    assert!(
        brolly_activitypub::follows::pending(&alice_pod, &actor).is_empty(),
        "an approved request must stop being pending, or it shows up twice"
    );
}

#[tokio::test]
async fn a_rejected_request_leaves_no_follower_and_no_request() {
    let h = harness().await;
    let (alice_id, alice_token) = a_member(&h, "alice").await;
    let (bob_id, _) = a_member(&h, "bob").await;

    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "locked=true",
        &alice_token,
    )
    .await;
    follow(&h, "bob", "alice").await;

    let bob_account_id = brolly_mastodon::translate::encode_account_id(bob_id);
    let rejected = form(
        &h,
        "POST",
        &format!("/api/v1/follow_requests/{bob_account_id}/reject"),
        "",
        &alice_token,
    )
    .await;
    assert_eq!(rejected.status, StatusCode::OK);
    assert_eq!(rejected.json()["followed_by"], false);

    let alice_pod = h.stores.pod(alice_id).unwrap();
    let actor = brolly_identity::webid::actor("alice", BASE);
    assert!(brolly_activitypub::follows::followers(&alice_pod, &actor).is_empty());
    assert!(brolly_activitypub::follows::pending(&alice_pod, &actor).is_empty());
}

#[tokio::test]
async fn approving_someone_who_never_asked_manufactures_nothing() {
    let h = harness().await;
    let (alice_id, alice_token) = a_member(&h, "alice").await;
    let (bob_id, _) = a_member(&h, "bob").await;

    let bob_account_id = brolly_mastodon::translate::encode_account_id(bob_id);
    let reply = form(
        &h,
        "POST",
        &format!("/api/v1/follow_requests/{bob_account_id}/authorize"),
        "",
        &alice_token,
    )
    .await;

    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let alice_pod = h.stores.pod(alice_id).unwrap();
    let actor = brolly_identity::webid::actor("alice", BASE);
    assert!(
        brolly_activitypub::follows::followers(&alice_pod, &actor).is_empty(),
        "approving a request nobody made invented a follower"
    );
}

#[tokio::test]
async fn the_actor_document_advertises_the_lock() {
    // Remote instances read `manuallyApprovesFollowers` to know whether to
    // expect an Accept. An actor that lies here strands every follow.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;
    form(
        &h,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        "locked=true",
        &token,
    )
    .await;

    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/actor")
                .header(header::HOST, format!("alice.{BASE}"))
                .header(header::ACCEPT, "application/activity+json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    let actor: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(
        actor["manuallyApprovesFollowers"], true,
        "the actor document must advertise the lock: {body}"
    );
}
