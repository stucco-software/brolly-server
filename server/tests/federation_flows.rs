//! Phase 5's exit criterion: follow → post → like → delete, end to end.
//!
//! Local delivery, with `FEDERATION_ENABLED` false. Every activity travels the
//! real path — outbox publication (ADR 0012), recipient resolution, the
//! processor, inbox containment — and the public index is populated *only* by
//! delivery. There is no crawler, and a test asserts there is no crawler.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_activitypub::{follows, inbox};
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_solid::storage;
use brolly_store::{StoreManager, index};
use http_body_util::BodyExt;
use oxigraph::model::NamedNode;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const BASE: &str = "brolly.test";
const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";
const PASSWORD: &str = "correct-horse-battery-staple";

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    stores: std::sync::Arc<StoreManager>,
    ids: std::collections::HashMap<String, Uuid>,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 4, 60).unwrap());

    let mut ids = std::collections::HashMap::new();
    for name in ["alice", "bob"] {
        let user = db::create_user(&db.pool, name, None, PASSWORD, "member")
            .await
            .unwrap();
        let pod = stores.pod(user.id).unwrap();
        storage::init_storage_root(&pod, &format!("https://{name}.{BASE}/~/")).unwrap();
        ids.insert(name.to_string(), user.id);
    }

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
        ids,
    }
}

impl Harness {
    async fn login(&self, username: &str) -> String {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::HOST, BASE)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "username={username}&password={PASSWORD}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        response
            .headers()
            .get(header::SET_COOKIE)
            .expect("session")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    /// Publish through the member's outbox — the publication surface (ADR 0012).
    async fn publish(&self, username: &str, cookie: &str, activity: &Value) -> (StatusCode, Value) {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/outbox")
                    .header(header::HOST, format!("{username}.{BASE}"))
                    .header(header::CONTENT_TYPE, "application/activity+json")
                    .header(header::COOKIE, cookie)
                    .body(Body::from(activity.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                .to_string();
        let value = serde_json::from_str(&body).unwrap_or(Value::String(body));
        (status, value)
    }

    fn pod(&self, username: &str) -> std::sync::Arc<brolly_store::Store> {
        self.stores.pod(self.ids[username]).unwrap()
    }

    fn index_count(&self) -> i64 {
        index::count_notes(self.stores.instance()).unwrap()
    }
}

fn actor(username: &str) -> String {
    format!("https://{username}.{BASE}/actor")
}

fn inbox_of(username: &str) -> String {
    format!("https://{username}.{BASE}/inbox")
}

// --- follow -----------------------------------------------------------------

#[tokio::test]
async fn a_follow_is_delivered_and_recorded_on_both_sides() {
    let h = harness().await;
    let bob = h.login("bob").await;

    let (status, _) = h
        .publish(
            "bob",
            &bob,
            &json!({"type": "Follow", "object": actor("alice")}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Alice's pod knows she has a follower — this is what delivery resolves
    // recipients from.
    assert_eq!(
        follows::followers(&h.pod("alice"), &actor("alice")),
        vec![actor("bob")]
    );
    // And bob's pod knows who he follows.
    assert_eq!(
        follows::following(&h.pod("bob"), &actor("bob")),
        vec![actor("alice")]
    );

    // The Follow itself reached alice's inbox, so it can be shown as a
    // notification.
    let notifications = inbox::timeline(&h.pod("alice"), &inbox_of("alice"), &["Follow"], 10, None);
    assert_eq!(notifications.len(), 1);
}

// --- post -------------------------------------------------------------------

#[tokio::test]
async fn a_post_reaches_followers_and_the_public_index() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;

    h.publish(
        "bob",
        &bob,
        &json!({"type": "Follow", "object": actor("alice")}),
    )
    .await;

    let (status, created) = h
        .publish(
            "alice",
            &alice,
            &json!({
                "type": "Note",
                "content": "hello from alice",
                "to": [PUBLIC],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "publish: {created}");

    let note = created["object"]["id"].as_str().expect("a note IRI");
    assert!(
        note.starts_with("https://alice.brolly.test/"),
        "a post must live in its author's pod: {note}"
    );

    // Bob's home timeline is his own inbox — one store, no fan-out.
    let timeline = inbox::timeline(&h.pod("bob"), &inbox_of("bob"), &["Create"], 10, None);
    assert_eq!(timeline.len(), 1, "the follower did not receive the post");
    assert_eq!(
        inbox::read_activity(&h.pod("bob"), note).expect("the note")["content"],
        "hello from alice"
    );

    // And the instance received the same delivery, recording a pointer.
    let page = index::public_timeline(
        h.stores.instance(),
        &NamedNode::new_unchecked(PUBLIC),
        10,
        None,
    )
    .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].note.as_str(), note);
    assert_eq!(page[0].author.as_str(), actor("alice"));
}

#[tokio::test]
async fn a_non_follower_does_not_receive_the_post() {
    let h = harness().await;
    let alice = h.login("alice").await;

    h.publish(
        "alice",
        &alice,
        &json!({"type": "Note", "content": "hello", "to": [PUBLIC]}),
    )
    .await;

    assert!(
        inbox::timeline(&h.pod("bob"), &inbox_of("bob"), &["Create"], 10, None).is_empty(),
        "delivery must go to followers, not to everyone"
    );
    // The instance still indexes it — that is what makes a public timeline
    // work for people who follow nobody.
    assert_eq!(h.index_count(), 1);
}

#[tokio::test]
async fn a_private_post_reaches_followers_but_not_the_public_index() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;
    h.publish(
        "bob",
        &bob,
        &json!({"type": "Follow", "object": actor("alice")}),
    )
    .await;

    h.publish(
        "alice",
        &alice,
        &json!({
            "type": "Note",
            "content": "followers only",
            "to": [format!("https://alice.{BASE}/followers")],
        }),
    )
    .await;

    assert_eq!(
        inbox::timeline(&h.pod("bob"), &inbox_of("bob"), &["Create"], 10, None).len(),
        1,
        "a follower must still receive it"
    );
    assert_eq!(
        h.index_count(),
        0,
        "indexing a followers-only post would publish it"
    );
}

// --- like -------------------------------------------------------------------

#[tokio::test]
async fn a_like_reaches_the_author() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;

    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "hello", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();

    let (status, _) = h
        .publish("bob", &bob, &json!({"type": "Like", "object": note}))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let notifications = inbox::timeline(&h.pod("alice"), &inbox_of("alice"), &["Like"], 10, None);
    assert_eq!(notifications.len(), 1, "the author was not notified");
    // A Like is not a post.
    assert_eq!(h.index_count(), 1, "a Like must not add a timeline row");
}

// --- delete -----------------------------------------------------------------

#[tokio::test]
async fn a_delete_reaches_everyone_the_post_did() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;
    h.publish(
        "bob",
        &bob,
        &json!({"type": "Follow", "object": actor("alice")}),
    )
    .await;

    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "regrettable", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();
    assert_eq!(h.index_count(), 1);

    let (status, _) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Delete", "object": note, "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    assert_eq!(h.index_count(), 0, "the public timeline still shows it");
    assert!(
        inbox::read_activity(&h.pod("bob"), &note).is_none(),
        "the follower's copy survived the delete"
    );
    assert!(
        inbox::timeline(&h.pod("bob"), &inbox_of("bob"), &["Create"], 10, None).is_empty(),
        "a deleted post left a hole in the timeline"
    );
}

// --- the properties the phase exists to establish ---------------------------

#[tokio::test]
async fn the_public_index_is_populated_only_by_delivery() {
    // Phase 5's exit criterion. Writing to a pod directly — as a Solid app
    // does — must not put anything on the public timeline; only publishing
    // through the outbox does, and that goes through delivery.
    let h = harness().await;
    let alice = h.login("alice").await;

    let pod = h.pod("alice");
    brolly_solid::ldp::put(
        &pod,
        None,
        &format!("https://alice.{BASE}"),
        "/~/notes/private",
        &brolly_identity::Subject::local(
            h.ids["alice"],
            String::new(),
            format!("https://alice.{BASE}/profile#me"),
            brolly_identity::Scope::parse("webid"),
            brolly_identity::Via::Session,
        ),
        b"<> <https://example.org/p> \"private CRUD\" .",
        "text/turtle",
        &format!("https://alice.{BASE}/~/"),
    )
    .ok();

    assert_eq!(
        h.index_count(),
        0,
        "a pod write is private CRUD (D9) and must not reach the public timeline"
    );

    h.publish(
        "alice",
        &alice,
        &json!({"type": "Note", "content": "published", "to": [PUBLIC]}),
    )
    .await;

    assert_eq!(
        h.index_count(),
        1,
        "publishing through the outbox is what puts a post on the timeline"
    );
}

#[tokio::test]
async fn one_member_cannot_publish_as_another() {
    let h = harness().await;
    let bob = h.login("bob").await;

    // Bob's session, alice's outbox.
    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/outbox")
                .header(header::HOST, format!("alice.{BASE}"))
                .header(header::CONTENT_TYPE, "application/activity+json")
                .header(header::COOKIE, &bob)
                .body(Body::from(
                    json!({"type": "Note", "content": "not mine", "to": [PUBLIC]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(h.index_count(), 0);
}

#[tokio::test]
async fn an_anonymous_post_is_refused() {
    let h = harness().await;
    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/outbox")
                .header(header::HOST, format!("alice.{BASE}"))
                .header(header::CONTENT_TYPE, "application/activity+json")
                .body(Body::from(
                    json!({"type": "Note", "content": "hello", "to": [PUBLIC]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn remote_delivery_is_suppressed_while_federation_is_off() {
    // D12. A follower on another host is resolved and then skipped, so the
    // code path runs and nothing leaves the instance.
    let h = harness().await;
    let alice = h.login("alice").await;

    // A remote follower, as an inbound Follow would have left behind.
    follows::record(
        &h.pod("alice"),
        "https://mastodon.social/users/carol",
        &actor("alice"),
    )
    .unwrap();

    let (status, _) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "hello", "to": [PUBLIC]}),
        )
        .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "a suppressed remote delivery must not fail the publish"
    );
    assert_eq!(h.index_count(), 1, "local delivery still happened");
}

#[tokio::test]
async fn publishing_stores_the_post_in_the_authors_own_pod() {
    // D2: content lives in exactly one place, and it is the author's pod.
    let h = harness().await;
    let alice = h.login("alice").await;

    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "mine", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap();

    assert!(
        inbox::read_activity(&h.pod("alice"), note).is_some(),
        "the author must hold their own post"
    );

    // Postgres holds no content, ever.
    let (rows,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.columns
         WHERE table_schema = 'public' AND column_name LIKE '%content%'",
    )
    .fetch_one(&h.db.pool)
    .await
    .unwrap();
    assert_eq!(rows, 0, "post content must never acquire a Postgres column");
}
