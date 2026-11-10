//! Phase 5's exit criterion: follow → post → like → delete, end to end.
//!
//! Local delivery, with `FEDERATION_ENABLED` false. Every activity travels the
//! real path — outbox publication (ADR 0012), recipient resolution, the
//! processor, inbox containment — and the public index is populated *only* by
//! delivery. There is no crawler, and a test asserts there is no crawler.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_activitypub::processor::{self, ProcessError};
use brolly_activitypub::{follows, inbox};
use brolly_identity::db;
use brolly_server::outbox::{DeliverError, Refusal, deliver};
use brolly_server::{AppState, app};
use brolly_store::resources::{Kind, PodRead};
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
    /// The state the router was built with, so a test can call
    /// `outbox::deliver` directly, the way a future caller might.
    state: AppState,
    stores: std::sync::Arc<StoreManager>,
    ids: std::collections::HashMap<String, Uuid>,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 8, 60).unwrap());

    let mut ids = std::collections::HashMap::new();
    for name in ["alice", "bob", "mallory"] {
        let user = db::create_user(&db.pool, name, None, PASSWORD, "member")
            .await
            .unwrap();
        let pod = stores.pod(user.id).unwrap();
        // The real provisioning, so each member has the root ACL an attack
        // would aim at.
        brolly_server::provision::pod(&pod, name, BASE).unwrap();
        ids.insert(name.to_string(), user.id);
    }

    let state = AppState {
        pool: db.pool.clone(),
        base_domain: BASE.into(),
        instance_name: BASE.to_string(),
        instance_description: "A private community server.".to_string(),
        source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
        terms_url: None,
        privacy_url: None,
        theme_css: false,
        public_registration: false,
        front_end: brolly_server::FrontEnd::default(),
        limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
        www_redirect: None,
        max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
        pod_quota_bytes: brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
        stores: std::sync::Arc::clone(&stores),
        provider_key: std::sync::Arc::new(
            brolly_solid::oidc::store::load_or_create_key(&db.pool)
                .await
                .expect("provider key"),
        ),
        instance_actor: std::sync::Arc::new(
            brolly_identity::instance::load_or_create(&db.pool, brolly_activitypub::keys::generate)
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
        issuer_jwks: std::sync::Arc::new(brolly_server::client_metadata::StaticDocuments::default()),
        webid_documents: std::sync::Arc::new(
            brolly_server::client_metadata::StaticDocuments::default(),
        ),
    };
    let router = app(state.clone(), "server/static");

    Harness {
        db,
        _dir: dir,
        router,
        state,
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

    async fn user(&self, username: &str) -> db::User {
        db::find_by_username(&self.db.pool, username)
            .await
            .unwrap()
            .unwrap()
    }

    fn pod(&self, username: &str) -> std::sync::Arc<brolly_store::resources::Pod> {
        self.stores.pod(self.ids[username]).unwrap()
    }

    fn index_count(&self) -> i64 {
        index::count_notes(self.stores.instance()).unwrap()
    }

    /// Every quad in one graph of a member's pod, as text, so "left untouched"
    /// compares content and not only size.
    fn graph(&self, username: &str, graph: &str) -> std::collections::BTreeSet<String> {
        self.pod(username)
            .read_store()
            .quads_for_pattern(
                None,
                None,
                None,
                Some(oxigraph::model::GraphNameRef::NamedNode(
                    NamedNode::new_unchecked(graph).as_ref(),
                )),
            )
            .filter_map(Result::ok)
            .map(|quad| quad.to_string())
            .collect()
    }

    /// GET a path in a member's pod with a session, for "can she still read her
    /// own storage".
    async fn get_status(&self, username: &str, cookie: &str, path: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, format!("{username}.{BASE}"))
                    .header(header::ACCEPT, "text/turtle")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    /// GET a path in a member's pod as Turtle, for its status and body.
    async fn get(&self, username: &str, cookie: &str, path: &str) -> (StatusCode, String) {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, format!("{username}.{BASE}"))
                    .header(header::ACCEPT, "text/turtle")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                .to_string();
        (status, body)
    }
}

fn actor(username: &str) -> String {
    format!("https://{username}.{BASE}/actor")
}

fn inbox_of(username: &str) -> String {
    format!("https://{username}.{BASE}/inbox")
}

fn outbox_of(username: &str) -> String {
    format!("https://{username}.{BASE}/outbox")
}

fn acl_of(username: &str) -> String {
    format!("https://{username}.{BASE}/~/.acl")
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
        follows::followers(&h.pod("alice").read_store(), &actor("alice")),
        vec![actor("bob")]
    );
    // And bob's pod knows who he follows.
    assert_eq!(
        follows::following(&h.pod("bob").read_store(), &actor("bob")),
        vec![actor("alice")]
    );

    // The Follow itself reached alice's inbox, so it can be shown as a
    // notification.
    let notifications = inbox::timeline(
        &h.pod("alice").read_store(),
        &inbox_of("alice"),
        &["Follow"],
        10,
        None,
    );
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
    let timeline = inbox::timeline(
        &h.pod("bob").read_store(),
        &inbox_of("bob"),
        &["Create"],
        10,
        None,
    );
    assert_eq!(timeline.len(), 1, "the follower did not receive the post");
    assert_eq!(
        inbox::read_activity(&h.pod("bob").read_store(), note).expect("the note")["content"],
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
        inbox::timeline(
            &h.pod("bob").read_store(),
            &inbox_of("bob"),
            &["Create"],
            10,
            None
        )
        .is_empty(),
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
        inbox::timeline(
            &h.pod("bob").read_store(),
            &inbox_of("bob"),
            &["Create"],
            10,
            None
        )
        .len(),
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

    let notifications = inbox::timeline(
        &h.pod("alice").read_store(),
        &inbox_of("alice"),
        &["Like"],
        10,
        None,
    );
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
        inbox::read_activity(&h.pod("bob").read_store(), &note).is_none(),
        "the follower's copy survived the delete"
    );
    assert!(
        inbox::timeline(
            &h.pod("bob").read_store(),
            &inbox_of("bob"),
            &["Create"],
            10,
            None
        )
        .is_empty(),
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
    h.pod("alice")
        .write(|w| follows::record(w, "https://mastodon.social/users/carol", &actor("alice")))
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
        inbox::read_activity(&h.pod("alice").read_store(), note).is_some(),
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

// --- posts are pod resources (stage 5a) --------------------------------------

/// A post is an LDP resource in its author's pod: the note is listed in
/// `/~/notes/` and its `Create` in `/~/activities/`. The author's `Delete`
/// de-lists both, because it goes through the same `remove` an LDP DELETE
/// does.
#[tokio::test]
async fn a_published_note_is_listed_in_the_authors_notes_until_she_deletes_it() {
    let h = harness().await;
    let alice = h.login("alice").await;

    let (status, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "listed", "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "publish: {created}");
    let note = created["object"]["id"].as_str().unwrap().to_string();
    let activity = created["id"].as_str().unwrap().to_string();
    let note_path = note
        .strip_prefix(&format!("https://alice.{BASE}"))
        .unwrap()
        .to_string();

    let (status, notes) = h.get("alice", &alice, "/~/notes/").await;
    assert_eq!(status, StatusCode::OK, "{notes}");
    assert!(notes.contains(&note), "the note isn't listed: {notes}");
    let (status, activities) = h.get("alice", &alice, "/~/activities/").await;
    assert_eq!(status, StatusCode::OK, "{activities}");
    assert!(
        activities.contains(&activity),
        "the Create isn't listed: {activities}"
    );
    assert_eq!(
        h.get_status("alice", &alice, &note_path).await,
        StatusCode::OK
    );

    let (status, _) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Delete", "object": note, "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, notes) = h.get("alice", &alice, "/~/notes/").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the container outlives its last member"
    );
    assert!(
        !notes.contains(&note),
        "the deleted note is still listed: {notes}"
    );
    let (_, activities) = h.get("alice", &alice, "/~/activities/").await;
    assert!(
        !activities.contains(&activity),
        "the deleted post's Create is still listed: {activities}"
    );
    assert_eq!(
        h.get_status("alice", &alice, &note_path).await,
        StatusCode::NOT_FOUND
    );
}

/// A follower's copy lives under the author's origin, so it can never be under
/// the follower's storage root. It's protocol state in their pod, not a
/// resource, and their own storage doesn't list it.
#[tokio::test]
async fn a_followers_copy_of_a_post_is_not_a_resource_in_their_pod() {
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
            &json!({"type": "Note", "content": "for my followers", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();

    // Setup: bob has the copy, or the rest proves nothing.
    assert!(inbox::read_activity(&h.pod("bob").read_store(), &note).is_some());

    assert!(
        !matches!(h.pod("bob").read(|r| r.meta(&note)), Ok(Some(_))),
        "bob's copy of alice's note was recorded as a resource in his pod"
    );
    let (status, listing) = h.get("bob", &bob, "/~/").await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(
        !listing.contains(&format!("alice.{BASE}")),
        "bob's storage lists something of alice's: {listing}"
    );

    // The same note is a resource in its author's pod.
    assert!(matches!(
        h.pod("alice").read(|r| r.meta(&note)),
        Ok(Some(meta)) if matches!(meta.kind, Kind::RdfSource)
    ));
}

// --- an activity only touches graphs its actor owns (stage 0, A1) -----------

#[tokio::test]
async fn a_delete_naming_another_members_acl_leaves_it_alone() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");
    assert_eq!(
        h.get_status("alice", &alice, "/~/").await,
        StatusCode::OK,
        "setup"
    );

    let (status, body) = h
        .publish(
            "mallory",
            &mallory,
            &json!({"type": "Delete", "object": acl_of("alice")}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "Mallory's Delete cleared Alice's ACL"
    );
    assert_eq!(
        h.get_status("alice", &alice, "/~/").await,
        StatusCode::OK,
        "Alice is locked out of her own storage"
    );
}

#[tokio::test]
async fn a_delete_of_your_own_note_removes_every_copy() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("mallory")}),
    )
    .await;

    let (_, created) = h
        .publish(
            "mallory",
            &mallory,
            &json!({"type": "Note", "content": "mine to take back", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();
    let create = created["id"].as_str().unwrap().to_string();

    // Setup: every copy exists, or the assertions below prove nothing.
    assert!(inbox::read_activity(&h.pod("alice").read_store(), &note).is_some());
    assert!(inbox::read_activity(&h.pod("mallory").read_store(), &note).is_some());
    assert_eq!(
        inbox::members(&h.pod("mallory").read_store(), &outbox_of("mallory")),
        vec![create.clone()]
    );
    assert_eq!(h.index_count(), 1);

    let (status, _) = h
        .publish(
            "mallory",
            &mallory,
            &json!({"type": "Delete", "object": note, "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    assert!(
        inbox::read_activity(&h.pod("alice").read_store(), &note).is_none(),
        "the follower's copy survived"
    );
    assert!(
        inbox::timeline(
            &h.pod("alice").read_store(),
            &inbox_of("alice"),
            &["Create"],
            10,
            None
        )
        .is_empty(),
        "a deleted post left a hole in the follower's timeline"
    );
    assert!(
        inbox::read_activity(&h.pod("mallory").read_store(), &note).is_none(),
        "the author's own note survived"
    );
    assert!(
        inbox::read_activity(&h.pod("mallory").read_store(), &create).is_none(),
        "the author's Create survived"
    );
    assert!(
        inbox::members(&h.pod("mallory").read_store(), &outbox_of("mallory")).is_empty(),
        "the author's outbox still lists the deleted post"
    );
    assert_eq!(h.index_count(), 0, "the public timeline still shows it");
}

#[tokio::test]
async fn an_owner_cannot_delete_their_own_acl_through_the_outbox() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    // Straight at it.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Delete", "object": acl_of("alice")}),
    )
    .await;
    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "a Delete through the outbox cleared an LDP resource without WAC"
    );

    // And after naming it in a Create first, so a stored activity mentions it.
    let (status, body) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Create", "object": acl_of("alice"), "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Delete", "object": acl_of("alice")}),
    )
    .await;

    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "a Create naming the ACL by string made it deletable"
    );
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}

#[tokio::test]
async fn another_member_cannot_take_over_a_post_on_the_public_timeline() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;

    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "hello", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();
    assert_eq!(h.index_count(), 1, "setup");

    h.publish(
        "mallory",
        &mallory,
        &json!({"type": "Delete", "object": note, "to": [PUBLIC]}),
    )
    .await;
    let page = index::public_timeline(
        h.stores.instance(),
        &NamedNode::new_unchecked(PUBLIC),
        10,
        None,
    )
    .unwrap();
    assert_eq!(
        page.len(),
        1,
        "Mallory's Delete took Alice's post off the public timeline"
    );
    assert_eq!(page[0].note.as_str(), note);
    let published = page[0].published.clone();

    h.publish(
        "mallory",
        &mallory,
        &json!({"type": "Announce", "object": note, "to": [PUBLIC]}),
    )
    .await;
    assert_eq!(
        h.index_count(),
        1,
        "Mallory's Announce added a second author to Alice's post"
    );
    let page = index::public_timeline(
        h.stores.instance(),
        &NamedNode::new_unchecked(PUBLIC),
        10,
        None,
    )
    .unwrap();
    assert_eq!(page.len(), 1, "the boost listed the post twice: {page:?}");
    assert_eq!(page[0].author.as_str(), actor("alice"));
    assert_eq!(page[0].published, published, "the boost moved the post");
}

#[tokio::test]
async fn a_public_announce_does_not_publish_a_followers_only_note() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;
    // Mallory follows Alice, so she receives, and can boost, a followers-only post.
    h.publish(
        "mallory",
        &mallory,
        &json!({"type": "Follow", "object": actor("alice")}),
    )
    .await;

    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({
                "type": "Note",
                "content": "just for followers",
                "to": [format!("https://alice.{BASE}/followers")],
            }),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();
    assert!(
        inbox::read_activity(&h.pod("mallory").read_store(), &note).is_some(),
        "setup: mallory received the post"
    );
    assert_eq!(
        h.index_count(),
        0,
        "setup: a followers-only post isn't indexed"
    );

    let (status, body) = h
        .publish(
            "mallory",
            &mallory,
            &json!({"type": "Announce", "object": note, "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    assert_eq!(
        h.index_count(),
        0,
        "Mallory's boost put Alice's followers-only post on the public timeline"
    );
    let page = index::public_timeline(
        h.stores.instance(),
        &NamedNode::new_unchecked(PUBLIC),
        10,
        None,
    )
    .unwrap();
    assert!(page.is_empty(), "{page:?}");
}

#[tokio::test]
async fn a_create_claiming_another_members_acl_gets_a_minted_id() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let mallory = h.login("mallory").await;
    // Alice follows Mallory, so Mallory's posts are delivered into Alice's pod.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("mallory")}),
    )
    .await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    let (status, created) = h
        .publish(
            "mallory",
            &mallory,
            &json!({
                "type": "Create",
                "to": [PUBLIC],
                "object": {
                    "type": "Note",
                    "id": acl_of("alice"),
                    "content": "mallory holds acl:Control now",
                },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let note = created["object"]["id"].as_str().unwrap();
    assert!(
        note.starts_with(&format!("https://mallory.{BASE}/~/notes/")),
        "{note}"
    );
    assert!(
        inbox::read_activity(&h.pod("alice").read_store(), note).is_some(),
        "the post is still delivered, under the id the server chose"
    );

    assert_eq!(h.graph("alice", &acl_of("alice")), before);
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}

#[tokio::test]
async fn an_owner_cannot_overwrite_their_own_acl_through_the_outbox() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    let (status, created) = h
        .publish(
            "alice",
            &alice,
            &json!({
                "type": "Create",
                "to": [PUBLIC],
                "object": {"type": "Note", "id": acl_of("alice"), "content": "no WAC here"},
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let note = created["object"]["id"].as_str().unwrap();
    assert!(
        note.starts_with(&format!("https://alice.{BASE}/~/notes/")),
        "{note}"
    );

    assert_eq!(
        h.graph("alice", &acl_of("alice")),
        before,
        "publishing replaced an LDP resource without WAC"
    );
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}

#[tokio::test]
async fn a_delete_of_an_embedded_tombstone_removes_the_note_everywhere() {
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

    let (status, delete) = h
        .publish(
            "alice",
            &alice,
            &json!({
                "type": "Delete",
                "object": {"type": "Tombstone", "id": note},
                "to": [PUBLIC],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{delete}");
    assert_eq!(
        delete["object"],
        json!(note),
        "the Tombstone is named by id"
    );

    assert!(inbox::read_activity(&h.pod("bob").read_store(), &note).is_none());
    assert!(
        inbox::timeline(
            &h.pod("bob").read_store(),
            &inbox_of("bob"),
            &["Create"],
            10,
            None
        )
        .is_empty()
    );
    assert!(inbox::read_activity(&h.pod("alice").read_store(), &note).is_none());
    assert!(inbox::members(&h.pod("alice").read_store(), &outbox_of("alice")).is_empty());
    assert_eq!(h.index_count(), 0);
}

#[tokio::test]
async fn an_undo_embedding_a_follow_names_it_by_id() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;
    // Alice follows Bob, so Bob's activities reach her as a follower.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("bob")}),
    )
    .await;
    let (_, follow) = h
        .publish(
            "bob",
            &bob,
            &json!({"type": "Follow", "object": actor("alice")}),
        )
        .await;
    let follow_id = follow["id"].as_str().unwrap().to_string();

    let (status, undo) = h
        .publish("bob", &bob, &json!({"type": "Undo", "object": follow}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{undo}");
    assert_eq!(undo["object"], json!(follow_id));

    let undos = inbox::timeline(
        &h.pod("alice").read_store(),
        &inbox_of("alice"),
        &["Undo"],
        10,
        None,
    );
    assert_eq!(undos.len(), 1, "the Undo did not reach Alice");
    let stored = inbox::read_activity(&h.pod("alice").read_store(), &undos[0].activity).unwrap();
    assert_eq!(stored["object"], json!(follow_id));
}

#[tokio::test]
async fn a_create_embedding_another_members_acl_is_refused_at_both_ends() {
    let h = harness().await;
    let alice = h.login("alice").await;
    // Alice follows Mallory, so Mallory's posts would be delivered to her.
    h.publish(
        "alice",
        &alice,
        &json!({"type": "Follow", "object": actor("mallory")}),
    )
    .await;
    let before = h.graph("alice", &acl_of("alice"));
    assert!(!before.is_empty(), "setup: alice has a root ACL");

    let attack = json!({
        "type": "Create",
        "id": format!("https://mallory.{BASE}/~/activities/{}", Uuid::new_v4()),
        "actor": actor("mallory"),
        "to": [PUBLIC],
        "object": {
            "type": "Note",
            "id": acl_of("alice"),
            "content": "mallory holds acl:Control now",
        },
    });

    // The outbox refuses it...
    let refused = deliver(
        &h.state,
        &h.user("mallory").await,
        &actor("mallory"),
        &attack,
    )
    .await;
    assert!(
        matches!(refused, Err(DeliverError::Refused(Refusal::ObjectId))),
        "got {refused:?}"
    );
    assert!(
        inbox::members(&h.pod("mallory").read_store(), &outbox_of("mallory")).is_empty(),
        "the author's copy was written before the refusal"
    );

    // ...and so does the processor, for the day it arrives from another server.
    let processed = h
        .pod("alice")
        .write(|w| {
            Ok(processor::process_member(
                w,
                &inbox_of("alice"),
                &outbox_of("alice"),
                &attack,
                "2026-09-17T12:00:00Z",
            ))
        })
        .unwrap();
    assert!(
        matches!(processed, Err(ProcessError::ForeignObject)),
        "got {processed:?}"
    );

    assert_eq!(h.graph("alice", &acl_of("alice")), before);
    assert_eq!(h.get_status("alice", &alice, "/~/").await, StatusCode::OK);
}

#[tokio::test]
async fn every_publishing_path_refuses_an_id_it_did_not_mint() {
    // POST /outbox and POST /api/v1/statuses both publish through
    // outbox::deliver, and both build a Create with an embedded note. Neither
    // can be made to carry a foreign id over HTTP any more, so this drives
    // deliver with each shape directly. The check has to hold for a caller that
    // forgets to mint.
    let h = harness().await;
    let alice = h.user("alice").await;
    let before = h.graph("alice", &acl_of("alice"));
    let activity_id = format!("https://alice.{BASE}/~/activities/{}", Uuid::new_v4());
    let followers = format!("https://alice.{BASE}/followers");

    let outbox_shaped = json!({
        "type": "Create",
        "id": activity_id,
        "actor": actor("alice"),
        "published": "2026-09-17T12:00:00Z",
        "to": [PUBLIC],
        "cc": [],
        "object": {
            "type": "Note",
            "id": acl_of("alice"),
            "attributedTo": actor("alice"),
            "content": "outbox",
        },
    });
    let compose_shaped = json!({
        "type": "Create",
        "id": activity_id,
        "actor": actor("alice"),
        "published": "2026-09-17T12:00:00Z",
        "to": [PUBLIC],
        "cc": [followers],
        "object": {
            "type": "Note",
            "id": format!(
                "https://bob.{BASE}/~/notes/{}",
                brolly_mastodon::status_id::mint_note_id()
            ),
            "attributedTo": actor("alice"),
            "content": "<p>compose</p>",
            "to": [PUBLIC],
            "cc": [followers],
            "sensitive": false,
        },
    });

    for activity in [&outbox_shaped, &compose_shaped] {
        let result = deliver(&h.state, &alice, &actor("alice"), activity).await;
        assert!(
            matches!(result, Err(DeliverError::Refused(Refusal::ObjectId))),
            "got {result:?} for {activity}"
        );
    }

    let mut foreign_activity = outbox_shaped.clone();
    foreign_activity["id"] = json!(acl_of("alice"));
    let result = deliver(&h.state, &alice, &actor("alice"), &foreign_activity).await;
    assert!(
        matches!(result, Err(DeliverError::Refused(Refusal::ActivityId))),
        "got {result:?}"
    );

    assert!(
        inbox::members(&h.pod("alice").read_store(), &outbox_of("alice")).is_empty(),
        "the author's copy was written before the refusal"
    );
    assert_eq!(h.graph("alice", &acl_of("alice")), before);
}

#[tokio::test]
async fn an_embedded_object_the_server_cannot_name_is_a_bad_request() {
    let h = harness().await;
    let bob = h.login("bob").await;

    let (status, body) = h
        .publish(
            "bob",
            &bob,
            &json!({"type": "Like", "object": {"type": "Note", "content": "no id"}}),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        inbox::members(&h.pod("bob").read_store(), &outbox_of("bob")).is_empty(),
        "a refused activity was stored"
    );
}

#[tokio::test]
async fn deliver_refuses_an_activity_whose_actor_is_not_its_author() {
    // Delivery trusts `actor`: the follow bookkeeping records it as the
    // follower, and every recipient checks ids against it. So an activity
    // published by Alice that names Bob, or nobody, as its actor is refused
    // before anything is stored.
    let h = harness().await;
    let alice = h.user("alice").await;

    for actor_field in [json!(actor("bob")), Value::Null] {
        let mut follow = json!({
            "type": "Follow",
            "id": format!("https://alice.{BASE}/~/activities/{}", Uuid::new_v4()),
            "object": actor("mallory"),
        });
        if !actor_field.is_null() {
            follow["actor"] = actor_field.clone();
        }

        let result = deliver(&h.state, &alice, &actor("alice"), &follow).await;
        assert!(
            matches!(result, Err(DeliverError::Refused(Refusal::Actor))),
            "got {result:?} for actor {actor_field}"
        );
    }

    assert!(
        inbox::members(&h.pod("alice").read_store(), &outbox_of("alice")).is_empty(),
        "a refused activity was stored"
    );
    assert!(
        follows::followers(&h.pod("mallory").read_store(), &actor("mallory")).is_empty(),
        "a refused Follow was recorded"
    );
}

#[tokio::test]
async fn a_post_is_attributed_to_whoever_published_it() {
    // The id is the server's, and so is the author: Mastodon's timelines render
    // a post under its `attributedTo`, so a client-chosen one would publish
    // under somebody else's name.
    let h = harness().await;
    let mallory = h.login("mallory").await;

    let (status, created) = h
        .publish(
            "mallory",
            &mallory,
            &json!({
                "type": "Create",
                "to": [PUBLIC],
                "object": {
                    "type": "Note",
                    "content": "alice said this",
                    "attributedTo": actor("alice"),
                },
            }),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["object"]["attributedTo"], json!(actor("mallory")));
    let note = created["object"]["id"].as_str().unwrap();
    let stored = inbox::read_activity(&h.pod("mallory").read_store(), note).expect("the note");
    assert_eq!(stored["attributedTo"], json!(actor("mallory")));
}
