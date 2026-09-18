//! D8, end to end: one node, three protocols.
//!
//! > **Harmonize on the subject IRI**, not via `owl:sameAs`. All writers assert
//! > onto `…/profile#me`; nothing to join.
//!
//! That claim is only worth anything if a write through *one* protocol is
//! visible through the *others*. This is the test that proves it, and it is the
//! reason the canonical layer writes into the profile document graph rather
//! than the record's own — the tidy-looking alternative would be invisible to
//! every reader that matters, and no unit test in either adapter would notice.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_identity::webid;
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
    }
}

async fn get_json(h: &Harness, host: &str, path: &str) -> serde_json::Value {
    let response = h
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::HOST, host)
                .header(header::ACCEPT, "application/activity+json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("expected JSON, got {body}: {e}"))
}

#[tokio::test]
async fn an_atproto_profile_write_is_visible_to_activitypub() {
    // The claim D8 actually makes. Write through ATProtocol; read through the
    // ActivityPub actor document, which is a different adapter that knows
    // nothing about lexicons.
    let h = harness().await;
    let user = db::create_user(&h.db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let pod = h.stores.pod(user.id).unwrap();
    brolly_server::provision::pod(&pod, "alice", BASE).unwrap();

    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    brolly_atproto::ingest::ingest(
        &pod,
        &json!({
            "$type": "app.bsky.actor.profile",
            "displayName": "Alice Example",
        }),
        &brolly_atproto::ingest::at_uri(did, "app.bsky.actor.profile", "self"),
        &webid::webid("alice", BASE),
        &webid::profile_document("alice", BASE),
    )
    .expect("ingest");

    let actor = get_json(&h, &format!("alice.{BASE}"), "/actor").await;
    assert_eq!(
        actor["name"], "Alice Example",
        "a profile written through ATProtocol must show in the ActivityPub actor"
    );
}

#[tokio::test]
async fn a_solid_profile_write_is_visible_to_activitypub() {
    // The same node from the other direction, so the harmonization is not an
    // accident of one writer's ordering.
    let h = harness().await;
    let user = db::create_user(&h.db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let pod = h.stores.pod(user.id).unwrap();
    brolly_server::provision::pod(&pod, "alice", BASE).unwrap();

    brolly_solid::profile::write(
        &pod,
        &webid::webid("alice", BASE),
        &webid::profile_document("alice", BASE),
        &brolly_solid::profile::Profile {
            display_name: "Written Through Solid".into(),
            bio: "and read through ActivityPub".into(),
            ..brolly_solid::profile::Profile::blank()
        },
    )
    .unwrap();

    let actor = get_json(&h, &format!("alice.{BASE}"), "/actor").await;
    assert_eq!(actor["name"], "Written Through Solid");
    assert_eq!(actor["summary"], "and read through ActivityPub");
}

#[tokio::test]
async fn an_unmapped_lexicon_does_not_touch_the_shared_profile() {
    // The other half of D7: faithful ingest accepts anything, but only the
    // mapping table decides what becomes shared. A third-party lexicon with a
    // `displayName` must not rewrite the member's name.
    let h = harness().await;
    let user = db::create_user(&h.db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let pod = h.stores.pod(user.id).unwrap();
    brolly_server::provision::pod(&pod, "alice", BASE).unwrap();

    brolly_solid::profile::write(
        &pod,
        &webid::webid("alice", BASE),
        &webid::profile_document("alice", BASE),
        &brolly_solid::profile::Profile {
            display_name: "The Real Name".into(),
            ..brolly_solid::profile::Profile::blank()
        },
    )
    .unwrap();

    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    brolly_atproto::ingest::ingest(
        &pod,
        &json!({
            "$type": "site.standard.doc",
            "displayName": "An Impostor",
        }),
        &brolly_atproto::ingest::at_uri(did, "site.standard.doc", "3kaaa"),
        &webid::webid("alice", BASE),
        &webid::profile_document("alice", BASE),
    )
    .expect("an unmapped lexicon still ingests");

    let actor = get_json(&h, &format!("alice.{BASE}"), "/actor").await;
    assert_eq!(
        actor["name"], "The Real Name",
        "an unmapped lexicon rewrote the shared profile"
    );

    // But it is still stored, faithfully, in its own space.
    let stored = brolly_atproto::ingest::read(
        &pod,
        &brolly_atproto::ingest::at_uri(did, "site.standard.doc", "3kaaa"),
    );
    assert_eq!(stored.unwrap()["displayName"], "An Impostor");
}
