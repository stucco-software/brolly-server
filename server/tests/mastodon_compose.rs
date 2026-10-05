//! Composing a status, over HTTP.
//!
//! Three verified P0 defects converge here, and all three were silent:
//!
//! 1. `media_ids` was never parsed, so an upload succeeded and the post
//!    published with no image.
//! 2. `sensitive`, `spoiler_text` and `language` were accepted and ignored, so
//!    a content-warned post published fully exposed.
//! 5. Fan-out queried a table a migration had dropped and the error was
//!    swallowed, so statuses were delivered to nobody.
//!
//! Each returned 200. Nothing a client could see was wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_store::resources::{Kind, PodRead};
use http_body_util::BodyExt;
use oxigraph::model::{GraphNameRef, NamedNodeRef};
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

async fn post_form(h: &Harness, uri: &str, body: &str, token: &str) -> Reply {
    send(
        h,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

/// A member with a pod, a storage root, and a token.
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
    let token =
        brolly_mastodon::oauth::issue_token(&h.db.pool, &app.app.client_id, user.id, "read write")
            .await
            .unwrap();
    (user.id, token)
}

/// Upload an image and return its media id.
async fn upload(h: &Harness, token: &str, description: Option<&str>) -> String {
    let boundary = "----brollytest";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\
         Content-Type: image/png\r\n\r\nPNG-BYTES\r\n"
    );
    if let Some(description) = description {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\n{description}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));

    let reply = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/api/v1/media")
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "upload: {}", reply.body);
    reply.json()["id"].as_str().unwrap().to_string()
}

// --- defect 2: content warnings ---------------------------------------------------

#[tokio::test]
async fn a_content_warning_survives_being_posted() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let reply = post_form(
        &h,
        "/api/v1/statuses",
        "status=the%20butler%20did%20it&spoiler_text=spoilers&visibility=public",
        &token,
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    let status = reply.json();
    assert_eq!(status["spoiler_text"], "spoilers");
    assert_eq!(
        status["sensitive"], true,
        "a warned post that publishes unmarked is the worst defect on the list"
    );
}

#[tokio::test]
async fn language_survives_being_posted() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let reply = post_form(
        &h,
        "/api/v1/statuses",
        "status=ol%C3%A1&language=pt&visibility=public",
        &token,
    )
    .await;
    assert_eq!(reply.json()["language"], "pt");
}

#[tokio::test]
async fn visibility_is_honoured_rather_than_defaulted() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    for visibility in ["public", "unlisted", "private"] {
        let reply = post_form(
            &h,
            "/api/v1/statuses",
            &format!("status=hello&visibility={visibility}"),
            &token,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
        assert_eq!(
            reply.json()["visibility"],
            visibility,
            "a post asked to be {visibility} was published otherwise"
        );
    }
}

// --- defect 1: media --------------------------------------------------------------

#[tokio::test]
async fn an_uploaded_image_reaches_the_post() {
    // The defect exactly: upload worked, the post had no image, nothing said so.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;
    let media_id = upload(&h, &token, Some("a small dog")).await;

    let reply = post_form(
        &h,
        "/api/v1/statuses",
        &format!("status=look&media_ids[]={media_id}&visibility=public"),
        &token,
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    let media = reply.json()["media_attachments"]
        .as_array()
        .expect("an array")
        .clone();
    assert_eq!(media.len(), 1, "the attachment was dropped");
    assert_eq!(media[0]["type"], "image");
    assert_eq!(
        media[0]["description"], "a small dog",
        "alt text must reach the published post"
    );
}

#[tokio::test]
async fn alt_text_can_be_set_after_upload_and_before_posting() {
    // Clients keep the composer open while the member types a description.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;
    let media_id = upload(&h, &token, None).await;

    let updated = send(
        &h,
        Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/media/{media_id}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("description=added%20later"))
            .unwrap(),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "body: {}", updated.body);
    assert_eq!(updated.json()["description"], "added later");

    let posted = post_form(
        &h,
        "/api/v1/statuses",
        &format!("status=look&media_ids[]={media_id}"),
        &token,
    )
    .await;
    assert_eq!(
        posted.json()["media_attachments"][0]["description"],
        "added later"
    );
}

async fn get_media(h: &Harness, token: &str, media_id: &str) -> Reply {
    send(
        h,
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/media/{media_id}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// Stage 5a: an upload's media type and blob live in the pod's resource
/// metadata, not in triples a client could write. `GET` and `PUT` on the media
/// read them from there, and the alt text sent with an upload arrives in the
/// same write as the upload itself.
#[tokio::test]
async fn an_upload_reads_back_from_metadata_with_its_alt_text() {
    let h = harness().await;
    let (user, token) = a_member(&h, "alice").await;

    let media_id = upload(&h, &token, Some("a small dog")).await;
    let got = get_media(&h, &token, &media_id).await;
    assert_eq!(got.status, StatusCode::OK, "body: {}", got.body);
    assert_eq!(
        got.json()["type"],
        "image",
        "the media type wasn't read from metadata"
    );
    assert_eq!(
        got.json()["description"],
        "a small dog",
        "the alt text sent with the upload was lost"
    );
    let iri = got.json()["url"].as_str().unwrap().to_string();

    // The server recorded the blob as the upload's metadata, and nothing in the
    // upload's own graph names it.
    let pod = h.stores.pod(user).unwrap();
    let meta = pod
        .read(|r| r.meta(&iri))
        .unwrap()
        .expect("the upload is a pod resource");
    assert!(matches!(meta.kind, Kind::NonRdfSource));
    assert_eq!(
        meta.blob.expect("with blob metadata").media_type,
        "image/png"
    );
    let pointers = pod
        .read_store()
        .quads_for_pattern(
            None,
            Some(NamedNodeRef::new_unchecked(
                "https://brolly.id/ns#blobDigest",
            )),
            None,
            Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(&iri))),
        )
        .count();
    assert_eq!(pointers, 0, "a blob pointer is still in the content graph");

    // The alt text lives in the upload's `.meta`, its description (spec 5d,
    // H6) — about the upload, never in the upload's own graph — and the
    // `.meta` is the auxiliary carrying it.
    let description = format!("{iri}.meta");
    let described = pod
        .read(|r| r.meta(&description))
        .unwrap()
        .expect("the description is its own resource");
    assert!(matches!(described.kind, Kind::Auxiliary));
    let alt: Vec<String> = pod
        .read_store()
        .quads_for_pattern(
            None,
            Some(NamedNodeRef::new_unchecked("https://brolly.id/ns#altText")),
            None,
            Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(&description))),
        )
        .map(|q| q.unwrap())
        .filter(|q| {
            matches!(&q.subject, oxigraph::model::NamedOrBlankNode::NamedNode(s) if s.as_str() == iri)
        })
        .map(|q| match q.object {
            oxigraph::model::Term::Literal(l) => l.value().to_string(),
            _ => String::new(),
        })
        .collect();
    assert_eq!(
        alt,
        vec!["a small dog"],
        "the alt text must be in the .meta, about the upload"
    );
    let own = pod
        .read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(&iri))),
        )
        .count();
    assert_eq!(own, 0, "the upload's own graph must be empty");

    // Alt text added later reads back through the same path.
    let later = upload(&h, &token, None).await;
    let updated = send(
        &h,
        Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/media/{later}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("description=added%20later"))
            .unwrap(),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "body: {}", updated.body);
    assert_eq!(updated.json()["type"], "image");
    let got = get_media(&h, &token, &later).await;
    assert_eq!(got.json()["type"], "image");
    assert_eq!(got.json()["description"], "added later");
}

#[tokio::test]
async fn another_members_attachment_cannot_be_posted() {
    // Mastodon answers "not found" rather than "forbidden" — a 403 would
    // confirm the attachment exists.
    let h = harness().await;
    let (_, alice) = a_member(&h, "alice").await;
    let (_, mallory) = a_member(&h, "mallory").await;
    let media_id = upload(&h, &alice, None).await;

    let reply = post_form(
        &h,
        "/api/v1/statuses",
        &format!("status=mine%20now&media_ids[]={media_id}"),
        &mallory,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn an_unknown_media_id_is_refused_rather_than_dropped() {
    // Silently posting without the attachment is the original defect.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let reply = post_form(
        &h,
        "/api/v1/statuses",
        "status=look&media_ids[]=not-a-real-id",
        &token,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(reply.json()["error"].as_str().is_some());
}

#[tokio::test]
async fn a_post_with_only_an_image_is_allowed() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;
    let media_id = upload(&h, &token, None).await;

    let reply = post_form(
        &h,
        "/api/v1/statuses",
        &format!("status=&media_ids[]={media_id}"),
        &token,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
}

// --- defect 5: fan-out ---------------------------------------------------------------

#[tokio::test]
async fn a_posted_status_is_delivered_to_followers() {
    // The predecessor's fan-out queried a table a migration had dropped and
    // swallowed the error, so posts reached nobody while returning 200.
    let h = harness().await;
    let (alice_id, alice_token) = a_member(&h, "alice").await;
    let (bob_id, _) = a_member(&h, "bob").await;

    // Bob follows alice.
    let bob_pod = h.stores.pod(bob_id).unwrap();
    let alice_pod = h.stores.pod(alice_id).unwrap();
    alice_pod
        .write(|w| {
            brolly_activitypub::follows::record(
                w,
                &brolly_identity::webid::actor("bob", BASE),
                &brolly_identity::webid::actor("alice", BASE),
            )
        })
        .unwrap();

    let reply = post_form(
        &h,
        "/api/v1/statuses",
        "status=hello%20followers&visibility=public",
        &alice_token,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);

    let bob_inbox = brolly_identity::webid::inbox("bob", BASE);
    let delivered = brolly_store::collection::members(&bob_pod.read_store(), &bob_inbox);
    assert!(
        !delivered.is_empty(),
        "the post reached nobody — this is the dropped-table defect"
    );
}

#[tokio::test]
async fn a_public_post_reaches_the_server_index() {
    // The instance actor is a delivery recipient like any other, so the public
    // timeline is populated by push with no crawler.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    post_form(
        &h,
        "/api/v1/statuses",
        "status=hello%20world&visibility=public",
        &token,
    )
    .await;

    let indexed = brolly_store::index::count_notes(h.stores.instance()).unwrap();
    assert_eq!(indexed, 1, "the public timeline index was not populated");
}

/// The same class of hole as resolve_repo, on a different code path, so it
/// needs its own assertion rather than being assumed from the ATProto fix.
#[tokio::test]
async fn a_disabled_member_is_off_the_public_timeline() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let created = post_form(
        &h,
        "/api/v1/statuses",
        "status=hello%20world&visibility=public",
        &token,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "setup: {}", created.body);

    // Confirm it IS on the timeline first — without this the test passes for
    // any reason the timeline happens to be empty.
    let before = send(
        &h,
        Request::builder()
            .uri("/api/v1/timelines/public")
            .header(header::HOST, BASE)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(before.status, StatusCode::OK, "setup: {}", before.body);
    assert!(
        before.body.contains("hello world"),
        "setup: {}",
        before.body
    );

    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&h.db.pool)
        .await
        .unwrap();

    let after = send(
        &h,
        Request::builder()
            .uri("/api/v1/timelines/public")
            .header(header::HOST, BASE)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(after.status, StatusCode::OK);
    assert!(
        !after.body.contains("hello world"),
        "a disabled member's notes are still on the public timeline: {}",
        after.body
    );
}

#[tokio::test]
async fn a_posted_status_is_fetchable_by_its_id() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let created = post_form(&h, "/api/v1/statuses", "status=hello", &token).await;
    let id = created.json()["id"].as_str().unwrap().to_string();

    let fetched = send(
        &h,
        Request::builder()
            .uri(format!("/api/v1/statuses/{id}"))
            .header(header::HOST, BASE)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(fetched.status, StatusCode::OK, "body: {}", fetched.body);
    assert_eq!(fetched.json()["content"], "hello");
}

// --- validation ------------------------------------------------------------------------

#[tokio::test]
async fn an_empty_post_is_refused_in_mastodons_error_shape() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let reply = post_form(&h, "/api/v1/statuses", "status=", &token).await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(reply.json()["error"].as_str().is_some());
}

#[tokio::test]
async fn an_overlong_post_is_refused_with_the_advertised_limit() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let long = "a".repeat(501);
    let reply = post_form(&h, "/api/v1/statuses", &format!("status={long}"), &token).await;

    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    let message = reply.json()["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains("500"),
        "the error should name the advertised limit, got {message}"
    );
}

#[tokio::test]
async fn posting_requires_a_write_scope() {
    let h = harness().await;
    let user = db::create_user(&h.db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let app = brolly_mastodon::oauth::register_app(
        &h.db.pool,
        "Reader",
        &["https://app.example/cb".into()],
        "read",
        None,
    )
    .await
    .unwrap();
    // Read-only: a posting attempt must not succeed.
    let token =
        brolly_mastodon::oauth::issue_token(&h.db.pool, &app.app.client_id, user.id, "read")
            .await
            .unwrap();

    let reply = post_form(&h, "/api/v1/statuses", "status=hello", &token).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn posting_requires_a_token_at_all() {
    let h = harness().await;
    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/api/v1/statuses")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("status=hello"))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}
