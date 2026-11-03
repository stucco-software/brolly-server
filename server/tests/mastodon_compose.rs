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
use serde_json::json;
use tower::ServiceExt;

/// The session cookie's name, from the one place that defines it.
const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;

const BASE: &str = "brolly.test";

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    stores: std::sync::Arc<brolly_store::StoreManager>,
}

async fn harness() -> Harness {
    // The advertised default (spec 4, H3), for the tests that don't care; the
    // limit tests want the real number or a small one.
    harness_with(brolly_domain::media::MAX_UPLOAD_BYTES).await
}

/// The harness with an overridden upload limit, for the tests that pin the
/// limit's behaviour (spec 4, H3) without putting megabytes in a multipart.
async fn harness_with(max_upload_bytes: usize) -> Harness {
    harness_sized(
        max_upload_bytes,
        brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
    )
    .await
}

/// And with a pod quota, for the tests that fill one.
async fn harness_sized(max_upload_bytes: usize, pod_quota_bytes: u64) -> Harness {
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
            theme_css: false,
            public_registration: false,
            limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
            www_redirect: None,
            max_upload_bytes,
            pod_quota_bytes,
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

/// The pod's quota holds for a Mastodon upload too: it is the same pod and
/// the same disk, whichever protocol wrote. A client that would pass it gets
/// Mastodon's error shape, not a dropped connection.
#[tokio::test]
async fn an_upload_past_the_pods_quota_is_refused() {
    let h = harness_sized(brolly_domain::media::MAX_UPLOAD_BYTES, 2 * 1024 * 1024).await;
    let (_user, token) = a_member(&h, "alice").await;
    let boundary = "----brollytest";
    let big = || {
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\
             Content-Type: image/png\r\n\r\n"
        );
        body.push_str(&"x".repeat(1024 * 1024));
        body.push_str(&format!("\r\n--{boundary}--\r\n"));
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
            .unwrap()
    };

    let first = send(&h, big()).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);

    let second = send(&h, big()).await;
    assert_eq!(
        second.status,
        StatusCode::INSUFFICIENT_STORAGE,
        "{}",
        second.body
    );
    assert!(
        second.json()["error"].as_str().is_some(),
        "Mastodon's error shape: {}",
        second.body
    );
}

/// The upload honours a member's override the way a Solid write does.
#[tokio::test]
async fn an_upload_honours_the_members_own_quota() {
    let h = harness_sized(brolly_domain::media::MAX_UPLOAD_BYTES, 2 * 1024 * 1024).await;
    let (user, token) = a_member(&h, "alice").await;
    db::set_quota(&h.db.pool, user, Some(4 * 1024 * 1024), None)
        .await
        .unwrap();
    let boundary = "----brollytest";
    let big = || {
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\
             Content-Type: image/png\r\n\r\n"
        );
        body.push_str(&"x".repeat(1024 * 1024));
        body.push_str(&format!("\r\n--{boundary}--\r\n"));
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
            .unwrap()
    };

    // Two mebibytes would have been one too many under the instance default.
    let first = send(&h, big()).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let second = send(&h, big()).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
}

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

/// Upload a file of `content_type`, raw: the `upload` helper above pins
/// `image/png` and asserts success, which is what every other test wants —
/// the refusal tests need their own type and no success assertion.
async fn upload_typed(h: &Harness, token: &str, content_type: &str, file: &str) -> Reply {
    let boundary = "----brollytest";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
         filename=\"a.file\"\r\nContent-Type: {content_type}\r\n\r\n{file}\r\n--{boundary}--\r\n"
    );
    send(
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
    .await
}

#[tokio::test]
async fn an_off_list_upload_is_a_415_whose_body_lists_the_allowed_ones() {
    // ADR 0018: the pod stores `text/html`, an attachment may not be it.
    // `upload_media` checks the media list before the pod's gate, and the 415
    // is this API's own error shape, with the list in it.
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let reply = upload_typed(&h, &token, "text/html", "<html>alert(1)</html>").await;
    assert_eq!(
        reply.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "{}",
        reply.body
    );
    let error = reply.json()["error"].as_str().unwrap().to_string();
    assert!(
        error.contains("text/html"),
        "must name what was sent: {error}"
    );
    assert!(
        error.contains("image/png"),
        "must list the allowed types: {error}"
    );
}

#[tokio::test]
async fn an_upload_over_the_limit_is_axums_own_413_framing_counts() {
    // H3 (spec 4): the limit is bytes-on-the-wire, so a file that fits on its
    // own can still 413 because its multipart framing counts too. Accepted
    // per the spec — no fudge factor. A small limit here proves the wiring;
    // the advertised 10 MiB is the same wiring with the real number.
    let h = harness_with(150).await;
    let (_, token) = a_member(&h, "alice").await;

    // The file's 64 bytes fit the 150-byte limit; the multipart framing
    // around them (~130 more) does not.
    let reply = upload_typed(&h, &token, "image/png", &"x".repeat(64)).await;
    assert_eq!(
        reply.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        reply.body
    );

    // Well under, framing included, it stands.
    let reply = upload_typed(&h, &token, "image/png", &"x".repeat(8)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
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

// --- read access follows the publication (spec 4, H5, ADR 0017) ----------------------

const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";

/// A session cookie, for the outbox path: `POST /outbox` authenticates as the
/// member, not as an OAuth client.
async fn a_session(h: &Harness, user: uuid::Uuid) -> String {
    db::create_session(&h.db.pool, user, time::Duration::hours(1), None)
        .await
        .unwrap()
}

/// Publish a bare note through the outbox, addressed to `to`/`cc`.
async fn publish_outbox(
    h: &Harness,
    session: &str,
    to: serde_json::Value,
    cc: serde_json::Value,
    attachments: serde_json::Value,
) -> (String, String) {
    let mut note = json!({
        "type": "Note",
        "content": "hello",
        "to": to,
        "cc": cc,
    });
    if !attachments.is_null() {
        note["attachment"] = attachments;
    }
    let reply = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/outbox")
            .header(header::HOST, "alice.brolly.test")
            .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(note.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "publish: {}", reply.body);
    let activity = serde_json::from_str::<serde_json::Value>(&reply.body).unwrap();
    (
        activity["id"].as_str().unwrap().to_string(),
        activity["object"]["id"].as_str().unwrap().to_string(),
    )
}

/// Every quad in the ACL at `resource.acl`.
fn acl_quads(h: &Harness, user: uuid::Uuid, resource: &str) -> Vec<oxigraph::model::Quad> {
    let pod = h.stores.pod(user).unwrap();
    let acl = format!("{resource}.acl");
    pod.read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(
                oxigraph::model::NamedNode::new_unchecked(&acl).as_ref(),
            )),
        )
        .filter_map(Result::ok)
        .collect()
}

/// Does the ACL at `resource.acl` carry this subject-predicate-object triple?
fn acl_grants(
    h: &Harness,
    user: uuid::Uuid,
    resource: &str,
    subject: &str,
    predicate: &str,
    object: &str,
) -> bool {
    acl_quads(h, user, resource).iter().any(|q| {
        q.subject.to_string() == format!("<{subject}>")
            && q.predicate.to_string() == format!("<{predicate}>")
            && q.object.to_string() == format!("<{object}>")
    })
}

/// The author's Read/Write/Control grant is on every composer-written ACL
/// (spec 4, H5): the closest ACL governs to the exclusion of ancestors, so an
/// audience-only ACL would lock the author out of their own note with no
/// Control to fix it with.
fn assert_author_grant(h: &Harness, user: uuid::Uuid, resource: &str) {
    let author = "https://alice.brolly.test/profile#me";
    let owner = format!("{resource}.acl#owner");
    for mode in ["Read", "Write", "Control"] {
        assert!(
            acl_grants(
                h,
                user,
                resource,
                &owner,
                &format!("{ACL}mode"),
                &format!("{ACL}{mode}"),
            ),
            "{resource}.acl lacks the author's {mode}"
        );
    }
    assert!(
        acl_grants(h, user, resource, &owner, &format!("{ACL}agent"), author),
        "{resource}.acl does not name the author"
    );
    assert!(
        acl_grants(
            h,
            user,
            resource,
            &owner,
            &format!("{ACL}accessTo"),
            resource,
        ),
        "{resource}.acl's owner grant does not scope to the resource"
    );
}

#[tokio::test]
async fn a_public_post_grants_the_public_class_and_the_author() {
    // The first row of the table (spec 4, H5): public → foaf:Agent, Read — on
    // the note, the activity, and each medium.
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;
    let media_id = upload(&h, &token, None).await;
    let local_id = media_id.split_at(26).0.to_string();
    let media_iri = format!("https://alice.brolly.test/~/media/{local_id}");

    let created = post_form(
        &h,
        "/api/v1/statuses",
        &format!("status=look&media_ids[]={media_id}&visibility=public"),
        &token,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "body: {}", created.body);
    let note_id = created.json()["id"]
        .as_str()
        .unwrap()
        .split_at(26)
        .0
        .to_string();
    let note_iri = format!("https://alice.brolly.test/~/notes/{note_id}");

    // The activity's id is minted server-side; the activities container holds
    // exactly this publication.
    let pod = h.stores.pod(alice).unwrap();
    let activity_iri = pod
        .write(|w| w.members("https://alice.brolly.test/~/activities/"))
        .unwrap()
        .pop()
        .expect("the publication minted an activity");

    for resource in [&note_iri, &activity_iri, &media_iri] {
        assert!(
            acl_quads(&h, alice, resource).iter().any(|q| {
                q.predicate.to_string() == format!("<{ACL}agentClass>")
                    && q.object.to_string() == format!("<{FOAF_AGENT}>")
            }),
            "{resource}.acl does not grant foaf:Agent"
        );
        assert_author_grant(&h, alice, resource);
    }
}

#[tokio::test]
async fn an_unlisted_post_reads_like_a_public_one() {
    // Unlisted is a discoverability question, not an access one: the grant is
    // the public one.
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;

    let created = post_form(
        &h,
        "/api/v1/statuses",
        "status=look&visibility=unlisted",
        &token,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "body: {}", created.body);
    let note_id = created.json()["id"]
        .as_str()
        .unwrap()
        .split_at(26)
        .0
        .to_string();
    let note_iri = format!("https://alice.brolly.test/~/notes/{note_id}");

    assert!(
        acl_quads(&h, alice, &note_iri).iter().any(|q| {
            q.predicate.to_string() == format!("<{ACL}agentClass>")
                && q.object.to_string() == format!("<{FOAF_AGENT}>")
        }),
        "an unlisted note's ACL does not grant foaf:Agent"
    );
    assert_author_grant(&h, alice, &note_iri);
}

#[tokio::test]
async fn a_followers_only_post_grants_the_followers_snapshot_not_strangers() {
    // The third row: one grant per local follower's WebID, snapshotted at
    // compose time. Bob follows; Carol doesn't; a remote follower isn't
    // granted — an agent that cannot authenticate here cannot present it.
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;
    a_member(&h, "bob").await;
    a_member(&h, "carol").await;

    let alice_pod = h.stores.pod(alice).unwrap();
    alice_pod
        .write(|w| {
            brolly_activitypub::follows::record(
                w,
                &brolly_identity::webid::actor("bob", BASE),
                &brolly_identity::webid::actor("alice", BASE),
            )?;
            brolly_activitypub::follows::record(
                w,
                "https://elsewhere.example/actor",
                &brolly_identity::webid::actor("alice", BASE),
            )
        })
        .unwrap();

    let created = post_form(
        &h,
        "/api/v1/statuses",
        "status=hello followers&visibility=private",
        &token,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "body: {}", created.body);
    let note_id = created.json()["id"]
        .as_str()
        .unwrap()
        .split_at(26)
        .0
        .to_string();
    let note_iri = format!("https://alice.brolly.test/~/notes/{note_id}");

    let quads = acl_quads(&h, alice, &note_iri);
    let bob_webid = "https://bob.brolly.test/profile#me";
    assert!(
        quads.iter().any(|q| {
            q.predicate.to_string() == format!("<{ACL}agent>")
                && q.object.to_string() == format!("<{bob_webid}>")
        }),
        "the follower at compose time is not granted"
    );
    for (who, label) in [
        ("https://carol.brolly.test/profile#me", "a stranger"),
        ("https://elsewhere.example/actor", "a remote follower"),
    ] {
        assert!(
            !quads
                .iter()
                .any(|q| q.object.to_string() == format!("<{who}>")),
            "{label} is granted on a followers-only post"
        );
    }
    assert!(
        !quads
            .iter()
            .any(|q| q.predicate.to_string() == format!("<{ACL}agentClass>")),
        "a followers-only post is not world-readable"
    );
    assert_author_grant(&h, alice, &note_iri);
}

#[tokio::test]
async fn a_direct_post_to_a_remote_webid_names_it_in_the_acl() {
    // The fourth row, through the outbox: a remote recipient is named exactly
    // as addressed, federation off — when the switch flips (ADR 0016), the
    // grants are already the right shape.
    let h = harness().await;
    let (alice, _) = a_member(&h, "alice").await;
    let session = a_session(&h, alice).await;

    let remote = "https://elsewhere.example/actor";
    let (_, note_iri) = publish_outbox(
        &h,
        &session,
        json!([remote]),
        json!([]),
        serde_json::Value::Null,
    )
    .await;

    let quads = acl_quads(&h, alice, &note_iri);
    assert!(
        quads.iter().any(|q| {
            q.predicate.to_string() == format!("<{ACL}agent>")
                && q.object.to_string() == format!("<{remote}>")
        }),
        "the remote recipient is not named in the ACL"
    );
    assert_author_grant(&h, alice, &note_iri);
}

#[tokio::test]
async fn a_direct_post_with_no_recipients_grants_only_the_author() {
    // The Mastodon composer's direct row addresses nobody (mention parsing is
    // not built), and an audience that addresses nobody grants nobody: the
    // note is the author's alone.
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;

    let created = post_form(
        &h,
        "/api/v1/statuses",
        "status=psst&visibility=direct",
        &token,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "body: {}", created.body);
    let note_id = created.json()["id"]
        .as_str()
        .unwrap()
        .split_at(26)
        .0
        .to_string();
    let note_iri = format!("https://alice.brolly.test/~/notes/{note_id}");

    // No grant on the note except the author's own: an audience that
    // addresses nobody grants nobody.
    let quads = acl_quads(&h, alice, &note_iri);
    let owner = format!("{note_iri}.acl#owner");
    assert!(
        !quads.iter().any(|q| {
            (q.predicate.to_string() == format!("<{ACL}agent>")
                || q.predicate.to_string() == format!("<{ACL}agentClass>"))
                && q.subject.to_string() != format!("<{owner}>")
        }),
        "a direct post with no recipients granted somebody: {quads:?}"
    );
    assert_author_grant(&h, alice, &note_iri);
}

// --- deleting a status deletes its media (spec 4, H5) --------------------------------

#[tokio::test]
async fn deleting_a_status_removes_its_media_and_their_auxiliaries() {
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;
    let media_id = upload(&h, &token, Some("a small dog")).await;
    let local_id = media_id.split_at(26).0.to_string();
    let media_iri = format!("https://alice.brolly.test/~/media/{local_id}");

    let created = post_form(
        &h,
        "/api/v1/statuses",
        &format!("status=look&media_ids[]={media_id}"),
        &token,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "body: {}", created.body);
    let status_id = created.json()["id"].as_str().unwrap().to_string();

    // The medium, its ACL, and its .meta are all there before the delete —
    // without this the test passes for any reason the delete removes
    // nothing.
    let pod = h.stores.pod(alice).unwrap();
    let before = pod
        .read(|r| {
            Ok((
                r.meta(&media_iri)?.is_some(),
                r.meta(&format!("{media_iri}.acl"))?.is_some(),
                r.meta(&format!("{media_iri}.meta"))?.is_some(),
            ))
        })
        .unwrap();
    assert_eq!(before, (true, true, true), "setup: the media must exist");

    let deleted = send(
        &h,
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/statuses/{status_id}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::OK, "body: {}", deleted.body);

    let after = pod
        .read(|r| {
            Ok((
                r.meta(&media_iri)?.is_some(),
                r.meta(&format!("{media_iri}.acl"))?.is_some(),
                r.meta(&format!("{media_iri}.meta"))?.is_some(),
            ))
        })
        .unwrap();
    assert_eq!(
        after,
        (false, false, false),
        "the medium or one of its auxiliaries outlived the post"
    );

    // And the status itself is gone, both surfaces.
    let fetched = send(
        &h,
        Request::builder()
            .uri(format!("/api/v1/statuses/{status_id}"))
            .header(header::HOST, BASE)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(fetched.status, StatusCode::NOT_FOUND);
    let media = get_media(&h, &token, &media_id).await;
    assert_eq!(media.status, StatusCode::NOT_FOUND, "body: {}", media.body);
}

#[tokio::test]
async fn a_binary_the_member_put_themselves_survives_the_delete() {
    // The composer minted the post's media; a member's own binary linked from
    // a hand-composed note is the member's (ADR 0017). It survives the post.
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;
    let session = a_session(&h, alice).await;

    let media_id = upload(&h, &token, None).await;
    let local_id = media_id.split_at(26).0.to_string();
    let minted = format!("https://alice.brolly.test/~/media/{local_id}");

    // The member's own binary, PUT into their pod directly — setup through
    // the pod, not through the code under test, in the acl_control.rs
    // tradition.
    let own = "https://alice.brolly.test/~/photos/dog.png";
    let pod = h.stores.pod(alice).unwrap();
    let digest = h.stores.blobs(alice).unwrap().put(b"PNG-BYTES").unwrap();
    pod.write(|w| {
        w.put(
            own,
            brolly_store::resources::Content::Binary(brolly_store::resources::BlobMeta {
                digest,
                media_type: "image/png".into(),
                byte_size: 9,
            }),
        )?;
        // A `.meta` of the member's own, so its survival is asserted too,
        // not just the binary's.
        let meta = format!("{own}.meta");
        let quads = [oxigraph::model::Quad::new(
            oxigraph::model::NamedOrBlankNode::NamedNode(
                oxigraph::model::NamedNode::new_unchecked(own),
            ),
            oxigraph::model::NamedNode::new_unchecked("https://brolly.id/ns#altText"),
            oxigraph::model::Term::Literal(oxigraph::model::Literal::new_simple_literal("my dog")),
            oxigraph::model::GraphName::NamedNode(oxigraph::model::NamedNode::new_unchecked(&meta)),
        )];
        w.put(&meta, brolly_store::resources::Content::Auxiliary(&quads))
    })
    .unwrap();

    let attachments = json!([
        {"type": "Document", "mediaType": "image/png", "url": minted},
        {"type": "Document", "mediaType": "image/png", "url": own},
    ]);
    let (activity_iri, note_iri) = publish_outbox(
        &h,
        &session,
        json!(["https://www.w3.org/ns/activitystreams#Public"]),
        json!([]),
        attachments,
    )
    .await;
    // A minted medium linked from a hand-composed note is still the post's.
    assert_author_grant(&h, alice, &minted);

    // The outbox-minted note id, as a Mastodon status id: the note id is the
    // status id's first half (ADR 0015).
    let note_id = note_iri.rsplit('/').next().unwrap().to_string();
    let status_id = brolly_mastodon::status_id::encode(&note_id, alice).unwrap();

    let deleted = send(
        &h,
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/statuses/{status_id}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::OK, "body: {}", deleted.body);

    let survives = pod
        .read(|r| {
            Ok((
                r.meta(own)?.is_some(),
                r.meta(&format!("{own}.meta"))?.is_some(),
                r.meta(&minted)?.is_some(),
                r.meta(&note_iri)?.is_some(),
                r.meta(&activity_iri)?.is_some(),
            ))
        })
        .unwrap();
    assert_eq!(
        survives,
        (true, true, false, false, false),
        "the member's own binary went with the post, or the post's resources survived it"
    );
}

#[tokio::test]
async fn deleting_someone_elses_status_is_not_found() {
    // Mastodon's semantics: a 403 would confirm it exists.
    let h = harness().await;
    let (_, alice) = a_member(&h, "alice").await;
    let (_, mallory) = a_member(&h, "mallory").await;

    let created = post_form(&h, "/api/v1/statuses", "status=hello", &alice).await;
    let status_id = created.json()["id"].as_str().unwrap().to_string();

    let deleted = send(
        &h,
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/statuses/{status_id}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {mallory}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleting_an_unknown_status_is_not_found() {
    let h = harness().await;
    let (_, token) = a_member(&h, "alice").await;

    let deleted = send(
        &h,
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/statuses/not-a-real-id")
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleting_requires_a_write_scope() {
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
    let token =
        brolly_mastodon::oauth::issue_token(&h.db.pool, &app.app.client_id, user.id, "read")
            .await
            .unwrap();

    let deleted = send(
        &h,
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/statuses/whatever")
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(deleted.status, StatusCode::FORBIDDEN);
}

// --- the avatar is a depiction (spec 4, H6) -----------------------------------

/// Write `<me> foaf:depiction <target>` into the profile graph, the way a
/// member's Solid client would with a `PATCH` on `/profile` — the write side
/// of the avatar mechanism, which is stage 6's and already built; these tests
/// are the reads.
fn depict(h: &Harness, user: uuid::Uuid, target: &str) {
    let pod = h.stores.pod(user).unwrap();
    pod.write(|w| {
        w.insert(&[oxigraph::model::Quad::new(
            oxigraph::model::NamedOrBlankNode::NamedNode(
                oxigraph::model::NamedNode::new_unchecked("https://alice.brolly.test/profile#me"),
            ),
            oxigraph::model::NamedNode::new_unchecked(brolly_domain::vocab::FOAF_DEPICTION),
            oxigraph::model::Term::NamedNode(oxigraph::model::NamedNode::new_unchecked(target)),
            oxigraph::model::GraphName::NamedNode(oxigraph::model::NamedNode::new_unchecked(
                "https://alice.brolly.test/profile",
            )),
        )])
    })
    .unwrap();
}

#[tokio::test]
async fn the_account_jsons_avatar_is_the_depiction_iri() {
    // H6 (spec 4): the account JSON resolves the depiction triple and emits
    // the target IRI — with no access check. The target here is a *private*
    // upload, never posted, so the only ACL on it is the author's own: a
    // private avatar is a valid avatar for a private audience, and the JSON
    // saying otherwise would be the server guessing privacy on the member's
    // behalf. The bytes stay WAC-guarded at their own address; the JSON leaks
    // a path, not bytes.
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;

    let account = send(
        &h,
        Request::builder()
            .uri("/api/v1/accounts/verify_credentials")
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(account.status, StatusCode::OK, "body: {}", account.body);
    assert!(account.json()["avatar"].is_null(), "no triple, no avatar");
    assert!(account.json()["avatar_static"].is_null());

    let media_id = upload(&h, &token, None).await;
    let local_id = media_id.split_at(26).0.to_string();
    let target = format!("https://alice.brolly.test/~/media/{local_id}");
    depict(&h, alice, &target);

    let account = send(
        &h,
        Request::builder()
            .uri("/api/v1/accounts/verify_credentials")
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(account.status, StatusCode::OK, "body: {}", account.body);
    assert_eq!(account.json()["avatar"], target);
    // The same IRI, not a second copy: we serve originals.
    assert_eq!(account.json()["avatar_static"], target);
}

#[tokio::test]
async fn writing_the_depiction_triple_grants_nothing_on_the_target() {
    // H6 (spec 4): "no auto-grant on writing the triple". Public read on the
    // depiction target is the member's call, made with an `.acl` — the server
    // guessing which uploads are meant to be public is the privacy decision it
    // must not make. So the write leaves the target's access exactly as it
    // found it: a private upload stays owner-only (anonymous bytes still
    // 401), and a public post's medium keeps the composer's grant — nothing
    // added, nothing widened.
    let h = harness().await;
    let (alice, token) = a_member(&h, "alice").await;

    // A private upload: never posted, so nothing but the author's root grant.
    let private_id = upload(&h, &token, None).await;
    let private_iri = format!(
        "https://alice.brolly.test/~/media/{}",
        private_id.split_at(26).0
    );

    // A public post's medium: the composer grants the world Read (spec 4, H5).
    let public_id = upload(&h, &token, None).await;
    let public_iri = format!(
        "https://alice.brolly.test/~/media/{}",
        public_id.split_at(26).0
    );
    let created = post_form(
        &h,
        "/api/v1/statuses",
        &format!("status=look&media_ids[]={public_id}&visibility=public"),
        &token,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "body: {}", created.body);

    let before = |resource: &str| -> std::collections::BTreeSet<String> {
        acl_quads(&h, alice, resource)
            .iter()
            .map(|q| q.to_string())
            .collect()
    };
    let private_before = before(&private_iri);
    let public_before = before(&public_iri);
    assert!(
        public_before.iter().any(|q| q.contains("agentClass")),
        "the public medium must start out public, or the test proves nothing"
    );

    // The member's call: point the profile at the private upload.
    depict(&h, alice, &private_iri);

    assert_eq!(
        before(&private_iri),
        private_before,
        "writing the triple changed the private target's ACL"
    );
    assert_eq!(
        before(&public_iri),
        public_before,
        "writing the triple changed the public target's ACL"
    );

    // And at the surface that matters: the private avatar's bytes are still
    // the author's alone.
    let fetched = send(
        &h,
        Request::builder()
            .uri(format!("/~/media/{}", private_id.split_at(26).0))
            .header(header::HOST, "alice.brolly.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        fetched.status,
        StatusCode::UNAUTHORIZED,
        "the private avatar's bytes were granted to the world: {}",
        fetched.body
    );
}
