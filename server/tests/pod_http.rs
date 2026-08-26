//! The pod over HTTP: subdomain routing, LDP verbs, and ADR 0010's default-deny.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_solid::storage;
use brolly_store::{StoreManager, insert_quads};
use http_body_util::BodyExt;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use tower::ServiceExt;

const HOST: &str = "alice.brolly.test";
const BASE: &str = "https://alice.brolly.test";
const ROOT: &str = "https://alice.brolly.test/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn t(g: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(n(s)),
        n(p),
        Term::NamedNode(n(o)),
        GraphName::NamedNode(n(g)),
    )
}

struct Harness {
    _db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    session: String,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 4, 60).unwrap());

    let user = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let session = db::create_session(&db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();

    // Seed the pod: storage root plus an ACL granting Alice everything.
    let pod = stores.pod(user.id).unwrap();
    storage::init_storage_root(&pod, ROOT).unwrap();
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    insert_quads(
        &pod,
        &[
            // A real pod root ACL carries both: acl:default governs the
            // container's children, acl:accessTo governs the container itself.
            // They are distinct scopes and conflating them is how ACLs
            // silently over-grant.
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(
                &g,
                &a,
                &format!("{ACL}agent"),
                &format!("{BASE}/profile#me"),
            ),
        ],
    )
    .unwrap();

    let router = app(
        AppState {
            pool: db.pool.clone(),
            base_domain: "brolly.test".into(),
            stores,
            provider_key: std::sync::Arc::new(
                brolly_solid::oidc::store::load_or_create_key(&db.pool)
                    .await
                    .expect("provider key"),
            ),
        },
        "server/static",
    );

    Harness {
        _db: db,
        _dir: dir,
        router,
        session,
    }
}

impl Harness {
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<(&str, &str)>,
        authed: bool,
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST);
        if authed {
            builder = builder.header(header::COOKIE, format!("brolly_session={}", self.session));
        }
        if let Some((content_type, _)) = body {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        let request = builder
            .body(body.map_or(Body::empty(), |(_, b)| Body::from(b.to_string())))
            .unwrap();

        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let text =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                .to_string();
        (status, text, headers)
    }
}

const NOTE: &str = r#"<> <https://example.org/title> "Written over HTTP" ."#;

#[tokio::test]
async fn put_then_get_over_http() {
    let h = harness().await;

    let (status, _, _) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body, headers) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Written over HTTP"), "got: {body}");
    assert_eq!(headers[header::CONTENT_TYPE], "text/turtle");
    // Clients use WAC-Allow to decide whether to offer an edit affordance
    // instead of discovering the answer by failing.
    assert!(headers["wac-allow"].to_str().unwrap().contains("write"));
    assert!(
        headers[header::LINK]
            .to_str()
            .unwrap()
            .contains("rel=\"acl\"")
    );
}

#[tokio::test]
async fn the_storage_root_is_reachable() {
    // A wildcard route does not match an empty remainder, so `/~/` needs its
    // own entry — without it the pod root 404s.
    let h = harness().await;
    let (status, body, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("pim/space#Storage"), "got: {body}");
}

#[tokio::test]
async fn an_anonymous_reader_gets_nothing() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, _) = h.send("GET", "/~/note", None, false).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "existence itself is a disclosure"
    );
}

#[tokio::test]
async fn rdf_xml_is_refused_over_http() {
    // ADR 0007 end to end.
    let h = harness().await;
    let (status, body, _) = h
        .send(
            "PUT",
            "/~/note",
            Some(("application/rdf+xml", "<rdf:RDF/>")),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(body.contains("rdf+xml"), "got: {body}");
}

#[tokio::test]
async fn patch_works_in_both_formats() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let n3 = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:p a solid:InsertDeletePatch ;
  solid:inserts { <https://alice.brolly.test/~/note> <https://example.org/tag> "n3" . } ."#;
    let (status, _, _) = h
        .send("PATCH", "/~/note", Some(("text/n3", n3)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let sparql =
        r#"INSERT DATA { <https://alice.brolly.test/~/note> <https://example.org/tag> "sparql" }"#;
    let (status, _, _) = h
        .send(
            "PATCH",
            "/~/note",
            Some(("application/sparql-update", sparql)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(
        body.contains("n3") && body.contains("sparql"),
        "got: {body}"
    );
}

#[tokio::test]
async fn a_failed_patch_precondition_is_a_conflict() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let n3 = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:p a solid:InsertDeletePatch ;
  solid:deletes { <https://alice.brolly.test/~/note> <https://example.org/absent> "x" . } ."#;
    let (status, _, _) = h
        .send("PATCH", "/~/note", Some(("text/n3", n3)), true)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_patch_in_an_unknown_format_is_refused() {
    let h = harness().await;
    let (status, _, _) = h
        .send("PATCH", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn delete_removes_the_resource() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, _) = h.send("DELETE", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn options_advertises_the_patch_formats() {
    let h = harness().await;
    let (status, _, headers) = h.send("OPTIONS", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let patch = headers["accept-patch"].to_str().unwrap();
    assert!(patch.contains("text/n3") && patch.contains("sparql-update"));
}

#[tokio::test]
async fn oauth_paths_on_a_subdomain_are_not_pod_writes() {
    // ADR 0010's guarantee, over the wire. This is the credential-capture case:
    // a client misconfigured with a user's subdomain must not be able to write
    // into that user's pod.
    let h = harness().await;
    for path in ["/oauth/token", "/oauth/authorize", "/api/v1/statuses"] {
        let (status, _, _) = h
            .send(
                "POST",
                path,
                Some(("application/x-www-form-urlencoded", "code=stolen")),
                true,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} must not be writable");
    }
}

#[tokio::test]
async fn an_unmatched_subdomain_path_does_not_fall_through_to_ldp() {
    let h = harness().await;
    let (status, body, _) = h.send("GET", "/random-path", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("/~/"),
        "the 404 should point at user storage: {body}"
    );
}

#[tokio::test]
async fn an_unknown_pod_is_not_found() {
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/~/note")
        .header(header::HOST, "nobody.brolly.test")
        .body(Body::empty())
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- LDP-NR over HTTP -------------------------------------------------------

/// A PDF header is a real binary signature that is still valid UTF-8, so the
/// `&str`-bodied helper above can carry it.
const PDF: &str = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";

#[tokio::test]
async fn a_binary_put_and_got_over_http_keeps_its_bytes_and_its_type() {
    let h = harness().await;

    let (status, _, _) = h
        .send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body, headers) = h.send("GET", "/~/paper.pdf", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PDF, "the bytes must come back unchanged");
    assert_eq!(headers[header::CONTENT_TYPE], "application/pdf");
    // WAC still applies, so the header a client reads for edit affordances is
    // present on a binary too.
    assert!(headers["wac-allow"].to_str().unwrap().contains("write"));
}

#[tokio::test]
async fn a_binary_is_invisible_to_a_caller_without_read() {
    // The failure mode this guards: media served off disk without an ACL check,
    // so a private image is public to anyone holding the URL.
    let h = harness().await;
    h.send(
        "PUT",
        "/~/private.pdf",
        Some(("application/pdf", PDF)),
        true,
    )
    .await;

    let (status, _, _) = h.send("GET", "/~/private.pdf", None, false).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_binary_can_be_deleted_over_http() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    let (status, _, _) = h.send("DELETE", "/~/paper.pdf", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = h.send("GET", "/~/paper.pdf", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rdf_xml_is_refused_over_http_rather_than_stored_as_a_blob() {
    // ADR 0007 through the full stack: the 415 must survive the addition of a
    // blob path that would otherwise happily accept it as opaque bytes.
    let h = harness().await;
    let (status, _, _) = h
        .send(
            "PUT",
            "/~/doc.rdf",
            Some(("application/rdf+xml", "<rdf:RDF/>")),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
