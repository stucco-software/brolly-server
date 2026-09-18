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
    /// Exposed so a test can write into the pod directly, rather than only
    /// through HTTP.
    stores: std::sync::Arc<StoreManager>,
    user: uuid::Uuid,
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
            instance_name: "brolly.test".to_string(),
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
        _db: db,
        _dir: dir,
        router,
        session,
        stores,
        user: user.id,
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

// --- the WebID profile document ----------------------------------------------

/// A GET with an explicit `Accept`, which `send` does not offer.
async fn get_accepting(h: &Harness, path: &str, accept: &str) -> (StatusCode, String, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ACCEPT, accept)
        .body(Body::empty())
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body, content_type)
}

/// The triple that makes WebID-first login possible.
///
/// An app handed a WebID dereferences it and reads `solid:oidcIssuer` to learn
/// where to send the member to authenticate. Before this endpoint existed the
/// WebID answered 501, so no conformant Solid client could log anybody in
/// however well the OIDC endpoints themselves worked.
#[tokio::test]
async fn a_webid_advertises_its_issuer_and_its_storage() {
    let h = harness().await;
    let (status, body, content_type) = get_accepting(&h, "/profile", "text/turtle").await;

    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert!(
        content_type.starts_with("text/turtle"),
        "got: {content_type}"
    );

    assert!(
        body.contains("http://www.w3.org/ns/solid/terms#oidcIssuer"),
        "no oidcIssuer, so no client can log in: {body}"
    );
    // The issuer is the apex, matching what /.well-known/openid-configuration
    // publishes — a client compares the two.
    assert!(body.contains("https://brolly.test"), "got: {body}");

    assert!(
        body.contains("http://www.w3.org/ns/pim/space#storage"),
        "got: {body}"
    );
    assert!(body.contains(ROOT), "storage must be discoverable: {body}");
}

/// The document is not the person, and `#me` is the difference.
#[tokio::test]
async fn the_profile_document_is_distinct_from_its_subject() {
    let h = harness().await;
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;

    assert!(body.contains("PersonalProfileDocument"), "got: {body}");
    assert!(body.contains("primaryTopic"), "got: {body}");
    assert!(body.contains("/profile#me"), "got: {body}");
}

/// A browser must not be handed a Turtle download.
///
/// Its Accept header ends in `*/*`, which the RDF negotiator maps to Turtle,
/// so this is a real trap rather than a hypothetical one.
#[tokio::test]
async fn a_browser_gets_a_page_it_can_read() {
    let h = harness().await;
    let (status, body, content_type) = get_accepting(
        &h,
        "/profile",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/html"),
        "a browser was handed {content_type}"
    );
    assert!(body.contains("alice"), "got: {body}");
}

/// A member's own triples survive the projection. The server adds to the
/// document; it does not replace it.
#[tokio::test]
async fn the_members_own_triples_are_still_there() {
    let h = harness().await;
    let pod = h.stores.pod(h.user).unwrap();
    let document = format!("{BASE}/profile");
    let me = format!("{document}#me");
    brolly_solid::profile::write(
        &pod,
        &me,
        &document,
        &brolly_solid::profile::Profile {
            display_name: "Alice Example".into(),
            ..brolly_solid::profile::Profile::blank()
        },
    )
    .unwrap();

    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(body.contains("Alice Example"), "got: {body}");
    // ...alongside the derived ones.
    assert!(body.contains("oidcIssuer"), "got: {body}");
}

// --- the actor's collections --------------------------------------------------

/// Followers and following are public, as the fediverse expects: a follower
/// list is how another server decides whether it already knows you.
#[tokio::test]
async fn the_follow_collections_are_public() {
    let h = harness().await;

    for path in ["/followers", "/following"] {
        let (status, body, content_type) =
            get_accepting(&h, path, "application/activity+json").await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert!(
            content_type.starts_with("application/activity+json"),
            "{path}: {content_type}"
        );
        assert!(body.contains("OrderedCollection"), "{path}: {body}");
        assert!(body.contains("totalItems"), "{path}: {body}");
    }
}

/// The inbox is the member's home timeline (D6), so it is the one collection
/// here that is not public — serving it anonymously would publish who they
/// follow and everything those people have sent them.
///
/// 404 rather than 403, matching `require_admin`: 403 would confirm both that
/// the resource exists and that the caller found a real member.
#[tokio::test]
async fn an_anonymous_caller_cannot_read_an_inbox() {
    let h = harness().await;
    let (status, _, _) = get_accepting(&h, "/inbox", "application/activity+json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_owner_can_read_their_own_inbox() {
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/inbox")
        .header(header::HOST, HOST)
        .header(header::ACCEPT, "application/activity+json")
        .header(header::COOKIE, format!("brolly_session={}", h.session))
        .body(Body::empty())
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();

    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert!(body.contains("OrderedCollection"), "got: {body}");
}

// --- CORS ----------------------------------------------------------------------

async fn headers_of(
    h: &Harness,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST);
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    let response = h
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    (response.status(), response.headers().clone())
}

/// Solid is a browser protocol: an app at another origin dereferences the
/// WebID. Without this header the browser refuses to hand the response to the
/// script, and login fails at the very first step.
#[tokio::test]
async fn a_webid_is_readable_cross_origin() {
    let h = harness().await;
    let (status, headers) =
        headers_of(&h, "GET", "/profile", &[("origin", "https://app.example")]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
}

/// The omission that matters more than the header.
///
/// `Allow-Origin: *` paired with `Allow-Credentials: true` would let any site
/// make cookie-authenticated requests to the dashboard and read the answers.
/// Solid authenticates with a header the calling script must already hold, so
/// credentials are never allowed here.
#[tokio::test]
async fn cors_never_allows_credentials() {
    let h = harness().await;
    let (_, headers) =
        headers_of(&h, "GET", "/profile", &[("origin", "https://app.example")]).await;

    assert!(
        headers.get("access-control-allow-credentials").is_none(),
        "a wildcard origin must never be paired with credentials"
    );
}

/// `DPoP` is not on the CORS safelist, so every authenticated Solid request is
/// preflighted. If the preflight does not name the header, the real request is
/// never sent.
#[tokio::test]
async fn a_preflight_admits_the_headers_a_solid_client_sends() {
    let h = harness().await;
    let (status, headers) = headers_of(
        &h,
        "OPTIONS",
        "/~/notes/first",
        &[
            ("origin", "https://app.example"),
            ("access-control-request-method", "PUT"),
            (
                "access-control-request-headers",
                "authorization,dpop,content-type",
            ),
        ],
    )
    .await;

    assert!(status.is_success(), "preflight rejected: {status}");
    let allowed = headers
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(allowed.contains("dpop"), "got: {allowed}");
    assert!(allowed.contains("authorization"), "got: {allowed}");

    let methods = headers
        .get("access-control-allow-methods")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_uppercase();
    assert!(methods.contains("PUT"), "got: {methods}");
    assert!(methods.contains("PATCH"), "got: {methods}");
}

/// A script can read only safelisted response headers unless they are exposed.
/// `Location` after a POST and `Link` for the ACL are both load-bearing in LDP.
#[tokio::test]
async fn the_headers_ldp_depends_on_are_exposed() {
    let h = harness().await;
    let (_, headers) =
        headers_of(&h, "GET", "/profile", &[("origin", "https://app.example")]).await;

    let exposed = headers
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    for wanted in ["location", "link", "etag", "wac-allow"] {
        assert!(exposed.contains(wanted), "{wanted} not exposed: {exposed}");
    }
}

// --- ACL resources -------------------------------------------------------------

/// Another member with a live session, for requests made by someone other
/// than the pod's owner.
async fn member_session(h: &Harness, username: &str) -> String {
    let user = db::create_user(
        &h._db.pool,
        username,
        None,
        "correct-horse-battery",
        "member",
    )
    .await
    .unwrap();
    db::create_session(&h._db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap()
}

/// [`Harness::send`], as whoever holds `session`.
async fn send_as(
    h: &Harness,
    session: &str,
    method: &str,
    path: &str,
    body: Option<(&str, &str)>,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("brolly_session={session}"));
    if let Some((content_type, _)) = body {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    let request = builder
        .body(body.map_or(Body::empty(), |(_, b)| Body::from(b.to_string())))
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let text = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, text, headers)
}

const BOB_WEBID: &str = "https://bob.brolly.test/profile#me";

/// `/~/shared/.acl`: Alice controls `/~/shared/`; Bob may read and write
/// everything inside it through `acl:default`, and holds no Control.
fn share_with_bob(h: &Harness) {
    let pod = h.stores.pod(h.user).unwrap();
    let shared = format!("{ROOT}shared/");
    let g = format!("{shared}.acl");
    let owner = format!("{g}#owner");
    let bob = format!("{g}#bob");
    insert_quads(
        &pod,
        &[
            t(&g, &owner, &format!("{ACL}accessTo"), &shared),
            t(&g, &owner, &format!("{ACL}default"), &shared),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(
                &g,
                &owner,
                &format!("{ACL}agent"),
                &format!("{BASE}/profile#me"),
            ),
            t(&g, &bob, &format!("{ACL}default"), &shared),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &bob, &format!("{ACL}agent"), BOB_WEBID),
        ],
    )
    .unwrap();
}

/// The takeover over the wire: inherited Write used to be enough to PATCH the
/// container's ACL and grant yourself Control.
#[tokio::test]
async fn bob_cannot_patch_an_acl_he_does_not_control() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let bob_auth = format!("{ROOT}shared/.acl#bob");
    let grab = format!("INSERT DATA {{ <{bob_auth}> <{ACL}mode> <{ACL}Control> }}");
    let (status, _, _) = send_as(
        &h,
        &bob,
        "PATCH",
        "/~/shared/.acl",
        Some(("application/sparql-update", &grab)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let pod = h.stores.pod(h.user).unwrap();
    let granted = pod
        .contains(&t(
            &format!("{ROOT}shared/.acl"),
            &bob_auth,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ))
        .unwrap();
    assert!(!granted, "the refused PATCH must not have landed");
}

/// The same takeover by replacing the whole document. `ldp::put` refuses with
/// `Forbidden`, which `pod.rs::ldp_error` answers with 403.
#[tokio::test]
async fn bob_cannot_put_an_acl_he_does_not_control() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let shared = format!("{ROOT}shared/");
    let takeover = format!(
        "@prefix acl: <{ACL}> .\n\
         <#bob> acl:agent <{BOB_WEBID}> ; acl:accessTo <{shared}> ; acl:default <{shared}> ;\n\
           acl:mode acl:Read, acl:Write, acl:Control .\n"
    );
    let (status, _, _) = send_as(
        &h,
        &bob,
        "PUT",
        "/~/shared/.acl",
        Some(("text/turtle", &takeover)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let pod = h.stores.pod(h.user).unwrap();
    let g = format!("{shared}.acl");
    let control = |auth: &str| {
        pod.contains(&t(
            &g,
            auth,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ))
        .unwrap()
    };
    assert!(!control(&format!("{g}#bob")), "the refused PUT landed");
    assert!(control(&format!("{g}#owner")), "Alice's grant was replaced");
}

/// Deleting the container's ACL would drop Alice's grants on `/~/shared/` and
/// fall back to the root ACL. `ldp::delete` refuses with `Forbidden` before it
/// looks for the resource, so this is a 403, not a 404.
#[tokio::test]
async fn bob_cannot_delete_an_acl_he_does_not_control() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let (status, _, _) = send_as(&h, &bob, "DELETE", "/~/shared/.acl", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let pod = h.stores.pod(h.user).unwrap();
    assert!(
        storage::exists(&pod, &format!("{ROOT}shared/.acl")),
        "the refused DELETE landed"
    );
}

#[tokio::test]
async fn wac_allow_on_an_acl_names_nothing_for_bob() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let (status, _, headers) = send_as(&h, &bob, "GET", "/~/shared/.acl", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "existence is a disclosure");
    // A refusal carries no WAC-Allow at all, and an empty one would do too.
    // What must never appear is a mode.
    let allowed = headers
        .get("wac-allow")
        .map(|v| v.to_str().unwrap().to_string());
    assert!(
        matches!(allowed.as_deref(), None | Some("user=\"\"")),
        "got {allowed:?}"
    );

    let (status, _, headers) = h.send("GET", "/~/shared/.acl", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["wac-allow"], "user=\"read write append control\"");
}
