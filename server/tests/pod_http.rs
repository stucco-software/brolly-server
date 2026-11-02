//! The pod over HTTP: subdomain routing, LDP verbs, and ADR 0010's default-deny.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_store::StoreManager;
use brolly_store::resources::{Content, Kind, Pod, PodRead};
use http_body_util::BodyExt;
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// The session cookie's name, from the one place that defines it.
const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;

const HOST: &str = "alice.brolly.test";
const BASE: &str = "https://alice.brolly.test";
const ROOT: &str = "https://alice.brolly.test/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";

/// Does the pod hold exactly this quad?
fn holds(pod: &Pod, quad: &Quad) -> bool {
    pod.read_store()
        .quads_for_pattern(
            Some(quad.subject.as_ref()),
            Some(quad.predicate.as_ref()),
            Some(quad.object.as_ref()),
            Some(quad.graph_name.as_ref()),
        )
        .next()
        .is_some()
}

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
    // The advertised default (spec 4, H3): most of these tests don't care
    // about the limit, and the ones that do want the real number or a small
    // one, not a silently different harness.
    harness_with(brolly_domain::media::MAX_UPLOAD_BYTES).await
}

/// The harness with an overridden upload limit, for the tests that pin the
/// limit's behaviour (spec 4, H3) without putting megabytes on the wire.
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
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 4, 60).unwrap());

    let user = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let session = db::create_session(&db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();

    // Seed the pod: storage root plus an ACL granting Alice everything.
    let pod = stores.pod(user.id).unwrap();
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    let grant = [
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
    ];
    pod.write(|w| {
        w.create_root(ROOT)?;
        w.put(&g, Content::Auxiliary(&grant))?;
        Ok(())
    })
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
            builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={}", self.session));
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

/// A request with extra headers, as whoever holds `session`, or anonymously.
fn conditional_request(
    method: &str,
    path: &str,
    body: Option<(&str, &str)>,
    session: Option<&str>,
    extra: &[(&str, &str)],
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST);
    if let Some(session) = session {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={session}"));
    }
    if let Some((content_type, _)) = body {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder
        .body(body.map_or(Body::empty(), |(_, b)| Body::from(b.to_string())))
        .unwrap()
}

/// Send a request. Takes the router by value so a test can `tokio::spawn` it.
async fn run(
    router: axum::Router,
    request: Request<Body>,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let text = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, text, headers)
}

impl Harness {
    /// [`Harness::send`] as the owner, with extra request headers.
    async fn send_if(
        &self,
        method: &str,
        path: &str,
        body: Option<(&str, &str)>,
        extra: &[(&str, &str)],
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        run(
            self.router.clone(),
            conditional_request(method, path, body, Some(self.session.as_str()), extra),
        )
        .await
    }

    /// A request with a body and **no** `Content-Type`, as the owner. The
    /// tuple-shaped helpers above always send one, so §2.1 can't be tested
    /// through them.
    async fn send_untyped(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::COOKIE, format!("{SESSION_COOKIE}={}", self.session))
            .body(Body::from(body.to_string()))
            .unwrap();
        run(self.router.clone(), request).await
    }

    /// A resource's stored `dcterms:modified`, read from the pod rather than a
    /// header, so a test about the value doesn't depend on how it is rendered.
    fn modified(&self, path: &str) -> String {
        self.stores
            .pod(self.user)
            .unwrap()
            .read_store()
            .meta(&format!("{BASE}{path}"))
            .unwrap()
            .unwrap()
            .modified
    }

    /// The `ETag` the owner sees on `path`.
    async fn etag(&self, path: &str) -> String {
        let (status, body, headers) = self.send("GET", path, None, true).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        headers
            .get(header::ETAG)
            .unwrap_or_else(|| panic!("no ETag on {path}"))
            .to_str()
            .unwrap()
            .to_string()
    }
}

const NOTE: &str = r#"<> <https://example.org/title> "Written over HTTP" ."#;

#[tokio::test]
async fn put_then_get_over_http() {
    let h = harness().await;

    let (status, _, _) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a PUT that creates is a 201 (H11)"
    );

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

/// The failure this guards is a member's own resource vanishing when it should
/// ask them to authenticate. An app whose access token expired mid-session used
/// to get a 404 and conclude the note had been deleted. H1 answers 401, with a
/// challenge it can act on.
///
/// Stage 0's A2 rule gave 404 so that existence wasn't disclosed. That
/// guarantee still holds, and
/// `an_anonymous_refusal_is_the_same_for_a_real_and_a_fictive_resource` pins
/// it. The 401 is the same whether the resource is there or not.
#[tokio::test]
async fn an_anonymous_reader_gets_nothing() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, body, headers) = h.send("GET", "/~/note", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("Written over HTTP"), "got: {body}");
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.starts_with("DPoP "), "got: {challenge}");
    assert!(
        challenge.contains(r#"as_uri="https://brolly.test""#),
        "Solid-OIDC §9.1 makes as_uri a MUST: {challenge}"
    );
    assert!(
        !challenge.contains("error="),
        "nothing was presented, so nothing was refused: {challenge}"
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

/// Spec 5a, *After an upgrade*. A pod as stage 0 wrote it keeps containment in
/// each container's own graph. After the upgrade, deleting a member de-lists
/// it. A copy-only upgrade would leave the old `ldp:contains` in the content
/// graph and list the member forever. The root's stale listing of its own
/// `.acl`, which `acl-uncontain` used to sweep, doesn't survive either.
#[tokio::test]
async fn an_upgraded_container_stops_listing_a_deleted_member() {
    const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    const LDP: &str = "http://www.w3.org/ns/ldp#";
    let h = harness().await;
    let folder = format!("{ROOT}folder/");
    let doc = format!("{folder}doc");
    let acl = format!("{ROOT}.acl");
    let owner = format!("{acl}#owner");

    // Everything goes, the metadata graph included, and the old layout goes in
    // its place: the root's types and listing in its own graph, the folder's
    // listing in the folder's graph, and the owner's grant.
    let pod = h.stores.pod(h.user).unwrap();
    let raw = pod.raw_store();
    raw.clear().unwrap();
    for quad in [
        t(ROOT, ROOT, RDF_TYPE, &format!("{LDP}BasicContainer")),
        t(
            ROOT,
            ROOT,
            RDF_TYPE,
            "http://www.w3.org/ns/pim/space#Storage",
        ),
        t(ROOT, ROOT, &format!("{LDP}contains"), &folder),
        t(ROOT, ROOT, &format!("{LDP}contains"), &acl),
        t(&folder, &folder, RDF_TYPE, &format!("{LDP}BasicContainer")),
        t(&folder, &folder, &format!("{LDP}contains"), &doc),
        t(
            &doc,
            &doc,
            "https://example.org/title",
            "https://example.org/a",
        ),
        t(&acl, &owner, &format!("{ACL}accessTo"), ROOT),
        t(&acl, &owner, &format!("{ACL}default"), ROOT),
        t(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(
            &acl,
            &owner,
            &format!("{ACL}agent"),
            &format!("{BASE}/profile#me"),
        ),
    ] {
        raw.insert(&quad).unwrap();
    }
    brolly_store::resources::upgrade(&pod).unwrap();
    drop(pod);

    let (status, root, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK, "{root}");
    assert!(
        root.contains(&folder),
        "the upgrade lost a listed container: {root}"
    );
    assert!(!root.contains(&acl), "the root still lists its ACL: {root}");

    let (status, listing, _) = h.send("GET", "/~/folder/", None, true).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(
        listing.contains(&doc),
        "setup: the member is listed: {listing}"
    );

    let (status, _, _) = h.send("DELETE", "/~/folder/doc", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, listing, _) = h.send("GET", "/~/folder/", None, true).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(
        !listing.contains(&doc),
        "the deleted member is still listed: {listing}"
    );
}

/// Rewritten for 5b. `OPTIONS` used to answer one static line for every
/// resource and every caller; now it is authenticated and per-resource, so the
/// PATCH formats go to a caller who may PATCH and to nobody else. What this
/// guards: an `Accept-Patch` offered to someone whose every PATCH is refused.
#[tokio::test]
async fn options_advertises_the_patch_formats() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h.send("OPTIONS", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let patch = header_of(&headers, "accept-patch");
    assert!(patch.contains("text/n3") && patch.contains("sparql-update"));

    // An anonymous caller holds nothing here, so it is told nothing.
    let (status, _, headers) = h.send("OPTIONS", "/~/note", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers.get("accept-patch").is_none(),
        "advertised to nobody"
    );
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
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a PUT that creates is a 201 (H11)"
    );

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

    let (status, body, _) = h.send("GET", "/~/private.pdf", None, false).await;
    // 401, not the bytes. The same refusal as for a graph: a binary is not a
    // side door around WAC.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("%PDF"), "the bytes leaked: {body}");
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

#[tokio::test]
async fn an_off_list_content_type_is_a_415_whose_body_lists_the_allowed_ones() {
    // H2 (spec 4): the exact defect this closes — a member PUTs `text/html`
    // with their own credentials and the bytes come back served as `text/html`
    // from the member's own origin, which is stored XSS. The 415's body
    // carries the list, because a client that gets a bare 415 has nothing to
    // act on.
    let h = harness().await;
    let (status, body, _) = h
        .send("PUT", "/~/page.html", Some(("text/html", "<html>")), true)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");
    assert!(
        body.contains("text/html"),
        "must name what was sent: {body}"
    );
    for allowed in ["image/png", "application/pdf", "application/zip"] {
        assert!(body.contains(allowed), "must list {allowed}: {body}");
    }

    // Nothing was recorded, and nothing is servable.
    let (status, _, _) = h.send("GET", "/~/page.html", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_svg_is_refused_like_any_other_off_list_type() {
    // The one absence that is a decision rather than an omission (spec 4,
    // H2): SVG is script, and a member-hosted SVG on the member's origin is
    // stored XSS with the pod's cookies in scope. This test exists so that
    // reopening the question means deleting it.
    let h = harness().await;
    let (status, body, _) = h
        .send(
            "PUT",
            "/~/icon.svg",
            Some(("image/svg+xml", "<svg onload=alert(1) />")),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");
    assert!(body.contains("image/svg+xml"), "{body}");
}

#[tokio::test]
async fn a_content_type_with_parameters_is_matched_by_its_bare_type() {
    // H2 (spec 4): parameters are stripped before the list is consulted —
    // `image/png; charset=utf-8` is `image/png`. A list that matched on the
    // raw header value would refuse every parameterised upload a real client
    // sends.
    let h = harness().await;
    let (status, _, _) = h
        .send(
            "PUT",
            "/~/avatar.png",
            Some(("image/png; charset=utf-8", "PNG-BYTES")),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // And the recorded type is the bare one, so that is what a read serves.
    let (_, _, headers) = h.send("GET", "/~/avatar.png", None, true).await;
    assert_eq!(headers[header::CONTENT_TYPE], "image/png");
}

#[tokio::test]
async fn an_upload_over_the_limit_is_axums_own_413() {
    // H3 (spec 4): the limit is enforced by `DefaultBodyLimit`, so the 413 is
    // axum's own — a small limit here proves the wiring, which is the same
    // wiring that carries the advertised 10 MiB.
    let h = harness_with(64).await;
    let (status, _, _) = h
        .send(
            "PUT",
            "/~/big.bin",
            Some(("application/octet-stream", &"x".repeat(65))),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // The boundary is inclusive: at exactly the limit, and not one byte over,
    // the PUT stands.
    let (status, _, _) = h
        .send(
            "PUT",
            "/~/exact.bin",
            Some(("application/octet-stream", &"x".repeat(64))),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn a_body_between_axums_default_and_the_advertised_limit_is_accepted() {
    // H3 (spec 4): axum's own default body limit is 2 MiB, so this proves the
    // pod routes carry the advertised 10 MiB rather than the framework's
    // default — the “advertises a limit it does not enforce” bug, inverted.
    let h = harness().await;
    let bytes = vec![b'x'; 3 * 1024 * 1024];
    let request = Request::builder()
        .method("PUT")
        .uri("/~/big.pdf")
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("{SESSION_COOKIE}={}", h.session))
        .header(header::CONTENT_TYPE, "application/pdf")
        .body(Body::from(bytes))
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn every_response_carries_nosniff() {
    // H4 (spec 4): one layer at composition, so the header is on every
    // response — the binary read where it is load-bearing, the profile and a
    // 404 where it is redundant, and `/health`, which is not a pod route at
    // all. The redundant cases are the point: per-route application is how
    // the header ends up missing on the one route that matters.
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    // (path, expected status): the binary read where the header is
    // load-bearing, the profile and `/health` where it is redundant but must
    // still be there, and a 404 — a refusal is a response too.
    for (path, expected) in [
        ("/~/paper.pdf", StatusCode::OK),
        ("/profile", StatusCode::OK),
        ("/health", StatusCode::OK),
        ("/~/nothing-here", StatusCode::NOT_FOUND),
    ] {
        let (status, _, headers) = h.send("GET", path, None, true).await;
        assert_eq!(status, expected, "{path}");
        assert_eq!(
            headers[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff",
            "{path}: the layer must be app-wide, not per-route"
        );
    }
}

/// A pod has a quota, and a write that would pass it is a 507. The disk is
/// the instance's, and a public inbox or a shared container is a grant to
/// write to it: without a ceiling, Append on one container is enough to
/// fill the box for everybody. The quota is what the directory holds —
/// store and blobs — so freeing space makes room again.
#[tokio::test]
async fn a_pod_refuses_a_write_past_its_quota() {
    // Two mebibytes over a store whose empty floor is a few hundred
    // kibibytes: one mebibyte of upload fits, a second does not.
    let h = harness_sized(brolly_domain::media::MAX_UPLOAD_BYTES, 2 * 1024 * 1024).await;
    let mebibyte = "x".repeat(1024 * 1024);

    let (status, body, _) = h
        .send(
            "PUT",
            "/~/one.pdf",
            Some(("application/pdf", &mebibyte)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, _, _) = h
        .send(
            "PUT",
            "/~/two.pdf",
            Some(("application/pdf", &mebibyte)),
            true,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::INSUFFICIENT_STORAGE,
        "a second mebibyte would pass the quota"
    );
    let (status, _, _) = h.send("GET", "/~/two.pdf", None, true).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the refused write left nothing"
    );

    // Not only binaries: a document counts the same.
    let (status, _, _) = h
        .send("PUT", "/~/big", Some(("text/turtle", &mebibyte)), true)
        .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);

    // Freeing space makes room again.
    let (status, _, _) = h.send("DELETE", "/~/one.pdf", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body, _) = h
        .send(
            "PUT",
            "/~/two.pdf",
            Some(("application/pdf", &mebibyte)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// An admin's override is the member's quota, not the instance's number.
/// Set directly in the database here — the console and the CLI are later
/// chunks — and read by the write path off the row it already loads.
#[tokio::test]
async fn a_members_own_quota_overrides_the_instance_default() {
    let h = harness_sized(brolly_domain::media::MAX_UPLOAD_BYTES, 2 * 1024 * 1024).await;
    db::set_quota(&h._db.pool, h.user, Some(4 * 1024 * 1024), None)
        .await
        .unwrap();
    let mebibyte = "x".repeat(1024 * 1024);

    // Three mebibytes fit under four where the instance default is two.
    for name in ["one", "two", "three"] {
        let (status, body, _) = h
            .send(
                "PUT",
                &format!("/~/{name}.pdf"),
                Some(("application/pdf", &mebibyte)),
                true,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {body}");
    }

    // Lowered below what the pod holds: an add is refused, a delete is not,
    // and the delete is how the member gets back under.
    db::set_quota(&h._db.pool, h.user, Some(1024 * 1024), None)
        .await
        .unwrap();
    let (status, _, _) = h
        .send(
            "PUT",
            "/~/four.pdf",
            Some(("application/pdf", &mebibyte)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    let (status, _, _) = h.send("DELETE", "/~/one.pdf", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "a delete always runs");
}

/// Nothing served by the instance may be framed, and a referrer leaves the
/// instance with its origin only. One layer, every response, for the same
/// reason as `nosniff`: the consent screen — rendered inside somebody else's
/// OAuth flow, the highest-stakes page in the product — is the one that must
/// not be clickjackable, and per-route application is how it would end up
/// being the one that is. `alice.<apex>` is same-site with the apex, so
/// `SameSite=Lax` is not the defence here; this is.
#[tokio::test]
async fn every_response_refuses_framing_and_limits_the_referrer() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for (path, expected) in [
        ("/~/paper.pdf", StatusCode::OK),
        ("/profile", StatusCode::OK),
        ("/health", StatusCode::OK),
        ("/~/nothing-here", StatusCode::NOT_FOUND),
    ] {
        let (status, _, headers) = h.send("GET", path, None, true).await;
        assert_eq!(status, expected, "{path}");
        assert_eq!(
            headers
                .get("content-security-policy")
                .map(|v| v.to_str().unwrap()),
            Some("frame-ancestors 'none'"),
            "{path}: frame-ancestors"
        );
        assert_eq!(
            headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
            Some("DENY"),
            "{path}: X-Frame-Options, for the browsers that predate CSP 2"
        );
        assert_eq!(
            headers.get("referrer-policy").map(|v| v.to_str().unwrap()),
            Some("strict-origin-when-cross-origin"),
            "{path}: Referrer-Policy"
        );
    }
}

// --- the settings resources (spec 6, H2) --------------------------------------

/// The IRIs provisioning creates, as `provision::pod` derives them.
const PREFERENCES: &str = "https://alice.brolly.test/~/settings/preferences.ttl";
const PUBLIC_INDEX: &str = "https://alice.brolly.test/~/settings/publicTypeIndex.ttl";
const PRIVATE_INDEX: &str = "https://alice.brolly.test/~/settings/privateTypeIndex.ttl";
const SOLID: &str = "http://www.w3.org/ns/solid/terms#";

/// The real provisioning path, on the harness pod. The harness seeds its own
/// root and root ACL so the LDP tests stand alone; the settings tests layer
/// the real `provision::pod` over that, which is the path registration takes.
fn provision(h: &Harness) {
    let pod = h.stores.pod(h.user).unwrap();
    brolly_server::provision::pod(&pod, "alice", "brolly.test").unwrap();
}

/// Provisioning creates the three settings resources with their types, and
/// the public index's ACL carries exactly the two grants the spec names —
/// asserted grant by grant, because an ACL that quietly dropped the owner's
/// half would lock the owner out, and one that quietly added `acl:default`
/// would publish whatever lands beside the index (spec 6, H2).
#[tokio::test]
async fn provisioning_creates_the_settings_and_the_public_indexs_acl() {
    let h = harness().await;
    provision(&h);
    let pod = h.stores.pod(h.user).unwrap();

    // The three resources, with their types as stored content in their own
    // graphs — not projection.
    let public_acl = format!("{PUBLIC_INDEX}.acl");
    for (resource, kind, class) in [
        (
            PREFERENCES,
            "the preferences file",
            format!("{SPACE}ConfigurationFile"),
        ),
        (
            PUBLIC_INDEX,
            "the public index",
            format!("{SOLID}TypeIndex"),
        ),
        (
            PUBLIC_INDEX,
            "the public index",
            format!("{SOLID}ListedDocument"),
        ),
        (
            PRIVATE_INDEX,
            "the private index",
            format!("{SOLID}TypeIndex"),
        ),
        (
            PRIVATE_INDEX,
            "the private index",
            format!("{SOLID}UnlistedDocument"),
        ),
    ] {
        let meta = pod.read(|r| r.meta(resource)).unwrap().expect(kind);
        assert_eq!(meta.kind, Kind::RdfSource, "{kind}");
        assert!(
            holds(&pod, &t(resource, resource, RDF_TYPE, &class)),
            "{kind} is not typed {class}"
        );
    }
    // No registrations anywhere: the containers are seeded empty, and the
    // only type triples in the indexes are the indexes' own.
    assert!(!holds(
        &pod,
        &t(
            PUBLIC_INDEX,
            PUBLIC_INDEX,
            RDF_TYPE,
            &format!("{SOLID}TypeRegistration"),
        )
    ));

    // The public index's ACL, grant by grant. The owner's half: the root
    // grant's shape, `acl:accessTo` the index.
    let owner = format!("{public_acl}#owner");
    for grant in [
        t(&public_acl, &owner, &format!("{ACL}accessTo"), PUBLIC_INDEX),
        t(
            &public_acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Read"),
        ),
        t(
            &public_acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Write"),
        ),
        t(
            &public_acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ),
        t(
            &public_acl,
            &owner,
            &format!("{ACL}agent"),
            &format!("{BASE}/profile#me"),
        ),
    ] {
        assert!(
            holds(&pod, &grant),
            "the owner's grant is missing {grant:?}"
        );
    }
    // The world's half: one Read, via `acl:agentClass foaf:Agent`.
    let world = format!("{public_acl}#public");
    for grant in [
        t(&public_acl, &world, &format!("{ACL}accessTo"), PUBLIC_INDEX),
        t(
            &public_acl,
            &world,
            &format!("{ACL}mode"),
            &format!("{ACL}Read"),
        ),
        t(
            &public_acl,
            &world,
            &format!("{ACL}agentClass"),
            "http://xmlns.com/foaf/0.1/Agent",
        ),
    ] {
        assert!(
            holds(&pod, &grant),
            "the world's grant is missing {grant:?}"
        );
    }
    // No `acl:default` on either authorization — nothing inherits either
    // grant.
    let defaults: Vec<Quad> = pod
        .read_store()
        .quads_for_pattern(
            None,
            Some(n(&format!("{ACL}default")).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(n(&public_acl).as_ref())),
        )
        .map(Result::unwrap)
        .collect();
    assert!(defaults.is_empty(), "the index's ACL carries acl:default");

    // And the world grant reaches exactly one resource: the root, the
    // preferences file and the private index stay owner-only (H2 — this is
    // the one place provisioning grants to foaf:Agent).
    let world_grants: Vec<Quad> = pod
        .read_store()
        .quads_for_pattern(
            None,
            Some(n(&format!("{ACL}agentClass")).as_ref()),
            Some(n("http://xmlns.com/foaf/0.1/Agent").as_ref().into()),
            None,
        )
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        world_grants.len(),
        1,
        "the world was granted more than the public index: {world_grants:?}"
    );
    for untouched in [PREFERENCES, PRIVATE_INDEX] {
        assert!(
            pod.read(|r| r.meta(&format!("{untouched}.acl")))
                .unwrap()
                .is_none(),
            "{untouched} has an ACL of its own"
        );
    }
}

/// The world grant is behavioural, not paperwork: an anonymous caller reads
/// the public index over HTTP, and is refused on the preferences file and the
/// private index — the owner-only default everywhere else (spec 6, H2).
#[tokio::test]
async fn the_world_reads_the_public_index_and_nothing_else() {
    let h = harness().await;
    provision(&h);

    let (status, body, headers) = h
        .send("GET", "/~/settings/publicTypeIndex.ttl", None, false)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("TypeIndex"),
        "the anonymous reader got the index: {body}"
    );
    // No challenge: the caller was not asked to authenticate, because nothing
    // refused them.
    assert!(headers.get(header::WWW_AUTHENTICATE).is_none());

    for refused in [
        "/~/settings/preferences.ttl",
        "/~/settings/privateTypeIndex.ttl",
    ] {
        let (status, body, headers) = h.send("GET", refused, None, false).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}: {body}");
        let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(challenge.starts_with("DPoP "), "got: {challenge}");
    }
}

/// The owner still reads and writes their public index through its own ACL —
/// the half that must come with the world grant, or the closest ACL would
/// lock the owner out of their own index (spec 6, H2).
#[tokio::test]
async fn the_owner_still_writes_the_public_index() {
    let h = harness().await;
    provision(&h);

    let (status, text, _) = h
        .send(
            "PUT",
            "/~/settings/publicTypeIndex.ttl",
            Some((
                "text/turtle",
                "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n<https://alice.brolly.test/~/settings/publicTypeIndex.ttl> a solid:TypeIndex, solid:ListedDocument ;\n  solid:forClass <http://xmlns.com/foaf/0.1/Agent> .\n",
            )),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");

    // And the anonymous reader still gets it: the owner's write did not
    // disturb the world grant.
    let (status, body, _) = h
        .send("GET", "/~/settings/publicTypeIndex.ttl", None, false)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
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
    pod.write(|w| {
        brolly_solid::profile::write(
            w,
            &me,
            &document,
            &brolly_solid::profile::Profile {
                display_name: "Alice Example".into(),
                ..brolly_solid::profile::Profile::blank()
            },
        )
    })
    .unwrap();

    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(body.contains("Alice Example"), "got: {body}");
    // ...alongside the derived ones.
    assert!(body.contains("oidcIssuer"), "got: {body}");
}

// --- the WebID profile document: the depiction (spec 4, H6) -------------------

/// Write `<me> foaf:depiction <target>` into the profile graph, the way a
/// member's Solid client would with a `PATCH` on `/profile`. The write side of
/// the avatar mechanism is stage 6's and already built; the page under test
/// here is the read.
fn depict(h: &Harness, target: &str) {
    let pod = h.stores.pod(h.user).unwrap();
    pod.write(|w| {
        w.insert(&[t(
            &format!("{BASE}/profile"),
            &format!("{BASE}/profile#me"),
            brolly_domain::vocab::FOAF_DEPICTION,
            target,
        )])
    })
    .unwrap();
}

/// A caller who can read the target sees the depiction; a caller who cannot
/// sees the page without it. H6 (spec 4): the page is the one surface that
/// embeds the bytes' fetch in a page it serves, so it is the one surface that
/// checks — the JSON surfaces emit the IRI unchecked, because a pointer leaks
/// a path, not bytes.
#[tokio::test]
async fn the_profile_page_renders_the_depiction_only_to_a_caller_who_can_read_it() {
    let h = harness().await;
    // A private binary: PUT as the owner, granted to nobody — the root's
    // `acl:default` is the only ACL that reaches it.
    h.send(
        "PUT",
        "/~/photos/me.png",
        Some(("image/png", "PNG-BYTES")),
        true,
    )
    .await;
    let target = format!("{ROOT}photos/me.png");
    depict(&h, &target);

    // The owner: the page renders the depiction.
    let (status, body, _) = run(
        h.router.clone(),
        conditional_request(
            "GET",
            "/profile",
            None,
            Some(&h.session),
            &[(header::ACCEPT.as_str(), "text/html")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert!(
        body.contains(&target),
        "the owner's page lost the depiction: {body}"
    );

    // Anonymous: the page renders, the depiction does not.
    let (status, body, _) = run(
        h.router.clone(),
        conditional_request(
            "GET",
            "/profile",
            None,
            None,
            &[(header::ACCEPT.as_str(), "text/html")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the page itself is public: {body}");
    assert!(
        !body.contains(&target),
        "the depiction leaked to anonymous: {body}"
    );
    assert!(
        !body.contains("<img"),
        "an anonymous page renders no image at all: {body}"
    );
}

/// The other half of H6's rule: a depiction the *world* can read renders for
/// an anonymous caller. The public target is a public post's medium — the
/// composer's ACL (spec 4, H5), chunk 3's substrate — rather than a
/// hand-built grant, so the page is tested against the access the rest of the
/// server actually produces.
#[tokio::test]
async fn the_profile_page_renders_a_public_depiction_to_anonymous_callers() {
    let h = harness().await;
    // A medium at the composer's minting ground: PUT the binary there, then
    // publish a public note that carries it, and the composer grants the
    // world Read on it in the same write as the publication.
    let local = brolly_mastodon::status_id::new_note_id(1_724_000_000_000, [7; 10]);
    h.send(
        "PUT",
        &format!("/~/media/{local}"),
        Some(("image/png", "PNG-BYTES")),
        true,
    )
    .await;
    let note = serde_json::json!({
        "type": "Note",
        "content": "hello",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "attachment": [{"type": "Document", "mediaType": "image/png", "url": format!("{ROOT}media/{local}")}],
    });
    let (status, _, _) = run(
        h.router.clone(),
        conditional_request(
            "POST",
            "/outbox",
            Some(("application/json", &note.to_string())),
            Some(&h.session),
            &[],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the publication failed");

    let target = format!("{ROOT}media/{local}");
    depict(&h, &target);

    let (status, body, _) = run(
        h.router.clone(),
        conditional_request(
            "GET",
            "/profile",
            None,
            None,
            &[(header::ACCEPT.as_str(), "text/html")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert!(
        body.contains(&target),
        "a world-readable depiction did not render for anonymous: {body}"
    );
}

// --- the WebID profile document: writing (spec 6, H1) -------------------------

/// The profile graph's IRIs, for the write tests.
const PROFILE: &str = "https://alice.brolly.test/profile";
const ME: &str = "https://alice.brolly.test/profile#me";
const FOAF: &str = "http://xmlns.com/foaf/0.1/";
const SPACE: &str = "http://www.w3.org/ns/pim/space#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

/// The owner replaces their profile over HTTP, and what the projection serves
/// is what was stored plus the derived five.
#[tokio::test]
async fn the_owner_puts_their_profile() {
    let h = harness().await;
    let (status, text, _) = h
        .send(
            "PUT",
            "/profile",
            Some((
                "text/turtle",
                r#"<#me> <http://xmlns.com/foaf/0.1/name> "Put over HTTP" ."#,
            )),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");

    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(body.contains("Put over HTTP"), "got: {body}");
    // The graph holds what was written; the five the projection derives are
    // served beside it, not stored.
    let pod = h.stores.pod(h.user).unwrap();
    assert!(!holds(
        &pod,
        &t(PROFILE, ME, RDF_TYPE, &format!("{FOAF}Person"))
    ));
}

/// What the projection serves, written back, is what the projection serves:
/// the round trip a read-modify-write client (SolidOS, Penny) performs is
/// lossless — the derived five are dropped on the way in and derived again on
/// the way out, and the dashboard's five carry.
#[tokio::test]
async fn a_read_modify_write_round_trip_is_lossless() {
    let h = harness().await;
    let pod = h.stores.pod(h.user).unwrap();
    pod.write(|w| {
        brolly_solid::profile::write(
            w,
            ME,
            PROFILE,
            &brolly_solid::profile::Profile {
                display_name: "Alice Example".into(),
                bio: "Founder".into(),
                locked: true,
                ..brolly_solid::profile::Profile::blank()
            },
        )
    })
    .unwrap();

    let (_, first, _) = get_accepting(&h, "/profile", "text/turtle").await;
    let (status, text, _) = h
        .send(
            "PUT",
            "/profile",
            Some(("text/turtle", first.as_str())),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");

    let (_, second, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert_eq!(second, first, "the round trip must be lossless");
    // The dashboard's five carried, not cleared: a locked account stays
    // locked (H1 — a read-modify-write is what every Solid client does).
    assert!(brolly_solid::profile::read(&pod.read_store(), ME, PROFILE).locked);
}

/// A `PUT` that omits the dashboard's predicates clears them — LDP `PUT`
/// semantics, owned by H1. The consequence the spec records:
/// `as:manuallyApprovesFollowers` absent reads as *false*, so a locked account
/// comes back unlocked. A client that hand-builds its body instead of editing
/// what it read pays it; one that read-modify-writes does not.
#[tokio::test]
async fn a_put_that_omits_the_dashboards_predicates_clears_them() {
    let h = harness().await;
    let pod = h.stores.pod(h.user).unwrap();
    pod.write(|w| {
        brolly_solid::profile::write(
            w,
            ME,
            PROFILE,
            &brolly_solid::profile::Profile {
                display_name: "Alice Example".into(),
                locked: true,
                ..brolly_solid::profile::Profile::blank()
            },
        )
    })
    .unwrap();

    let (status, text, _) = h
        .send(
            "PUT",
            "/profile",
            Some((
                "text/turtle",
                r#"<#me> <http://xmlns.com/foaf/0.1/nick> "Hand-built" ."#,
            )),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");

    let profile = brolly_solid::profile::read(&pod.read_store(), ME, PROFILE);
    assert_eq!(profile.display_name, "", "the PUT replaced the graph");
    // The locked-account consequence H1 owns: absent reads as false.
    assert!(!profile.locked, "a locked account came back unlocked");
    // ...and what was written is there.
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(body.contains("Hand-built"), "got: {body}");
    assert!(!body.contains("Alice Example"), "got: {body}");
}

/// A self-asserted storage root is dropped on write and the deployment's value
/// is served on read; a member's own type survives. Positions, not predicates:
/// `rdf:type` is at once a reserved position and the commonest predicate in a
/// hand-written profile, and `<#me> a schema:Person` is an ordinary triple.
#[tokio::test]
async fn a_self_asserted_storage_root_is_dropped_and_the_deployments_is_served() {
    let h = harness().await;
    let (status, text, _) = h
        .send(
            "PUT",
            "/profile",
            Some((
                "text/turtle",
                "<#me> <http://www.w3.org/ns/pim/space#storage> <https://elsewhere.example/~carol/> ;\n<http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .",
            )),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");

    // Dropped on write: the stored graph holds the member's type, not their
    // storage root.
    let pod = h.stores.pod(h.user).unwrap();
    assert!(holds(
        &pod,
        &t(PROFILE, ME, RDF_TYPE, "http://schema.org/Person")
    ));
    assert!(!holds(
        &pod,
        &t(
            PROFILE,
            ME,
            &format!("{SPACE}storage"),
            "https://elsewhere.example/~carol/"
        )
    ));

    // The deployment's value is served on read — and it is the only one.
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(!body.contains("elsewhere"), "got: {body}");
    assert!(body.contains(ROOT), "the deployment's storage root: {body}");
    assert_eq!(
        body.matches(&format!("{SPACE}storage")).count(),
        1,
        "one storage root, the deployment's: {body}"
    );
    assert!(
        body.contains("http://schema.org/Person"),
        "a member's own type survives: {body}"
    );
}

/// The three settings links (H2), derived from the storage root like
/// `space:storage` is and served unconditionally — SolidOS reads them off
/// every profile, so a profile without them is a pod it can log into and do
/// nothing with. A member-written alternative is dropped on write and the
/// deployment's served alone on read: deployment-fact slots, the H1
/// `solid:oidcIssuer`/`space:storage` precedent carried forward.
#[tokio::test]
async fn the_settings_links_are_derived_and_reserved() {
    let h = harness().await;

    // Served before any write, pointing at the provisioned resources — the
    // IRIs derive from the storage root, so no provisioning has to have run
    // for the links to be right.
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    for (predicate, target) in [
        (format!("{SOLID}publicTypeIndex"), PUBLIC_INDEX),
        (format!("{SOLID}privateTypeIndex"), PRIVATE_INDEX),
        (format!("{SPACE}preferencesFile"), PREFERENCES),
    ] {
        assert!(
            body.contains(&predicate),
            "no {predicate} on the profile: {body}"
        );
        assert!(
            body.contains(target),
            "{predicate} does not point at {target}: {body}"
        );
        assert_eq!(
            body.matches(&predicate).count(),
            1,
            "one {predicate}, the deployment's: {body}"
        );
    }

    // A member's alternatives are dropped on write — all three slots, whole
    // slots, whatever the object.
    let (status, text, _) = h
        .send(
            "PUT",
            "/profile",
            Some((
                "text/turtle",
                "<#me> <http://www.w3.org/ns/solid/terms#publicTypeIndex> <https://elsewhere.example/publicTypeIndex.ttl> ;\n<http://www.w3.org/ns/solid/terms#privateTypeIndex> <https://elsewhere.example/privateTypeIndex.ttl> ;\n<http://www.w3.org/ns/pim/space#preferencesFile> <https://elsewhere.example/prefs.ttl> .\n",
            )),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");

    let pod = h.stores.pod(h.user).unwrap();
    for predicate in [
        format!("{SOLID}publicTypeIndex"),
        format!("{SOLID}privateTypeIndex"),
        format!("{SPACE}preferencesFile"),
    ] {
        assert!(
            !holds(
                &pod,
                &t(
                    PROFILE,
                    ME,
                    &predicate,
                    "https://elsewhere.example/anything"
                )
            ),
            "{predicate} was stored"
        );
        let stored: Vec<Quad> = pod
            .read_store()
            .quads_for_pattern(
                Some(n(ME).as_ref().into()),
                Some(n(&predicate).as_ref()),
                None,
                Some(GraphNameRef::NamedNode(n(PROFILE).as_ref())),
            )
            .map(Result::unwrap)
            .collect();
        assert!(
            stored.is_empty(),
            "{predicate} seated a self-asserted settings link: {stored:?}"
        );
    }

    // ...and the deployment's links are served alone on read.
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(!body.contains("elsewhere"), "got: {body}");
    assert!(
        body.matches(PUBLIC_INDEX).count() == 1
            && body.matches(PRIVATE_INDEX).count() == 1
            && body.matches(PREFERENCES).count() == 1,
        "the deployment's links, once each: {body}"
    );
}

/// Nobody but the owner writes the profile (H1): anonymous gets 401 with a
/// challenge, another member 403, a foreign WebID 401 naming the token — per
/// stage 5b's H1 table, from the credential alone.
#[tokio::test]
async fn nobody_but_the_owner_writes_the_profile() {
    let h = harness().await;
    const BODY: &str = r#"<#me> <http://xmlns.com/foaf/0.1/name> "No" ."#;

    // Anonymous: 401 and a challenge, like every unauthenticated refusal.
    let (status, _, headers) = h
        .send("PUT", "/profile", Some(("text/turtle", BODY)), false)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.starts_with("DPoP "), "got: {challenge}");

    // Another member: authenticated, and not the owner.
    let bob = db::create_user(&h._db.pool, "bob", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let bob = db::create_session(&h._db.pool, bob.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    let (status, body, _) = run(
        h.router.clone(),
        conditional_request(
            "PUT",
            "/profile",
            Some(("text/turtle", BODY)),
            Some(&bob),
            &[],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A foreign WebID: a token that verifies but names a WebID this instance
    // doesn't host, so it is the token that is wrong (stage 5, `solid_subject`).
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let sec1 = key.verifying_key().to_sec1_bytes();
    let jkt = brolly_identity::dpop::thumbprint(&brolly_identity::dpop::PublicJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: B64.encode(&sec1[1..33]),
        y: B64.encode(&sec1[33..65]),
    });
    let provider_key = brolly_solid::oidc::store::load_or_create_key(&h._db.pool)
        .await
        .unwrap();
    let token = brolly_solid::oidc::tokens::issue_access(
        &provider_key,
        "https://brolly.test",
        "https://elsewhere.example/carol#me",
        "https://app.example",
        "webid",
        &jkt,
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    let proof = dpop_proof(
        &key,
        "PUT",
        PROFILE,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let (status, _, headers) = run(
        h.router.clone(),
        conditional_request(
            "PUT",
            "/profile",
            Some(("text/turtle", BODY)),
            None,
            &[
                (header::AUTHORIZATION.as_str(), &format!("DPoP {token}")),
                ("dpop", &proof),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.contains("invalid_token"), "got: {challenge}");
}

/// A DPoP proof, as `solid_token_access.rs` builds one: the profile's foreign
/// caller has to arrive with a token that verifies, or the refusal is the
/// token's and not the WebID's.
fn dpop_proof(key: &SigningKey, method: &str, url: &str, ath: Option<&str>) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(&sec1[1..33]),
            "y": B64.encode(&sec1[33..65]),
        },
    });
    let mut claims = serde_json::json!({
        "htm": method,
        "htu": url,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": time::OffsetDateTime::now_utc().unix_timestamp(),
    });
    if let Some(ath) = ath {
        claims["ath"] = serde_json::Value::String(ath.to_string());
    }
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// `DELETE` and `POST` are 405 with an `Allow` naming what the profile takes
/// (5b, H16): the method router's own refusal, which carries its own list.
#[tokio::test]
async fn the_profile_cannot_be_deleted_or_posted_to() {
    let h = harness().await;
    for method in ["DELETE", "POST"] {
        let (status, _, headers) = h
            .send(method, "/profile", Some(("text/turtle", NOTE)), true)
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        let allow = headers[header::ALLOW].to_str().unwrap();
        for expected in ["GET", "HEAD", "PUT", "PATCH"] {
            assert!(allow.contains(expected), "{method}: Allow was {allow}");
        }
    }
}

/// A patch inserts, deletes, and refuses what every other patch refuses —
/// through the same solver, scoped to the profile graph (H1).
#[tokio::test]
async fn the_owner_patches_their_profile() {
    let h = harness().await;
    h.send(
        "PUT",
        "/profile",
        Some((
            "text/turtle",
            r#"<#me> <http://xmlns.com/foaf/0.1/name> "Before" ."#,
        )),
        true,
    )
    .await;

    // An insert-only patch — Append, in 5c's classification — inserts.
    let insert = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:p a solid:InsertDeletePatch ;
  solid:inserts { <#me> <http://xmlns.com/foaf/0.1/nick> "Patchy" . } ."#;
    let (status, text, _) = h
        .send("PATCH", "/profile", Some(("text/n3", insert)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(body.contains("Patchy"), "got: {body}");
    // An insert, not a replace: what was there is still there.
    assert!(body.contains("Before"), "got: {body}");

    // A deleting patch — Write, in 5c's classification — deletes.
    let delete = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:p a solid:InsertDeletePatch ;
  solid:deletes { <#me> <http://xmlns.com/foaf/0.1/nick> "Patchy" . } ."#;
    let (status, text, _) = h
        .send("PATCH", "/profile", Some(("text/n3", delete)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(!body.contains("Patchy"), "got: {body}");

    // A delete of an absent triple is the 409 every other patch answers (5c):
    // the solver is the same, so its preconditions are too.
    let absent = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:p a solid:InsertDeletePatch ;
  solid:deletes { <#me> <http://xmlns.com/foaf/0.1/nick> "Never there" . } ."#;
    let (status, text, _) = h
        .send("PATCH", "/profile", Some(("text/n3", absent)), true)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{text}");
}

/// The reserved-position filter applies to a patch's result as it applies to a
/// `PUT`'s body: a patch may not seat a self-asserted storage root either.
#[tokio::test]
async fn a_patch_cannot_seat_a_self_asserted_storage_root() {
    let h = harness().await;
    let insert = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:p a solid:InsertDeletePatch ;
  solid:inserts { <#me> <http://www.w3.org/ns/pim/space#storage> <https://elsewhere.example/~carol/> . } ."#;
    let (status, text, _) = h
        .send("PATCH", "/profile", Some(("text/n3", insert)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");

    let pod = h.stores.pod(h.user).unwrap();
    assert!(!holds(
        &pod,
        &t(
            PROFILE,
            ME,
            &format!("{SPACE}storage"),
            "https://elsewhere.example/~carol/"
        )
    ));
    let (_, body, _) = get_accepting(&h, "/profile", "text/turtle").await;
    assert!(!body.contains("elsewhere"), "got: {body}");
    assert_eq!(
        body.matches(&format!("{SPACE}storage")).count(),
        1,
        "one storage root, the deployment's: {body}"
    );
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
        .header(header::COOKIE, format!("{SESSION_COOKIE}={}", h.session))
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
    // Echoed, not `*`. With credentials disallowed the two grant a browser
    // identical permission, but a named origin is cacheable per-origin, and
    // CTS checks for the echo (`protocol/cors/acao-vary.feature`).
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://app.example")
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
    for wanted in [
        "location",
        "link",
        "etag",
        "wac-allow",
        "accept-put",
        "www-authenticate",
        "vary",
    ] {
        assert!(exposed.contains(wanted), "{wanted} not exposed: {exposed}");
    }
    // Nothing sends it until stage 7, and an expose list is a promise.
    assert!(
        !exposed.contains("updates-via"),
        "still exposing updates-via: {exposed}"
    );
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
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"));
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
    let quads = [
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
    ];
    pod.write(|w| w.put(&g, Content::Auxiliary(&quads)).map(|_| ()))
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
    let granted = holds(
        &pod,
        &t(
            &format!("{ROOT}shared/.acl"),
            &bob_auth,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ),
    );
    assert!(!granted, "the refused PATCH must not have landed");
}

/// The same takeover by replacing the whole document. `ldp::put` refuses with
/// `Denied`, which `pod.rs::ldp_error` answers with 403 to an authenticated
/// caller.
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
        holds(
            &pod,
            &t(&g, auth, &format!("{ACL}mode"), &format!("{ACL}Control")),
        )
    };
    assert!(!control(&format!("{g}#bob")), "the refused PUT landed");
    assert!(control(&format!("{g}#owner")), "Alice's grant was replaced");
}

/// Deleting the container's ACL would drop Alice's grants on `/~/shared/` and
/// fall back to the root ACL. `ldp::delete` refuses with `Denied` before it
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
        pod.read(|r| r.meta(&format!("{ROOT}shared/.acl")))
            .unwrap()
            .is_some(),
        "the refused DELETE landed"
    );
}

/// Bob has authenticated and lacks Control, so he gets 403 (H1). A 401 would
/// ask him for a credential he has already presented. What must never happen
/// is a mode appearing in `WAC-Allow` on an ACL he can't read, because that
/// would be an edit affordance the next request refuses.
#[tokio::test]
async fn wac_allow_on_an_acl_names_nothing_for_bob() {
    let h = harness().await;
    share_with_bob(&h);
    let bob = member_session(&h, "bob").await;

    let (status, _, headers) = send_as(&h, &bob, "GET", "/~/shared/.acl", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        headers.get(header::WWW_AUTHENTICATE).is_none(),
        "Bob has already authenticated"
    );
    // A refusal carries no WAC-Allow at all, and an empty one would do too.
    // What must never appear is a mode.
    let allowed = headers
        .get("wac-allow")
        .map(|v| v.to_str().unwrap().to_string());
    assert!(
        matches!(allowed.as_deref(), None | Some("user=\"\", public=\"\"")),
        "got {allowed:?}"
    );

    let (status, _, headers) = h.send("GET", "/~/shared/.acl", None, true).await;
    assert_eq!(status, StatusCode::OK);
    // An ACL is all-or-nothing on Control: Alice holds it and gets all four,
    // the anonymous probe doesn't and gets none.
    assert_eq!(
        headers["wac-allow"],
        "user=\"read write append control\", public=\"\""
    );
}

// --- refusals (stage 5b, H1–H3) -------------------------------------------------

/// This is the core of H1's safety argument: the status depends on the
/// caller's effective modes, never on whether the target exists. If these two
/// responses ever differed, the pod would be an existence oracle for anyone on
/// the internet.
#[tokio::test]
async fn an_anonymous_refusal_is_the_same_for_a_real_and_a_fictive_resource() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (real, real_body, real_headers) = h.send("GET", "/~/note", None, false).await;
    let (fictive, fictive_body, fictive_headers) =
        h.send("GET", "/~/no-such-note", None, false).await;

    assert_eq!(real, StatusCode::UNAUTHORIZED);
    assert_eq!(fictive, StatusCode::UNAUTHORIZED);
    assert_eq!(real_body, fictive_body);
    assert_eq!(
        real_headers.get(header::WWW_AUTHENTICATE),
        fictive_headers.get(header::WWW_AUTHENTICATE)
    );
}

/// The same argument for a caller who *did* authenticate: 403, and again the
/// same answer whether the resource exists or not. CTS checks this
/// (`read-access-public.feature`: public → 401, Bob → 403).
#[tokio::test]
async fn a_member_without_access_is_forbidden_rather_than_challenged() {
    let h = harness().await;
    let bob = member_session(&h, "bob").await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    for path in ["/~/note", "/~/no-such-note"] {
        let (status, _, headers) = send_as(&h, &bob, "GET", path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert!(
            headers.get(header::WWW_AUTHENTICATE).is_none(),
            "{path}: a challenge Bob has already satisfied"
        );
    }
}

/// This is why the split exists. Only a caller who may read learns the
/// difference between empty and refused, and that is the information they
/// need. CTS: a *permitted* caller reading a fictive resource gets 404.
#[tokio::test]
async fn a_permitted_reader_of_a_missing_resource_gets_a_404() {
    let h = harness().await;
    let (status, _, headers) = h.send("GET", "/~/no-such-note", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(headers.get(header::WWW_AUTHENTICATE).is_none());
}

/// The status must not depend on the `Content-Type`. `Target::prepare`'s WAC
/// check runs only for a non-RDF body. If it still returned `Forbidden`, an
/// anonymous PNG would get 403 while anonymous Turtle got 401. That second
/// code path is easy to miss, so this pins both paths.
#[tokio::test]
async fn an_anonymous_write_is_challenged_whatever_its_body() {
    let h = harness().await;
    for (content_type, body) in [("text/turtle", NOTE), ("application/pdf", PDF)] {
        let (status, _, headers) = h
            .send("PUT", "/~/anonymous", Some((content_type, body)), false)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{content_type}");
        assert!(
            headers.contains_key(header::WWW_AUTHENTICATE),
            "{content_type}"
        );
    }
}

/// H2 applies only to the `Authorization` header. `__Host-brolly_session` is
/// `SameSite=Lax`, so a browser sends it on any top-level navigation. A
/// logged-out member opening a public image in their own pod would otherwise be
/// challenged for a credential they never offered. The missing `error=` shows
/// that the stale cookie was treated as no credential at all.
#[tokio::test]
async fn a_stale_cookie_falls_through_to_anonymous() {
    let h = harness().await;
    let (status, _, headers) = run(
        h.router.clone(),
        conditional_request("GET", "/~/note", None, Some("not-a-session"), &[]),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        !challenge.contains("error="),
        "a cookie the browser sent unasked is not a presented credential: {challenge}"
    );
}

/// The other side of that line: an `Authorization` header *is* a presented
/// credential, so one we can't parse is refused rather than ignored. This
/// guards against a client with a broken header looking exactly like a client
/// with none, and never learning why it sees nothing. A session cookie sent
/// alongside the header does not rescue it, because the explicit header is
/// the one the client meant (`extract::credential`'s precedence).
#[tokio::test]
async fn an_authorization_header_we_cannot_parse_is_refused() {
    let h = harness().await;
    let (status, _, headers) = run(
        h.router.clone(),
        conditional_request(
            "GET",
            "/~/note",
            None,
            Some(h.session.as_str()),
            &[("authorization", "Basic cGxlYXNl")],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "got: {challenge}"
    );
}

/// H2 applies to the inbox too. Without it, a client whose credential no
/// longer verifies is downgraded to anonymous, fails the owner check, and is
/// told its member's inbox does not exist.
#[tokio::test]
async fn a_broken_credential_on_the_inbox_is_challenged_not_hidden() {
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/inbox")
        .header(header::HOST, HOST)
        .header(header::ACCEPT, "application/activity+json")
        .header(header::AUTHORIZATION, "DPoP not-a-token")
        .body(Body::empty())
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "got: {challenge}"
    );
}

// --- conditional requests (stage 5a) -------------------------------------------

const EDITED: &str = r#"<> <https://example.org/title> "Edited" ."#;

#[tokio::test]
async fn get_and_head_carry_an_etag_and_last_modified() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, get) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let etag = get
        .get(header::ETAG)
        .expect("no ETag on GET")
        .to_str()
        .unwrap();
    assert!(
        etag.len() > 2 && etag.starts_with('"') && etag.ends_with('"'),
        "a strong tag: {etag}"
    );
    let modified = get
        .get(header::LAST_MODIFIED)
        .expect("no Last-Modified on GET")
        .to_str()
        .unwrap();
    assert!(modified.ends_with(" GMT"), "an HTTP-date: {modified}");

    // HEAD is GET without the body, so it carries the same validators.
    let (status, body, head) = h.send("HEAD", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "HEAD sent a body: {body}");
    assert_eq!(head.get(header::ETAG), get.get(header::ETAG));
    assert_eq!(
        head.get(header::LAST_MODIFIED),
        get.get(header::LAST_MODIFIED)
    );
}

/// Every kind has a version: a container (here the root) and a binary too.
#[tokio::test]
async fn a_container_and_a_binary_have_an_etag_too() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for path in ["/~/", "/~/paper.pdf"] {
        let (status, _, headers) = h.send("GET", path, None, true).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(headers.get(header::ETAG).is_some(), "{path}: no ETag");
        assert!(
            headers.get(header::LAST_MODIFIED).is_some(),
            "{path}: no Last-Modified"
        );
    }
}

/// RFC 9110 §9.3.4: the server transforms what it stores, so a write response
/// carries no ETag. The version still moves.
#[tokio::test]
async fn a_write_response_carries_no_etag_and_the_etag_moves() {
    let h = harness().await;
    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert!(status.is_success(), "{status}");
    assert!(
        headers.get(header::ETAG).is_none(),
        "PUT (create) sent an ETag"
    );
    let before = h.etag("/~/note").await;

    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", EDITED)), true)
        .await;
    assert!(status.is_success(), "{status}");
    assert!(
        headers.get(header::ETAG).is_none(),
        "PUT (replace) sent an ETag"
    );
    let after = h.etag("/~/note").await;
    assert_ne!(after, before, "the ETag didn't change after a PUT");

    let sparql =
        r#"INSERT DATA { <https://alice.brolly.test/~/note> <https://example.org/tag> "x" }"#;
    let (status, _, headers) = h
        .send(
            "PATCH",
            "/~/note",
            Some(("application/sparql-update", sparql)),
            true,
        )
        .await;
    assert!(status.is_success(), "{status}");
    assert!(headers.get(header::ETAG).is_none(), "PATCH sent an ETag");
    assert_ne!(
        h.etag("/~/note").await,
        after,
        "the ETag didn't change after a PATCH"
    );

    let (status, _, headers) = h
        .send("POST", "/~/", Some(("text/turtle", NOTE)), true)
        .await;
    assert!(status.is_success(), "{status}");
    assert!(headers.get(header::ETAG).is_none(), "POST sent an ETag");
}

/// What Solid clients use to create without overwriting.
#[tokio::test]
async fn if_none_match_star_creates_but_never_overwrites() {
    let h = harness().await;

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", NOTE)),
            &[("if-none-match", "*")],
        )
        .await;
    assert!(status.is_success(), "a new resource is created: {status}");

    let before = h.etag("/~/note").await;
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-none-match", "*")],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(
        body.contains("Written over HTTP") && !body.contains("Edited"),
        "the refused PUT landed: {body}"
    );
    assert_eq!(
        h.etag("/~/note").await,
        before,
        "a refused PUT moved the version"
    );
}

/// A binary's bytes reach disk before the transaction that decides whether to
/// keep them (R12: uploads don't queue behind the write lock). So a refused
/// upload has already written a file, and nothing else will ever reference it —
/// an attacker who can be refused repeatedly could fill the volume one 412 at a
/// time. The refusal path has to hand the bytes back.
#[tokio::test]
async fn a_binary_refused_by_a_precondition_leaves_no_bytes_behind() {
    use sha2::{Digest, Sha256};

    let h = harness().await;
    const OTHER: &str = "%PDF-1.4\n1 0 obj\n<< /Type /Nothing >>\nendobj\n";
    let refused: String = Sha256::digest(OTHER.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let (status, _, _) = h
        .send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a PUT that creates is a 201 (H11)"
    );

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/paper.pdf",
            Some(("application/pdf", OTHER)),
            &[("if-none-match", "*")],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let (status, body, _) = h.send("GET", "/~/paper.pdf", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, PDF, "the refused upload landed");

    let blobs = h.stores.blobs(h.user).unwrap();
    assert!(
        !blobs.contains(&refused),
        "the refused upload's bytes are still on disk"
    );
}

/// What Solid clients use to detect a conflicting edit.
#[tokio::test]
async fn if_match_needs_the_current_strong_tag() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let stale = h.etag("/~/note").await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;
    assert_ne!(stale, current);

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", stale.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "a stale tag");
    assert_eq!(h.etag("/~/note").await, current, "the refused PUT landed");

    // A weak tag never matches, even with the right opaque value.
    let weak = format!("W/{current}");
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", weak.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "a weak tag");
    assert_eq!(h.etag("/~/note").await, current, "the refused PUT landed");

    // A list holds if any member matches.
    let list = format!("{stale}, {current}");
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", list.as_str())],
        )
        .await;
    assert!(status.is_success(), "the current tag: {status}");
    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(body.contains("Edited"), "got: {body}");
}

#[tokio::test]
async fn if_match_star_needs_the_resource_to_exist() {
    let h = harness().await;

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/absent",
            Some(("text/turtle", NOTE)),
            &[("if-match", "*")],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    let (status, _, _) = h.send("GET", "/~/absent", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the refused PUT created it");

    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", "*")],
        )
        .await;
    assert!(status.is_success(), "{status}");
}

#[tokio::test]
async fn if_none_match_with_the_current_tag() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;

    // GET and HEAD: 304, with the ETag and no body.
    for method in ["GET", "HEAD"] {
        let (status, body, headers) = h
            .send_if(
                method,
                "/~/note",
                None,
                &[("if-none-match", current.as_str())],
            )
            .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED, "{method}");
        assert_eq!(
            headers.get(header::ETAG).and_then(|v| v.to_str().ok()),
            Some(current.as_str()),
            "{method}: a 304 names the version it confirms"
        );
        assert!(body.is_empty(), "{method}: a 304 has no body: {body}");
    }

    // Another tag is a full response.
    let (status, body, _) = h
        .send_if("GET", "/~/note", None, &[("if-none-match", "\"other\"")])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Written over HTTP"), "got: {body}");

    // PUT and DELETE: 412, and nothing written.
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-none-match", current.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "PUT");
    let (status, _, _) = h
        .send_if(
            "DELETE",
            "/~/note",
            None,
            &[("if-none-match", current.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "DELETE");
    assert_eq!(h.etag("/~/note").await, current, "a refused write landed");
}

#[tokio::test]
async fn patch_and_delete_honour_if_match() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let stale = h.etag("/~/note").await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;

    let sparql =
        r#"INSERT DATA { <https://alice.brolly.test/~/note> <https://example.org/tag> "patched" }"#;
    let (status, _, _) = h
        .send_if(
            "PATCH",
            "/~/note",
            Some(("application/sparql-update", sparql)),
            &[("if-match", stale.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "PATCH, stale");
    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(
        !body.contains("patched"),
        "the refused PATCH landed: {body}"
    );

    let (status, _, _) = h
        .send_if(
            "PATCH",
            "/~/note",
            Some(("application/sparql-update", sparql)),
            &[("if-match", current.as_str())],
        )
        .await;
    assert!(status.is_success(), "PATCH, current: {status}");
    let patched = h.etag("/~/note").await;

    // `current` is stale now.
    let (status, _, _) = h
        .send_if("DELETE", "/~/note", None, &[("if-match", current.as_str())])
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "DELETE, stale");
    let (status, _, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK, "the refused DELETE landed");

    let (status, _, _) = h
        .send_if("DELETE", "/~/note", None, &[("if-match", patched.as_str())])
        .await;
    assert!(status.is_success(), "DELETE, current: {status}");
    let (status, _, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A POST's `If-Match` names the container, the request's target, not the
/// member it would mint.
#[tokio::test]
async fn if_match_on_a_post_is_about_the_container() {
    let h = harness().await;
    let (status, _, _) = h
        .send("PUT", "/~/c/", Some(("text/turtle", "")), true)
        .await;
    assert!(status.is_success(), "an empty container: {status}");
    let stale = h.etag("/~/c/").await;

    // A member moves the container's version (R9).
    let (status, _, _) = h
        .send("POST", "/~/c/", Some(("text/turtle", NOTE)), true)
        .await;
    assert!(status.is_success(), "{status}");
    let current = h.etag("/~/c/").await;
    assert_ne!(stale, current);

    let (status, _, _) = h
        .send_if(
            "POST",
            "/~/c/",
            Some(("text/turtle", NOTE)),
            &[("if-match", stale.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        h.etag("/~/c/").await,
        current,
        "the refused POST added a member"
    );

    let (status, _, headers) = h
        .send_if(
            "POST",
            "/~/c/",
            Some(("text/turtle", NOTE)),
            &[("if-match", current.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(headers.get(header::LOCATION).is_some());
}

/// The ETag is authoritative; dates are ignored.
#[tokio::test]
async fn date_preconditions_are_ignored() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    // Honoured, this would be a 304.
    let (status, _, _) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT")],
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Honoured, this would be a 412.
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-unmodified-since", "Mon, 01 Jan 1990 00:00:00 GMT")],
        )
        .await;
    assert!(status.is_success(), "{status}");
}

/// One disclosure case: the method, a path that exists, a path that doesn't,
/// the body to send, and the conditional header.
type DisclosureCase = (
    &'static str,
    &'static str,
    &'static str,
    Option<(&'static str, &'static str)>,
    (&'static str, &'static str),
);

/// A caller without the mode a method needs gets the same answer whether or
/// not the resource exists. The precondition is evaluated after authorisation,
/// so it can't become an existence oracle.
#[tokio::test]
async fn a_caller_without_the_mode_learns_nothing_from_a_precondition() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/c/", Some(("text/turtle", "")), true)
        .await;
    // Bob holds no grant anywhere in Alice's pod.
    let bob = member_session(&h, "bob").await;

    let turtle = Some(("text/turtle", NOTE));
    let sparql = Some((
        "application/sparql-update",
        r#"INSERT DATA { <https://alice.brolly.test/~/note> <https://example.org/tag> "bob" }"#,
    ));
    let cases: [DisclosureCase; 8] = [
        (
            "PUT",
            "/~/note",
            "/~/absent",
            turtle,
            ("if-none-match", "*"),
        ),
        ("PUT", "/~/note", "/~/absent", turtle, ("if-match", "*")),
        (
            "PUT",
            "/~/note",
            "/~/absent",
            turtle,
            ("if-match", "\"stale\""),
        ),
        ("PATCH", "/~/note", "/~/absent", sparql, ("if-match", "*")),
        (
            "PATCH",
            "/~/note",
            "/~/absent",
            sparql,
            ("if-none-match", "*"),
        ),
        (
            "DELETE",
            "/~/note",
            "/~/absent",
            None,
            ("if-match", "\"stale\""),
        ),
        ("POST", "/~/c/", "/~/absent/", turtle, ("if-match", "*")),
        ("GET", "/~/note", "/~/absent", None, ("if-none-match", "*")),
    ];

    for (method, existing, missing, body, condition) in cases {
        let (on_existing, _, _) = run(
            h.router.clone(),
            conditional_request(method, existing, body, Some(bob.as_str()), &[condition]),
        )
        .await;
        let (on_missing, _, _) = run(
            h.router.clone(),
            conditional_request(method, missing, body, Some(bob.as_str()), &[condition]),
        )
        .await;
        assert_eq!(
            on_existing, on_missing,
            "{method} {condition:?}: the answer depends on existence"
        );
        assert!(
            !on_existing.is_success()
                && on_existing != StatusCode::PRECONDITION_FAILED
                && on_existing != StatusCode::NOT_MODIFIED,
            "{method} {condition:?}: got {on_existing}, not a refusal"
        );
    }

    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(!body.contains("bob"), "a refused write landed: {body}");
    let (status, _, _) = h.send("GET", "/~/absent", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a refused write created it");
}

/// The lost-update case `If-Match` exists for. The check and the write are one
/// `Pod::write`, under the pod's lock, so two writers holding the same tag
/// can't both pass. Spawned, so they run on different worker threads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn of_two_concurrent_puts_with_one_if_match_exactly_one_lands() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    for round in 0..8 {
        let tag = h.etag("/~/note").await;
        let spawn = |writer: &str| {
            let body = format!("<> <https://example.org/writer> \"{writer}-{round}\" .");
            let request = conditional_request(
                "PUT",
                "/~/note",
                Some(("text/turtle", body.as_str())),
                Some(h.session.as_str()),
                &[("if-match", tag.as_str())],
            );
            tokio::spawn(run(h.router.clone(), request))
        };
        let (a, b) = (spawn("a"), spawn("b"));
        let (a, b) = (a.await.unwrap().0, b.await.unwrap().0);

        let landed = [a, b].iter().filter(|s| s.is_success()).count();
        assert_eq!(landed, 1, "round {round}: {a} and {b}");
        assert!(
            [a, b].contains(&StatusCode::PRECONDITION_FAILED),
            "round {round}: {a} and {b}"
        );
    }
}

// --- what a caller may do (stage 5b, H4 and H5) --------------------------------

/// `foaf:Agent`, WAC's "everyone, signed in or not".
const EVERYONE: &str = "http://xmlns.com/foaf/0.1/Agent";

/// A header's value, or a panic naming the header that was missing.
fn header_of(headers: &axum::http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("no {name} header"))
        .to_str()
        .unwrap()
        .to_string()
}

/// Write `quads` as the ACL at `graph`, replacing whatever was there.
///
/// A direct ACL replaces the root's `acl:default` for its own resource, so a
/// test that needs the owner to keep a mode has to name her here too.
fn set_acl(h: &Harness, graph: &str, quads: &[Quad]) {
    let pod = h.stores.pod(h.user).unwrap();
    pod.write(|w| w.put(graph, Content::Auxiliary(quads)).map(|_| ()))
        .unwrap();
}

/// What a static `Allow` breaks: SolidOS picks its edit affordances from it,
/// so one line promising every method to every caller draws a save button
/// whose every press is refused.
#[tokio::test]
async fn options_tells_this_caller_what_it_may_do_with_this_resource() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h.send("OPTIONS", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "CTS accepts 204 or 200");
    // 5c H3: POST is a container method, so a document's `Allow` no longer
    // offers it — and `Accept-Post` went with it.
    assert_eq!(
        header_of(&headers, "allow"),
        "GET, HEAD, PUT, PATCH, DELETE, OPTIONS"
    );
    // Each Accept-* is sent because its method is in Allow.
    assert_eq!(
        header_of(&headers, "accept-patch"),
        "text/n3, application/sparql-update"
    );
    assert!(
        headers.get("accept-post").is_none(),
        "a document is not a POST target"
    );
    assert_eq!(
        header_of(&headers, "accept-put"),
        "*/*",
        "a document's PUT takes any media type today"
    );
}

/// "May I create here?" is what `OPTIONS` on a missing target asks, and
/// `Accept-Put` is the answer. A `GET` of the same path is a 404, so an
/// `Allow` offering `GET` would be the very lie H4 exists to stop.
#[tokio::test]
async fn options_offers_creation_where_nothing_exists_yet() {
    let h = harness().await;

    let (status, _, headers) = h.send("OPTIONS", "/~/not-yet", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "a writer may ask");
    assert_eq!(header_of(&headers, "allow"), "PUT, PATCH, OPTIONS");
    assert_eq!(header_of(&headers, "accept-put"), "*/*");
    assert!(
        headers.get("accept-post").is_none(),
        "a missing document-shaped target is not a POST target either (5c H3)"
    );

    // 5c H3: a missing container-shaped target is POSTable — existence is
    // irrelevant to the creation methods, the same way it is for `PUT` and
    // `PATCH` — and the intermediate containers are auto-created on the way in.
    let (status, _, headers) = h.send("OPTIONS", "/~/newdir/", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "a writer may ask");
    assert_eq!(header_of(&headers, "allow"), "PUT, POST, PATCH, OPTIONS");
    assert!(header_of(&headers, "accept-post").contains("text/turtle"));

    let (status, _, headers) = h
        .send_if(
            "POST",
            "/~/newdir/",
            Some(("text/turtle", NOTE)),
            &[("slug", "note")],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "the offer was honest");
    assert_eq!(
        header_of(&headers, "location"),
        format!("{ROOT}newdir/note")
    );

    let (status, _, _) = h.send("GET", "/~/not-yet", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "asking created nothing");
}

/// An Append-only caller — the inbox, the drop box — may ask what it may do
/// at a path, and H4 answers. It may not learn whether anything is *there*:
/// a `rel="type"` link goes out only for a target that exists, so an
/// `OPTIONS` per guessed name enumerated a container the caller could not
/// list. To a caller without Read, an existing target and a missing one
/// answer identically.
#[tokio::test]
async fn options_tells_an_append_only_caller_nothing_about_what_exists() {
    let h = harness().await;
    let pod = h.stores.pod(h.user).unwrap();
    let inbox = format!("{ROOT}inbox/");
    let g = format!("{inbox}.acl");
    let owner = format!("{g}#owner");
    let bob = format!("{g}#bob");
    let quads = [
        t(&g, &owner, &format!("{ACL}accessTo"), &inbox),
        t(&g, &owner, &format!("{ACL}default"), &inbox),
        t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Control")),
        t(
            &g,
            &owner,
            &format!("{ACL}agent"),
            &format!("{BASE}/profile#me"),
        ),
        t(&g, &bob, &format!("{ACL}accessTo"), &inbox),
        t(&g, &bob, &format!("{ACL}default"), &inbox),
        t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Append")),
        t(&g, &bob, &format!("{ACL}agent"), BOB_WEBID),
    ];
    pod.write(|w| w.put(&g, Content::Auxiliary(&quads)).map(|_| ()))
        .unwrap();
    let (status, _, _) = h
        .send("PUT", "/~/inbox/present", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let bob = member_session(&h, "bob").await;
    let (present_status, _, present) = send_as(&h, &bob, "OPTIONS", "/~/inbox/present", None).await;
    let (absent_status, _, absent) = send_as(&h, &bob, "OPTIONS", "/~/inbox/absent", None).await;
    assert_eq!(present_status, StatusCode::NO_CONTENT);
    assert_eq!(absent_status, StatusCode::NO_CONTENT);

    for name in [
        "allow",
        "accept-patch",
        "accept-post",
        "accept-put",
        "wac-allow",
        "etag",
        "last-modified",
    ] {
        assert_eq!(
            present.get(name),
            absent.get(name),
            "{name} tells a caller who may not read whether the target exists"
        );
    }
    // The `acl` and `describedby` links name the target, so they differ by
    // the one thing the caller chose. With the name put back, nothing else
    // may differ — and in particular no `rel="type"`.
    assert_eq!(
        header_of(&present, "link").replace("/inbox/present", "/inbox/absent"),
        header_of(&absent, "link"),
        "link tells a caller who may not read whether the target exists"
    );
    assert!(
        !header_of(&present, "link").contains("rel=\"type\""),
        "no type for a caller who may not read: {}",
        header_of(&present, "link")
    );
}

/// Solid Protocol §5.4 names exactly two resources a server must refuse to
/// delete, and requires `DELETE` to be missing from their `Allow`. What this
/// guards: a client invited to remove the pod's root, leaving the member
/// nowhere to put anything.
#[tokio::test]
async fn the_storage_root_and_its_own_acl_are_never_offered_for_deletion() {
    let h = harness().await;
    // The harness grants Alice Read and Write. An ACL answers only to Control.
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    set_acl(
        &h,
        &g,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(
                &g,
                &a,
                &format!("{ACL}agent"),
                &format!("{BASE}/profile#me"),
            ),
        ],
    );

    for path in ["/~/", "/~/.acl"] {
        let (status, _, headers) = h.send("OPTIONS", path, None, true).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{path}");
        let allow = header_of(&headers, "allow");
        assert!(!allow.contains("DELETE"), "{path} offered DELETE: {allow}");
        assert!(allow.contains("PUT"), "{path}: {allow}");
        // 5a's NotRdf refusal, made discoverable: both take RDF and only RDF.
        let put = header_of(&headers, "accept-put");
        assert!(!put.contains("*/*"), "{path} accepts anything: {put}");
        // Only the root is a container (5c H3): POST is a container method,
        // offered there and advertised with the same RDF list, and offered
        // nowhere on the root's own ACL.
        if path == "/~/" {
            assert_eq!(put, header_of(&headers, "accept-post"), "{path}");
        } else {
            assert!(!allow.contains("POST"), "{path} offered POST: {allow}");
            assert!(
                headers.get("accept-post").is_none(),
                "{path} advertised POST"
            );
        }
    }

    // Any other ACL may be deleted by a caller with Control. WAC §3.2 makes
    // removing it the way to put a resource back on its container's rules.
    share_with_bob(&h);
    let (_, _, headers) = h.send("OPTIONS", "/~/shared/.acl", None, true).await;
    assert!(header_of(&headers, "allow").contains("DELETE"));
}

/// A reader is offered reading. What this guards: a viewer shown an editor,
/// and a client trying a `PUT` it was promised and getting a 403 it had no way
/// to predict.
#[tokio::test]
async fn a_public_reader_is_offered_reading_and_nothing_else() {
    let h = harness().await;
    h.send("PUT", "/~/public", Some(("text/turtle", NOTE)), true)
        .await;
    let g = format!("{ROOT}public.acl");
    let a = format!("{g}#everyone");
    set_acl(
        &h,
        &g,
        &[
            t(&g, &a, &format!("{ACL}accessTo"), &format!("{ROOT}public")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}agentClass"), EVERYONE),
        ],
    );

    let (status, _, headers) = h.send("OPTIONS", "/~/public", None, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(header_of(&headers, "allow"), "GET, HEAD, OPTIONS");
    for absent in ["accept-patch", "accept-post", "accept-put"] {
        assert!(
            headers.get(absent).is_none(),
            "{absent} offered to a reader"
        );
    }
}

/// The drop-box and inbox pattern, and why H4 gates `OPTIONS` on holding
/// *any* mode rather than Read. An append-only client most needs `Allow` to
/// tell it that it may `POST`, and has no other way to learn it: it can't
/// read the container.
#[tokio::test]
async fn an_append_only_caller_can_discover_that_it_may_post() {
    let h = harness().await;
    h.send("PUT", "/~/drop/", Some(("text/turtle", "")), true)
        .await;
    let g = format!("{ROOT}drop/.acl");
    let a = format!("{g}#everyone");
    set_acl(
        &h,
        &g,
        &[
            t(&g, &a, &format!("{ACL}accessTo"), &format!("{ROOT}drop/")),
            t(&g, &a, &format!("{ACL}default"), &format!("{ROOT}drop/")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Append")),
            t(&g, &a, &format!("{ACL}agentClass"), EVERYONE),
        ],
    );

    let (status, _, headers) = h.send("OPTIONS", "/~/drop/", None, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "Append is a mode");
    assert_eq!(header_of(&headers, "allow"), "POST, PATCH, OPTIONS");
    assert!(header_of(&headers, "accept-post").contains("text/turtle"));
    // H5: an insert-only PATCH is an Append operation, so PATCH — and its
    // `Accept-Patch` — are the appender's.
    assert!(header_of(&headers, "accept-patch").contains("text/n3"));
    assert!(headers.get("accept-put").is_none());

    // And the promise holds: an insert-only PATCH lands (204, the container
    // already exists), and a deleting one is refused.
    let insert = format!("INSERT DATA {{ <{ROOT}drop/> <https://example.org/tag> \"added\" }}");
    let (status, body, _) = h
        .send(
            "PATCH",
            "/~/drop/",
            Some(("application/sparql-update", insert.as_str())),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let remove = format!("DELETE DATA {{ <{ROOT}drop/> <https://example.org/tag> \"added\" }}");
    let (status, _, _) = h
        .send(
            "PATCH",
            "/~/drop/",
            Some(("application/sparql-update", remove.as_str())),
            false,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Append must not permit removal — and an anonymous caller is challenged"
    );

    // And the POST promise still holds.
    let (status, _, _) = h
        .send("POST", "/~/drop/", Some(("text/turtle", NOTE)), false)
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// 5c H1: a POST's `Slug` names the minted member, and the 201's `Location`
/// is the name the client can bookmark and reconstruct.
#[tokio::test]
async fn a_slug_names_the_minted_member() {
    let h = harness().await;
    let (status, _, headers) = h
        .send_if(
            "POST",
            "/~/",
            Some(("text/turtle", NOTE)),
            &[("slug", "hello")],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(header_of(&headers, "location"), format!("{ROOT}hello"));

    // A taken name is disambiguated `-1`, `-2`, … before any extension — the
    // contract CSS implements and `solid-client` depends on.
    for expect in ["note.ttl", "note-1.ttl", "note-2.ttl"] {
        let (status, _, headers) = h
            .send_if(
                "POST",
                "/~/",
                Some(("text/turtle", NOTE)),
                &[("slug", "note.ttl")],
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(header_of(&headers, "location"), format!("{ROOT}{expect}"));
    }
}

/// H1: the slug is raw bytes, not a pre-encoded segment, so a `%` survives as
/// `%25` — lossless, and unambiguous where passing it through would not be.
#[tokio::test]
async fn a_slug_is_percent_encoded_not_passed_through() {
    let h = harness().await;
    let (status, _, headers) = h
        .send_if(
            "POST",
            "/~/",
            Some(("text/turtle", NOTE)),
            &[("slug", "a%20b")],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(header_of(&headers, "location"), format!("{ROOT}a%2520b"));
}

/// H1: a slug that cannot be made one safe segment is a 400 naming the slug
/// and the rule — a silent UUID would leave the client building links to a
/// name it was never given.
#[tokio::test]
async fn slugs_that_cannot_be_a_segment_are_refused() {
    let h = harness().await;
    for slug in [
        "a/b",
        "a?b",
        "a#b",
        ".",
        "..",
        "note.acl",
        "note.meta",
        "a\tb",
    ] {
        let (status, body, _) = h
            .send_if(
                "POST",
                "/~/",
                Some(("text/turtle", NOTE)),
                &[("slug", slug)],
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{slug:?}: {body}");
        assert!(
            body.contains(slug.trim()),
            "{slug:?}: the 400 must name it: {body}"
        );
    }
    // Nothing was minted by any of them.
    let (_, body, _) = h.send("GET", "/~/", None, true).await;
    assert!(!body.contains("note.acl"), "a refused slug landed: {body}");
    assert!(!body.contains("note.meta"), "a refused slug landed: {body}");
}

/// H2: `Link rel="type"` naming an LDP container class creates a container —
/// the way every Solid library does — with the trailing slash, the container
/// types on the 201 (H4), and members it can hold.
#[tokio::test]
async fn a_link_typed_post_creates_a_container() {
    let h = harness().await;
    let (status, _, headers) = h
        .send_if(
            "POST",
            "/~/",
            Some(("text/turtle", "")),
            &[(
                "link",
                r#"<http://www.w3.org/ns/ldp#BasicContainer>; rel="type""#,
            )],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let location = header_of(&headers, "location");
    assert!(
        location.ends_with('/'),
        "a container's IRI ends in `/`: {location}"
    );
    let link = header_of(&headers, "link");
    assert!(link.contains("ldp#BasicContainer"), "got: {link}");
    assert!(link.contains("ldp#Container"), "got: {link}");
    // H4: the 201's `Link` set names the ACL too — the client learns where
    // the rules go in the same round trip that minted the container.
    assert!(link.contains(r#"rel="acl""#), "got: {link}");

    // It is a container: it holds a member.
    let path = location.strip_prefix(BASE).unwrap();
    let (status, _, headers) = h
        .send_if(
            "POST",
            path,
            Some(("text/turtle", NOTE)),
            &[("slug", "note")],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "a container holds members");
    assert_eq!(header_of(&headers, "location"), format!("{location}note"));
}

/// H2: only an exact `ldp:BasicContainer`/`ldp:Container` target with a `rel`
/// token list that includes `type` decides anything. A target that merely
/// *contains* the IRI, or a `rel` that is not `type`, is ignored — the body's
/// content type decides, as it always has.
#[tokio::test]
async fn only_an_exact_container_type_link_decides() {
    let h = harness().await;
    for link in [
        r#"<http://www.w3.org/ns/ldp#BasicContainerish>; rel="type""#,
        r#"<http://www.w3.org/ns/ldp#NotBasicContainer>; rel="type""#,
        r#"<http://www.w3.org/ns/ldp#BasicContainer>; rel="alternate""#,
        r#"<http://www.w3.org/ns/ldp#BasicContainer>; title="type""#,
    ] {
        let (status, _, headers) = h
            .send_if(
                "POST",
                "/~/",
                Some(("text/turtle", NOTE)),
                &[("link", link)],
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{link}");
        let location = header_of(&headers, "location");
        assert!(
            !location.ends_with('/'),
            "{link}: decided anyway: {location}"
        );
    }

    // The positive control: the rel is a token list, quoted or bare, and the
    // deciding field may sit among others on the same header — it decides.
    for link in [
        r#"<http://www.w3.org/ns/ldp#Container>; rel="alternate type""#,
        r#"<http://www.w3.org/ns/ldp#BasicContainer>; rel=type"#,
        r#"<http://example.org/x>; rel="describedby", <http://www.w3.org/ns/ldp#BasicContainer>; rel="type""#,
    ] {
        let (status, _, headers) = h
            .send_if("POST", "/~/", Some(("text/turtle", "")), &[("link", link)])
            .await;
        assert_eq!(status, StatusCode::CREATED, "{link}");
        assert!(
            header_of(&headers, "location").ends_with('/'),
            "{link}: a container was not minted"
        );
    }
}

/// H2: a container-typed POST takes RDF or empty — a binary body is the
/// existing 415, whatever the `Link` header says.
#[tokio::test]
async fn a_container_typed_post_takes_rdf_only() {
    let h = harness().await;
    let (status, body, _) = h
        .send_if(
            "POST",
            "/~/",
            Some(("image/png", "not really a png")),
            &[(
                "link",
                r#"<http://www.w3.org/ns/ldp#BasicContainer>; rel="type""#,
            )],
        )
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");
}

/// H3: POST is a container method. A document-shaped target — existing or
/// not — is a 405 whose `Allow` comes from the same builder `OPTIONS` uses,
/// so the two cannot disagree.
#[tokio::test]
async fn a_post_to_a_document_is_a_405_with_the_targets_allow() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, body, headers) = h
        .send("POST", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{body}");
    let allow = allowed(&headers);
    assert!(!allow.iter().any(|m| m == "POST"), "{allow:?}");
    for method in ["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        assert!(
            allow.iter().any(|m| m == method),
            "{method} missing: {allow:?}"
        );
    }
    // The append it used to perform is a `PATCH` with `INSERT` now, and it
    // didn't land anything on the way out.
    let (status, body, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.matches("Written over HTTP").count(), 1, "{body}");

    // Absent target, same answer: the 405 is about the method and the shape.
    let (status, _, headers) = h
        .send("POST", "/~/absent", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header_of(&headers, "allow"), "PUT, PATCH, OPTIONS");
}

/// H3: the 405 comes after authorization, so a caller with no mode at all
/// still sees 401 — the 405 must not become an existence oracle.
#[tokio::test]
async fn a_post_to_a_document_refuses_an_anonymous_caller_first() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (status, _, headers) = h
        .send("POST", "/~/note", Some(("text/turtle", NOTE)), false)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers.get("www-authenticate").is_some(),
        "401 carries its challenge (5b H1)"
    );
}

/// H4: a creating POST carries the same `Link` set a creating `PUT` sends:
/// what it made, where its rules are, which storage it belongs to.
#[tokio::test]
async fn a_creating_post_carries_the_link_set() {
    let h = harness().await;
    let (status, _, headers) = h
        .send_if(
            "POST",
            "/~/",
            Some(("text/turtle", NOTE)),
            &[("slug", "posted")],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let link = header_of(&headers, "link");
    assert!(
        link.contains(r#"<http://www.w3.org/ns/ldp#Resource>; rel="type""#),
        "got: {link}"
    );
    assert!(
        link.contains(r#"<http://www.w3.org/ns/ldp#RDFSource>; rel="type""#),
        "got: {link}"
    );
    assert!(link.contains(r#"rel="acl""#), "got: {link}");
    // H3 (spec 5d): the 201's `Link` set names where the description of what
    // it made goes, too — the client needs the IRI to create it.
    assert!(
        link.contains(&format!(r#"<{ROOT}posted.meta>; rel="describedby""#)),
        "got: {link}"
    );
    assert!(link.contains("storageDescription"), "got: {link}");
}

/// 5c H4: a PATCH that creates answers 201 with the `Location` and the same
/// `Link` set a creating `PUT` or `POST` sends, not the 204 a modifying patch
/// answers — creation and modification are not indistinguishable on the wire.
#[tokio::test]
async fn a_creating_patch_answers_201_with_the_link_set() {
    let h = harness().await;
    let update =
        r#"INSERT DATA { <https://alice.brolly.test/~/made> <https://example.org/title> "x" }"#;
    let (status, body, headers) = h
        .send(
            "PATCH",
            "/~/made",
            Some(("application/sparql-update", update)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        header_of(&headers, "location"),
        "https://alice.brolly.test/~/made"
    );
    let link = header_of(&headers, "link");
    assert!(
        link.contains(r#"<http://www.w3.org/ns/ldp#RDFSource>; rel="type""#),
        "got: {link}"
    );
    assert!(link.contains(r#"rel="acl""#), "got: {link}");
    assert!(
        link.contains(&format!(r#"<{ROOT}made.meta>; rel="describedby""#)),
        "got: {link}"
    );

    // The same patch again is a modification now: 204, and no `Location`.
    let (status, _, headers) = h
        .send(
            "PATCH",
            "/~/made",
            Some(("application/sparql-update", update)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(headers.get("location").is_none());
}

/// `OPTIONS` must not become the existence oracle the rest of the surface
/// refuses to be. A caller holding nothing gets H1's refusal, the same one
/// whether or not the target is there, and no `Allow` with it.
#[tokio::test]
async fn options_refuses_a_caller_who_holds_no_mode_at_all() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let bob = member_session(&h, "bob").await;

    for path in ["/~/note", "/~/not-yet"] {
        let (status, _, headers) = send_as(&h, &bob, "OPTIONS", path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: signed in, denied");
        assert!(
            headers.get("allow").is_none(),
            "{path}: Allow leaked to Bob"
        );

        let (status, _, headers) = h.send("OPTIONS", path, None, false).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: no credential");
        assert!(headers.get("allow").is_none(), "{path}: Allow leaked");
    }
}

/// CTS reads `Allow` from a `GET`, and SolidOS from whichever method it made
/// last. Two builders would drift apart, so there is one.
#[tokio::test]
async fn get_and_head_carry_the_same_affordances_as_options() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/docs/", Some(("text/turtle", "")), true)
        .await;

    // A document carries no `Accept-Post` (5c H3: POST is a container
    // method); a container does. Both must agree with `OPTIONS` either way.
    for (path, with_post) in [("/~/note", false), ("/~/docs/", true)] {
        let (_, _, options) = h.send("OPTIONS", path, None, true).await;
        assert_eq!(
            options.get("accept-post").is_some(),
            with_post,
            "{path}: a document is not a POST target (5c H3)"
        );
        for method in ["GET", "HEAD"] {
            let (status, _, headers) = h.send(method, path, None, true).await;
            assert_eq!(status, StatusCode::OK, "{method} {path}");
            for name in ["allow", "accept-patch", "accept-post", "accept-put"] {
                assert_eq!(
                    headers.get(name),
                    options.get(name),
                    "{method} and OPTIONS disagree about {name} on {path}"
                );
            }
        }
    }
}

// --- discovery (stage 5b, H6–H8) ------------------------------------------------

/// The `Link` field, as one string.
///
/// Several link values may arrive on one line or on several; RFC 9110 §5.3
/// says they mean the same thing, and a test that asks whether a link is there
/// shouldn't care which way the handler spelled it.
fn links(headers: &axum::http::HeaderMap) -> String {
    headers
        .get_all(header::LINK)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The target of the first link with this relation.
fn link_target(headers: &axum::http::HeaderMap, rel: &str) -> String {
    let all = links(headers);
    let marker = format!("; rel=\"{rel}\"");
    let end = all
        .find(&marker)
        .unwrap_or_else(|| panic!("no rel={rel} in {all}"));
    let start = all[..end].rfind('<').expect("a link target");
    all[start + 1..end - 1].to_string()
}

/// The failure mode: nothing emitted `Link rel="type"`, so a client had to
/// parse the body to tell a container from a document, and had no way at all
/// to classify a binary.
#[tokio::test]
async fn a_read_says_what_kind_of_resource_it_returned() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    let (status, _, headers) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let document = links(&headers);
    assert!(
        document.contains("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\""),
        "{document}"
    );
    assert!(
        document.contains("ldp#RDFSource>; rel=\"type\""),
        "{document}"
    );
    assert!(!document.contains("ldp#Container"), "{document}");

    // HEAD is the request a file manager makes, and it must learn the same.
    let (_, _, headers) = h.send("HEAD", "/~/paper.pdf", None, true).await;
    assert!(
        links(&headers).contains("ldp#NonRDFSource>; rel=\"type\""),
        "{:?}",
        links(&headers)
    );

    let (_, _, headers) = h.send("GET", "/~/", None, true).await;
    let container = links(&headers);
    assert!(
        container.contains("ldp#Container>; rel=\"type\""),
        "{container}"
    );
    assert!(
        container.contains("ldp#BasicContainer>; rel=\"type\""),
        "{container}"
    );
}

/// §4.1's MUST, and the fix for problem 4: before this, `pim:Storage` was
/// stated only inside the root's own body, which a client had to already be
/// reading to find.
#[tokio::test]
async fn the_storage_root_advertises_itself_and_its_owner() {
    let h = harness().await;
    let (status, _, headers) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let root = links(&headers);
    assert!(
        root.contains("<http://www.w3.org/ns/pim/space#Storage>; rel=\"type\""),
        "{root}"
    );
    assert!(
        root.contains(&format!(
            "<{BASE}/profile#me>; rel=\"http://www.w3.org/ns/solid/terms#owner\""
        )),
        "{root}"
    );

    // Only the root. A resource inside a storage is not itself one.
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, _, headers) = h.send("GET", "/~/note", None, true).await;
    let note = links(&headers);
    assert!(!note.contains("space#Storage"), "{note}");
    assert!(!note.contains("terms#owner"), "{note}");
}

/// `pod.rs` built this link by concatenation, so a GET of an `.acl`
/// advertised `<…/.acl.acl>` — an IRI with no ACL semantics that a client
/// following the link would create as an ordinary resource.
#[tokio::test]
async fn an_acl_links_itself_rather_than_a_fiction() {
    let h = harness().await;
    share_with_bob(&h);

    let (status, _, headers) = h.send("GET", "/~/shared/.acl", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let link = links(&headers);
    assert!(
        link.contains(&format!("<{ROOT}shared/.acl>; rel=\"acl\"")),
        "{link}"
    );
    assert!(!link.contains(".acl.acl"), "{link}");
}

/// SolidOS reads its affordances from whichever of the two it made last. Two
/// answers for one resource is two different UIs for one resource.
#[tokio::test]
async fn options_carries_the_same_links_as_a_get() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (_, _, read) = h.send("GET", "/~/note", None, true).await;
    let (status, _, options) = h.send("OPTIONS", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(links(&options), links(&read));
}

/// "May I create here?" is a fair question (H4), and the answer must not say
/// what kind of thing is — or isn't — already there.
#[tokio::test]
async fn options_on_a_target_that_does_not_exist_claims_no_kind() {
    let h = harness().await;
    let (status, _, headers) = h.send("OPTIONS", "/~/nothing-here", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let link = links(&headers);
    assert!(!link.contains("rel=\"type\""), "{link}");
    assert!(
        link.contains(&format!("<{ROOT}nothing-here.acl>; rel=\"acl\"")),
        "{link}"
    );
}

/// The link and the route drifting apart is the failure: §4.1 requires the
/// relation, and a client that follows it to a 404 has no other way to
/// discover the storage. So follow it, rather than asserting the path.
#[tokio::test]
async fn the_advertised_storage_description_resolves() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, _, headers) = h.send("GET", "/~/note", None, true).await;
    let target = link_target(
        &headers,
        "http://www.w3.org/ns/solid/terms#storageDescription",
    );
    let path = target
        .strip_prefix(BASE)
        .unwrap_or_else(|| panic!("the description is on the pod's own origin: {target}"));

    // Anonymously: discovery precedes credentials.
    let (status, body, headers) = h.send("GET", path, None, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/turtle"),
        "{headers:?}"
    );
    assert!(
        body.contains("http://www.w3.org/ns/pim/space#Storage"),
        "{body}"
    );
    assert!(body.contains(&format!("{BASE}/profile#me")), "{body}");
}

/// A JSON-LD client (Inrupt's, LDO) asks for JSON-LD everywhere. Answering
/// Turtle regardless is a parse error a long way from its cause.
#[tokio::test]
async fn the_storage_description_negotiates_like_a_pod_read() {
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/solid")
        .header(header::HOST, HOST)
        .header(header::ACCEPT, "application/ld+json")
        .body(Body::empty())
        .unwrap();
    let (status, body, headers) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/ld+json"),
        "{headers:?}"
    );
}

/// It is generated from the routing table, so there is nothing a write could
/// change. The failure is a write that *looks* accepted — or a 405 with no
/// `Allow`, which RFC 9110 §15.5.6 makes a MUST (H16).
#[tokio::test]
async fn the_storage_description_is_read_only() {
    let h = harness().await;
    for method in ["PUT", "POST", "PATCH", "DELETE"] {
        let (status, _, headers) = h
            .send(
                method,
                "/.well-known/solid",
                Some(("text/turtle", NOTE)),
                true,
            )
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(headers[header::ALLOW], "GET, HEAD, OPTIONS", "{method}");
    }

    let (status, _, headers) = h.send("OPTIONS", "/.well-known/solid", None, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers[header::ALLOW], "GET, HEAD, OPTIONS");

    // HEAD is GET without the body, and anonymous like GET.
    let (status, body, _) = h.send("HEAD", "/.well-known/solid", None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "HEAD sent a body: {body}");
}

/// Routes aren't host-scoped, so the handler decides. The apex is not a
/// storage, and a description there would describe nobody's pod. Every method
/// gets the 404 — a 405 would say the resource exists.
#[tokio::test]
async fn the_apex_has_no_storage_description() {
    let h = harness().await;
    for method in ["GET", "OPTIONS", "PUT"] {
        let request = Request::builder()
            .method(method)
            .uri("/.well-known/solid")
            .header(header::HOST, "brolly.test")
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = run(h.router.clone(), request).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
    }
}

/// A description naming a member who doesn't exist would be a storage that
/// isn't there.
#[tokio::test]
async fn an_unknown_pod_has_no_storage_description() {
    let h = harness().await;
    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/solid")
        .header(header::HOST, "nobody.brolly.test")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- the storage root (stage 5b, H12 and H16; stage 5c, H9) -------------------

/// The methods an `Allow` field names. Axum's own 405 joins them with `,` and
/// ours with `, `; a test asking whether a method is offered shouldn't care.
fn allowed(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get(header::ALLOW)
        .expect("a 405 without Allow breaks RFC 9110 §15.5.6")
        .to_str()
        .unwrap()
        .split(',')
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect()
}

/// Rewrite the root ACL so Alice holds `Control` there as well. The harness's
/// ACL grants only Read and Write, so that no other test can touch an `.acl` by
/// accident. This one has to be able to.
fn control_at_the_root(h: &Harness) {
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    set_acl(
        h,
        &g,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(
                &g,
                &a,
                &format!("{ACL}agent"),
                &format!("{BASE}/profile#me"),
            ),
        ],
    );
}

/// Authorization comes before method availability (H4). Axum's generated 405
/// answered this before any handler ran, which told a caller with no access at
/// all that the target exists and is special.
#[tokio::test]
async fn an_anonymous_delete_of_the_storage_root_is_a_challenge_not_a_405() {
    let h = harness().await;
    let (status, _, headers) = h.send("DELETE", "/~/", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers.contains_key(header::WWW_AUTHENTICATE),
        "a 401 tells the client how to authenticate: {headers:?}"
    );
}

/// §5.4's first undeletable resource. Without its root a pod has nowhere to
/// put anything, and only provisioning records one. The 405 must list what the
/// owner *can* do, which is everything but this.
#[tokio::test]
async fn the_owner_cannot_delete_the_storage_root() {
    let h = harness().await;
    let (status, _, headers) = h.send("DELETE", "/~/", None, true).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let allow = allowed(&headers);
    assert!(!allow.iter().any(|m| m == "DELETE"), "{allow:?}");
    for method in ["GET", "PUT", "PATCH", "POST"] {
        assert!(
            allow.iter().any(|m| m == method),
            "the owner holds Write, so {method} is on offer: {allow:?}"
        );
    }

    let (status, _, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK, "the refused DELETE landed");
}

/// A member may describe their own storage root like any other container.
/// With no route, both were axum's 405, whatever the caller's modes.
#[tokio::test]
async fn the_storage_root_takes_a_put_and_a_patch() {
    let h = harness().await;
    let (status, body, _) = h
        .send(
            "PUT",
            "/~/",
            Some(("text/turtle", r#"<> <https://example.org/title> "Home" ."#)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, body, _) = h
        .send(
            "PATCH",
            "/~/",
            Some((
                "application/sparql-update",
                r#"INSERT DATA { <https://alice.brolly.test/~/> <https://example.org/note> "Mine" }"#,
            )),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, root, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(root.contains("Home") && root.contains("Mine"), "{root}");
}

/// H9 (spec 5c): `/~` without its slash is the storage prefix, not a resource,
/// and every method on it answers 308 (Permanent Redirect) to `/~/`. 308 and
/// not 301: RFC 9110 §15.4.9 forbids a client changing the method when it
/// follows one, where §15.4.2 lets a 301 turn a `PUT /~` into a `GET /~/`.
/// This was 5b's 405 with an empty `Allow` (H16) — the one path that reaches
/// `subdomain_fallback`'s storage arm.
#[tokio::test]
async fn the_bare_storage_path_redirects_to_the_storage_root() {
    let h = harness().await;
    for method in ["GET", "HEAD", "PUT", "POST", "PATCH", "DELETE", "OPTIONS"] {
        let body = matches!(method, "PUT" | "POST" | "PATCH").then_some(("text/turtle", NOTE));
        let (status, _, headers) = h.send(method, "/~", body, true).await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT, "{method}");
        assert_eq!(header_of(&headers, "location"), "/~/", "{method}");
    }

    // The redirect is the prefix's, not a resource's: it is the same for a
    // caller with no credential, because it says where storage lives and
    // nothing about what is in it.
    let (status, _, headers) = h
        .send("PUT", "/~", Some(("text/turtle", NOTE)), false)
        .await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    let location = header_of(&headers, "location");

    // A client that follows re-sends the method and the body, and lands on
    // the storage root: the PUT it meant is the PUT that happens.
    let (status, body, _) = h
        .send("PUT", &location, Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, root, _) = h.send("GET", &location, None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(root.contains("Written over HTTP"), "{root}");
}

/// A redirect that dropped the query would send a different request than the
/// one it was given, which is what H9's "preserving" rules out.
#[tokio::test]
async fn the_bare_storage_path_keeps_its_query_when_it_redirects() {
    let h = harness().await;
    let (status, _, headers) = h.send("GET", "/~?ext=ttl", None, true).await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header_of(&headers, "location"), "/~/?ext=ttl");
}

/// H9's second bullet (spec 5c): `/foo` and `/foo/` are two IRIs and two
/// resources, and neither redirects to the other. Both may exist at once — a
/// document and a container — so a redirect would make one of them
/// unreachable.
#[tokio::test]
async fn a_trailing_slash_names_a_different_resource_and_never_redirects() {
    let h = harness().await;
    let (status, body, _) = h
        .send("PUT", "/~/thing", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The container-shaped twin is simply not there.
    let (status, _, headers) = h.send("GET", "/~/thing/", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!headers.contains_key(header::LOCATION), "{headers:?}");

    let (status, body, _) = h
        .send("PUT", "/~/thing/", Some(("text/turtle", "")), true)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Both exist now, each its own kind.
    let (status, document, headers) = h.send("GET", "/~/thing", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(document.contains("Written over HTTP"), "{document}");
    assert!(!header_of(&headers, "link").contains("ldp#BasicContainer"));
    let (status, _, headers) = h.send("GET", "/~/thing/", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(header_of(&headers, "link").contains("ldp#BasicContainer"));

    // And a container that exists without its document twin doesn't redirect
    // the slashless IRI either.
    h.send("PUT", "/~/only/", Some(("text/turtle", "")), true)
        .await;
    let (status, _, headers) = h.send("GET", "/~/only", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!headers.contains_key(header::LOCATION), "{headers:?}");
}

/// Solid Protocol §5.4 names two undeletable resources, the storage root and
/// its ACL, and until 5b the second one could be deleted by anyone holding
/// `Control`. That shuts the pod to its own member. Deleting an ACL is how a
/// resource falls back to its container's rules (WAC §3.2), the root has no
/// container, so no rule is left anywhere, and only provisioning ever writes a
/// root ACL.
#[tokio::test]
async fn the_storage_roots_acl_cannot_be_deleted() {
    let h = harness().await;
    control_at_the_root(&h);

    // Authorization first (H4). A caller without Control is refused for that
    // reason, and learns nothing about the resource being special.
    let (status, _, _) = h.send("DELETE", "/~/.acl", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, headers) = h.send("DELETE", "/~/.acl", None, true).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let allow = allowed(&headers);
    assert!(!allow.iter().any(|m| m == "DELETE"), "{allow:?}");
    assert!(
        allow.iter().any(|m| m == "PUT"),
        "Control still lets the member rewrite their root's rules: {allow:?}"
    );

    let pod = h.stores.pod(h.user).unwrap();
    assert!(
        pod.read(|r| r.meta(&format!("{ROOT}.acl")))
            .unwrap()
            .is_some(),
        "the refused DELETE landed"
    );
    let (status, _, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the member can still read their pod"
    );
}

// --- caching (stage 5b, H10) ---------------------------------------------------

/// Spec problem 9: one ETag served every syntax, and the 304 was decided from
/// the version alone, so a client that cached Turtle and revalidated asking
/// for JSON-LD was told its Turtle was fresh — and then parsed Turtle as
/// JSON-LD, a parse error a long way from its cause.
#[tokio::test]
async fn a_turtle_tag_does_not_revalidate_a_json_ld_read() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h
        .send_if("GET", "/~/note", None, &[("accept", "text/turtle")])
        .await;
    assert_eq!(status, StatusCode::OK);
    let turtle_tag = headers[header::ETAG].to_str().unwrap().to_string();
    assert!(turtle_tag.ends_with(".ttl\""), "got {turtle_tag}");

    // The Turtle tag confirms the Turtle representation.
    let (status, _, _) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[
                ("accept", "text/turtle"),
                ("if-none-match", turtle_tag.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED, "its own syntax");

    // It confirms nothing else.
    let (status, _, headers) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[
                ("accept", "application/ld+json"),
                ("if-none-match", turtle_tag.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "a Turtle tag confirmed JSON-LD");
    assert_eq!(headers[header::CONTENT_TYPE], "application/ld+json");
    let json_tag = headers[header::ETAG].to_str().unwrap().to_string();
    assert!(json_tag.ends_with(".jsonld\""), "got {json_tag}");
    assert_ne!(json_tag, turtle_tag);

    // The version half is the same resource state either way, which is what
    // makes a write guarded by either tag work (H10).
    assert_eq!(
        turtle_tag.trim_end_matches(".ttl\""),
        json_tag.trim_end_matches(".jsonld\"")
    );
}

/// A binary's bytes are the same for every `Accept`, so its tag says so and
/// one token serves. Nothing negotiates, so nothing can be confirmed wrongly.
#[tokio::test]
async fn a_binary_is_tagged_as_a_binary() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    let (status, _, headers) = h
        .send_if("GET", "/~/paper.pdf", None, &[("accept", "*/*")])
        .await;
    assert_eq!(status, StatusCode::OK);
    let tag = headers[header::ETAG].to_str().unwrap().to_string();
    assert!(tag.ends_with(".bin\""), "got {tag}");

    // Asking for JSON-LD doesn't change the bytes, so the tag still holds.
    let (status, _, _) = h
        .send_if(
            "GET",
            "/~/paper.pdf",
            None,
            &[
                ("accept", "application/ld+json"),
                ("if-none-match", tag.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
}

/// H10's deviation from RFC 9110 §13.1.1, over the wire. A client that read a
/// resource as Turtle and writes it back as JSON-LD guards the write with the
/// tag it has, and must not be refused for a syntax it never claimed.
#[tokio::test]
async fn a_tag_from_one_syntax_guards_a_write_in_another() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (_, _, headers) = h
        .send_if("GET", "/~/note", None, &[("accept", "text/turtle")])
        .await;
    let turtle_tag = headers[header::ETAG].to_str().unwrap().to_string();

    let json = r#"[{"@id":"https://alice.brolly.test/~/note",
        "https://example.org/title":[{"@value":"Edited"}]}]"#;
    let (status, body, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("application/ld+json", json)),
            &[("if-match", turtle_tag.as_str())],
        )
        .await;
    assert!(status.is_success(), "{status}: {body}");

    // And a tag for a version that has moved on is still refused.
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", turtle_tag.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "a stale version");
}

/// A tag cached before this stage has no syntax token, so it names no version
/// and no representation. `If-Match` fails closed and the client re-`GET`s;
/// `If-None-Match` is a full response rather than a wrong 304.
#[tokio::test]
async fn a_tag_from_before_this_stage_matches_nothing() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;
    let bare = format!("\"{}\"", current.trim_matches('"').trim_end_matches(".ttl"));
    assert_ne!(bare, current, "the tag has no token to strip");

    let (status, _, _) = h
        .send_if("GET", "/~/note", None, &[("if-none-match", bare.as_str())])
        .await;
    assert_eq!(status, StatusCode::OK, "a 5a-era tag confirmed a read");

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", bare.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "fail closed");
    assert_eq!(h.etag("/~/note").await, current, "the refused PUT landed");
}

// --- WAC-Allow (stage 5b, H9) --------------------------------------------------

/// Grant the world Read on a resource, the way a member's share UI would.
///
/// A direct ACL replaces the inherited one rather than adding to it, so
/// Alice's own grants have to be restated here or she loses them — which is
/// WAC working, not a bug in the helper.
fn make_public(h: &Harness, path: &str) {
    let resource = format!("{ROOT}{path}");
    let g = format!("{resource}.acl");
    let owner = format!("{g}#owner");
    let public = format!("{g}#public");
    set_acl(
        h,
        &g,
        &[
            t(&g, &owner, &format!("{ACL}accessTo"), &resource),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(
                &g,
                &owner,
                &format!("{ACL}agent"),
                &format!("{BASE}/profile#me"),
            ),
            t(&g, &public, &format!("{ACL}accessTo"), &resource),
            t(&g, &public, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &public, &format!("{ACL}agentClass"), EVERYONE),
        ],
    );
}

/// Spec problem 7: a share UI has to show whether what it is looking at is
/// world-readable, and it cannot learn that by asking as itself. `public=` is
/// a second `granted_modes` probe with an anonymous subject, run inside the
/// same snapshot so both components describe the same ACL.
#[tokio::test]
async fn wac_allow_names_what_the_public_holds() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/open", Some(("text/turtle", NOTE)), true)
        .await;
    make_public(&h, "open");

    // The harness's root ACL grants Alice Read and Write, and Write satisfies
    // Append (`AccessMode::satisfying`), so she holds three modes on both.
    let (status, _, headers) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["wac-allow"], "user=\"read write append\", public=\"\"",
        "a private resource still reports an empty public group"
    );

    let (status, _, headers) = h.send("GET", "/~/open", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["wac-allow"],
        "user=\"read write append\", public=\"read\""
    );

    // And HEAD carries it too (WAC §6's MUST), and OPTIONS, which now makes
    // the same evaluation (H9).
    for method in ["HEAD", "OPTIONS"] {
        let (status, _, headers) = h.send(method, "/~/open", None, true).await;
        assert!(status.is_success(), "{method}: {status}");
        assert_eq!(
            headers["wac-allow"], "user=\"read write append\", public=\"read\"",
            "{method}"
        );
    }
}

/// An anonymous reader of a public resource sees the same `public=` group it
/// is a member of, and a `user=` group that is the same thing said twice.
#[tokio::test]
async fn an_anonymous_reader_of_a_public_resource_sees_both_groups() {
    let h = harness().await;
    h.send("PUT", "/~/open", Some(("text/turtle", NOTE)), true)
        .await;
    make_public(&h, "open");

    let (status, _, headers) = h.send("GET", "/~/open", None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["wac-allow"], "user=\"read\", public=\"read\"");
}

// --- Vary and the 304 (stage 5b, H10) -------------------------------------------

/// All the `Vary` field lines as one value. A repeated field line means the
/// same as one line joined with commas (RFC 9110 §5.3), and this stage sets
/// the header from two places: the handler and the CORS layer.
fn vary_of(headers: &axum::http::HeaderMap) -> String {
    headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ")
        .to_ascii_lowercase()
}

/// Spec problem 8: `GET` negotiates on `Accept` and never said so, so a shared
/// cache could hand a client asking for JSON-LD the Turtle it stored for
/// someone else. A binary gets no `Vary: Accept`: its bytes are the same for
/// every `Accept`, and claiming otherwise fragments a cache for nothing.
#[tokio::test]
async fn a_negotiated_read_varies_on_accept_and_a_binary_does_not() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for path in ["/~/note", "/~/"] {
        for method in ["GET", "HEAD"] {
            let (status, _, headers) = h.send(method, path, None, true).await;
            assert_eq!(status, StatusCode::OK, "{method} {path}");
            assert!(
                vary_of(&headers).contains("accept"),
                "{method} {path}: {}",
                vary_of(&headers)
            );
        }
    }

    let (status, _, headers) = h.send("GET", "/~/paper.pdf", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !vary_of(&headers).contains("accept"),
        "a binary varied on Accept: {}",
        vary_of(&headers)
    );
}

/// RFC 9110 §15.4.5 requires `ETag` and `Vary` on a 304. We send more: a
/// client that revalidates must not lose the affordances it had, so `Allow`,
/// `Accept-*` and `WAC-Allow` — control and resource metadata, not the
/// representation metadata §15.4.5's SHOULD NOT covers — ride along, and so
/// does `Link`. `Last-Modified` is the one deviation, and it is deliberate.
#[tokio::test]
async fn a_304_carries_what_the_200_carried() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, ok) = h
        .send_if("GET", "/~/note", None, &[("accept", "text/turtle")])
        .await;
    assert_eq!(status, StatusCode::OK);
    let tag = ok[header::ETAG].to_str().unwrap().to_string();

    let (status, body, not_modified) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[("accept", "text/turtle"), ("if-none-match", tag.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty(), "a 304 has no body: {body}");

    // 5c H3 removed `Accept-Post` from a document — POST is a container
    // method — so the container case is where that header's 200/304 agreement
    // is checked.
    h.send("PUT", "/~/docs/", Some(("text/turtle", "")), true)
        .await;
    let (_, _, ok_docs) = h
        .send_if("GET", "/~/docs/", None, &[("accept", "text/turtle")])
        .await;
    let (_, _, not_modified_docs) = h
        .send_if(
            "GET",
            "/~/docs/",
            None,
            &[
                ("accept", "text/turtle"),
                ("if-none-match", ok_docs[header::ETAG].to_str().unwrap()),
            ],
        )
        .await;

    for (name, (ok, not_modified)) in [
        ("etag", (&ok, &not_modified)),
        ("last-modified", (&ok, &not_modified)),
        ("link", (&ok, &not_modified)),
        ("allow", (&ok, &not_modified)),
        ("accept-patch", (&ok, &not_modified)),
        ("accept-post", (&ok_docs, &not_modified_docs)),
        ("accept-put", (&ok, &not_modified)),
        ("wac-allow", (&ok, &not_modified)),
    ] {
        let on_200 = ok.get_all(name).iter().collect::<Vec<_>>();
        let on_304 = not_modified.get_all(name).iter().collect::<Vec<_>>();
        assert!(!on_200.is_empty(), "{name} missing from the 200");
        assert_eq!(on_304, on_200, "{name} differs on the 304");
    }
    assert_eq!(vary_of(&not_modified), vary_of(&ok), "Vary differs");

    // §15.4.5's SHOULD NOT: representation metadata stays off.
    for name in [header::CONTENT_TYPE, header::CONTENT_LENGTH] {
        assert!(
            not_modified.get(&name).is_none(),
            "{name} on a 304: representation metadata"
        );
    }
}

// --- CORS (stage 5b, H14) -------------------------------------------------------

/// CTS `protocol/cors/acao-vary.feature`: a response whose `Allow-Origin`
/// depends on the request's `Origin` must say so, or a shared cache serves one
/// origin's response to another. It uses a `.txt`, so this has to hold for a
/// binary too — the one response with nothing else to vary on.
#[tokio::test]
async fn every_response_varies_on_origin_binaries_included() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for path in ["/profile", "/~/paper.pdf", "/~/nothing-here"] {
        let (_, headers) = headers_of(&h, "GET", path, &[("origin", "https://app.example")]).await;
        assert!(
            vary_of(&headers).contains("origin"),
            "{path}: {}",
            vary_of(&headers)
        );
    }
}

/// The handler sets `Vary: Accept` and the CORS layer is outermost. If it
/// `insert`s rather than appends, the negotiated read silently stops
/// advertising that it negotiates, and a shared cache serves Turtle to a
/// JSON-LD request — problem 8 restored by the layer meant to fix it.
#[tokio::test]
async fn the_cors_layer_adds_to_vary_rather_than_replacing_it() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let request = conditional_request(
        "GET",
        "/~/note",
        None,
        Some(h.session.as_str()),
        &[("origin", "https://app.example"), ("accept", "text/turtle")],
    );
    let (status, _, headers) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::OK);

    let vary = vary_of(&headers);
    assert!(
        vary.contains("accept"),
        "the handler's Accept was lost: {vary}"
    );
    assert!(vary.contains("origin"), "no Origin: {vary}");
}

/// With no `Origin` there is no origin to echo, and `*` is the only answer
/// that lets a `file://` page or a curl-style client read the response.
#[tokio::test]
async fn a_request_with_no_origin_still_gets_a_wildcard() {
    let h = harness().await;
    let (status, headers) = headers_of(&h, "GET", "/profile", &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert!(headers.get("access-control-allow-credentials").is_none());
}

/// Solid §8.1 wants an app able to send any combination of headers. A fixed
/// `Allow-Headers` list can never admit one it doesn't already name, so a
/// client sending a header we haven't thought of is blocked by the browser
/// before the request is made. CTS also asserts the response does *not* carry
/// `Accept` when the preflight didn't ask for it
/// (`protocol/cors/accept-acah.feature`).
#[tokio::test]
async fn a_preflight_is_answered_with_the_headers_it_asked_for() {
    let h = harness().await;
    let (status, headers) = headers_of(
        &h,
        "OPTIONS",
        "/~/notes/first",
        &[
            ("origin", "https://app.example"),
            ("access-control-request-method", "PUT"),
            ("access-control-request-headers", "x-invented-by-the-app"),
        ],
    )
    .await;

    assert!(status.is_success(), "preflight rejected: {status}");
    let allowed = headers
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(allowed.contains("x-invented-by-the-app"), "got: {allowed}");
    assert!(
        !allowed.contains("accept"),
        "named a header the preflight didn't ask for: {allowed}"
    );
}

// --- write responses and bodies (stage 5b, H11–H13, H17) ------------------------

/// Solid §2.1: a server MUST reject a PUT, POST or PATCH that contains content
/// but lacks `Content-Type`. Guessing `text/turtle` turns a client bug into
/// stored garbage that parses, and PATCH's 415 tells a client its media type
/// was unsupported when it never sent one — the wrong thing to retry.
#[tokio::test]
async fn a_body_without_a_content_type_is_refused() {
    let h = harness().await;
    for (method, path) in [("PUT", "/~/note"), ("POST", "/~/"), ("PATCH", "/~/note")] {
        let (status, body, _) = h.send_untyped(method, path, NOTE).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method}: {body}");
        assert!(
            body.to_lowercase().contains("content-type"),
            "{method}: the 400 must name the missing header: {body}",
        );
    }
    // Nothing was guessed into the pod.
    let (status, _, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A PATCH with a type we don't parse is still a 415: the client sent one,
    // and it is the media type that's wrong.
    let (status, _, _) = h
        .send("PATCH", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// §2.1's MUST is about requests that "contain content". An empty body is how
/// a client creates an empty resource, which 5a made possible, and refusing it
/// would take that away — `ldp::prepare` still needs a type to reach
/// `Content::Rdf(&[])`, so the default survives for exactly this case.
#[tokio::test]
async fn an_empty_body_without_a_content_type_creates_an_empty_resource() {
    let h = harness().await;
    let (status, body, _) = h.send_untyped("PUT", "/~/empty", "").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body, _) = h.send("GET", "/~/empty", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.trim().is_empty(), "got: {body}");

    // A container, the same way.
    let (status, body, _) = h.send_untyped("PUT", "/~/c/", "").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// LDP and every Solid client expect 201 from a PUT that creates, and a
/// `Location` they can follow. Before 5b a create and a replace were both 204,
/// so a client had to GET to find out whether it had just made something.
#[tokio::test]
async fn a_put_that_creates_answers_201_with_a_location_and_its_kinds() {
    let h = harness().await;

    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers[header::LOCATION], format!("{BASE}/~/note"));
    let link = links(&headers);
    assert!(link.contains("ldp#RDFSource>; rel=\"type\""), "got: {link}");
    assert!(link.contains("rel=\"acl\""), "got: {link}");

    // The same PUT again replaced something, and says so.
    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "204 with a Location"
    );
}

/// Solid Protocol §5.4 requires the status *and* a body describing the error.
/// Before 5b this was a 403, which says "you may not" when the truth is "not
/// while it has members" — a client can act on the second and not the first.
#[tokio::test]
async fn deleting_a_non_empty_container_is_a_409_that_says_what_to_do() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, body, _) = h.send("DELETE", "/~/c/", None, true).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body.contains("members"),
        "the body must name the problem: {body}"
    );

    // Emptying it is the way through, and the caller had the access all along.
    h.send("DELETE", "/~/c/m", None, true).await;
    let (status, _, _) = h.send("DELETE", "/~/c/", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// The read-modify-write every Solid client does on a container. Inrupt's
/// solid-client, LDO and SolidOS all GET a listing, change one triple and PUT
/// the whole thing back; §4.2.1's protection has to tolerate the echo or none
/// of them can edit a container's description at all. Each syntax respells
/// the literals its own way, which is where the by-value comparison earns its
/// keep.
#[tokio::test]
async fn a_container_listing_put_back_unchanged_is_accepted() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;

    for accept in [
        "text/turtle",
        "application/ld+json",
        "application/n-triples",
    ] {
        let (status, listing, _) = h.send_if("GET", "/~/c/", None, &[("accept", accept)]).await;
        assert_eq!(status, StatusCode::OK, "{accept}: {listing}");
        assert!(listing.contains("modified"), "{accept}: no member metadata");

        let (status, body, _) = h
            .send("PUT", "/~/c/", Some((accept, listing.as_str())), true)
            .await;
        assert!(
            status.is_success(),
            "{accept}: the echo was refused: {body}"
        );
    }

    // And the listing still comes from metadata rather than from what was
    // stored: the member's modified time is listed once, not twice.
    let (_, listing, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "application/n-triples")])
        .await;
    let member = format!("{ROOT}c/m");
    assert_eq!(
        listing
            .matches(&format!("<{member}> <http://purl.org/dc/terms/modified>"))
            .count(),
        1,
        "an echoed statement was stored beside the generated one: {listing}",
    );
}

/// §4.2.1's MUST. Without it a client could GET a listing, change a member's
/// modified time, PUT it back, and have the wrong number stored as content —
/// served beside the generated one, stale forever, with no way to remove it
/// except by finding it.
#[tokio::test]
async fn changing_a_members_modified_time_in_a_listing_is_a_409() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, listing, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "application/n-triples")])
        .await;
    let altered = listing.replace(&h.modified("/~/c/m"), "1999-01-01T00:00:00.000Z");
    assert_ne!(altered, listing, "setup: the listing carries the time");

    let (status, body, _) = h
        .send(
            "PUT",
            "/~/c/",
            Some(("application/n-triples", altered.as_str())),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body.contains("re-read"),
        "the 409 must tell the client how to resolve it: {body}",
    );
}

/// The race §4.2.1's rule creates, which containment's set-wise rule doesn't
/// have: a member's modified time moves on *every* write to it, not only on
/// create and delete. So a client that reads a listing, saves a member, and
/// then writes the container's own description back is refused for metadata it
/// never touched — and the only thing it can do is re-read. That is why the
/// 409 carries a body and why the body says so.
#[tokio::test]
async fn a_listing_written_back_after_a_member_changed_is_a_409_the_client_re_reads() {
    let h = harness().await;
    h.send("PUT", "/~/c/m", Some(("text/turtle", NOTE)), true)
        .await;
    let (_, stale, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "text/turtle")])
        .await;

    // The client edits the member it was listing.
    h.send("PUT", "/~/c/m", Some(("text/turtle", EDITED)), true)
        .await;

    let (status, body, _) = h
        .send("PUT", "/~/c/", Some(("text/turtle", stale.as_str())), true)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Re-reading and retrying is the resolution, and it works.
    let (_, fresh, _) = h
        .send_if("GET", "/~/c/", None, &[("accept", "text/turtle")])
        .await;
    let (status, body, _) = h
        .send("PUT", "/~/c/", Some(("text/turtle", fresh.as_str())), true)
        .await;
    assert!(status.is_success(), "the retry was refused too: {body}");
}

// --- a PUT cannot change a kind (stage 5c, H8) ----------------------------------

/// H8 (spec 5c): a `PUT` cannot change an existing resource's kind. 422
/// (RFC 9110 §15.5.21) and neither 415 nor 409: the request is well-formed and
/// the media type is one this server stores — just not over *this* resource —
/// and no other request is in the way. The body names the recorded kind and
/// the incoming content type, so a client can tell which of the two to change,
/// and the old representation is untouched.
#[tokio::test]
async fn a_put_that_would_change_a_resources_kind_is_a_422() {
    let h = harness().await;

    // A binary over an RDF document.
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let tag = h.etag("/~/note").await;
    let (status, body, _) = h
        .send("PUT", "/~/note", Some(("application/pdf", PDF)), true)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("ldp:RDFSource"), "{body}");
    assert!(body.contains("application/pdf"), "{body}");
    let (status, served, headers) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(served.contains("Written over HTTP"), "{served}");
    assert_eq!(
        header_of(&headers, "etag"),
        tag,
        "the refusal wrote something"
    );

    // RDF over a binary.
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;
    let tag = h.etag("/~/paper.pdf").await;
    let (status, body, _) = h
        .send("PUT", "/~/paper.pdf", Some(("text/turtle", NOTE)), true)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("ldp:NonRDFSource"), "{body}");
    assert!(body.contains("text/turtle"), "{body}");
    let (status, served, headers) = h.send("GET", "/~/paper.pdf", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(served, PDF, "the refused PUT replaced the bytes");
    assert_eq!(headers[header::CONTENT_TYPE], "application/pdf");
    assert_eq!(
        header_of(&headers, "etag"),
        tag,
        "the refusal wrote something"
    );
}

/// H8 refuses after the upload's bytes are on disk (R12: they are written
/// before the write lock is taken), exactly as a 412 does. The refusal has to
/// hand them back, or a caller who can be refused repeatedly fills the volume
/// one 422 at a time.
#[tokio::test]
async fn a_binary_refused_as_a_kind_change_leaves_no_bytes_behind() {
    use sha2::{Digest, Sha256};

    let h = harness().await;
    let refused: String = Sha256::digest(PDF.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (status, body, _) = h
        .send("PUT", "/~/note", Some(("application/pdf", PDF)), true)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    let blobs = h.stores.blobs(h.user).unwrap();
    assert!(
        !blobs.contains(&refused),
        "the refused upload's bytes are still on disk"
    );
}

/// H8 is authorization-gated like every other refusal (5b, H1): a caller
/// without Write gets the same 401 for a kind-changing `PUT` as for any other,
/// and learns nothing about what kind of resource is there.
#[tokio::test]
async fn a_kind_change_is_not_disclosed_to_a_caller_who_may_not_write() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, body, _) = h
        .send("PUT", "/~/note", Some(("application/pdf", PDF)), false)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("RDFSource"), "{body}");
}

/// H8's two edges. A container IRI never takes a binary, so a binary `PUT`
/// over an existing container is the 415 it always was, not a 422; and a
/// binary replaced by new bytes is the same kind, so it is the 204 it always
/// was.
#[tokio::test]
async fn a_binary_on_a_container_is_still_a_415_and_a_same_kind_put_still_replaces() {
    let h = harness().await;

    h.send("PUT", "/~/c/", Some(("text/turtle", "")), true)
        .await;
    let (status, body, _) = h
        .send("PUT", "/~/c/", Some(("application/pdf", PDF)), true)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");

    const OTHER: &str = "%PDF-1.4\n1 0 obj\n<< /Type /Nothing >>\nendobj\n";
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;
    let (status, body, _) = h
        .send(
            "PUT",
            "/~/paper.pdf",
            Some(("application/pdf", OTHER)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, served, _) = h.send("GET", "/~/paper.pdf", None, true).await;
    assert_eq!(served, OTHER);
}

// --- the `.meta` auxiliary (stage 5d, H1–H4) --------------------------------------

/// H3 (spec 5d): every non-auxiliary resource's `Link` set gains
/// `rel="describedby"` pointing at its `.meta` — always sent, exists or not,
/// the same contract as `rel="acl"`: the client needs the IRI to create the
/// description, not to find it.
#[tokio::test]
async fn a_resource_links_its_description_exist_or_not() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        link_target(&headers, "describedby"),
        format!("{ROOT}note.meta")
    );

    // `OPTIONS` on a target that does not exist yet answers the same question
    // for a creation (5b, H4): no `rel="type"`, but the description's IRI.
    let (status, _, headers) = h.send("OPTIONS", "/~/not-yet", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        link_target(&headers, "describedby"),
        format!("{ROOT}not-yet.meta")
    );

    // The root is no exception: its description lives inside it, like its ACL.
    let (_, _, headers) = h.send("GET", "/~/", None, true).await;
    assert_eq!(link_target(&headers, "describedby"), format!("{ROOT}.meta"));
}

/// H3 (spec 5d): a `.meta`'s own `Link` set answers the inverse —
/// `rel="describes"` pointing at its subject — and its `rel="acl"` points at
/// the *subject's* ACL, the one that actually governs it under H2, where
/// `acl_iri` on the `.meta` itself would name `note.meta.acl`, a fiction.
/// Neither auxiliary kind carries a `describedby`: their described target is
/// the subject, announced there.
#[tokio::test]
async fn a_meta_links_its_subject_and_its_subjects_acl() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/note.meta", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, headers) = h.send("GET", "/~/note.meta", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let link = links(&headers);
    assert_eq!(link_target(&headers, "describes"), format!("{ROOT}note"));
    assert_eq!(link_target(&headers, "acl"), format!("{ROOT}note.acl"));
    assert!(
        !link.contains("describedby"),
        "an auxiliary's described target is its subject, announced there: {link}"
    );
    // Its types stay `ldp:Resource, ldp:RDFSource` — LDP names no auxiliary
    // class, and 5b declined to invent one.
    assert!(link.contains("ldp#RDFSource>; rel=\"type\""), "{link}");
    assert!(!link.contains("ldp#Container"), "{link}");

    // An `.acl` carries no `describedby` either.
    share_with_bob(&h);
    let (status, _, headers) = h.send("GET", "/~/shared/.acl", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!links(&headers).contains("describedby"));
}

/// H1 (spec 5d): a path ending in two auxiliary suffixes is a fiction — the
/// resource can never exist — and every method answers 404, decided by the
/// IRI's shape before any lookup and deliberately before WAC: the shape is
/// syntactic public knowledge, so there is no existence to protect. Even the
/// owner, who may write anywhere here, and an anonymous caller, who may do
/// nothing, get the same 404 — not a store refusal, not a 401.
/// A request target that is not an IRI is a 400, decided by its shape alone
/// — before any lookup, and before the authorization query it would
/// otherwise be spliced into as text. The decoded path becomes the resource
/// IRI, and the IRI becomes the ACL candidate list the access decision is
/// built from; a path that cannot be an IRI has no business reaching either.
#[tokio::test]
async fn a_path_that_is_not_an_iri_is_refused_before_anything_looks_at_it() {
    let h = harness().await;
    for path in [
        // `>`, space and `}` — the three characters that would close an IRI
        // term, a VALUES list, and a graph pattern in the query.
        "/~/a%3E%20%7D%20%7D",
        // A control character.
        "/~/a%01b",
        // A NUL.
        "/~/a%00b",
        // Characters an IRI reference cannot carry.
        "/~/a%7Cb",
        "/~/a%5Cb",
        "/~/a%22b",
    ] {
        for (method, body) in [
            ("GET", None),
            ("HEAD", None),
            ("OPTIONS", None),
            ("DELETE", None),
            ("PUT", Some(("text/turtle", NOTE))),
            ("POST", Some(("text/turtle", NOTE))),
        ] {
            let (status, text, _) = h.send(method, path, body, true).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {text}");
        }
        // Anonymous too: the shape is public knowledge, so there is nothing
        // a 401 would protect.
        let (status, _, _) = h.send("GET", path, None, false).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "anonymous GET {path}");
    }
}

/// Dot segments and empty segments are refused, not resolved. The router does
/// not normalise them, so `/~/pub/../x` would be a resource named `../x`
/// inside `/~/pub/` — governed by `/~/pub/.acl`, listed by `/~/pub/` as a
/// member every client resolves to `/~/x`. A path that needs normalising is
/// a 400; the client can send the normalised one.
#[tokio::test]
async fn dot_and_empty_segments_are_refused_not_resolved() {
    let h = harness().await;
    for path in [
        "/~/pub/../x",
        "/~/pub/./x",
        "/~/../x",
        "/~/..",
        "/~/.",
        "/~/a//b",
        // Percent-encoded spellings decode to the same segments.
        "/~/pub/%2E%2E/x",
        "/~/pub/%2E/x",
    ] {
        for (method, body) in [
            ("GET", None),
            ("PUT", Some(("text/turtle", NOTE))),
            ("POST", Some(("text/turtle", NOTE))),
        ] {
            let (status, text, _) = h.send(method, path, body, true).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {text}");
        }
    }
    // Nothing was minted under any of them.
    let pod = h.stores.pod(h.user).unwrap();
    assert!(
        pod.read(|r| r.meta(&format!("{ROOT}pub/")))
            .unwrap()
            .is_none(),
        "a container was created for a refused path"
    );
}

/// `%2F` decodes to `/`, so `a%2Fb` and `a/b` would be one resource reached
/// by two spellings — of which only one is the IRI the server mints, lists
/// and authorizes. Refused rather than merged.
#[tokio::test]
async fn an_encoded_slash_is_refused() {
    let h = harness().await;
    for path in ["/~/a%2Fb", "/~/a%2fb", "/~/a%2F"] {
        for (method, body) in [("GET", None), ("PUT", Some(("text/turtle", NOTE)))] {
            let (status, text, _) = h.send(method, path, body, true).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {text}");
        }
    }
}

#[tokio::test]
async fn an_auxiliary_of_an_auxiliary_is_a_fiction_every_method_answers_404() {
    let h = harness().await;
    let insert = "INSERT DATA { <https://alice.brolly.test/~/x> <https://example.org/t> \"x\" }";
    for path in [
        "/~/x.acl.acl",
        "/~/x.acl.meta",
        "/~/x.meta.acl",
        "/~/x.meta.meta",
        "/~/.acl.acl",
        "/~/.meta.meta",
        // The gate reads the decoded path, so a percent-encoded suffix is
        // the same fiction, not a way around it.
        "/~/x.meta%2Emeta",
    ] {
        for (method, body) in [
            ("GET", None),
            ("HEAD", None),
            ("OPTIONS", None),
            ("DELETE", None),
            ("PUT", Some(("text/turtle", NOTE))),
            ("PATCH", Some(("application/sparql-update", insert))),
            ("POST", Some(("text/turtle", NOTE))),
        ] {
            let (status, text, headers) = h.send(method, path, body, true).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {text}");
            assert!(
                headers.get("allow").is_none(),
                "{method} {path}: Allow leaked"
            );
        }
        // Before WAC: the anonymous caller gets the fiction's 404, not the 401
        // every real target answers with.
        let (status, _, _) = h.send("GET", path, None, false).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "anonymous GET {path}");
    }
    // And nothing was recorded under any of them.
    let pod = h.stores.pod(h.user).unwrap();
    for path in ["x.acl.acl", "x.acl.meta", "x.meta.acl", "x.meta.meta"] {
        assert!(
            pod.read(|r| r.meta(&format!("{ROOT}{path}")))
                .unwrap()
                .is_none(),
            "{path} was recorded"
        );
    }
}

/// H4 (spec 5d): a `.meta` is RDF-only, like an `.acl` — `Accept-Put`
/// advertises the RDF types, and a binary `PUT` is the 415 it always was for
/// an auxiliary target.
#[tokio::test]
async fn a_meta_takes_rdf_only() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/note.meta", Some(("text/turtle", NOTE)), true)
        .await;

    let (_, _, headers) = h.send("OPTIONS", "/~/note.meta", None, true).await;
    let accept_put = header_of(&headers, "accept-put");
    assert!(accept_put.contains("text/turtle"), "got: {accept_put}");
    assert!(!accept_put.contains("*/*"), "got: {accept_put}");

    let (status, text, _) = h
        .send("PUT", "/~/note.meta", Some(("application/pdf", PDF)), true)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{text}");
}

// --- read access follows the publication (spec 4, H5, ADR 0017) -----------------

/// Plant a composer medium in the pod directly — `upload_media`'s own shape —
/// so the publish path is exercised over HTTP without the OAuth machinery
/// these tests don't otherwise need. Setup through the pod, not through the
/// code under test.
async fn a_medium(h: &Harness) -> String {
    let id = brolly_mastodon::status_id::mint_note_id();
    let iri = format!("{BASE}/~/media/{id}");
    let digest = h.stores.blobs(h.user).unwrap().put(b"PNG-BYTES").unwrap();
    h.stores
        .pod(h.user)
        .unwrap()
        .write(|w| {
            w.put(
                &iri,
                Content::Binary(brolly_store::resources::BlobMeta {
                    digest,
                    media_type: "image/png".into(),
                    byte_size: 9,
                }),
            )
        })
        .unwrap();
    format!("/~/media/{id}")
}

/// Publish a bare note through the outbox as the harness member, attaching
/// `media` and addressed to `to`.
async fn publish(h: &Harness, to: serde_json::Value, media: &str) {
    let note = serde_json::json!({
        "type": "Note",
        "content": "hello",
        "to": to,
        "cc": [],
        "attachment": [{"type": "Document", "mediaType": "image/png", "url": format!("{BASE}{media}")}]
    });
    let request = Request::builder()
        .method("POST")
        .uri("/outbox")
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("{SESSION_COOKIE}={}", h.session))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(note.to_string()))
        .unwrap();
    let (status, text, _) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::CREATED, "publish: {text}");
}

/// Another member's session, for the cross-member reads.
async fn a_stranger(h: &Harness, username: &str) -> String {
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

#[tokio::test]
async fn a_public_posts_media_is_readable_by_anonymous_callers() {
    // The flip this chunk makes: a published medium reads 200 for its
    // audience, where every binary was owner-only before. The note too — the
    // same grants, the same ACL.
    let h = harness().await;
    let media = a_medium(&h).await;
    publish(
        &h,
        serde_json::json!(["https://www.w3.org/ns/activitystreams#Public"]),
        &media,
    )
    .await;

    let (status, body, _) = h.send("GET", &media, None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "PNG-BYTES", "the bytes must come back");
}

#[tokio::test]
async fn a_followers_only_posts_media_reads_for_the_follower_alone() {
    // The private row: the compose-time snapshot reads, and nobody else —
    // not a stranger, not an anonymous caller.
    let h = harness().await;
    let media = a_medium(&h).await;

    // Bob follows alice; carol doesn't.
    let bob = db::create_user(&h._db.pool, "bob", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let carol = a_stranger(&h, "carol").await;
    let bob_session = db::create_session(&h._db.pool, bob.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    h.stores
        .pod(h.user)
        .unwrap()
        .write(|w| {
            brolly_activitypub::follows::record(
                w,
                &brolly_identity::webid::actor("bob", "brolly.test"),
                &brolly_identity::webid::actor("alice", "brolly.test"),
            )
        })
        .unwrap();

    publish(
        &h,
        serde_json::json!(["https://alice.brolly.test/followers"]),
        &media,
    )
    .await;

    let request = conditional_request("GET", &media, None, Some(&bob_session), &[]);
    let (status, _, _) = run(h.router.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "the follower at compose time reads");

    // 403 for the stranger (authenticated, unauthorized) and 401 for the
    // anonymous caller, per stage 5b's H1 table.
    let request = conditional_request("GET", &media, None, Some(&carol), &[]);
    let (status, body, _) = run(h.router.clone(), request).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a stranger reads a followers-only medium: {body}"
    );
    let (status, body, _) = h.send("GET", &media, None, false).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an anonymous caller reads a followers-only medium: {body}"
    );
}

#[tokio::test]
async fn a_followers_only_medium_stays_unreadable_by_a_follower_gained_later() {
    // The snapshot is the model: carol follows *after* the post, and the post
    // predates her.
    let h = harness().await;
    let media = a_medium(&h).await;
    publish(
        &h,
        serde_json::json!(["https://alice.brolly.test/followers"]),
        &media,
    )
    .await;

    let carol = a_stranger(&h, "carol").await;
    h.stores
        .pod(h.user)
        .unwrap()
        .write(|w| {
            brolly_activitypub::follows::record(
                w,
                &brolly_identity::webid::actor("carol", "brolly.test"),
                &brolly_identity::webid::actor("alice", "brolly.test"),
            )
        })
        .unwrap();

    let request = conditional_request("GET", &media, None, Some(&carol), &[]);
    let (status, _, _) = run(h.router.clone(), request).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a follower gained later reads a post that predates them"
    );
}
