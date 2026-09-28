//! The pod over HTTP: subdomain routing, LDP verbs, and ADR 0010's default-deny.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_store::StoreManager;
use brolly_store::resources::{Content, Pod, PodRead};
use http_body_util::BodyExt;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use tower::ServiceExt;

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
        builder = builder.header(header::COOKIE, format!("brolly_session={session}"));
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
        matches!(allowed.as_deref(), None | Some("user=\"\"")),
        "got {allowed:?}"
    );

    let (status, _, headers) = h.send("GET", "/~/shared/.acl", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["wac-allow"], "user=\"read write append control\"");
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

/// H2 applies only to the `Authorization` header. `brolly_session` is
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
    assert_eq!(status, StatusCode::NO_CONTENT);

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
