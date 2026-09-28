//! Phase 4 exit criterion: LDP + WAC behaviour, exercised together.
//!
//! These drive the protocol layer directly rather than through HTTP, which is
//! the point of keeping it transport-free — the same operations the axum
//! handlers call are the ones under test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_authz::AccessMode;
use brolly_domain::vocab;
use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp::{self, LdpError};
use brolly_store::StoreManager;
use brolly_store::resources::{Content, Kind, Pod, PodRead, ResourceMeta};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.id";
const ROOT: &str = "https://alice.brolly.id/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const FOAF: &str = "http://xmlns.com/foaf/0.1/";

/// Add `quads` to the ACL at `acl`, recording it as an auxiliary resource if
/// it's new. Metadata is what makes an ACL exist, so a raw seed isn't enough.
/// Goes through the pod, not through `ldp`, so the setup doesn't depend on the
/// code under test.
fn grant(pod: &Pod, acl: &str, quads: &[Quad]) {
    pod.write(|w| {
        let mut all = w
            .quads_for_pattern(
                None,
                None,
                None,
                Some(GraphNameRef::NamedNode(n(acl).as_ref())),
            )
            .collect::<Result<Vec<_>, _>>()?;
        all.extend_from_slice(quads);
        w.put(acl, Content::Auxiliary(&all))?;
        Ok(())
    })
    .unwrap();
}

/// What the metadata records about `resource`: `Some` is existence.
fn meta(pod: &Pod, resource: &str) -> Option<ResourceMeta> {
    pod.read(|r| r.meta(resource)).unwrap()
}

/// A container's members, sorted, from metadata.
fn members(pod: &Pod, container: &str) -> Vec<String> {
    let mut members = pod.write(|w| w.members(container)).unwrap();
    members.sort();
    members
}

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn t(graph: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(n(s)),
        n(p),
        Term::NamedNode(n(o)),
        GraphName::NamedNode(n(graph)),
    )
}

fn alice() -> Subject {
    Subject::local(
        Uuid::new_v4(),
        "did:plc:alice".into(),
        "https://alice.brolly.id/profile#me".into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    )
}

fn anonymous() -> Subject {
    Subject {
        user_id: None,
        did: None,
        webid: None,
        scope: Scope::default(),
        via: Via::Session,
    }
}

fn stranger() -> Subject {
    Subject::local(
        Uuid::new_v4(),
        "did:plc:mallory".into(),
        "https://mallory.example/profile#me".into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    )
}

/// A pod whose root ACL grants Alice full control and nothing to anyone else.
fn pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();
    store.write(|w| w.create_root(ROOT)).unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    grant(
        &store,
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
                "https://alice.brolly.id/profile#me",
            ),
        ],
    );
    (mgr, dir, store)
}

const NOTE: &[u8] = br#"<> <https://example.org/title> "First note" ."#;

#[test]
fn put_then_get_round_trips() {
    let (_m, _d, store) = pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/note",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let out = ldp::read(&store, None, BASE, "/~/note", &alice(), Some("text/turtle")).unwrap();
    let body = String::from_utf8(out.body).unwrap();
    assert!(body.contains("First note"), "got: {body}");
    assert_eq!(out.media_type, "text/turtle");
    assert!(out.granted.contains(&AccessMode::Write));
}

#[test]
fn rdf_xml_is_refused_on_write_and_not_stored_as_a_blob() {
    // ADR 0007 — the mitigation for two unfixed quick-xml DoS advisories.
    let (_m, _d, store) = pod();
    let err = ldp::put(
        &store,
        None,
        BASE,
        "/~/note",
        &alice(),
        b"<rdf:RDF/>",
        "application/rdf+xml",
        ROOT,
    )
    .unwrap_err();

    assert!(matches!(err, LdpError::Syntax(_)), "got {err:?}");
    assert!(
        meta(&store, &format!("{ROOT}note")).is_none(),
        "a refused write must not leave a resource behind"
    );
}

#[test]
fn content_negotiation_serves_what_was_asked_for() {
    let (_m, _d, store) = pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/note",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    for (accept, expected) in [
        ("application/n-triples", "application/n-triples"),
        ("application/ld+json", "application/ld+json"),
        // Serving RDF/XML is fine; only parsing it is refused.
        ("application/rdf+xml", "application/rdf+xml"),
    ] {
        let out = ldp::read(&store, None, BASE, "/~/note", &alice(), Some(accept)).unwrap();
        assert_eq!(out.media_type, expected);
        assert!(!out.body.is_empty());
    }
}

#[test]
fn an_unauthorized_reader_cannot_tell_the_resource_exists() {
    let (_m, _d, store) = pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/secret",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let missing = ldp::read(&store, None, BASE, "/~/does-not-exist", &stranger(), None);
    let forbidden = ldp::read(&store, None, BASE, "/~/secret", &stranger(), None);

    // Identical responses, so probing cannot enumerate a pod. `Denied` for
    // both: the stranger holds no Read on either IRI, and H1 decides the
    // status from the modes alone, never from whether the target is there.
    assert!(matches!(missing, Err(LdpError::Denied)));
    assert!(matches!(forbidden, Err(LdpError::Denied)));
}

/// The third row of H1's table, and the only reason to distinguish the two
/// refusals at all: a caller who *may* read learns that there is nothing
/// there. Without this, `Denied` could quietly swallow every missing resource
/// and the owner of a pod could never tell an empty path from a broken one.
#[test]
fn a_permitted_reader_of_a_missing_resource_is_told_it_is_missing() {
    let (_m, _d, store) = pod();
    let absent = ldp::read(&store, None, BASE, "/~/does-not-exist", &alice(), None);
    assert!(
        matches!(absent, Err(LdpError::NotFound)),
        "got {:?}",
        absent.as_ref().err()
    );
}

#[test]
fn anonymous_writes_are_refused() {
    let (_m, _d, store) = pod();
    let err = ldp::put(
        &store,
        None,
        BASE,
        "/~/note",
        &anonymous(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::Denied));
}

#[test]
fn writes_cannot_escape_the_storage_root() {
    // ADR 0010's guarantee, checked at the operation rather than only the router.
    let (_m, _d, store) = pod();
    for path in ["/profile", "/oauth/token", "/actor"] {
        let err = ldp::put(
            &store,
            None,
            BASE,
            path,
            &alice(),
            NOTE,
            "text/turtle",
            ROOT,
        )
        .unwrap_err();
        assert!(
            matches!(err, LdpError::OutsideStorage),
            "{path} should be outside storage, got {err:?}"
        );
    }
}

#[test]
fn a_body_cannot_write_into_another_resources_graph() {
    // A trig body naming a different graph must not escape its own resource.
    let (_m, _d, store) = pod();
    let hostile =
        br#"<https://alice.brolly.id/~/other> { <https://a.example/s> <https://a.example/p> "x" }"#;
    ldp::put(
        &store,
        None,
        BASE,
        "/~/note",
        &alice(),
        hostile,
        "application/trig",
        ROOT,
    )
    .unwrap();

    assert!(
        meta(&store, &format!("{ROOT}other")).is_none(),
        "a PUT must only write its own named graph"
    );
    assert!(meta(&store, &format!("{ROOT}note")).is_some());
}

#[test]
fn containment_is_maintained_up_the_tree() {
    let (_m, _d, store) = pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/a/b/c",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(members(&store, &format!("{ROOT}a/b/")).contains(&format!("{ROOT}a/b/c")));
    assert!(members(&store, &format!("{ROOT}a/")).contains(&format!("{ROOT}a/b/")));
    assert!(members(&store, ROOT).contains(&format!("{ROOT}a/")));
}

#[test]
fn posting_to_a_container_mints_a_member() {
    let (_m, _d, store) = pod();
    let created = ldp::append(
        &store,
        None,
        BASE,
        "/~/",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(created.starts_with(ROOT));
    assert!(members(&store, ROOT).contains(&created));
}

#[test]
fn delete_removes_the_resource_and_its_containment() {
    let (_m, _d, store) = pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/note",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert!(meta(&store, &format!("{ROOT}note")).is_some());

    ldp::delete(&store, BASE, "/~/note", &alice(), ROOT).unwrap();
    assert!(meta(&store, &format!("{ROOT}note")).is_none());
    assert!(!members(&store, ROOT).contains(&format!("{ROOT}note")));
}

#[test]
fn a_non_empty_container_cannot_be_deleted() {
    let (_m, _d, store) = pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/a/b",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let err = ldp::delete(&store, BASE, "/~/a/", &alice(), ROOT).unwrap_err();
    assert!(
        matches!(err, LdpError::NotEmpty),
        "deleting a populated container would orphan its subtree"
    );
}

#[test]
fn append_permission_does_not_confer_replace() {
    let (_m, _d, store) = pod();

    // Bob gets Append on the root, and nothing else.
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#bob");
    grant(
        &store,
        &g,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Append")),
            t(
                &g,
                &a,
                &format!("{ACL}agent"),
                "https://bob.example/profile#me",
            ),
        ],
    );

    let bob = Subject::local(
        Uuid::new_v4(),
        "did:plc:bob".into(),
        "https://bob.example/profile#me".into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    );

    assert!(
        ldp::append(
            &store,
            None,
            BASE,
            "/~/inbox/",
            &bob,
            NOTE,
            "text/turtle",
            ROOT
        )
        .is_ok(),
        "Append should permit POST"
    );
    assert!(
        matches!(
            ldp::put(
                &store,
                None,
                BASE,
                "/~/note",
                &bob,
                NOTE,
                "text/turtle",
                ROOT
            ),
            Err(LdpError::Denied)
        ),
        "Append must not permit PUT — replacing is not adding"
    );
}

#[test]
fn public_read_works_for_anonymous_callers() {
    let (_m, _d, store) = pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/public",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let g = format!("{ROOT}public.acl");
    let a = format!("{g}#public");
    grant(
        &store,
        &g,
        &[
            t(&g, &a, &format!("{ACL}accessTo"), &format!("{ROOT}public")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}agentClass"), &format!("{FOAF}Agent")),
        ],
    );

    let out = ldp::read(&store, None, BASE, "/~/public", &anonymous(), None).unwrap();
    assert!(!out.body.is_empty());
    assert_eq!(out.granted, vec![AccessMode::Read], "public read only");
}

#[test]
fn the_storage_root_is_typed_as_a_pod_root() {
    let (_m, _d, store) = pod();
    let out = ldp::read(&store, None, BASE, "/~/", &alice(), Some("text/turtle")).unwrap();
    let body = String::from_utf8(out.body).unwrap();

    assert!(out.is_container);
    assert!(body.contains("pim/space#Storage"), "got: {body}");
    assert!(body.contains("ldp#BasicContainer"), "got: {body}");
}

// --- stage 5a: server-managed metadata ---------------------------------------

/// Every quad in one resource's own graph, through the pod.
fn own_graph(pod: &Pod, resource: &str) -> Vec<Quad> {
    pod.read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(n(resource).as_ref())),
        )
        .map(Result::unwrap)
        .collect()
}

fn put_turtle(store: &Pod, path: &str, body: &[u8]) -> Result<(), LdpError> {
    ldp::put(store, None, BASE, path, &alice(), body, "text/turtle", ROOT)
}

fn ntriples(store: &Pod, path: &str) -> String {
    let out = ldp::read(
        store,
        None,
        BASE,
        path,
        &alice(),
        Some("application/n-triples"),
    )
    .unwrap();
    String::from_utf8(out.body).unwrap()
}

#[test]
fn an_empty_document_exists() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/empty", b"").unwrap();

    assert!(
        ntriples(&store, "/~/empty").trim().is_empty(),
        "GET is 200, and empty"
    );
    assert!(matches!(
        meta(&store, &format!("{ROOT}empty")).unwrap().kind,
        Kind::RdfSource
    ));
    assert!(members(&store, ROOT).contains(&format!("{ROOT}empty")));

    // It can be deleted, so its listing can be removed too.
    ldp::delete(&store, BASE, "/~/empty", &alice(), ROOT).unwrap();
    assert!(!members(&store, ROOT).contains(&format!("{ROOT}empty")));
}

#[test]
fn an_empty_container_has_its_types_and_no_members() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/", b"").unwrap();

    let body = ntriples(&store, "/~/c/");
    assert!(body.contains("ldp#BasicContainer"), "{body}");
    assert!(body.contains("ldp#Container>"), "{body}");
    assert!(body.contains("ldp#Resource"), "{body}");
    assert!(!body.contains("ldp#contains"), "{body}");
    assert!(
        !body.contains("space#Storage"),
        "only the root is a pim:Storage: {body}"
    );
    assert!(matches!(
        meta(&store, &format!("{ROOT}c/")).unwrap().kind,
        Kind::Container
    ));
}

#[test]
fn a_container_put_with_an_extra_triple_keeps_its_members() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    put_turtle(&store, "/~/c/", br#"<> <https://example.org/title> "C" ."#).unwrap();

    assert_eq!(
        members(&store, &format!("{ROOT}c/")),
        vec![format!("{ROOT}c/m")]
    );
    let body = ntriples(&store, "/~/c/");
    assert!(body.contains("\"C\""), "{body}");
    assert!(body.contains(&format!("<{ROOT}c/m>")), "{body}");
}

#[test]
fn a_container_put_naming_a_non_member_is_a_containment_change() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let body = format!(
        "<> <{}> <{ROOT}c/m>, <{ROOT}c/ghost> .",
        vocab::LDP_CONTAINS
    );

    let err = put_turtle(&store, "/~/c/", body.as_bytes()).unwrap_err();
    assert!(matches!(err, LdpError::ContainmentChange), "got {err:?}");
    assert_eq!(
        members(&store, &format!("{ROOT}c/")),
        vec![format!("{ROOT}c/m")]
    );
    assert!(
        meta(&store, &format!("{ROOT}c/ghost")).is_none(),
        "a member was invented"
    );
}

#[test]
fn a_container_put_echoing_its_listing_succeeds() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let got = ldp::read(&store, None, BASE, "/~/c/", &alice(), Some("text/turtle")).unwrap();

    put_turtle(&store, "/~/c/", &got.body).unwrap();

    assert_eq!(
        members(&store, &format!("{ROOT}c/")),
        vec![format!("{ROOT}c/m")]
    );
    let own = own_graph(&store, &format!("{ROOT}c/"));
    assert!(
        own.is_empty(),
        "the echoed types and containment are the server's, not stored: {own:?}"
    );
}

#[test]
fn a_container_put_with_a_non_rdf_body_is_not_rdf() {
    let (_m, _d, store) = pod();
    let err = ldp::put(
        &store,
        None,
        BASE,
        "/~/c/",
        &alice(),
        b"\x89PNG",
        "image/png",
        ROOT,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::NotRdf), "got {err:?}");
    assert!(meta(&store, &format!("{ROOT}c/")).is_none());
}

#[test]
fn an_ordinary_document_serves_containment_and_digest_triples_as_data() {
    let (_m, _d, store) = pod();
    let digest = "ab".repeat(32);
    let body = format!(
        "<> <{}> <{ROOT}secret> ;\n   <{}> \"{digest}\" .",
        vocab::LDP_CONTAINS,
        vocab::BROLLY_BLOB_DIGEST
    );
    put_turtle(&store, "/~/doc", body.as_bytes()).unwrap();

    let served = ntriples(&store, "/~/doc");
    assert!(served.contains("ldp#contains"), "{served}");
    assert!(served.contains(&digest), "{served}");
    assert!(matches!(
        meta(&store, &format!("{ROOT}doc")).unwrap().kind,
        Kind::RdfSource
    ));
    assert!(ldp::blob_digest(&store, &format!("{ROOT}doc")).is_none());
    assert!(
        meta(&store, &format!("{ROOT}secret")).is_none(),
        "inert data made a member"
    );
    assert_eq!(members(&store, ROOT), vec![format!("{ROOT}doc")]);
}

#[test]
fn a_patch_that_creates_a_resource_lists_it() {
    let (_m, _d, store) = pod();
    let update = format!(r#"INSERT DATA {{ <{ROOT}made/new> <https://example.org/title> "x" }}"#);
    ldp::patch(
        &store,
        BASE,
        "/~/made/new",
        &alice(),
        ldp::PatchBody::SparqlUpdate(&update),
        ROOT,
    )
    .unwrap();

    assert_eq!(
        members(&store, &format!("{ROOT}made/")),
        vec![format!("{ROOT}made/new")]
    );
    assert!(members(&store, ROOT).contains(&format!("{ROOT}made/")));
    assert!(matches!(
        meta(&store, &format!("{ROOT}made/new")).unwrap().kind,
        Kind::RdfSource
    ));
}

#[test]
fn a_container_with_members_cannot_be_emptied_by_put_and_then_deleted() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();

    // Before 5a this PUT wiped the listing, and the DELETE then removed the
    // container over a live member.
    put_turtle(&store, "/~/c/", b"").unwrap();
    assert_eq!(
        members(&store, &format!("{ROOT}c/")),
        vec![format!("{ROOT}c/m")]
    );
    assert!(matches!(
        ldp::delete(&store, BASE, "/~/c/", &alice(), ROOT),
        Err(LdpError::NotEmpty)
    ));
    assert!(ldp::read(&store, None, BASE, "/~/c/m", &alice(), None).is_ok());
}

#[test]
fn the_storage_root_cannot_be_deleted() {
    let (_m, _d, store) = pod();
    assert!(matches!(
        ldp::delete(&store, BASE, "/~/", &alice(), ROOT),
        Err(LdpError::Undeletable)
    ));
    assert!(meta(&store, ROOT).is_some());
}
