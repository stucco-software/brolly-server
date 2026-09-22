//! Phase 4 exit criterion: LDP + WAC behaviour, exercised together.
//!
//! These drive the protocol layer directly rather than through HTTP, which is
//! the point of keeping it transport-free — the same operations the axum
//! handlers call are the ones under test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_authz::AccessMode;
use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp::{self, LdpError};
use brolly_solid::storage;
use brolly_store::StoreManager;
use brolly_store::resources::Pod;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.id";
const ROOT: &str = "https://alice.brolly.id/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const FOAF: &str = "http://xmlns.com/foaf/0.1/";

/// Setup straight into the store, bypassing `Pod::write` (`test-fixtures`),
/// so it doesn't depend on the code under test.
fn seed(target: &Pod, quads: &[Quad]) {
    let store = target.raw_store();
    for quad in quads {
        store.insert(quad).unwrap();
    }
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

    store
        .write(|w| storage::init_storage_root(w, ROOT))
        .unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    let quads = vec![
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
    ];
    seed(&store, &quads);
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
        !storage::exists(&store.read_store(), &format!("{ROOT}note")),
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

    // Identical responses, so probing cannot enumerate a pod.
    assert!(matches!(missing, Err(LdpError::NotFound)));
    assert!(matches!(forbidden, Err(LdpError::NotFound)));
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
    assert!(matches!(err, LdpError::Forbidden));
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
        !storage::exists(&store.read_store(), &format!("{ROOT}other")),
        "a PUT must only write its own named graph"
    );
    assert!(storage::exists(&store.read_store(), &format!("{ROOT}note")));
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

    assert!(
        storage::members(&store.read_store(), &format!("{ROOT}a/b/"))
            .contains(&format!("{ROOT}a/b/c"))
    );
    assert!(
        storage::members(&store.read_store(), &format!("{ROOT}a/"))
            .contains(&format!("{ROOT}a/b/"))
    );
    assert!(storage::members(&store.read_store(), ROOT).contains(&format!("{ROOT}a/")));
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
    assert!(storage::members(&store.read_store(), ROOT).contains(&created));
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
    assert!(storage::exists(&store.read_store(), &format!("{ROOT}note")));

    ldp::delete(&store, None, BASE, "/~/note", &alice(), ROOT).unwrap();
    assert!(!storage::exists(
        &store.read_store(),
        &format!("{ROOT}note")
    ));
    assert!(!storage::members(&store.read_store(), ROOT).contains(&format!("{ROOT}note")));
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

    let err = ldp::delete(&store, None, BASE, "/~/a/", &alice(), ROOT).unwrap_err();
    assert!(
        matches!(err, LdpError::Forbidden),
        "deleting a populated container would orphan its subtree"
    );
}

#[test]
fn append_permission_does_not_confer_replace() {
    let (_m, _d, store) = pod();

    // Bob gets Append on the root, and nothing else.
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#bob");
    seed(
        &store,
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
            Err(LdpError::Forbidden)
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
    seed(
        &store,
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
