//! Phase 4 exit criterion: LDP + WAC behaviour, exercised together.
//!
//! These drive the protocol layer directly rather than through HTTP, which is
//! the point of keeping it transport-free — the same operations the axum
//! handlers call are the ones under test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_authz::AccessMode;
use brolly_domain::vocab;
use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp::{self, LdpError, PatchBody};
use brolly_solid::patch::PatchError;
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
    assert!(out.description.holds(AccessMode::Write));
}

/// LDP and every Solid client branch on 201 vs 204, and the only place that
/// knows which happened is the write itself: `put_in` already reads the
/// target's metadata for its preconditions, so the answer is free. Deriving it
/// in `pod.rs` from a read before or after the write would race.
#[test]
fn a_put_says_whether_it_created_or_replaced() {
    let (_m, _d, store) = pod();
    assert_eq!(
        put_turtle(&store, "/~/note", NOTE).unwrap(),
        ldp::Written::Created
    );
    assert_eq!(
        put_turtle(&store, "/~/note", NOTE).unwrap(),
        ldp::Written::Replaced
    );

    // A container answers the same way.
    assert_eq!(
        put_turtle(&store, "/~/c/", b"").unwrap(),
        ldp::Written::Created
    );
    assert_eq!(
        put_turtle(&store, "/~/c/", b"").unwrap(),
        ldp::Written::Replaced
    );

    // An intermediate container a PUT created on the way is not the target.
    assert_eq!(
        put_turtle(&store, "/~/d/e", NOTE).unwrap(),
        ldp::Written::Created
    );
    assert_eq!(
        put_turtle(&store, "/~/d/", b"").unwrap(),
        ldp::Written::Replaced
    );
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
        None,
        ldp::RequestedKind::Auto,
    )
    .unwrap();

    assert!(created.member.starts_with(ROOT));
    assert_eq!(created.kind, Kind::RdfSource);
    assert!(members(&store, ROOT).contains(&created.member));
}

/// H1 (spec 5c): a POST's `Slug` names the minted member, and the 201's
/// `Location` — the `member` here — is the name the client can bookmark.
#[test]
fn a_slug_names_the_minted_member() {
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
        Some("hello"),
        ldp::RequestedKind::Auto,
    )
    .unwrap();
    assert_eq!(created.member, format!("{ROOT}hello"));
    assert!(members(&store, ROOT).contains(&created.member));
}

/// H1: a taken name is disambiguated `-1`, `-2`, … before any extension —
/// the contract CSS implements and `solid-client` depends on.
#[test]
fn a_colliding_slug_is_disambiguated_before_the_extension() {
    let (_m, _d, store) = pod();
    for _ in 0..3 {
        ldp::append(
            &store,
            None,
            BASE,
            "/~/",
            &alice(),
            NOTE,
            "text/turtle",
            ROOT,
            Some("note.ttl"),
            ldp::RequestedKind::Auto,
        )
        .unwrap();
    }
    let members = members(&store, ROOT);
    assert!(members.contains(&format!("{ROOT}note.ttl")));
    assert!(members.contains(&format!("{ROOT}note-1.ttl")));
    assert!(members.contains(&format!("{ROOT}note-2.ttl")));
}

/// H1: the slug is raw bytes, not a pre-encoded segment, so a `%` survives
/// as `%25` — lossless, and unambiguous where passing it through would not be.
#[test]
fn a_slug_is_percent_encoded_not_passed_through() {
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
        Some("a%20b"),
        ldp::RequestedKind::Auto,
    )
    .unwrap();
    assert_eq!(created.member, format!("{ROOT}a%2520b"));
}

/// H1: a slug that cannot be made one safe segment is refused with the rule,
/// because a silent UUID would leave the client building links to a name it
/// was never given.
#[test]
fn slugs_that_are_not_one_safe_segment_are_refused() {
    let (_m, _d, store) = pod();
    for slug in ["a/b", "a?b", "a#b", ".", "..", "note.acl", "a\u{0}b"] {
        let err = ldp::append(
            &store,
            None,
            BASE,
            "/~/",
            &alice(),
            NOTE,
            "text/turtle",
            ROOT,
            Some(slug),
            ldp::RequestedKind::Auto,
        )
        .unwrap_err();
        assert!(
            matches!(&err, LdpError::InvalidSlug(rule) if rule.contains(slug.trim())),
            "{slug:?}: got {err:?}"
        );
    }
    // Nothing was minted by any of them.
    assert!(members(&store, ROOT).is_empty());
}

/// H1: the cap is 128 bytes of UTF-8.
#[test]
fn a_slug_over_128_bytes_is_refused() {
    let (_m, _d, store) = pod();
    let slug = "x".repeat(129);
    let err = ldp::append(
        &store,
        None,
        BASE,
        "/~/",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
        Some(&slug),
        ldp::RequestedKind::Auto,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::InvalidSlug(_)), "got {err:?}");
}

/// H1: no slug, an empty one, and a whitespace one all mint a UUID, as they
/// always have.
#[test]
fn absent_and_blank_slugs_mint_a_uuid() {
    let (_m, _d, store) = pod();
    for slug in [None, Some(""), Some("   ")] {
        let created = ldp::append(
            &store,
            None,
            BASE,
            "/~/",
            &alice(),
            NOTE,
            "text/turtle",
            ROOT,
            slug,
            ldp::RequestedKind::Auto,
        )
        .unwrap();
        assert!(
            created.member.trim_start_matches(ROOT).len() == 36,
            "{}: not a UUID",
            created.member
        );
    }
}

/// H2 (spec 5c): a container-typed POST mints a container — the IRI ends in
/// `/` whatever the slug ended with — and its content goes through
/// `Content::Container`, so the containment protections apply from birth.
#[test]
fn a_container_typed_post_mints_a_container() {
    let (_m, _d, store) = pod();
    let created = ldp::append(
        &store,
        None,
        BASE,
        "/~/",
        &alice(),
        b"",
        "text/turtle",
        ROOT,
        Some("docs"),
        ldp::RequestedKind::Container,
    )
    .unwrap();
    assert_eq!(created.member, format!("{ROOT}docs/"));
    assert_eq!(created.kind, Kind::Container);
    assert!(members(&store, ROOT).contains(&created.member));
    // It is a container: it can hold members, and it takes RDF only.
    let inside = ldp::append(
        &store,
        None,
        BASE,
        "/~/docs/",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
        Some("note"),
        ldp::RequestedKind::Auto,
    )
    .unwrap();
    assert_eq!(inside.member, format!("{ROOT}docs/note"));
}

/// H2: a container-typed POST with a binary body is the existing `NotRdf`
/// 415 — containers take RDF. (The blob-carrying fixture lives in
/// `ldp_nonrdf.rs`; this one drives the refusal without bytes to store.)
#[test]
fn a_container_typed_post_takes_rdf_only() {
    let (_m, _d, store) = pod();
    let err = ldp::append(
        &store,
        None,
        BASE,
        "/~/",
        &alice(),
        b"not rdf",
        "application/octet-stream",
        ROOT,
        Some("pics"),
        ldp::RequestedKind::Container,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::NotRdf), "got {err:?}");
    assert!(members(&store, ROOT).is_empty());
}

/// H3 (spec 5c): POST is a container method. A document-shaped target is
/// `NotAPostTarget`, not an append — the insertion it used to perform is a
/// `PATCH` with `INSERT`.
#[test]
fn a_post_to_a_document_is_not_a_post_target() {
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
    let err = ldp::append(
        &store,
        None,
        BASE,
        "/~/note",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
        None,
        ldp::RequestedKind::Auto,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::NotAPostTarget), "got {err:?}");
    // And nothing was appended.
    let after = ldp::read(&store, None, BASE, "/~/note", &alice(), None).unwrap();
    let body = String::from_utf8(after.body).unwrap();
    assert_eq!(
        body.matches("First note").count(),
        1,
        "the refused POST changed the document: {body}"
    );
}

/// H3: the refusal comes after the WAC check, so a caller with no mode at all
/// still sees `Denied` — the 405 must not become an existence oracle.
#[test]
fn a_post_to_a_document_refuses_a_modeless_caller_first() {
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
    let stranger = Subject::local(
        Uuid::new_v4(),
        "did:plc:stranger".into(),
        "https://stranger.example/profile#me".into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    );
    let err = ldp::append(
        &store,
        None,
        BASE,
        "/~/note",
        &stranger,
        NOTE,
        "text/turtle",
        ROOT,
        None,
        ldp::RequestedKind::Auto,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::Denied), "got {err:?}");
}

/// H3: a POST to a missing container path keeps today's auto-creation of the
/// intermediate container — it matches `PUT`'s behaviour on missing parents.
#[test]
fn a_post_to_a_missing_container_auto_creates_it() {
    let (_m, _d, store) = pod();
    let created = ldp::append(
        &store,
        None,
        BASE,
        "/~/newdir/",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
        Some("note"),
        ldp::RequestedKind::Auto,
    )
    .unwrap();
    assert_eq!(created.member, format!("{ROOT}newdir/note"));
    assert!(meta(&store, &format!("{ROOT}newdir/")).is_some());
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
            ROOT,
            None,
            ldp::RequestedKind::Auto,
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
    assert_eq!(
        out.description.granted,
        vec![AccessMode::Read],
        "public read only"
    );
}

#[test]
fn the_storage_root_is_typed_as_a_pod_root() {
    let (_m, _d, store) = pod();
    let out = ldp::read(&store, None, BASE, "/~/", &alice(), Some("text/turtle")).unwrap();
    let body = String::from_utf8(out.body).unwrap();

    assert!(out.description.is_container());
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

fn put_turtle(store: &Pod, path: &str, body: &[u8]) -> Result<ldp::Written, LdpError> {
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

/// The listing a client reads back, with one statement altered — the shape of
/// a client that "fixed up" a timestamp, or of a stale description written
/// after someone else's edit. §4.2.1 makes it a 409, not a silent store of a
/// number the server will contradict on the next GET.
#[test]
fn a_container_put_that_changes_a_members_modified_time_is_refused() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let listing = ntriples(&store, "/~/c/");
    let own = meta(&store, &format!("{ROOT}c/m")).unwrap().modified;
    let altered = listing.replace(&own, "1999-01-01T00:00:00.000Z");
    assert_ne!(altered, listing, "setup: the listing carries the time");

    let err = put_turtle(&store, "/~/c/", altered.as_bytes()).unwrap_err();
    assert!(matches!(err, LdpError::MemberMetadata), "got {err:?}");
    assert_eq!(
        meta(&store, &format!("{ROOT}c/m")).unwrap().modified,
        own,
        "a refused PUT moved a member's modified time",
    );
    assert!(
        own_graph(&store, &format!("{ROOT}c/")).is_empty(),
        "a refused PUT stored something",
    );
}

/// The same rule for the other two predicates, so a client can't reach one of
/// them by picking a different one of §4.2.1's statements.
#[test]
fn a_container_put_that_changes_a_members_mtime_or_size_is_refused() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let member = format!("{ROOT}c/m");

    for (predicate, object) in [
        (vocab::STAT_MTIME, "0"),
        // We serve no size for an RDF source, so any value differs from ours.
        (vocab::STAT_SIZE, "4096"),
    ] {
        let body = format!("<{member}> <{predicate}> {object} .");
        let err = put_turtle(&store, "/~/c/", body.as_bytes()).unwrap_err();
        assert!(
            matches!(err, LdpError::MemberMetadata),
            "{predicate}: {err:?}"
        );
    }
}

/// The rule is per statement and by value. A client that round-trips a
/// listing through JSON-LD or a date library respells the literal; refusing
/// that would refuse every read-modify-write Inrupt's solid-client, LDO and
/// SolidOS do.
#[test]
fn a_member_statement_respelled_but_unchanged_is_still_an_echo() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let member = format!("{ROOT}c/m");
    let modified = meta(&store, &member).unwrap().modified;
    // The same instant with an explicit zero offset, and the same integer
    // with a leading `+`.
    let respelled = modified.replace('Z', "+00:00");
    let seconds = brolly_store::resources::modified_ms(&modified).unwrap() / 1000;
    let body = format!(
        "<{member}> <{}> \"{respelled}\"^^<{}> ; <{}> \"+{seconds}\"^^<{}> .",
        vocab::DCTERMS_MODIFIED,
        vocab::XSD_DATE_TIME,
        vocab::STAT_MTIME,
        vocab::XSD_INTEGER
    );

    put_turtle(&store, "/~/c/", body.as_bytes()).unwrap();
    assert!(
        own_graph(&store, &format!("{ROOT}c/")).is_empty(),
        "an echo was stored as content",
    );
}

/// `rdf:type` is not on the list, because we don't serve it: `<…/m> a
/// schema:Note` in a container's description is the client's own data, and so
/// is any other predicate on a member. A blanket "nothing about a member" rule
/// would make a container's description useless.
#[test]
fn ordinary_statements_about_a_member_are_kept() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let member = format!("{ROOT}c/m");
    let body = format!(
        "<{member}> <{}> <https://schema.org/Note> ; <http://www.w3.org/2000/01/rdf-schema#label> \"First\" .",
        vocab::RDF_TYPE
    );

    put_turtle(&store, "/~/c/", body.as_bytes()).unwrap();
    let served = ntriples(&store, "/~/c/");
    assert!(served.contains("schema.org/Note"), "{served}");
    assert!(served.contains("\"First\""), "{served}");
}

/// The race §4.2.1's rule creates, and the reason the 409 has to carry a body.
/// A member's `dcterms:modified` moves on every write to that member, not only
/// on create and delete — so a client that reads a listing, edits a member, and
/// then writes the container's own description back is refused for metadata it
/// never touched. The answer is to re-read, which the body has to say.
#[test]
fn a_description_written_after_a_member_changed_is_refused_until_a_re_read() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let stale = ntriples(&store, "/~/c/");

    // The client edits the member, then writes back the description it read
    // before the edit.
    put_turtle(
        &store,
        "/~/c/m",
        br#"<> <https://example.org/title> "Edited" ."#,
    )
    .unwrap();
    let err = put_turtle(&store, "/~/c/", stale.as_bytes()).unwrap_err();
    assert!(matches!(err, LdpError::MemberMetadata), "got {err:?}");

    // Re-reading and retrying is the resolution, and it succeeds.
    let fresh = ntriples(&store, "/~/c/");
    put_turtle(&store, "/~/c/", fresh.as_bytes()).unwrap();
}

/// §4.2.1 names PATCH as well as PUT and POST. `ldp::patch` routes a container
/// through the same `container_body`, so the rule holds for the verb a client
/// is most likely to reach for when editing one statement — and a PATCH that
/// leaves a member's metadata alone still goes through.
#[test]
fn a_patch_cannot_rewrite_a_members_modified_time() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let member = format!("{ROOT}c/m");

    let rewrite = format!(
        "INSERT DATA {{ <{member}> <{}> \"1999-01-01T00:00:00.000Z\"^^<{}> }}",
        vocab::DCTERMS_MODIFIED,
        vocab::XSD_DATE_TIME
    );
    let err = ldp::patch(
        &store,
        BASE,
        "/~/c/",
        &alice(),
        PatchBody::SparqlUpdate(&rewrite),
        ROOT,
    )
    .unwrap_err();
    assert!(
        matches!(err, PatchError::Ldp(LdpError::MemberMetadata)),
        "got {err:?}"
    );

    let label = format!(
        "INSERT DATA {{ <{member}> <http://www.w3.org/2000/01/rdf-schema#label> \"First\" }}"
    );
    ldp::patch(
        &store,
        BASE,
        "/~/c/",
        &alice(),
        PatchBody::SparqlUpdate(&label),
        ROOT,
    )
    .unwrap();
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

// --- stage 5b: describe --------------------------------------------------------

/// `OPTIONS` has to answer "may I create here?", which means describing an
/// IRI with nothing behind it. A `describe` that refused like `read` does
/// would make that question unanswerable, and H5's `Accept-Put` is the answer.
#[test]
fn describing_an_absent_target_reports_what_a_creation_could_do() {
    let (_m, _d, store) = pod();

    let d = ldp::describe(&store, BASE, "/~/not-yet", &alice()).unwrap();
    assert!(!d.exists(), "nothing has been written there");
    assert_eq!(d.kind(), None);
    assert!(d.holds(AccessMode::Write), "Alice may create it");
}

/// The kind, the version and the modified time all come from one snapshot, so
/// a header set built from them can't describe a state the body never had.
#[test]
fn a_description_reports_the_kind_and_the_validators_of_what_is_there() {
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

    let note = ldp::describe(&store, BASE, "/~/note", &alice()).unwrap();
    assert!(note.exists());
    assert_eq!(note.kind(), Some(Kind::RdfSource));
    assert!(!note.is_container());
    let recorded = meta(&store, &format!("{ROOT}note")).unwrap();
    let described = note.meta.expect("the resource exists");
    assert_eq!(described.version, recorded.version);
    assert_eq!(described.modified, recorded.modified);

    let root = ldp::describe(&store, BASE, "/~/", &alice()).unwrap();
    assert_eq!(root.kind(), Some(Kind::Container));
    assert!(root.is_container(), "the storage root is a container");

    let acl = ldp::describe(&store, BASE, "/~/.acl", &alice()).unwrap();
    assert_eq!(
        acl.kind(),
        Some(Kind::Auxiliary),
        "an ACL is not an RDF source"
    );
}

/// H9: `WAC-Allow`'s `public=`. A share UI has to show whether the thing it is
/// looking at is world-readable, and the probe has to run against the same ACL
/// as `granted` — a second pass in `pod.rs` would run after the snapshot
/// closed and could report a different pod.
#[test]
fn a_description_says_what_the_public_may_do_as_well_as_the_caller() {
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
    ldp::put(
        &store,
        None,
        BASE,
        "/~/private",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let g = format!("{ROOT}public.acl");
    let everyone = format!("{g}#everyone");
    let owner = format!("{g}#owner");
    grant(
        &store,
        &g,
        &[
            t(
                &g,
                &everyone,
                &format!("{ACL}accessTo"),
                &format!("{ROOT}public"),
            ),
            t(&g, &everyone, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(
                &g,
                &everyone,
                &format!("{ACL}agentClass"),
                &format!("{FOAF}Agent"),
            ),
            t(
                &g,
                &owner,
                &format!("{ACL}accessTo"),
                &format!("{ROOT}public"),
            ),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(
                &g,
                &owner,
                &format!("{ACL}agent"),
                "https://alice.brolly.id/profile#me",
            ),
        ],
    );

    let public = ldp::describe(&store, BASE, "/~/public", &alice()).unwrap();
    assert_eq!(public.public, vec![AccessMode::Read], "world-readable");
    assert!(
        public.holds(AccessMode::Write),
        "and Alice can still edit it"
    );

    let private = ldp::describe(&store, BASE, "/~/private", &alice()).unwrap();
    assert!(private.public.is_empty(), "nothing is granted to everyone");
    assert!(private.holds(AccessMode::Write));
}

/// `describe` reports; it does not refuse. The gate is H4's, in
/// `pod::options`, which answers 401 or 403 to a caller holding no mode at all
/// — `options_refuses_a_caller_who_holds_no_mode_at_all` in
/// `server/tests/pod_http.rs` is what keeps this off the wire. Refusing here
/// instead would collapse "you may create here" and "this already exists" into
/// one answer, and H4 needs both.
#[test]
fn a_description_is_a_report_and_not_a_decision() {
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

    let d = ldp::describe(&store, BASE, "/~/secret", &stranger()).unwrap();
    assert!(d.granted.is_empty(), "the stranger holds nothing");
    assert!(d.public.is_empty());
    // Whereas `read` refuses outright.
    assert!(ldp::read(&store, None, BASE, "/~/secret", &stranger(), None).is_err());
}

/// `read` is built on `describe`, so `GET` and `OPTIONS` cannot disagree about
/// what a caller may do. The failure this guards: two code paths computing
/// modes, and a client drawing an edit affordance from the one that is wrong.
#[test]
fn a_read_carries_the_description_describe_would_have_given() {
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

    let out = ldp::read(&store, None, BASE, "/~/note", &alice(), None).unwrap();
    let described = ldp::describe(&store, BASE, "/~/note", &alice()).unwrap();
    assert_eq!(out.description.granted, described.granted);
    assert_eq!(out.description.public, described.public);
    assert_eq!(out.description.kind(), described.kind());
    assert_eq!(out.version, described.meta.expect("it exists").version);
}
