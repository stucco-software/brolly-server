//! Phase 1 exit criterion: no stored quad may use a non-canonical namespace.
//!
//! The predecessor stored whichever AS2 spelling the sender used, so five
//! reader modules had to match both `http://…/activitystreams#` and the `https`
//! form — and a production bug shipped when one of them matched only one
//! (`fix(relationships): find Follow/Like receipts written in the https AS2
//! namespace`). Normalizing at a single choke point is only worth anything if
//! nothing can bypass it, so this asserts the invariant over a fixture set that
//! deliberately includes the wrong spellings.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_domain::iri::{canonicalize_quad, iris_in, is_canonical};
use brolly_domain::vocab;
use oxrdf::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};

fn node(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// Quads as they arrive from the wire — every one using a non-canonical form
/// that some real implementation actually emits.
fn hostile_fixture() -> Vec<Quad> {
    let graph = GraphName::NamedNode(node("https://alice.brolly.id/inbox"));
    vec![
        // Mastodon emits the http spelling of AS2.
        Quad::new(
            NamedOrBlankNode::NamedNode(node("https://alice.brolly.id/notes/1")),
            node("http://www.w3.org/ns/activitystreams#content"),
            Term::NamedNode(node("http://www.w3.org/ns/activitystreams#Public")),
            graph.clone(),
        ),
        // Actor documents carry the v1 security context.
        Quad::new(
            NamedOrBlankNode::NamedNode(node("https://alice.brolly.id/actor")),
            node("https://w3id.org/security/v1#publicKey"),
            Term::NamedNode(node("https://alice.brolly.id/actor#main-key")),
            graph.clone(),
        ),
        // …and some emit v2.
        Quad::new(
            NamedOrBlankNode::NamedNode(node("https://alice.brolly.id/actor")),
            node("https://w3id.org/security/v2#owner"),
            Term::NamedNode(node("https://alice.brolly.id/actor")),
            graph.clone(),
        ),
        // Mastodon's extension namespace, https variant.
        Quad::new(
            NamedOrBlankNode::NamedNode(node("https://alice.brolly.id/actor")),
            node("https://joinmastodon.org/ns#discoverable"),
            Term::NamedNode(node("http://www.w3.org/ns/activitystreams#Person")),
            graph,
        ),
    ]
}

#[test]
fn the_fixture_is_actually_hostile() {
    // Guard the guard: if canonicalization silently became a no-op, this test
    // would still pass below unless we assert the input was non-canonical.
    let offenders: Vec<_> = hostile_fixture()
        .iter()
        .flat_map(|q| {
            iris_in(q)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|iri| !is_canonical(iri))
        .collect();
    assert!(
        offenders.len() >= 5,
        "fixture should contain several non-canonical IRIs, found {offenders:?}"
    );
}

#[test]
fn no_quad_survives_storage_with_a_non_canonical_namespace() {
    let stored: Vec<_> = hostile_fixture().iter().map(canonicalize_quad).collect();

    let offenders: Vec<_> = stored
        .iter()
        .flat_map(|q| {
            iris_in(q)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|iri| !is_canonical(iri))
        .collect();

    assert!(
        offenders.is_empty(),
        "non-canonical IRIs reached storage: {offenders:?}"
    );
}

#[test]
fn as2_terms_collapse_to_one_spelling() {
    let stored: Vec<_> = hostile_fixture().iter().map(canonicalize_quad).collect();
    let as2: Vec<_> = stored
        .iter()
        .flat_map(|q| {
            iris_in(q)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|iri| iri.contains("activitystreams"))
        .collect();

    assert!(!as2.is_empty());
    for iri in &as2 {
        assert!(
            iri.starts_with(vocab::AS2),
            "{iri} is not the canonical AS2 namespace"
        );
    }
}
