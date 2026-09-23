//! N3 Patch and SPARQL Update, through one solver.
//!
//! The predecessor implemented these twice — SPARQL delegated to the engine,
//! N3 Patch got a hand-rolled parser and pattern solver. These tests run the
//! same semantics through both entry points and assert they agree.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_solid::patch::{self, PatchError};
use brolly_store::StoreManager;
use brolly_store::resources::{Content, Pod, PodRead};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const RESOURCE: &str = "https://alice.brolly.id/~/note";
const ROOT: &str = "https://alice.brolly.id/~/";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();

    let original = [Quad::new(
        NamedOrBlankNode::NamedNode(n(RESOURCE)),
        n("https://example.org/title"),
        Term::Literal(oxigraph::model::Literal::new_simple_literal("Original")),
        GraphName::NamedNode(n(RESOURCE)),
    )];
    store
        .write(|w| {
            w.create_root(ROOT)?;
            w.put(RESOURCE, Content::Rdf(&original))?;
            Ok(())
        })
        .unwrap();
    (mgr, dir, store)
}

/// Apply an N3 Patch in one write, as `pod.rs` does.
fn n3(store: &Pod, body: &[u8]) -> Result<(), PatchError> {
    store
        .write(|w| Ok(patch::apply_n3_patch(w, RESOURCE, body)))
        .map_err(|e| PatchError::Store(e.to_string()))
        .flatten()
}

/// Apply a SPARQL Update in one write, as `pod.rs` does.
fn sparql(store: &Pod, update: &str) -> Result<(), PatchError> {
    store
        .write(|w| Ok(patch::apply_sparql_update(w, RESOURCE, update)))
        .map_err(|e| PatchError::Store(e.to_string()))
        .flatten()
}

fn triples(store: &Pod) -> Vec<String> {
    store
        .read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(n(RESOURCE).as_ref())),
        )
        .filter_map(Result::ok)
        .map(|q| format!("{} {} {}", q.subject, q.predicate, q.object))
        .collect()
}

const N3_INSERT: &[u8] = br#"
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:patch a solid:InsertDeletePatch ;
  solid:inserts { <https://alice.brolly.id/~/note> <https://example.org/tag> "rdf" . } .
"#;

#[test]
fn an_n3_patch_inserts() {
    let (_m, _d, store) = pod();
    n3(&store, N3_INSERT).unwrap();
    assert!(triples(&store).iter().any(|t| t.contains("rdf")));
}

#[test]
fn an_n3_patch_deletes_what_exists() {
    let (_m, _d, store) = pod();
    let body = br#"
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:patch a solid:InsertDeletePatch ;
  solid:deletes { <https://alice.brolly.id/~/note> <https://example.org/title> "Original" . } .
"#;
    n3(&store, body).unwrap();
    assert!(!triples(&store).iter().any(|t| t.contains("Original")));
}

#[test]
fn deleting_an_absent_triple_is_a_precondition_failure() {
    // Solid requires this to fail rather than silently no-op. Plain SPARQL
    // DELETE would succeed and report nothing, which is why the precondition
    // is checked separately.
    let (_m, _d, store) = pod();
    let body = br#"
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:patch a solid:InsertDeletePatch ;
  solid:deletes { <https://alice.brolly.id/~/note> <https://example.org/title> "Never here" . } .
"#;
    let err = n3(&store, body).unwrap_err();
    assert!(matches!(err, PatchError::Precondition(_)), "got {err:?}");
    assert!(
        triples(&store).iter().any(|t| t.contains("Original")),
        "a failed patch must not have changed anything"
    );
}

#[test]
fn a_where_clause_that_matches_nothing_fails() {
    let (_m, _d, store) = pod();
    let body = br#"
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:patch a solid:InsertDeletePatch ;
  solid:where   { <https://alice.brolly.id/~/note> <https://example.org/absent> ?v . } ;
  solid:inserts { <https://alice.brolly.id/~/note> <https://example.org/tag> "x" . } .
"#;
    let err = n3(&store, body).unwrap_err();
    assert!(matches!(err, PatchError::Precondition(_)), "got {err:?}");
    assert!(!triples(&store).iter().any(|t| t.contains("tag")));
}

#[test]
fn a_where_clause_binds_variables_for_delete_and_insert() {
    let (_m, _d, store) = pod();
    let body = br#"
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
_:patch a solid:InsertDeletePatch ;
  solid:where   { <https://alice.brolly.id/~/note> <https://example.org/title> ?t . } ;
  solid:deletes { <https://alice.brolly.id/~/note> <https://example.org/title> ?t . } ;
  solid:inserts { <https://alice.brolly.id/~/note> <https://example.org/title> "Revised" . } .
"#;
    n3(&store, body).unwrap();

    let out = triples(&store);
    assert!(out.iter().any(|t| t.contains("Revised")));
    assert!(
        !out.iter().any(|t| t.contains("Original")),
        "the bound triple was removed"
    );
}

#[test]
fn both_patch_formats_produce_the_same_result() {
    // The whole point of one solver: the same edit expressed either way must
    // land identically.
    let (_m1, _d1, a) = pod();
    let (_m2, _d2, b) = pod();

    n3(&a, N3_INSERT).unwrap();
    sparql(
        &b,
        r#"INSERT DATA { <https://alice.brolly.id/~/note> <https://example.org/tag> "rdf" }"#,
    )
    .unwrap();

    let mut left = triples(&a);
    let mut right = triples(&b);
    left.sort();
    right.sort();
    assert_eq!(left, right);
}

#[test]
fn a_sparql_update_naming_a_graph_is_refused() {
    let (_m, _d, store) = pod();
    let err = sparql(
        &store,
        "INSERT DATA { GRAPH <https://alice.brolly.id/~/other> { <a:b> <a:c> <a:d> } }",
    )
    .unwrap_err();
    assert!(matches!(err, PatchError::EscapesGraph));
}

#[test]
fn a_patch_cannot_reintroduce_a_non_canonical_namespace() {
    // A PATCH writes through the SPARQL engine, bypassing the store's
    // canonicalization choke point. Without the re-normalization pass a client
    // could reintroduce the http:// AS2 spelling this way and the invariant
    // would quietly stop holding.
    let (_m, _d, store) = pod();
    sparql(
        &store,
        r#"INSERT DATA { <https://alice.brolly.id/~/note>
             <http://www.w3.org/ns/activitystreams#content> "hi" }"#,
    )
    .unwrap();

    for triple in triples(&store) {
        assert!(
            !triple.contains("http://www.w3.org/ns/activitystreams#"),
            "non-canonical namespace survived a PATCH: {triple}"
        );
    }
    assert!(
        triples(&store)
            .iter()
            .any(|t| t.contains("https://www.w3.org/ns/activitystreams#content")),
        "the triple should still be there, canonicalized"
    );
}

#[test]
fn a_body_that_is_not_a_patch_is_refused() {
    let (_m, _d, store) = pod();
    let err = n3(&store, b"<a:b> <a:c> <a:d> .").unwrap_err();
    assert!(matches!(err, PatchError::NotAPatch(_)), "got {err:?}");
}

#[test]
fn a_malformed_body_is_an_error_not_a_panic() {
    let (_m, _d, store) = pod();
    let err = n3(&store, b"{{{ not n3").unwrap_err();
    assert!(matches!(err, PatchError::Malformed(_)), "got {err:?}");
}
