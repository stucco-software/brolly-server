//! N3 Patch and SPARQL Update, through one solver.
//!
//! The predecessor implemented these twice — SPARQL delegated to the engine,
//! N3 Patch got a hand-rolled parser and pattern solver. These tests run the
//! same semantics through both entry points and assert they agree.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_solid::ldp::LdpError;
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

/// Apply an N3 Patch to `resource` — the container tests' target.
fn n3_on(store: &Pod, resource: &str, body: &[u8]) -> Result<(), PatchError> {
    store
        .write(|w| Ok(patch::apply_n3_patch(w, resource, body)))
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

/// A container at `/~/c/` holding one member `/~/c/m`, so a patch aimed at
/// the container has members to see.
fn container() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();
    let container = format!("{ROOT}c/");
    let member = format!("{ROOT}c/m");
    let original = [Quad::new(
        NamedOrBlankNode::NamedNode(n(&member)),
        n("https://example.org/title"),
        Term::Literal(oxigraph::model::Literal::new_simple_literal("Member")),
        GraphName::NamedNode(n(&member)),
    )];
    store
        .write(|w| {
            w.create_root(ROOT)?;
            w.put(&container, Content::Container(&[]))?;
            w.put(&member, Content::Rdf(&original))?;
            Ok(())
        })
        .unwrap();
    (mgr, dir, store)
}

/// Apply a SPARQL Update to `resource`, as the container tests do.
fn n3_sparql_on(store: &Pod, resource: &str, update: &str) -> Result<(), PatchError> {
    store
        .write(|w| Ok(patch::apply_sparql_update(w, resource, update)))
        .map_err(|e| PatchError::Store(e.to_string()))
        .flatten()
}

fn triples(store: &Pod) -> Vec<String> {
    ntriples_of(store, RESOURCE)
}

fn ntriples_of(store: &Pod, resource: &str) -> Vec<String> {
    store
        .read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(n(resource).as_ref())),
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

/// H7: `LOAD` is refused — a deny-list is how it got missed. An allow-list of
/// update forms, read from the parse, is the rule.
#[test]
fn a_load_is_refused() {
    let (_m, _d, store) = pod();
    let err = sparql(&store, "LOAD <https://example.com/evil>").unwrap_err();
    assert!(matches!(err, PatchError::EscapesGraph), "got {err:?}");
    assert!(
        triples(&store).iter().any(|t| t.contains("Original")),
        "a refused patch must not have changed anything"
    );
}

/// H7: `CLEAR`, `DROP` and `CREATE` are refused with the same 403 mapping —
/// they are destructive or graph-addressing in ways the patch path does not
/// model.
#[test]
fn destructive_updates_are_refused() {
    let (_m, _d, store) = pod();
    for update in ["CLEAR DEFAULT", "DROP DEFAULT", "CREATE GRAPH <a:g>"] {
        let err = sparql(&store, update).unwrap_err();
        assert!(
            matches!(err, PatchError::EscapesGraph),
            "{update}: got {err:?}"
        );
    }
    assert!(
        triples(&store).iter().any(|t| t.contains("Original")),
        "a refused patch must not have changed anything"
    );
}

/// H7: a literal containing "with" is not a `WITH` clause. The substring
/// matcher's false positive, retired by reading the parse.
#[test]
fn a_literal_containing_with_is_not_a_with_clause() {
    let (_m, _d, store) = pod();
    sparql(
        &store,
        r#"INSERT DATA { <https://alice.brolly.id/~/note> <https://example.org/tag> "with or without" }"#,
    )
    .unwrap();
    assert!(
        triples(&store)
            .iter()
            .any(|t| t.contains("with or without"))
    );
}

/// H6: a container's `solid:where` sees `ldp:contains`, and the member's
/// served metadata — everything a `GET` serves, through the same one call —
/// and can still only add what the write-back rules allow.
#[test]
fn a_containers_where_sees_its_members() {
    let (_m, _d, store) = container();
    let container = format!("{ROOT}c/");
    let member = format!("{ROOT}c/m");

    let body = format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
         @prefix ldp: <http://www.w3.org/ns/ldp#> .\n\
         _:p a solid:InsertDeletePatch ;\n\
           solid:where {{ <{container}> ldp:contains ?member . \
                         ?member <http://purl.org/dc/terms/modified> ?modified . }} ;\n\
           solid:inserts {{ <{container}> <https://example.org/first-seen> ?member . }} ."
    );
    n3_on(&store, &container, body.as_bytes()).unwrap();

    let out = ntriples_of(&store, &container);
    assert!(
        out.contains(&format!(
            "<{container}> <https://example.org/first-seen> <{member}>"
        )),
        "{out:?}"
    );

    // A where that names a member that isn't there does not bind, and a patch
    // that does not apply is not reported as applied.
    let absent = format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n\
         @prefix ldp: <http://www.w3.org/ns/ldp#> .\n\
         _:p a solid:InsertDeletePatch ;\n\
           solid:where {{ ?member <https://example.org/title> \"Absent\" . }} ;\n\
           solid:inserts {{ <{container}> <https://example.org/tag> \"x\" . }} ."
    );
    let err = n3_on(&store, &container, absent.as_bytes()).unwrap_err();
    assert!(matches!(err, PatchError::Precondition(_)), "got {err:?}");
}

/// H6's other half: the patch can *read* the members and still cannot
/// *rewrite* them — the write-back goes through the same `container_body` a
/// PUT does, so a containment change is a 409 and a metadata rewrite a
/// refusal, whatever the `where` clause matched.
#[test]
fn a_containers_patch_still_cannot_rewrite_its_members() {
    let (_m, _d, store) = container();
    let container = format!("{ROOT}c/");
    let member = format!("{ROOT}c/m");

    // A containment *change* — naming a member that isn't one — is the 409 a
    // PUT of the same body would answer. Deleting the served statements
    // outright is not a change, the same way a PUT carrying none is not:
    // membership is left alone either way.
    let fictitious = format!(
        "INSERT DATA {{ <{container}> <http://www.w3.org/ns/ldp#contains> <{ROOT}c/fictitious> }}"
    );
    let err = n3_sparql_on(&store, &container, &fictitious).unwrap_err();
    assert!(
        matches!(err, PatchError::Ldp(LdpError::ContainmentChange)),
        "got {err:?}"
    );

    let rewrite = format!(
        "INSERT DATA {{ <{member}> <http://purl.org/dc/terms/modified> \
                       \"1999-01-01T00:00:00.000Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> }}"
    );
    let err = n3_sparql_on(&store, &container, &rewrite).unwrap_err();
    assert!(
        matches!(err, PatchError::Ldp(LdpError::MemberMetadata)),
        "got {err:?}"
    );

    // Membership is untouched by both. Containment lives in metadata, not
    // the content graph, so this is the listing's own question.
    let mut listing = store.write(|w| w.members(&container)).unwrap();
    listing.sort();
    assert_eq!(listing, vec![member.clone()], "membership survived both");
}
