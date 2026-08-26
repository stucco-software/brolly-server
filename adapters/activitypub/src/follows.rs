//! Who follows whom.
//!
//! Both sides are recorded, in the pod of whoever the fact is about: a
//! member's followers live in *their* pod, and who they follow lives there
//! too. Delivery resolves recipients by reading the author's own followers,
//! which keeps fan-out a single-store read — the same property the inbox gives
//! the timeline.
//!
//! `as:followers` and `as:following` rather than anything invented: they are
//! the predicates the actor document already advertises as collections, so a
//! Solid client reading the pod sees the same graph a fediverse client sees
//! through the collection endpoints.

use brolly_store::Store;
use brolly_store::write::{WriteError, insert_quads};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};

pub const AS_FOLLOWERS: &str = "https://www.w3.org/ns/activitystreams#followers";
pub const AS_FOLLOWING: &str = "https://www.w3.org/ns/activitystreams#following";

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// The graph a member's social relationships live in.
///
/// Derived from the actor IRI rather than being a fixed name, so two actors'
/// relationships cannot end up in one graph if a pod ever holds both.
fn graph_for(actor: &str) -> NamedNode {
    iri(&format!("{actor}#social"))
}

/// Record `follower` as following `followee`, in `store`.
///
/// Idempotent — a Follow re-sent after a missed Accept must not produce a
/// duplicate follower.
pub fn record(store: &Store, follower: &str, followee: &str) -> Result<(), WriteError> {
    let graph = graph_for(followee);
    insert_quads(
        store,
        &[Quad::new(
            NamedOrBlankNode::NamedNode(iri(followee)),
            iri(AS_FOLLOWERS),
            Term::NamedNode(iri(follower)),
            GraphName::NamedNode(graph),
        )],
    )?;
    Ok(())
}

/// Record that `follower` follows `followee`, from the follower's side.
pub fn record_following(store: &Store, follower: &str, followee: &str) -> Result<(), WriteError> {
    let graph = graph_for(follower);
    insert_quads(
        store,
        &[Quad::new(
            NamedOrBlankNode::NamedNode(iri(follower)),
            iri(AS_FOLLOWING),
            Term::NamedNode(iri(followee)),
            GraphName::NamedNode(graph),
        )],
    )?;
    Ok(())
}

/// Everyone following `actor`. The recipient list for a post.
pub fn followers(store: &Store, actor: &str) -> Vec<String> {
    objects(store, actor, AS_FOLLOWERS)
}

/// Everyone `actor` follows.
pub fn following(store: &Store, actor: &str) -> Vec<String> {
    objects(store, actor, AS_FOLLOWING)
}

fn objects(store: &Store, actor: &str, predicate: &str) -> Vec<String> {
    let graph = graph_for(actor);
    let mut out: Vec<String> = store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(iri(actor))).into()),
            Some(iri(predicate).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(graph.as_ref())),
        )
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            Term::NamedNode(n) => Some(n.as_str().to_string()),
            _ => None,
        })
        .collect();
    // Stable order, so a recipient list is reproducible and a test can assert
    // on it without sorting at every call site.
    out.sort();
    out.dedup();
    out
}

/// Undo a follow.
pub fn remove(
    store: &Store,
    follower: &str,
    followee: &str,
) -> Result<(), oxigraph::store::StorageError> {
    store.remove(&Quad::new(
        NamedOrBlankNode::NamedNode(iri(followee)),
        iri(AS_FOLLOWERS),
        Term::NamedNode(iri(follower)),
        GraphName::NamedNode(graph_for(followee)),
    ))?;
    store.remove(&Quad::new(
        NamedOrBlankNode::NamedNode(iri(follower)),
        iri(AS_FOLLOWING),
        Term::NamedNode(iri(followee)),
        GraphName::NamedNode(graph_for(follower)),
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "https://alice.brolly.test/actor";
    const BOB: &str = "https://bob.brolly.test/actor";

    fn store() -> (tempfile::TempDir, std::sync::Arc<Store>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).expect("stores");
        let store = manager.pod(uuid::Uuid::new_v4()).expect("pod");
        (dir, store)
    }

    #[test]
    fn a_follower_is_recorded_and_listed() {
        let (_dir, store) = store();
        record(&store, BOB, ALICE).expect("record");
        assert_eq!(followers(&store, ALICE), vec![BOB.to_string()]);
    }

    #[test]
    fn recording_the_same_follow_twice_yields_one_follower() {
        // A Follow re-sent after a missed Accept is normal.
        let (_dir, store) = store();
        record(&store, BOB, ALICE).expect("first");
        record(&store, BOB, ALICE).expect("second");
        assert_eq!(followers(&store, ALICE).len(), 1);
    }

    #[test]
    fn the_two_directions_are_independent() {
        let (_dir, store) = store();
        record(&store, BOB, ALICE).expect("record");

        assert_eq!(followers(&store, ALICE), vec![BOB.to_string()]);
        assert!(
            followers(&store, BOB).is_empty(),
            "following someone must not make them follow you"
        );
        assert!(following(&store, ALICE).is_empty());
    }

    #[test]
    fn an_unfollow_removes_both_sides() {
        let (_dir, store) = store();
        record(&store, BOB, ALICE).expect("record");
        record_following(&store, BOB, ALICE).expect("record");

        remove(&store, BOB, ALICE).expect("remove");

        assert!(followers(&store, ALICE).is_empty());
        assert!(following(&store, BOB).is_empty());
    }

    #[test]
    fn two_actors_relationships_stay_separate() {
        // Both can live in one store during tests, and in principle a pod could
        // hold more than one actor's graph.
        let (_dir, store) = store();
        record(&store, BOB, ALICE).expect("record");
        record(&store, ALICE, BOB).expect("record");

        assert_eq!(followers(&store, ALICE), vec![BOB.to_string()]);
        assert_eq!(followers(&store, BOB), vec![ALICE.to_string()]);
    }
}
