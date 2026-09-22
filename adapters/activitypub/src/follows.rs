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
//!
//! `#social` is protocol state outside the storage root, so it is written with
//! `PodWrite`'s outside-root methods.

use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
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
/// Ours: AS2 has no term for a follow that has been asked for and not yet
/// granted. `as:Follow` is the activity, not the pending state.
const PENDING: &str = "https://brolly.id/ns#pendingFollower";

fn graph_for(actor: &str) -> NamedNode {
    iri(&format!("{actor}#social"))
}

/// Record `follower` as following `followee`, in `store`.
///
/// Idempotent — a Follow re-sent after a missed Accept must not produce a
/// duplicate follower.
pub fn record(w: &mut PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError> {
    let graph = graph_for(followee);
    w.insert(&[Quad::new(
        NamedOrBlankNode::NamedNode(iri(followee)),
        iri(AS_FOLLOWERS),
        Term::NamedNode(iri(follower)),
        GraphName::NamedNode(graph),
    )])
}

/// Record that `follower` follows `followee`, from the follower's side.
pub fn record_following(
    w: &mut PodWrite<'_>,
    follower: &str,
    followee: &str,
) -> Result<(), StoreError> {
    let graph = graph_for(follower);
    w.insert(&[Quad::new(
        NamedOrBlankNode::NamedNode(iri(follower)),
        iri(AS_FOLLOWING),
        Term::NamedNode(iri(followee)),
        GraphName::NamedNode(graph),
    )])
}

/// A follow waiting for its subject to decide.
///
/// A locked account's Follow lands here instead of in `followers`, which is the
/// whole of what "locked" means. The predecessor accepted the flag and then
/// recorded the follow unconditionally, so locking an account did nothing —
/// and did nothing *invisibly*, since the profile still showed the lock.
pub fn record_request(
    w: &mut PodWrite<'_>,
    follower: &str,
    followee: &str,
) -> Result<(), StoreError> {
    let graph = graph_for(followee);
    w.insert(&[Quad::new(
        NamedOrBlankNode::NamedNode(iri(followee)),
        iri(PENDING),
        Term::NamedNode(iri(follower)),
        GraphName::NamedNode(graph),
    )])
}

/// Everyone waiting on `actor` to approve them.
pub fn pending(store: &impl PodRead, actor: &str) -> Vec<String> {
    objects(store, actor, PENDING)
}

/// Approve a pending follow: it stops being pending and becomes a follow.
///
/// Both halves in one call, because a request left pending *and* followed shows
/// up twice in the UI, and one that is neither has silently vanished.
pub fn approve(w: &mut PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError> {
    drop_request(w, follower, followee)?;
    record(w, follower, followee)
}

/// Refuse a pending follow. The follower is not recorded.
pub fn reject(w: &mut PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError> {
    drop_request(w, follower, followee)
}

fn drop_request(w: &mut PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError> {
    let graph = graph_for(followee);
    w.remove_quads(&[Quad::new(
        NamedOrBlankNode::NamedNode(iri(followee)),
        iri(PENDING),
        Term::NamedNode(iri(follower)),
        GraphName::NamedNode(graph),
    )])
}

/// Everyone following `actor`. The recipient list for a post.
pub fn followers(store: &impl PodRead, actor: &str) -> Vec<String> {
    objects(store, actor, AS_FOLLOWERS)
}

/// Everyone `actor` follows.
pub fn following(store: &impl PodRead, actor: &str) -> Vec<String> {
    objects(store, actor, AS_FOLLOWING)
}

fn objects(store: &impl PodRead, actor: &str, predicate: &str) -> Vec<String> {
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
pub fn remove(w: &mut PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError> {
    w.remove_quads(&[
        Quad::new(
            NamedOrBlankNode::NamedNode(iri(followee)),
            iri(AS_FOLLOWERS),
            Term::NamedNode(iri(follower)),
            GraphName::NamedNode(graph_for(followee)),
        ),
        Quad::new(
            NamedOrBlankNode::NamedNode(iri(follower)),
            iri(AS_FOLLOWING),
            Term::NamedNode(iri(followee)),
            GraphName::NamedNode(graph_for(follower)),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use brolly_store::resources::Pod;

    const ALICE: &str = "https://alice.brolly.test/actor";
    const BOB: &str = "https://bob.brolly.test/actor";

    fn store() -> (tempfile::TempDir, std::sync::Arc<Pod>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).expect("stores");
        let store = manager.pod(uuid::Uuid::new_v4()).expect("pod");
        (dir, store)
    }

    #[test]
    fn a_follower_is_recorded_and_listed() {
        let (_dir, store) = store();
        store.write(|w| record(w, BOB, ALICE)).expect("record");
        assert_eq!(followers(&store.read_store(), ALICE), vec![BOB.to_string()]);
    }

    #[test]
    fn recording_the_same_follow_twice_yields_one_follower() {
        // A Follow re-sent after a missed Accept is normal.
        let (_dir, store) = store();
        store.write(|w| record(w, BOB, ALICE)).expect("first");
        store.write(|w| record(w, BOB, ALICE)).expect("second");
        assert_eq!(followers(&store.read_store(), ALICE).len(), 1);
    }

    #[test]
    fn the_two_directions_are_independent() {
        let (_dir, store) = store();
        store.write(|w| record(w, BOB, ALICE)).expect("record");

        assert_eq!(followers(&store.read_store(), ALICE), vec![BOB.to_string()]);
        assert!(
            followers(&store.read_store(), BOB).is_empty(),
            "following someone must not make them follow you"
        );
        assert!(following(&store.read_store(), ALICE).is_empty());
    }

    #[test]
    fn an_unfollow_removes_both_sides() {
        let (_dir, store) = store();
        store.write(|w| record(w, BOB, ALICE)).expect("record");
        store
            .write(|w| record_following(w, BOB, ALICE))
            .expect("record");

        store.write(|w| remove(w, BOB, ALICE)).expect("remove");

        assert!(followers(&store.read_store(), ALICE).is_empty());
        assert!(following(&store.read_store(), BOB).is_empty());
    }

    #[test]
    fn two_actors_relationships_stay_separate() {
        // Both can live in one store during tests, and in principle a pod could
        // hold more than one actor's graph.
        let (_dir, store) = store();
        store.write(|w| record(w, BOB, ALICE)).expect("record");
        store.write(|w| record(w, ALICE, BOB)).expect("record");

        assert_eq!(followers(&store.read_store(), ALICE), vec![BOB.to_string()]);
        assert_eq!(followers(&store.read_store(), BOB), vec![ALICE.to_string()]);
    }
}
