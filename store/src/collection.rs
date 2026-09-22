//! Reading a collection in a pod: membership, receipt order, stored records.
//!
//! An inbox is a collection, and **more than one protocol projects from it**.
//! That is D6 — "your inbox *is* your home timeline" — so the Mastodon home
//! timeline and the ActivityPub inbox are two readings of the same quads.
//!
//! The readers live here rather than beside the writer for one reason: the
//! Mastodon adapter may not depend on the ActivityPub adapter
//! (`server/tests/architecture.rs`), and the alternative — a second copy of the
//! query — is precisely the reader/writer drift that shipped a production bug
//! last time, when the writer stored one AS2 namespace and readers scanned the
//! other. One query, one place.
//!
//! Writing into a collection stays with the protocol that owns delivery.

use brolly_domain::faithful;
use oxigraph::model::{GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::Value;

use crate::resources::PodRead;

/// The lexicon marker naming AS2's term space in the faithful layer.
///
/// Faithful quads land on `at://as2#<field>`, **not** on the canonical AS2
/// namespace — D7's two layers are not interchangeable. Anything reading stored
/// activities back has to use this space or it matches nothing.
const AS2: &str = "as2";

/// LDP containment, reused rather than invented: an inbox is a collection, and
/// `ldp:contains` is what the Solid side already walks.
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";

/// When *this recipient* received the activity.
///
/// Ours, and deliberately not `as:published`: publication is a claim the sender
/// makes, receipt is a fact we observed.
pub const RECEIVED_AT: &str = "https://brolly.id/ns#receivedAt";

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// One row of a timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub activity: String,
    pub activity_type: String,
    /// The cursor. Receipt time, not claimed publication.
    pub received_at: String,
}

/// Everything in this collection.
pub fn members(store: &impl PodRead, collection: &str) -> Vec<String> {
    let node = iri(collection);
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(node.clone())).into()),
            Some(iri(LDP_CONTAINS).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            Term::NamedNode(n) => Some(n.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// When this collection received an activity.
pub fn received_at(store: &impl PodRead, collection: &str, activity: &str) -> Option<String> {
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(iri(activity))).into()),
            Some(iri(RECEIVED_AT).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(collection).as_ref())),
        )
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
}

/// One literal object, for a subject and predicate in a named graph.
///
/// The explicit-graph form. A profile triple lives in the *profile document's*
/// graph while its subject is the WebID, so the two differ and the caller has
/// to say which it means.
pub fn literal_in(
    store: &impl PodRead,
    subject: &str,
    predicate: &str,
    graph: &str,
) -> Option<String> {
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(iri(subject))).into()),
            Some(iri(predicate).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(graph).as_ref())),
        )
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
}

/// One literal object, for a subject and predicate in the subject's own graph.
///
/// The small read that sits under "what media type is this blob" and "what is
/// this attachment's alt text" — both of which are single triples on a resource
/// rather than records to decode.
pub fn literal(store: &impl PodRead, subject: &str, predicate: &str) -> Option<String> {
    let node = iri(subject);
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(node.clone())).into()),
            Some(iri(predicate).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
}

/// Read a stored record back as the wire format it arrived in.
pub fn read_record(store: &impl PodRead, id: &str) -> Option<Value> {
    let node = iri(id);
    let quads: Vec<Quad> = store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .collect();
    if quads.is_empty() {
        return None;
    }
    faithful::decode(&quads, &node).ok()
}

/// The AS2 `type` of a stored activity.
///
/// Read from the **faithful** layer's term space (`at://as2#type`), not the
/// canonical AS2 namespace. Filtering on the canonical predicate would silently
/// match nothing for every activity type outside the mapping table (D7).
pub fn record_type(store: &impl PodRead, activity: &str) -> Option<String> {
    let node = iri(activity);
    let predicate = iri(&brolly_domain::nsid::predicate(AS2, "type"));
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(node.clone())).into()),
            Some(predicate.as_ref()),
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            Term::NamedNode(n) => Some(n.as_str().to_string()),
            _ => None,
        })
}

/// A collection's contents, filtered by type, newest first.
///
/// One store, no fan-out, and correct for remote authors — which outbox-walking
/// never was, since it could only resolve local actors and dropped the rest.
///
/// Sorted by **receipt** rather than the `published` the sender claimed:
/// `published` is attacker-controlled, and sorting on it lets one instance pin
/// itself to the top of every timeline forever.
///
/// `before` is an exclusive cursor: passing the last row of a page returns the
/// next page without repeating the boundary.
pub fn timeline(
    store: &impl PodRead,
    collection: &str,
    types: &[&str],
    limit: usize,
    before: Option<&str>,
) -> Vec<Entry> {
    let mut entries: Vec<Entry> = members(store, collection)
        .into_iter()
        .filter_map(|activity| {
            let received_at = received_at(store, collection, &activity)?;
            if before.is_some_and(|cursor| received_at.as_str() >= cursor) {
                return None;
            }
            let activity_type = record_type(store, &activity)?;
            types.contains(&activity_type.as_str()).then_some(Entry {
                activity,
                activity_type,
                received_at,
            })
        })
        .collect();

    entries.sort_by(|a, b| b.received_at.cmp(&a.received_at));
    entries.truncate(limit);
    entries
}
