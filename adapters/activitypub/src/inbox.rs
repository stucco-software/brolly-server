//! Inbox arrival: store the activity, make it a member, give it a sort key.
//!
//! **Your inbox is your home timeline** (D6). Delivery writes into the
//! *recipient's* store, so the timeline is a single-store read that stays
//! correct for remote authors — which outbox-walking never could, since only
//! local actors can be resolved back to a store.
//!
//! The predecessor got the write half right and then never used it. From the
//! learnings: it "writes the note graph into the recipient's store but never
//! adds a containment triple, so there is no collection to walk", and the read
//! path fell back to opening one store per followee. The two triples this
//! module adds on arrival — membership and a sort key — are what close that.

use brolly_domain::faithful;
use brolly_store::Store;
use brolly_store::write::{WriteError, insert_quads};
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::Value;

/// The lexicon marker naming AS2's term space in the faithful layer.
///
/// Faithful quads land on `at://as2#<field>`, *not* on the canonical AS2
/// namespace — that is D7's two layers, and they are not interchangeable.
/// Faithful is emitted for everything and keeps each protocol's fields
/// separate; canonical triples are asserted only for entities in the mapping
/// table. Anything reading stored activities back has to use this space or it
/// matches nothing.
const AS2: &str = "as2";

/// LDP containment, reused rather than invented: an inbox is a collection, and
/// `ldp:contains` is what the Solid side already walks.
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";

/// When *this recipient* received the activity.
///
/// Ours, and deliberately not `as:published`: publication is a claim the sender
/// makes, receipt is a fact we observed.
pub const RECEIVED_AT: &str = "https://brolly.id/ns#receivedAt";

#[derive(Debug)]
pub enum InboxError {
    /// An activity with no `id` cannot be deduplicated, referenced by a later
    /// `Delete`, or given a graph to live in.
    NoId,
    Encode(faithful::FaithfulError),
    Store(String),
}

impl std::fmt::Display for InboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InboxError::NoId => write!(f, "activity has no id"),
            InboxError::Encode(e) => write!(f, "{e}"),
            InboxError::Store(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for InboxError {}

impl From<WriteError> for InboxError {
    fn from(e: WriteError) -> Self {
        InboxError::Store(e.to_string())
    }
}

impl From<oxigraph::store::StorageError> for InboxError {
    fn from(e: oxigraph::store::StorageError) -> Self {
        InboxError::Store(e.to_string())
    }
}

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

/// Store an activity in the recipient's inbox.
///
/// Idempotent: a remote instance may deliver to both the shared inbox and the
/// personal one, and arriving twice must not show the post twice. The graph is
/// named by the activity IRI and containment is a single triple, so a repeat
/// delivery rewrites the same quads rather than adding more.
pub fn deliver(
    store: &Store,
    inbox: &str,
    activity: &Value,
    received_at: &str,
) -> Result<String, InboxError> {
    let id = activity["id"].as_str().ok_or(InboxError::NoId)?.to_string();

    write_record(store, &id, activity)?;

    // An embedded object gets its own graph too, so a later Like or Delete can
    // name the note directly and the note is dereferenceable without unwrapping
    // the activity that carried it.
    if let Some(object) = activity.get("object")
        && object.is_object()
        && let Some(object_id) = object["id"].as_str()
    {
        write_record(store, object_id, object)?;
    }

    let inbox_graph = GraphName::NamedNode(iri(inbox));
    let subject = NamedOrBlankNode::NamedNode(iri(inbox));
    let activity_node = iri(&id);

    // Re-delivery must not leave two sort keys behind, so the old one goes
    // before the new one lands.
    clear_received_at(store, inbox, &id)?;

    insert_quads(
        store,
        &[
            Quad::new(
                subject,
                iri(LDP_CONTAINS),
                Term::NamedNode(activity_node.clone()),
                inbox_graph.clone(),
            ),
            Quad::new(
                NamedOrBlankNode::NamedNode(activity_node),
                iri(RECEIVED_AT),
                // RFC 3339, stored as a string because it sorts
                // lexicographically and the cursor is a plain comparison.
                Term::Literal(Literal::new_simple_literal(received_at)),
                inbox_graph,
            ),
        ],
    )?;

    Ok(id)
}

fn write_record(store: &Store, id: &str, record: &Value) -> Result<(), InboxError> {
    let node = iri(id);
    let quads = faithful::encode(record, &node, &node, AS2).map_err(InboxError::Encode)?;
    // Replace rather than merge: a redelivered activity that lost a field
    // should not keep the old value alongside the new one.
    store.clear_graph(GraphNameRef::NamedNode(node.as_ref()))?;
    insert_quads(store, &quads)?;
    Ok(())
}

fn clear_received_at(store: &Store, inbox: &str, activity: &str) -> Result<(), InboxError> {
    let existing: Vec<Quad> = store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(iri(activity))).into()),
            Some(iri(RECEIVED_AT).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(inbox).as_ref())),
        )
        .filter_map(Result::ok)
        .collect();
    for quad in &existing {
        store.remove(quad)?;
    }
    Ok(())
}

/// Everything in this inbox.
pub fn members(store: &Store, inbox: &str) -> Vec<String> {
    let node = iri(inbox);
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

/// When this inbox received an activity.
pub fn received_at(store: &Store, inbox: &str, activity: &str) -> Option<String> {
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(iri(activity))).into()),
            Some(iri(RECEIVED_AT).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(inbox).as_ref())),
        )
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
}

/// Read a stored record back as the wire format it arrived in.
pub fn read_activity(store: &Store, id: &str) -> Option<Value> {
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

/// The recipient's timeline: their own inbox, filtered, newest first.
///
/// One store, no fan-out, and correct for remote authors. Sorted by **receipt**
/// rather than by the `published` the sender claimed — `published` is
/// attacker-controlled, and sorting on it lets one instance pin itself to the
/// top of every timeline forever.
///
/// `before` is an exclusive cursor: passing the last row of a page returns the
/// next one without repeating the boundary.
pub fn timeline(
    store: &Store,
    inbox: &str,
    types: &[&str],
    limit: usize,
    before: Option<&str>,
) -> Vec<Entry> {
    let mut entries: Vec<Entry> = members(store, inbox)
        .into_iter()
        .filter_map(|activity| {
            let received_at = received_at(store, inbox, &activity)?;
            if before.is_some_and(|cursor| received_at.as_str() >= cursor) {
                return None;
            }
            let activity_type = activity_type(store, &activity)?;
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

/// The AS2 `type` of a stored activity.
///
/// Read from the **faithful** layer's term space (`at://as2#type`), not the
/// canonical AS2 namespace. Those are different by design (D7): faithful quads
/// are emitted for everything and keep each protocol's fields in their own
/// space, while canonical triples are asserted only for the entities in the
/// mapping table. Filtering on the canonical predicate would silently match
/// nothing for every activity type that is not mapped.
fn activity_type(store: &Store, activity: &str) -> Option<String> {
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

/// Drop an activity from an inbox, graph and all.
///
/// Both halves matter: a membership row left pointing at a cleared graph is a
/// hole in every timeline that tries to render it.
pub fn remove(store: &Store, inbox: &str, activity: &str) -> Result<(), InboxError> {
    let inbox_node = iri(inbox);
    let activity_node = iri(activity);

    store.remove(&Quad::new(
        NamedOrBlankNode::NamedNode(inbox_node.clone()),
        iri(LDP_CONTAINS),
        Term::NamedNode(activity_node.clone()),
        GraphName::NamedNode(inbox_node),
    ))?;
    clear_received_at(store, inbox, activity)?;
    store.clear_graph(GraphNameRef::NamedNode(activity_node.as_ref()))?;
    Ok(())
}
