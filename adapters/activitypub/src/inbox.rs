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
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::Value;

/// The collection readers moved to `brolly-store` so the Mastodon adapter can
/// use them without depending on this crate — see `store::collection`. They are
/// re-exported here because delivery and reading are one story from the inbox's
/// point of view, and a caller should not have to know which crate holds which
/// half.
pub use brolly_store::collection::{
    Entry, LDP_CONTAINS, RECEIVED_AT, members, read_record as read_activity, received_at,
    record_type, timeline,
};

/// The lexicon marker naming AS2's term space in the faithful layer.
///
/// Faithful quads land on `at://as2#<field>`, *not* on the canonical AS2
/// namespace — that is D7's two layers, and they are not interchangeable.
/// Faithful is emitted for everything and keeps each protocol's fields
/// separate; canonical triples are asserted only for entities in the mapping
/// table. Anything reading stored activities back has to use this space or it
/// matches nothing.
const AS2: &str = "as2";

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

impl From<StoreError> for InboxError {
    fn from(e: StoreError) -> Self {
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

/// Store an activity in the recipient's inbox, inside the caller's write.
///
/// Idempotent: a remote instance may deliver to both the shared inbox and the
/// personal one, and arriving twice must not show the post twice. The graph is
/// named by the activity IRI and containment is a single triple, so a repeat
/// delivery rewrites the same quads rather than adding more.
pub fn deliver(
    w: &mut PodWrite<'_>,
    inbox: &str,
    activity: &Value,
    received_at: &str,
) -> Result<String, InboxError> {
    let id = activity["id"].as_str().ok_or(InboxError::NoId)?.to_string();

    write_record(w, &id, activity)?;

    // An embedded object gets its own graph too, so a later Like or Delete can
    // name the note directly and the note is dereferenceable without unwrapping
    // the activity that carried it.
    if let Some(object) = activity.get("object")
        && object.is_object()
        && let Some(object_id) = object["id"].as_str()
    {
        write_record(w, object_id, object)?;
    }

    let inbox_graph = GraphName::NamedNode(iri(inbox));
    let subject = NamedOrBlankNode::NamedNode(iri(inbox));
    let activity_node = iri(&id);

    // Re-delivery must not leave two sort keys behind, so the old one goes
    // before the new one lands.
    clear_received_at(w, inbox, &id)?;

    // The collection is protocol state outside the storage root.
    w.insert(&[
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
    ])?;

    Ok(id)
}

fn write_record(w: &mut PodWrite<'_>, id: &str, record: &Value) -> Result<(), InboxError> {
    let node = iri(id);
    let quads = faithful::encode(record, &node, &node, AS2).map_err(InboxError::Encode)?;
    // Replace rather than merge: a redelivered activity that lost a field
    // should not keep the old value alongside the new one.
    //
    // The record may be the author's own post, under their storage root, or a
    // recipient's copy of someone else's. Until the pod keeps resource
    // metadata, both are written the way they always were.
    w.legacy_under_root().replace_graph(id, &quads)?;
    Ok(())
}

fn clear_received_at(w: &mut PodWrite<'_>, inbox: &str, activity: &str) -> Result<(), InboxError> {
    let existing: Vec<Quad> = w
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(iri(activity))).into()),
            Some(iri(RECEIVED_AT).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(inbox).as_ref())),
        )
        .filter_map(Result::ok)
        .collect();
    w.remove_quads(&existing)?;
    Ok(())
}

/// Drop an activity from an inbox, graph and all, inside the caller's write.
///
/// Both halves matter: a membership row left pointing at a cleared graph is a
/// hole in every timeline that tries to render it.
pub fn remove(w: &mut PodWrite<'_>, inbox: &str, activity: &str) -> Result<(), InboxError> {
    let inbox_node = iri(inbox);
    w.remove_quads(&[Quad::new(
        NamedOrBlankNode::NamedNode(inbox_node.clone()),
        iri(LDP_CONTAINS),
        Term::NamedNode(iri(activity)),
        GraphName::NamedNode(inbox_node),
    )])?;
    clear_received_at(w, inbox, activity)?;
    w.legacy_under_root().clear_graph(activity)?;
    Ok(())
}
