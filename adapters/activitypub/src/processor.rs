//! What a recipient does with a delivered activity.
//!
//! One delivery mechanism, two subscribers. From the learnings: the server
//! agent is "a delivery recipient like any other: local activities are
//! delivered to it, and its processor writes the pointer row. The same delivery
//! path that fills a user's inbox fills the index — one mechanism, two
//! subscribers, no crawler to schedule or debug."
//!
//! The difference between the two subscribers is the design:
//!
//! | | Member | Instance |
//! |---|---|---|
//! | Stores | the activity, as content | a pointer and filter keys |
//! | Answers | their home timeline, notifications | the public timeline, search |
//! | On delete | removes their copy | drops the row |
//!
//! The instance **never stores content** (D5). The index is a denormalization,
//! and the moment it holds content it stops being one and becomes a second
//! source of truth nobody remembers is derived.

use brolly_store::index::{self, NotePointer};
use brolly_store::{Store, StoreError};
use oxigraph::model::NamedNode;
use serde_json::Value;

use crate::inbox::{self, InboxError};

/// The public audience. A post addressed here is on the public timeline; one
/// addressed anywhere else is not, and indexing it would publish it.
pub const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

/// Who a delivery is for.
pub enum Recipient<'a> {
    /// A member. Their inbox is their home timeline (D6), so it holds the
    /// activity itself.
    Member { inbox: &'a str },
    /// The instance actor (D4). Records a pointer, never content.
    Instance,
}

#[derive(Debug)]
pub enum ProcessError {
    Inbox(InboxError),
    Store(String),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Inbox(e) => write!(f, "{e}"),
            ProcessError::Store(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for ProcessError {}

impl From<InboxError> for ProcessError {
    fn from(e: InboxError) -> Self {
        ProcessError::Inbox(e)
    }
}

impl From<StoreError> for ProcessError {
    fn from(e: StoreError) -> Self {
        ProcessError::Store(e.to_string())
    }
}

impl From<brolly_store::write::WriteError> for ProcessError {
    fn from(e: brolly_store::write::WriteError) -> Self {
        ProcessError::Store(e.to_string())
    }
}

/// Handle one delivered activity.
pub fn process(
    store: &Store,
    recipient: Recipient<'_>,
    activity: &Value,
    received_at: &str,
) -> Result<(), ProcessError> {
    match recipient {
        Recipient::Member { inbox } => process_for_member(store, inbox, activity, received_at),
        Recipient::Instance => process_for_instance(store, activity),
    }
}

fn process_for_member(
    store: &Store,
    inbox: &str,
    activity: &Value,
    received_at: &str,
) -> Result<(), ProcessError> {
    if activity["type"] == "Delete" {
        // Remove what the Delete names, and the activity that carried it in.
        if let Some(target) = object_id(activity) {
            for member in inbox::members(store, inbox) {
                if references(store, &member, target) {
                    inbox::remove(store, inbox, &member)?;
                }
            }
            inbox::remove(store, inbox, target)?;
        }
        return Ok(());
    }

    inbox::deliver(store, inbox, activity, received_at)?;
    Ok(())
}

/// Does this stored activity carry `target` as its object?
///
/// Used to find the `Create` that delivered a now-deleted note, so a tombstoned
/// post does not leave a row in the timeline pointing at a cleared graph.
fn references(store: &Store, activity: &str, target: &str) -> bool {
    inbox::read_activity(store, activity).is_some_and(|stored| object_id(&stored) == Some(target))
}

fn process_for_instance(store: &Store, activity: &Value) -> Result<(), ProcessError> {
    match activity["type"].as_str() {
        Some("Create") | Some("Announce") => index_note(store, activity),
        Some("Delete") => {
            // A delete for something we never saw is normal, not an error: the
            // sender fans out to every follower's instance regardless of what
            // each one happened to store.
            if let Some(target) = object_id(activity) {
                index::forget_note(store, &NamedNode::new_unchecked(target))?;
            }
            Ok(())
        }
        // A Like or a Follow is a notification, not a post. Neither belongs on
        // a public timeline.
        _ => Ok(()),
    }
}

fn index_note(store: &Store, activity: &Value) -> Result<(), ProcessError> {
    // Public only. The index backs the public timeline, so indexing a
    // followers-only post would publish it.
    if !addressed_publicly(activity) {
        return Ok(());
    }

    let (Some(note), Some(author)) = (object_id(activity), activity["actor"].as_str()) else {
        return Ok(());
    };

    // An `Announce` points at someone else's note; the pointer names what was
    // announced, because that is what a reader will dereference.
    let object = activity.get("object");
    let published = activity["published"]
        .as_str()
        .or_else(|| object?.get("published")?.as_str())
        .unwrap_or_default()
        .to_string();

    let in_reply_to = object
        .and_then(|o| o.get("inReplyTo"))
        .and_then(Value::as_str)
        .map(NamedNode::new_unchecked);

    index::record_note(
        store,
        &NotePointer {
            note: NamedNode::new_unchecked(note),
            author: NamedNode::new_unchecked(author),
            published,
            audience: NamedNode::new_unchecked(PUBLIC),
            in_reply_to,
        },
    )?;
    Ok(())
}

/// The IRI of an activity's object, whether it is embedded or referenced.
fn object_id(activity: &Value) -> Option<&str> {
    match activity.get("object")? {
        Value::String(iri) => Some(iri),
        object @ Value::Object(_) => object["id"].as_str(),
        _ => None,
    }
}

/// Is `as:Public` among the recipients?
///
/// Checked across `to`, `cc`, `audience` and their `bto`/`bcc` counterparts,
/// each of which may be a string or an array — the shape varies by
/// implementation and missing one silently drops posts from the timeline.
fn addressed_publicly(activity: &Value) -> bool {
    ["to", "cc", "audience", "bto", "bcc"]
        .iter()
        .any(|field| mentions_public(activity.get(*field)))
}

fn mentions_public(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(s)) => s == PUBLIC,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(PUBLIC)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_object_id_is_found_whether_embedded_or_referenced() {
        assert_eq!(
            object_id(&json!({"object": "https://example/1"})),
            Some("https://example/1")
        );
        assert_eq!(
            object_id(&json!({"object": {"id": "https://example/1"}})),
            Some("https://example/1")
        );
        assert_eq!(object_id(&json!({"object": {}})), None);
        assert_eq!(object_id(&json!({})), None);
    }

    #[test]
    fn public_addressing_is_recognised_in_every_shape_it_arrives_in() {
        // Implementations differ, and missing one drops posts silently.
        assert!(addressed_publicly(&json!({"to": PUBLIC})));
        assert!(addressed_publicly(&json!({"to": [PUBLIC]})));
        assert!(addressed_publicly(
            &json!({"to": ["https://x/followers"], "cc": [PUBLIC]})
        ));
        assert!(addressed_publicly(&json!({"audience": [PUBLIC]})));
    }

    #[test]
    fn a_post_addressed_only_to_followers_is_not_public() {
        assert!(!addressed_publicly(
            &json!({"to": ["https://bob.example/followers"]})
        ));
        assert!(!addressed_publicly(&json!({})));
        // A near-miss must not count.
        assert!(!addressed_publicly(
            &json!({"to": ["https://www.w3.org/ns/activitystreams#PublicIsh"]})
        ));
    }
}
