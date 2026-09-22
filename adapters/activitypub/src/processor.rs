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
use brolly_store::resources::{PodRead, PodWrite};
use brolly_store::{InstanceStore, StoreError};
use oxigraph::model::NamedNode;
use serde_json::Value;

use crate::inbox::{self, InboxError};

/// The public audience. A post addressed here is on the public timeline; one
/// addressed anywhere else is not, and indexing it would publish it.
pub const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

#[derive(Debug)]
pub enum ProcessError {
    Inbox(InboxError),
    Store(String),
    /// The activity's own id, or the id of an object embedded in it, isn't on
    /// its actor's origin. Delivering it would let one actor write a graph
    /// another actor owns.
    ForeignObject,
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessError::Inbox(e) => write!(f, "{e}"),
            ProcessError::Store(e) => write!(f, "storage: {e}"),
            ProcessError::ForeignObject => {
                write!(f, "activity names a graph its actor does not own")
            }
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

/// Handle one activity delivered to a member, inside the caller's write.
///
/// Before anything is written, the activity is refused with
/// [`ProcessError::ForeignObject`] if its own id, or the id of an object
/// embedded in it, isn't on its actor's origin. A string `object` is a
/// reference and may name anyone's IRI: that is what a `Like` or a `Follow` is.
///
/// The member's inbox is their home timeline (D6), so it holds the activity
/// itself. Their outbox holds their own published activities, and a `Delete`
/// has to be able to clear a copy in either.
///
/// This is where every recipient's copy arrives, whether from local delivery
/// or, once federation is on, from another server (ADR 0016).
pub fn process_member(
    w: &mut PodWrite<'_>,
    inbox: &str,
    outbox: &str,
    activity: &Value,
    received_at: &str,
) -> Result<(), ProcessError> {
    let actor = owning_actor(activity)?;
    if activity["type"] == "Delete" {
        // Remove only what delivery put there: a graph on the actor's origin
        // that arrived as the embedded object of one of the actor's activities,
        // in this pod's inbox (a recipient's copy) or outbox (the author's own).
        //
        // Origin alone isn't enough. The owner's pod receives the owner's own
        // activities, so a Delete naming their `/~/.acl` would pass it and clear
        // the ACL without WAC ever seeing the request. An LDP resource is never
        // the embedded object of a delivered activity, so this can't reach one.
        if let Some(target) = object_id(activity)
            && same_origin(target, actor)
        {
            let mut carried = false;
            for collection in [inbox, outbox] {
                for carrier in carriers(&*w, collection, actor, target) {
                    inbox::remove(w, collection, &carrier)?;
                    carried = true;
                }
            }
            if carried {
                inbox::remove(w, inbox, target)?;
            }
        }
        return Ok(());
    }

    inbox::deliver(w, inbox, activity, received_at)?;
    Ok(())
}

/// Handle one activity delivered to the instance actor (D4). It records a
/// pointer, never content, and applies the same origin rule as
/// [`process_member`] first.
pub fn process_instance(instance: &InstanceStore, activity: &Value) -> Result<(), ProcessError> {
    let actor = owning_actor(activity)?;
    process_for_instance(instance, actor, activity)
}

/// The actor's activities in `collection` that carried `target` in as their
/// embedded object.
///
/// Embedded, not merely named. A `Create` whose `object` is a plain string IRI
/// names a graph delivery never wrote, so it's no evidence the graph is
/// delivery's to remove. That's why this doesn't use [`object_id`], which
/// treats the two alike.
fn carriers(store: &impl PodRead, collection: &str, actor: &str, target: &str) -> Vec<String> {
    inbox::members(store, collection)
        .into_iter()
        .filter(|member| same_origin(member, actor))
        .filter(|member| {
            inbox::read_activity(store, member).is_some_and(|stored| {
                stored["object"].is_object() && stored["object"]["id"].as_str() == Some(target)
            })
        })
        .collect()
}

fn process_for_instance(
    instance: &InstanceStore,
    actor: &str,
    activity: &Value,
) -> Result<(), ProcessError> {
    match activity["type"].as_str() {
        // A Create publishes the actor's own note. Indexing one that names
        // somebody else's would put it on the public timeline under the wrong
        // name.
        Some("Create") => match object_id(activity) {
            Some(note) if same_origin(note, actor) => index_note(instance, activity),
            _ => Ok(()),
        },
        // An Announce names someone else's note by definition, so it can keep a
        // post on the public timeline but never put one there. A note nobody
        // indexed may be followers-only or direct, and the Mastodon public
        // timeline reads whatever a pointer names out of the owner's pod
        // without checking its audience. Indexing the boost would publish that
        // post under the booster's name.
        //
        // For a note that is indexed, `index::record_note` keeps the pointer as
        // its Create wrote it: same author, same `published`, same place. So
        // today this writes nothing new. The guard is what matters.
        Some("Announce") => {
            if let Some(note) = object_id(activity)
                && index::is_indexed(instance, &NamedNode::new_unchecked(note))?
            {
                index_note(instance, activity)?;
            }
            Ok(())
        }
        Some("Delete") => {
            // A delete for something we never saw is normal, not an error: the
            // sender fans out to every follower's instance regardless of what
            // each one happened to store.
            //
            // Only the note's own origin can take it off the public timeline.
            if let Some(target) = object_id(activity)
                && same_origin(target, actor)
            {
                index::forget_note(instance, &NamedNode::new_unchecked(target))?;
            }
            Ok(())
        }
        // A Like or a Follow is a notification, not a post. Neither belongs on
        // a public timeline.
        _ => Ok(()),
    }
}

fn index_note(instance: &InstanceStore, activity: &Value) -> Result<(), ProcessError> {
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
        instance,
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

/// The activity's actor, provided every graph the activity would write is on
/// that actor's origin.
///
/// Strict on shape: no string `actor`, no string `id`, or an embedded object
/// whose `id` isn't a string, all refuse. Each of them leaves nothing to check
/// ownership against.
fn owning_actor(activity: &Value) -> Result<&str, ProcessError> {
    let actor = activity["actor"]
        .as_str()
        .ok_or(ProcessError::ForeignObject)?;
    let own_id = activity["id"]
        .as_str()
        .is_some_and(|id| same_origin(id, actor));
    let own_object = match activity.get("object") {
        Some(object @ Value::Object(_)) => object
            .get("id")
            .is_none_or(|id| id.as_str().is_some_and(|id| same_origin(id, actor))),
        _ => true,
    };
    if own_id && own_object {
        Ok(actor)
    } else {
        Err(ProcessError::ForeignObject)
    }
}

/// Do two IRIs share an origin: scheme, host and port?
///
/// False if either doesn't parse, or has an opaque origin (`urn:` and the
/// like). Nobody owns an origin that can't be compared.
fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            let origin = a.origin();
            origin.is_tuple() && origin == b.origin()
        }
        _ => false,
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

    #[test]
    fn origin_is_scheme_host_and_port() {
        let actor = "https://alice.brolly.test/actor";
        assert!(same_origin("https://alice.brolly.test/~/notes/1", actor));
        assert!(
            same_origin("https://alice.brolly.test:443/~/notes/1", actor),
            "the default port is the port"
        );
        assert!(
            same_origin("https://ALICE.brolly.test/~/notes/1", actor),
            "hosts compare case-insensitively"
        );

        assert!(
            !same_origin("https://alice.brolly.test:8443/x", actor),
            "port"
        );
        assert!(!same_origin("http://alice.brolly.test/x", actor), "scheme");
        assert!(!same_origin("https://bob.brolly.test/x", actor), "host");
        assert!(
            !same_origin("https://alice.brolly.test.evil/x", actor),
            "host suffix"
        );
    }

    #[test]
    fn an_unparseable_or_opaque_iri_has_no_origin_in_common() {
        let actor = "https://alice.brolly.test/actor";
        assert!(!same_origin("not a url", actor));
        assert!(!same_origin(actor, ""));
        assert!(!same_origin("", ""));
        // An opaque origin equals nothing, not even itself.
        assert!(!same_origin("urn:example:a", "urn:example:a"));
    }
}
