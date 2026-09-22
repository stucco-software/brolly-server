//! Timelines: home from the viewer's own store, public from the index.
//!
//! **Home reads one store.** The viewer's inbox already holds every post
//! delivered to them, remote authors included, pre-denormalized by the protocol
//! itself (D6). The predecessor instead walked each followee's outbox — N
//! stores per request to reassemble what was sitting in the one store it had
//! just closed — and, because it could only resolve *local* actors, silently
//! dropped every remote followee with a `continue`. Both problems have the same
//! fix, and it is a smaller function.
//!
//! **Public reads the index, then dereferences only the page it returns.** The
//! index holds pointers and filter keys, never content (D5), so the cost of a
//! page is the page size rather than the size of the instance. Pointers into
//! deleted pods are expected and skipped: account deletion is `rm -rf` on one
//! directory, and the index sweeps lazily.
//!
//! Nothing here writes. `server/tests/architecture.rs` enforces that.

use brolly_store::collection;
use brolly_store::resources::PodRead;
use serde_json::Value;

/// Activity types a timeline renders. A `Follow` or a `Like` belongs in
/// notifications; rendering one as a status shows an empty post.
const RENDERABLE: [&str; 2] = ["Create", "Announce"];

/// One row: the note to render, who wrote it, and the cursor to page from.
#[derive(Debug, Clone)]
pub struct Row {
    /// The AS2 object, unwrapped from the activity that carried it. Clients
    /// want the Note, not the Create.
    pub note: Value,
    /// The actor IRI, for the caller to resolve into an author.
    pub author_actor: String,
    /// Opaque pagination cursor — receipt time, matching `collection::timeline`.
    pub cursor: String,
}

/// Pull the renderable object out of an activity.
///
/// `None` when the activity carries a bare IRI rather than an embedded object:
/// there is nothing to render, and emitting a status with null content would
/// show an empty post in the timeline.
fn embedded_object(activity: &Value) -> Option<Value> {
    let object = activity.get("object")?;
    object.is_object().then(|| object.clone())
}

/// The viewer's home timeline, from their own inbox.
///
/// `before` is an exclusive cursor — pass the last row of a page to get the
/// next one without repeating the boundary.
pub fn home(store: &impl PodRead, inbox: &str, limit: usize, before: Option<&str>) -> Vec<Row> {
    collection::timeline(store, inbox, &RENDERABLE, limit, before)
        .into_iter()
        .filter_map(|entry| {
            let activity = collection::read_record(store, &entry.activity)?;
            let note = embedded_object(&activity)?;
            Some(Row {
                author_actor: activity["actor"].as_str()?.to_string(),
                note,
                cursor: entry.received_at,
            })
        })
        .collect()
}

/// The public timeline, from index pointers.
///
/// `fetch` dereferences one note IRI from its author's pod. It is called once
/// per row *in the page*, never once per row in the index — that bound is the
/// whole reason a pointer index is allowed to exist at all (D5).
///
/// A pointer that no longer resolves is skipped. Dangling rows are the correct
/// steady state, and one deleted note must not blank the timeline.
pub fn public<F>(pointers: &[String], mut fetch: F) -> Vec<Row>
where
    F: FnMut(&str) -> Option<Value>,
{
    pointers
        .iter()
        .filter_map(|iri| {
            let note = fetch(iri)?;
            if !note.is_object() {
                return None;
            }
            Some(Row {
                author_actor: note["attributedTo"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                cursor: note["published"].as_str().unwrap_or_default().to_string(),
                note,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_bare_object_reference_yields_nothing_to_render() {
        let activity = json!({
            "type": "Create",
            "object": "https://alice.brolly.test/~/notes/x",
        });
        assert!(embedded_object(&activity).is_none());
    }

    #[test]
    fn an_embedded_object_is_returned_whole() {
        let activity = json!({
            "type": "Create",
            "object": {"type": "Note", "content": "hi"},
        });
        assert_eq!(embedded_object(&activity).unwrap()["content"], "hi");
    }

    #[test]
    fn only_posts_and_boosts_are_renderable() {
        // Pinned so that adding a type here is a deliberate act — a Like
        // rendered as a status is an empty row in every client.
        assert_eq!(RENDERABLE, ["Create", "Announce"]);
    }
}
