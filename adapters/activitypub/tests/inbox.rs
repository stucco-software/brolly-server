//! Inbox arrival, and the containment the predecessor never wrote.
//!
//! From the learnings: "`process_create` writes the note graph into the
//! recipient's store but never adds a containment triple, so there is no
//! collection to walk. Add membership plus a sort key on inbox arrival and the
//! timeline becomes a single-store read."
//!
//! That is the whole point of this module. Without containment the home
//! timeline has nothing to enumerate, which is what forced the outbox-walking
//! that made reads O(followees) — and which silently dropped every remote
//! author, since only local actors could be resolved back to a store.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_activitypub::inbox::{self, InboxError};
use brolly_store::resources::Pod;
use serde_json::{Value, json};

const ALICE_INBOX: &str = "https://alice.brolly.test/inbox";
const BOB_INBOX: &str = "https://bob.brolly.test/inbox";

fn store() -> (tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = manager.pod(uuid::Uuid::new_v4()).unwrap();
    (dir, store)
}

/// Deliver in one write, as the processor's caller does.
fn deliver(pod: &Pod, collection: &str, activity: &Value, at: &str) -> Result<String, InboxError> {
    pod.write(|w| Ok(inbox::deliver(w, collection, activity, at)))
        .map_err(InboxError::from)
        .flatten()
}

fn a_note(id: &str, content: &str) -> Value {
    json!({
        "type": "Create",
        "id": format!("{id}/activity"),
        "actor": "https://bob.brolly.test/actor",
        "published": "2026-08-26T12:00:00Z",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "object": {
            "type": "Note",
            "id": id,
            "attributedTo": "https://bob.brolly.test/actor",
            "content": content,
            "published": "2026-08-26T12:00:00Z",
        },
    })
}

#[test]
fn a_delivered_activity_becomes_a_member_of_the_inbox() {
    // The missing piece. Without this triple there is no collection to walk.
    let (_dir, store) = store();
    let activity = a_note("https://bob.brolly.test/~/notes/1", "hello");

    let id = deliver(&store, ALICE_INBOX, &activity, "2026-08-26T12:00:01Z").expect("deliver");
    assert_eq!(id, "https://bob.brolly.test/~/notes/1/activity");

    let members = inbox::members(&store.read_store(), ALICE_INBOX);
    assert_eq!(members, vec![id], "the activity must be enumerable");
}

#[test]
fn the_sort_key_lives_in_the_inbox_and_not_in_the_activity() {
    // Receipt time is a fact about *this recipient's copy*, not about the
    // activity. Writing it into the activity graph would put a local timestamp
    // into an export and into anything that re-serialises the activity.
    let (_dir, store) = store();
    let activity = a_note("https://bob.brolly.test/~/notes/1", "hello");
    deliver(&store, ALICE_INBOX, &activity, "2026-08-26T12:00:01Z").unwrap();

    let received = inbox::received_at(
        &store.read_store(),
        ALICE_INBOX,
        "https://bob.brolly.test/~/notes/1/activity",
    );
    assert_eq!(received.as_deref(), Some("2026-08-26T12:00:01Z"));

    // Round-tripping the activity must not surface the receipt time.
    let restored = inbox::read_activity(
        &store.read_store(),
        "https://bob.brolly.test/~/notes/1/activity",
    )
    .expect("read back");
    assert!(
        !restored.to_string().contains("receivedAt"),
        "receipt time leaked into the activity: {restored}"
    );
}

#[test]
fn an_activity_survives_the_store_unchanged() {
    // The property that makes `rawJson` unnecessary — the predecessor stashed
    // the original JSON beside every activity because nothing guaranteed this.
    let (_dir, store) = store();
    let activity = a_note(
        "https://bob.brolly.test/~/notes/1",
        "<p>hello &amp; goodbye</p>",
    );
    deliver(&store, ALICE_INBOX, &activity, "2026-08-26T12:00:01Z").unwrap();

    let restored = inbox::read_activity(
        &store.read_store(),
        "https://bob.brolly.test/~/notes/1/activity",
    )
    .expect("read back");
    assert_eq!(restored, activity);
}

#[test]
fn redelivery_does_not_duplicate() {
    // A remote instance may deliver to both the shared inbox and the personal
    // one. Arriving twice must not show the post twice.
    let (_dir, store) = store();
    let activity = a_note("https://bob.brolly.test/~/notes/1", "hello");

    deliver(&store, ALICE_INBOX, &activity, "2026-08-26T12:00:01Z").unwrap();
    deliver(&store, ALICE_INBOX, &activity, "2026-08-26T12:00:02Z").unwrap();

    assert_eq!(inbox::members(&store.read_store(), ALICE_INBOX).len(), 1);
    let timeline = inbox::timeline(&store.read_store(), ALICE_INBOX, &["Create"], 10, None);
    assert_eq!(timeline.len(), 1);
}

#[test]
fn an_activity_without_an_id_is_refused() {
    // An activity with no id cannot be deduplicated, referenced by a Delete, or
    // given a graph to live in.
    let (_dir, store) = store();
    let anonymous = json!({"type": "Create", "actor": "https://bob.brolly.test/actor"});

    assert!(matches!(
        deliver(&store, ALICE_INBOX, &anonymous, "2026-08-26T12:00:01Z"),
        Err(InboxError::NoId)
    ));
    assert!(inbox::members(&store.read_store(), ALICE_INBOX).is_empty());
}

#[test]
fn an_embedded_object_also_gets_its_own_graph() {
    // So a later Like or Delete can name the note directly, and so the note is
    // dereferenceable without unwrapping the activity that carried it.
    let (_dir, store) = store();
    let activity = a_note("https://bob.brolly.test/~/notes/1", "hello");
    deliver(&store, ALICE_INBOX, &activity, "2026-08-26T12:00:01Z").unwrap();

    let note = inbox::read_activity(&store.read_store(), "https://bob.brolly.test/~/notes/1")
        .expect("the note is addressable on its own");
    assert_eq!(note["type"], "Note");
    assert_eq!(note["content"], "hello");
}

#[test]
fn the_timeline_is_newest_first() {
    let (_dir, store) = store();
    for n in 1..=3 {
        deliver(
            &store,
            ALICE_INBOX,
            &a_note(&format!("https://bob.brolly.test/~/notes/{n}"), "hello"),
            &format!("2026-08-26T12:00:0{n}Z"),
        )
        .unwrap();
    }

    let timeline = inbox::timeline(&store.read_store(), ALICE_INBOX, &["Create"], 10, None);
    let ids: Vec<&str> = timeline.iter().map(|e| e.activity.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "https://bob.brolly.test/~/notes/3/activity",
            "https://bob.brolly.test/~/notes/2/activity",
            "https://bob.brolly.test/~/notes/1/activity",
        ]
    );
}

#[test]
fn the_timeline_sorts_by_receipt_not_by_claimed_publication() {
    // `published` comes from the sender and can say anything. Sorting by it
    // lets a remote instance pin itself to the top of every timeline forever.
    let (_dir, store) = store();

    let mut future = a_note("https://bob.brolly.test/~/notes/1", "from the future");
    future["published"] = json!("2099-01-01T00:00:00Z");
    future["object"]["published"] = json!("2099-01-01T00:00:00Z");
    deliver(&store, ALICE_INBOX, &future, "2026-08-26T12:00:01Z").unwrap();

    deliver(
        &store,
        ALICE_INBOX,
        &a_note("https://bob.brolly.test/~/notes/2", "ordinary"),
        "2026-08-26T12:00:02Z",
    )
    .unwrap();

    let timeline = inbox::timeline(&store.read_store(), ALICE_INBOX, &["Create"], 10, None);
    assert_eq!(
        timeline[0].activity, "https://bob.brolly.test/~/notes/2/activity",
        "a claimed publication date must not reorder the timeline"
    );
}

#[test]
fn the_timeline_filters_by_activity_type() {
    let (_dir, store) = store();
    deliver(
        &store,
        ALICE_INBOX,
        &a_note("https://bob.brolly.test/~/notes/1", "hello"),
        "2026-08-26T12:00:01Z",
    )
    .unwrap();
    deliver(
        &store,
        ALICE_INBOX,
        &json!({
            "type": "Follow",
            "id": "https://bob.brolly.test/~/follows/1",
            "actor": "https://bob.brolly.test/actor",
            "object": "https://alice.brolly.test/actor",
        }),
        "2026-08-26T12:00:02Z",
    )
    .unwrap();

    // A home timeline shows posts; a Follow belongs in notifications.
    let posts = inbox::timeline(
        &store.read_store(),
        ALICE_INBOX,
        &["Create", "Announce"],
        10,
        None,
    );
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].activity_type, "Create");

    let follows = inbox::timeline(&store.read_store(), ALICE_INBOX, &["Follow"], 10, None);
    assert_eq!(follows.len(), 1);

    // Both are in the inbox regardless — filtering is a read concern.
    assert_eq!(inbox::members(&store.read_store(), ALICE_INBOX).len(), 2);
}

#[test]
fn the_timeline_paginates() {
    let (_dir, store) = store();
    for n in 1..=5 {
        deliver(
            &store,
            ALICE_INBOX,
            &a_note(&format!("https://bob.brolly.test/~/notes/{n}"), "hello"),
            &format!("2026-08-26T12:00:0{n}Z"),
        )
        .unwrap();
    }

    let first = inbox::timeline(&store.read_store(), ALICE_INBOX, &["Create"], 2, None);
    assert_eq!(first.len(), 2);
    assert_eq!(
        first[0].activity,
        "https://bob.brolly.test/~/notes/5/activity"
    );

    let next = inbox::timeline(
        &store.read_store(),
        ALICE_INBOX,
        &["Create"],
        2,
        Some(&first[1].received_at),
    );
    assert_eq!(next.len(), 2);
    assert_eq!(
        next[0].activity, "https://bob.brolly.test/~/notes/3/activity",
        "the cursor must be exclusive, or the page boundary repeats a row"
    );
}

#[test]
fn inboxes_do_not_see_each_others_deliveries() {
    // Two inboxes can share a store — the instance actor's and, during tests,
    // anyone's. Containment is scoped to the inbox IRI, not to the store.
    let (_dir, store) = store();
    deliver(
        &store,
        ALICE_INBOX,
        &a_note("https://bob.brolly.test/~/notes/1", "for alice"),
        "2026-08-26T12:00:01Z",
    )
    .unwrap();
    deliver(
        &store,
        BOB_INBOX,
        &a_note("https://carol.brolly.test/~/notes/1", "for bob"),
        "2026-08-26T12:00:02Z",
    )
    .unwrap();

    assert_eq!(inbox::members(&store.read_store(), ALICE_INBOX).len(), 1);
    assert_eq!(inbox::members(&store.read_store(), BOB_INBOX).len(), 1);
    assert_ne!(
        inbox::members(&store.read_store(), ALICE_INBOX),
        inbox::members(&store.read_store(), BOB_INBOX)
    );
}

#[test]
fn removing_an_activity_takes_it_out_of_the_collection() {
    // What a Delete needs. A row left in the collection pointing at a cleared
    // graph is a hole in every timeline that renders it.
    let (_dir, store) = store();
    let activity = a_note("https://bob.brolly.test/~/notes/1", "hello");
    let id = deliver(&store, ALICE_INBOX, &activity, "2026-08-26T12:00:01Z").unwrap();

    store
        .write(|w| Ok(inbox::remove(w, ALICE_INBOX, &id)))
        .unwrap()
        .expect("remove");

    assert!(inbox::members(&store.read_store(), ALICE_INBOX).is_empty());
    assert!(inbox::read_activity(&store.read_store(), &id).is_none());
    assert!(inbox::timeline(&store.read_store(), ALICE_INBOX, &["Create"], 10, None).is_empty());
}
