//! Delivery processing, and the instance as a second subscriber.
//!
//! From the learnings: the server agent is "a delivery recipient like any
//! other: local activities are delivered to it, and its processor writes the
//! pointer row. The public timeline is then literally the server actor's
//! inbox... The same delivery path that fills a user's inbox fills the index —
//! one mechanism, two subscribers, no crawler to schedule or debug."
//!
//! The two subscribers do different things with the same activity, and that
//! difference is the whole design: a member's processor stores content, the
//! instance's stores a pointer and never content (D5).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_activitypub::inbox;
use brolly_activitypub::processor::{self, Recipient};
use brolly_store::{Store, StoreManager, index};
use oxigraph::model::{GraphNameRef, NamedNode};
use serde_json::{Value, json};

const ALICE_INBOX: &str = "https://alice.brolly.test/inbox";
const BOB_ACTOR: &str = "https://bob.brolly.test/actor";
const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";
const NOTE: &str = "https://bob.brolly.test/~/notes/1";
const ACTIVITY: &str = "https://bob.brolly.test/~/notes/1/activity";

fn stores() -> (tempfile::TempDir, StoreManager) {
    let dir = tempfile::tempdir().unwrap();
    let manager = StoreManager::open(dir.path(), 4, 60).unwrap();
    (dir, manager)
}

fn create(audience: &str, content: &str) -> Value {
    json!({
        "type": "Create",
        "id": ACTIVITY,
        "actor": BOB_ACTOR,
        "published": "2026-08-26T12:00:00Z",
        "to": [audience],
        "object": {
            "type": "Note",
            "id": NOTE,
            "attributedTo": BOB_ACTOR,
            "content": content,
            "published": "2026-08-26T12:00:00Z",
        },
    })
}

/// Every literal anywhere in a store, for the "no content" assertion.
fn literals(store: &Store) -> Vec<String> {
    store
        .quads_for_pattern(None, None, None, None)
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            oxigraph::model::Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
        .collect()
}

// --- the member subscriber --------------------------------------------------

#[test]
fn a_create_delivered_to_a_member_lands_in_their_inbox() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX },
        &create(PUBLIC, "hello"),
        "2026-08-26T12:00:01Z",
    )
    .expect("process");

    let timeline = inbox::timeline(&pod, ALICE_INBOX, &["Create"], 10, None);
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].activity, ACTIVITY);

    // The member's copy is the content itself — this is their home timeline.
    let note = inbox::read_activity(&pod, NOTE).expect("the note");
    assert_eq!(note["content"], "hello");
}

// --- the instance subscriber ------------------------------------------------

#[test]
fn a_public_create_delivered_to_the_instance_becomes_a_pointer() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process(
        index_store,
        Recipient::Instance,
        &create(PUBLIC, "hello"),
        "2026-08-26T12:00:01Z",
    )
    .expect("process");

    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");

    assert_eq!(page.len(), 1);
    assert_eq!(page[0].note.as_str(), NOTE, "the pointer names the note");
    assert_eq!(page[0].author.as_str(), BOB_ACTOR);
    assert_eq!(page[0].published, "2026-08-26T12:00:00Z");
}

#[test]
fn the_instance_stores_a_pointer_and_never_content() {
    // D5, enforced where it can actually be violated. The index is a
    // denormalization; the moment it holds content it stops being one and
    // starts being a second source of truth nobody remembers is derived.
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process(
        index_store,
        Recipient::Instance,
        &create(PUBLIC, "a distinctive body nobody else would write"),
        "2026-08-26T12:00:01Z",
    )
    .expect("process");

    let stored = literals(index_store);
    assert!(
        !stored
            .iter()
            .any(|l| l.contains("a distinctive body nobody else would write")),
        "post content reached the server index: {stored:?}"
    );

    // And nothing outside the allowlist got in.
    let predicates: Vec<String> = index_store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(
                NamedNode::new_unchecked(index::PUBLIC_TIMELINE).as_ref(),
            )),
        )
        .filter_map(Result::ok)
        .map(|q| q.predicate.as_str().to_string())
        .collect();
    assert!(!predicates.is_empty());
    for predicate in &predicates {
        assert!(
            index::ALLOWED_PREDICATES.contains(&predicate.as_str()),
            "{predicate} is not a pointer or filter key"
        );
    }
}

#[test]
fn a_private_post_never_reaches_the_public_index() {
    // The index backs the *public* timeline. A followers-only post delivered
    // to the instance must be stored by nobody — indexing it would publish it.
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process(
        index_store,
        Recipient::Instance,
        &create("https://bob.brolly.test/followers", "just for followers"),
        "2026-08-26T12:00:01Z",
    )
    .expect("process");

    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");
    assert!(page.is_empty(), "a private post was indexed");
    assert_eq!(index::count_notes(index_store).unwrap(), 0);
}

#[test]
fn a_like_is_a_notification_and_not_a_timeline_entry() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    let like = json!({
        "type": "Like",
        "id": "https://bob.brolly.test/~/likes/1",
        "actor": BOB_ACTOR,
        "object": NOTE,
    });

    processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX },
        &like,
        "2026-08-26T12:00:01Z",
    )
    .expect("member");
    processor::process(
        index_store,
        Recipient::Instance,
        &like,
        "2026-08-26T12:00:01Z",
    )
    .expect("instance");

    // The member sees it — that is a notification.
    assert_eq!(
        inbox::timeline(&pod, ALICE_INBOX, &["Like"], 10, None).len(),
        1
    );
    // The public timeline does not — a Like is not a post.
    assert_eq!(index::count_notes(index_store).unwrap(), 0);
}

#[test]
fn an_announce_is_indexed_like_a_create() {
    // A boost is how a post reaches the public timeline of an instance whose
    // members do not follow the author.
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process(
        index_store,
        Recipient::Instance,
        &json!({
            "type": "Announce",
            "id": "https://bob.brolly.test/~/boosts/1",
            "actor": BOB_ACTOR,
            "published": "2026-08-26T12:05:00Z",
            "to": [PUBLIC],
            "object": "https://carol.example/notes/9",
        }),
        "2026-08-26T12:05:01Z",
    )
    .expect("process");

    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");
    assert_eq!(page.len(), 1);
    assert_eq!(
        page[0].note.as_str(),
        "https://carol.example/notes/9",
        "the pointer names the announced note, not the Announce"
    );
}

#[test]
fn a_reply_records_what_it_replies_to() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    let mut reply = create(PUBLIC, "replying");
    reply["id"] = json!("https://bob.brolly.test/~/notes/2/activity");
    reply["object"]["id"] = json!("https://bob.brolly.test/~/notes/2");
    reply["object"]["inReplyTo"] = json!(NOTE);

    processor::process(
        index_store,
        Recipient::Instance,
        &reply,
        "2026-08-26T12:00:01Z",
    )
    .expect("process");

    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");
    assert_eq!(
        page[0].in_reply_to.as_ref().map(|n| n.as_str()),
        Some(NOTE),
        "threading needs the parent, and it is a filter key not content"
    );
}

// --- deletion ---------------------------------------------------------------

#[test]
fn a_delete_removes_both_the_members_copy_and_the_pointer() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    let activity = create(PUBLIC, "regrettable");

    for (store, recipient) in [
        (&pod, Recipient::Member { inbox: ALICE_INBOX }),
        (index_store, Recipient::Instance),
    ] {
        processor::process(store, recipient, &activity, "2026-08-26T12:00:01Z").unwrap();
    }
    assert_eq!(index::count_notes(index_store).unwrap(), 1);

    let delete = json!({
        "type": "Delete",
        "id": "https://bob.brolly.test/~/deletes/1",
        "actor": BOB_ACTOR,
        "object": NOTE,
    });
    processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX },
        &delete,
        "2026-08-26T12:01:00Z",
    )
    .unwrap();
    processor::process(
        index_store,
        Recipient::Instance,
        &delete,
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert_eq!(
        index::count_notes(index_store).unwrap(),
        0,
        "the pointer must go"
    );
    assert!(
        inbox::read_activity(&pod, NOTE).is_none(),
        "the member's copy must go"
    );
    assert!(
        inbox::timeline(&pod, ALICE_INBOX, &["Create"], 10, None).is_empty(),
        "and it must leave no hole in the timeline"
    );
}

#[test]
fn a_delete_for_something_we_never_had_is_not_an_error() {
    // Deletes arrive for posts an instance never saw all the time — the sender
    // fans out to every follower's instance regardless of what each stored.
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process(
        index_store,
        Recipient::Instance,
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/deletes/1",
            "actor": BOB_ACTOR,
            "object": "https://bob.brolly.test/~/notes/never-seen",
        }),
        "2026-08-26T12:01:00Z",
    )
    .expect("a delete for an unknown object must be a no-op, not a failure");
}

// --- what the index is not --------------------------------------------------

#[test]
fn the_index_only_ever_grows_by_delivery() {
    // "The index is populated by push, never by crawling." There is no other
    // way in: the only public writer is the processor.
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    // A member's pod filling up must not move the index by itself.
    processor::process(
        &pod,
        Recipient::Member { inbox: ALICE_INBOX },
        &create(PUBLIC, "hello"),
        "2026-08-26T12:00:01Z",
    )
    .unwrap();

    assert_eq!(
        index::count_notes(index_store).unwrap(),
        0,
        "writing to a pod must not populate the index — only delivery does"
    );
}
