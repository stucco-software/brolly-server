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

use brolly_activitypub::inbox::{self, InboxError};
use brolly_activitypub::processor::{self, ProcessError};
use brolly_store::resources::{Pod, PodRead};
use brolly_store::{StoreManager, index};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::{Value, json};

const ALICE_INBOX: &str = "https://alice.brolly.test/inbox";
const BOB_ACTOR: &str = "https://bob.brolly.test/actor";
const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";
const NOTE: &str = "https://bob.brolly.test/~/notes/1";
const ACTIVITY: &str = "https://bob.brolly.test/~/notes/1/activity";
const ALICE_ACL: &str = "https://alice.brolly.test/~/.acl";
const ALICE_OUTBOX: &str = "https://alice.brolly.test/outbox";
const BOB_INBOX: &str = "https://bob.brolly.test/inbox";
const BOB_OUTBOX: &str = "https://bob.brolly.test/outbox";
const BOB_ACL: &str = "https://bob.brolly.test/~/.acl";
const MALLORY_ACTOR: &str = "https://mallory.brolly.test/actor";

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

/// Deliver to a member in one write, as `outbox` does.
fn member(
    pod: &Pod,
    inbox: &str,
    outbox: &str,
    activity: &Value,
    at: &str,
) -> Result<(), ProcessError> {
    pod.write(|w| Ok(processor::process_member(w, inbox, outbox, activity, at)))
        .map_err(ProcessError::from)
        .flatten()
}

/// Store an author's copy straight into a collection, as `outbox::deliver` does.
fn deliver(pod: &Pod, collection: &str, activity: &Value, at: &str) -> Result<String, InboxError> {
    pod.write(|w| Ok(inbox::deliver(w, collection, activity, at)))
        .map_err(InboxError::from)
        .flatten()
}

/// Every literal anywhere in a store, for the "no content" assertion.
fn literals(store: &impl PodRead) -> Vec<String> {
    store
        .quads_for_pattern(None, None, None, None)
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            oxigraph::model::Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
        .collect()
}

/// Put one quad in `name`, standing in for a resource someone would attack.
/// Straight into the store (`test-fixtures`), so the setup doesn't depend on
/// the code under test.
fn seed(pod: &Pod, name: &str) {
    pod.raw_store()
        .insert(&Quad::new(
            NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(format!("{name}#owner"))),
            NamedNode::new_unchecked("http://www.w3.org/ns/auth/acl#mode"),
            Term::NamedNode(NamedNode::new_unchecked(
                "http://www.w3.org/ns/auth/acl#Control",
            )),
            GraphName::NamedNode(NamedNode::new_unchecked(name)),
        ))
        .unwrap();
}

/// Every quad in one graph, as sorted text, so "untouched" compares content
/// and not only size.
fn graph(store: &impl PodRead, name: &str) -> Vec<String> {
    let mut quads: Vec<String> = store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(
                NamedNode::new_unchecked(name).as_ref(),
            )),
        )
        .filter_map(Result::ok)
        .map(|quad| quad.to_string())
        .collect();
    quads.sort();
    quads
}

// --- the member subscriber --------------------------------------------------

#[test]
fn a_create_delivered_to_a_member_lands_in_their_inbox() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &create(PUBLIC, "hello"),
        "2026-08-26T12:00:01Z",
    )
    .expect("process");

    let timeline = inbox::timeline(&pod.read_store(), ALICE_INBOX, &["Create"], 10, None);
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].activity, ACTIVITY);

    // The member's copy is the content itself — this is their home timeline.
    let note = inbox::read_activity(&pod.read_store(), NOTE).expect("the note");
    assert_eq!(note["content"], "hello");
}

// --- the instance subscriber ------------------------------------------------

#[test]
fn a_public_create_delivered_to_the_instance_becomes_a_pointer() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process_instance(index_store, &create(PUBLIC, "hello")).expect("process");

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

    processor::process_instance(
        index_store,
        &create(PUBLIC, "a distinctive body nobody else would write"),
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

    processor::process_instance(
        index_store,
        &create("https://bob.brolly.test/followers", "just for followers"),
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

    member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &like,
        "2026-08-26T12:00:01Z",
    )
    .expect("member");
    processor::process_instance(index_store, &like).expect("instance");

    // The member sees it — that is a notification.
    assert_eq!(
        inbox::timeline(&pod.read_store(), ALICE_INBOX, &["Like"], 10, None).len(),
        1
    );
    // The public timeline does not — a Like is not a post.
    assert_eq!(index::count_notes(index_store).unwrap(), 0);
}

#[test]
fn an_announce_is_indexed_like_a_create() {
    // A boost keeps an already-public post on the public timeline, under its
    // author. It can't put one there: the note has to be indexed first, by its
    // own public Create, or a boost of a followers-only post would publish it.
    const CAROL_ACTOR: &str = "https://carol.example/actor";
    const CAROL_NOTE: &str = "https://carol.example/notes/9";
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process_instance(
        index_store,
        &json!({
            "type": "Create",
            "id": "https://carol.example/notes/9/activity",
            "actor": CAROL_ACTOR,
            "published": "2026-08-26T12:00:00Z",
            "to": [PUBLIC],
            "object": {"type": "Note", "id": CAROL_NOTE, "attributedTo": CAROL_ACTOR},
        }),
    )
    .expect("setup: carol's post is public");

    processor::process_instance(
        index_store,
        &json!({
            "type": "Announce",
            "id": "https://bob.brolly.test/~/boosts/1",
            "actor": BOB_ACTOR,
            "published": "2026-08-26T12:05:00Z",
            "to": [PUBLIC],
            "object": CAROL_NOTE,
        }),
    )
    .expect("process");

    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");
    assert_eq!(page.len(), 1, "{page:?}");
    assert_eq!(
        page[0].note.as_str(),
        CAROL_NOTE,
        "the pointer names the announced note, not the Announce"
    );
    assert_eq!(
        page[0].author.as_str(),
        CAROL_ACTOR,
        "a boost doesn't change whose post it is"
    );
    assert_eq!(page[0].published, "2026-08-26T12:00:00Z");
}

#[test]
fn a_reply_records_what_it_replies_to() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    let mut reply = create(PUBLIC, "replying");
    reply["id"] = json!("https://bob.brolly.test/~/notes/2/activity");
    reply["object"]["id"] = json!("https://bob.brolly.test/~/notes/2");
    reply["object"]["inReplyTo"] = json!(NOTE);

    processor::process_instance(index_store, &reply).expect("process");

    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");
    assert_eq!(
        page[0].in_reply_to.as_ref().map(|n| n.as_str()),
        Some(NOTE),
        "threading needs the parent, and it is a filter key not content"
    );
}

#[test]
fn a_create_naming_someone_elses_note_is_not_indexed() {
    // A Create publishes the actor's own note. Indexing one that names somebody
    // else's would put it on the public timeline under the wrong name.
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process_instance(
        index_store,
        &json!({
            "type": "Create",
            "id": "https://mallory.brolly.test/~/activities/1",
            "actor": MALLORY_ACTOR,
            "to": [PUBLIC],
            "object": NOTE,
        }),
    )
    .unwrap();

    assert_eq!(index::count_notes(index_store).unwrap(), 0);
}

#[test]
fn an_announce_of_a_note_nobody_indexed_is_not_indexed() {
    // Bob's post is for his followers only, so the instance didn't index it.
    // Mallory can see it and boosts it publicly. If the boost were indexed, the
    // public timeline would read Bob's followers-only post out of his pod and
    // show it to everyone.
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    processor::process_instance(
        index_store,
        &create("https://bob.brolly.test/followers", "just for followers"),
    )
    .unwrap();
    assert!(
        graph(index_store, index::PUBLIC_TIMELINE).is_empty(),
        "setup"
    );

    processor::process_instance(
        index_store,
        &json!({
            "type": "Announce",
            "id": "https://mallory.brolly.test/~/activities/1",
            "actor": MALLORY_ACTOR,
            "published": "2026-08-26T12:05:00Z",
            "to": [PUBLIC],
            "object": NOTE,
        }),
    )
    .unwrap();

    assert!(
        graph(index_store, index::PUBLIC_TIMELINE).is_empty(),
        "a boost published a note nobody had made public"
    );
    assert_eq!(index::count_notes(index_store).unwrap(), 0);
}

#[test]
fn an_announce_of_an_indexed_note_keeps_its_author_and_its_place() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    const LATER: &str = "https://bob.brolly.test/~/notes/2";

    // Bob posts NOTE at 12:00 and LATER at 12:03, both public.
    let mut later = create(PUBLIC, "later");
    later["id"] = json!("https://bob.brolly.test/~/notes/2/activity");
    later["published"] = json!("2026-08-26T12:03:00Z");
    later["object"]["id"] = json!(LATER);
    later["object"]["published"] = json!("2026-08-26T12:03:00Z");
    for activity in [create(PUBLIC, "hello"), later] {
        processor::process_instance(index_store, &activity).unwrap();
    }

    // Mallory boosts the older one at 12:05.
    processor::process_instance(
        index_store,
        &json!({
            "type": "Announce",
            "id": "https://mallory.brolly.test/~/activities/1",
            "actor": MALLORY_ACTOR,
            "published": "2026-08-26T12:05:00Z",
            "to": [PUBLIC],
            "object": NOTE,
        }),
    )
    .unwrap();

    assert_eq!(
        index::count_notes(index_store).unwrap(),
        2,
        "the Announce added a second author"
    );
    let page = index::public_timeline(index_store, &NamedNode::new_unchecked(PUBLIC), 10, None)
        .expect("query");
    let rows: Vec<(&str, &str, &str)> = page
        .iter()
        .map(|row| {
            (
                row.note.as_str(),
                row.author.as_str(),
                row.published.as_str(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (LATER, BOB_ACTOR, "2026-08-26T12:03:00Z"),
            (NOTE, BOB_ACTOR, "2026-08-26T12:00:00Z"),
        ],
        "the boosted note moved, or appears twice"
    );
}

// --- deletion ---------------------------------------------------------------

#[test]
fn a_delete_removes_both_the_members_copy_and_the_pointer() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    let activity = create(PUBLIC, "regrettable");

    member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &activity,
        "2026-08-26T12:00:01Z",
    )
    .unwrap();
    processor::process_instance(index_store, &activity).unwrap();
    assert_eq!(index::count_notes(index_store).unwrap(), 1);

    let delete = json!({
        "type": "Delete",
        "id": "https://bob.brolly.test/~/deletes/1",
        "actor": BOB_ACTOR,
        "object": NOTE,
    });
    member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &delete,
        "2026-08-26T12:01:00Z",
    )
    .unwrap();
    processor::process_instance(index_store, &delete).unwrap();

    assert_eq!(
        index::count_notes(index_store).unwrap(),
        0,
        "the pointer must go"
    );
    assert!(
        inbox::read_activity(&pod.read_store(), NOTE).is_none(),
        "the member's copy must go"
    );
    assert!(
        inbox::timeline(&pod.read_store(), ALICE_INBOX, &["Create"], 10, None).is_empty(),
        "and it must leave no hole in the timeline"
    );
}

#[test]
fn a_delete_for_something_we_never_had_is_not_an_error() {
    // Deletes arrive for posts an instance never saw all the time — the sender
    // fans out to every follower's instance regardless of what each stored.
    let (_dir, manager) = stores();
    let index_store = manager.instance();

    processor::process_instance(
        index_store,
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/deletes/1",
            "actor": BOB_ACTOR,
            "object": "https://bob.brolly.test/~/notes/never-seen",
        }),
    )
    .expect("a delete for an unknown object must be a no-op, not a failure");
}

#[test]
fn a_delete_of_a_graph_on_another_origin_removes_nothing() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, ALICE_ACL);
    let before = graph(&pod.read_store(), ALICE_ACL);

    member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/activities/9",
            "actor": BOB_ACTOR,
            "object": ALICE_ACL,
        }),
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert_eq!(
        graph(&pod.read_store(), ALICE_ACL),
        before,
        "Bob's Delete cleared Alice's ACL"
    );
}

#[test]
fn a_delete_removes_only_what_arrived_embedded() {
    // Bob's own pod. Origin alone would let him clear his own ACL through
    // delivery without WAC ever seeing the request.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, BOB_ACL);
    let before = graph(&pod.read_store(), BOB_ACL);

    // Named, not embedded: a string object is a graph delivery never wrote.
    deliver(
        &pod,
        BOB_OUTBOX,
        &json!({
            "type": "Create",
            "id": "https://bob.brolly.test/~/activities/1",
            "actor": BOB_ACTOR,
            "to": [PUBLIC],
            "object": BOB_ACL,
        }),
        "2026-08-26T12:00:00Z",
    )
    .unwrap();

    member(
        &pod,
        BOB_INBOX,
        BOB_OUTBOX,
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/activities/2",
            "actor": BOB_ACTOR,
            "object": BOB_ACL,
        }),
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert_eq!(
        graph(&pod.read_store(), BOB_ACL),
        before,
        "a Delete reached an LDP resource"
    );
}

#[test]
fn a_delete_also_clears_the_authors_outbox_copy() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    // Stored the way outbox::deliver stores the author's copy: straight into
    // the outbox, not through `process`.
    deliver(
        &pod,
        BOB_OUTBOX,
        &create(PUBLIC, "regrettable"),
        "2026-08-26T12:00:00Z",
    )
    .unwrap();

    member(
        &pod,
        BOB_INBOX,
        BOB_OUTBOX,
        &json!({
            "type": "Delete",
            "id": "https://bob.brolly.test/~/activities/2",
            "actor": BOB_ACTOR,
            "object": NOTE,
        }),
        "2026-08-26T12:01:00Z",
    )
    .unwrap();

    assert!(
        inbox::read_activity(&pod.read_store(), NOTE).is_none(),
        "the note survived"
    );
    assert!(
        inbox::read_activity(&pod.read_store(), ACTIVITY).is_none(),
        "the Create that carried it survived"
    );
    assert!(
        inbox::members(&pod.read_store(), BOB_OUTBOX).is_empty(),
        "the outbox still lists a deleted post"
    );
}

#[test]
fn a_delete_from_another_origin_leaves_the_pointer() {
    let (_dir, manager) = stores();
    let index_store = manager.instance();
    processor::process_instance(index_store, &create(PUBLIC, "hello")).unwrap();

    processor::process_instance(
        index_store,
        &json!({
            "type": "Delete",
            "id": "https://mallory.brolly.test/~/activities/2",
            "actor": MALLORY_ACTOR,
            "object": NOTE,
        }),
    )
    .unwrap();

    assert_eq!(
        index::count_notes(index_store).unwrap(),
        1,
        "Mallory took Bob's post off the public timeline"
    );
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
    member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
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

// --- origin -----------------------------------------------------------------

#[test]
fn an_embedded_object_on_another_origin_is_refused_and_writes_nothing() {
    // The hole: Bob's Create, carrying an object whose id is Alice's root ACL,
    // cleared that graph and wrote Bob's content into it.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, ALICE_ACL);
    let before = graph(&pod.read_store(), ALICE_ACL);

    let mut attack = create(PUBLIC, "bob holds acl:Control now");
    attack["object"]["id"] = json!(ALICE_ACL);

    let delivered = member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &attack,
        "2026-08-26T12:00:01Z",
    );
    assert!(
        matches!(delivered, Err(ProcessError::ForeignObject)),
        "got {delivered:?}"
    );
    assert_eq!(
        graph(&pod.read_store(), ALICE_ACL),
        before,
        "the ACL graph was rewritten"
    );
    assert!(
        inbox::members(&pod.read_store(), ALICE_INBOX).is_empty(),
        "a refused activity must not be delivered at all"
    );

    let indexed = processor::process_instance(manager.instance(), &attack);
    assert!(
        matches!(indexed, Err(ProcessError::ForeignObject)),
        "got {indexed:?}"
    );
    assert_eq!(index::count_notes(manager.instance()).unwrap(), 0);
}

#[test]
fn an_activity_whose_own_id_is_on_another_origin_is_refused() {
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    seed(&pod, ALICE_ACL);
    let before = graph(&pod.read_store(), ALICE_ACL);

    let mut attack = create(PUBLIC, "hello");
    attack["id"] = json!(ALICE_ACL);

    let result = member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &attack,
        "2026-08-26T12:00:01Z",
    );
    assert!(
        matches!(result, Err(ProcessError::ForeignObject)),
        "got {result:?}"
    );
    assert_eq!(graph(&pod.read_store(), ALICE_ACL), before);
}

#[test]
fn an_activity_without_an_actor_is_refused() {
    // With no actor there is no origin to check against, so nothing is owned.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    let mut anonymous = create(PUBLIC, "hello");
    anonymous.as_object_mut().unwrap().remove("actor");

    let result = member(
        &pod,
        ALICE_INBOX,
        ALICE_OUTBOX,
        &anonymous,
        "2026-08-26T12:00:01Z",
    );
    assert!(
        matches!(result, Err(ProcessError::ForeignObject)),
        "got {result:?}"
    );
}

#[test]
fn a_reference_may_name_anyone() {
    // A Like or a Follow names another actor's IRI by definition. Only embedded
    // objects are held to the actor's origin.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();

    for activity in [
        json!({
            "type": "Like",
            "id": "https://bob.brolly.test/~/activities/1",
            "actor": BOB_ACTOR,
            "object": "https://alice.brolly.test/~/notes/1",
        }),
        json!({
            "type": "Follow",
            "id": "https://bob.brolly.test/~/activities/2",
            "actor": BOB_ACTOR,
            "object": "https://alice.brolly.test/actor",
        }),
    ] {
        member(
            &pod,
            ALICE_INBOX,
            ALICE_OUTBOX,
            &activity,
            "2026-08-26T12:00:01Z",
        )
        .expect("a reference is not a foreign object");
    }

    assert_eq!(inbox::members(&pod.read_store(), ALICE_INBOX).len(), 2);
}

// --- reads inside a write ---------------------------------------------------

#[test]
fn a_reader_inside_a_write_sees_that_writes_own_changes() {
    // The carrier check reads the collection it is about to change. Inside one
    // write it has to see the author's copy stored earlier in the same closure,
    // or a Delete composed with its Create would find nothing to remove.
    let (_dir, manager) = stores();
    let pod = manager.pod(uuid::Uuid::new_v4()).unwrap();
    let delete = json!({
        "type": "Delete",
        "id": "https://bob.brolly.test/~/activities/2",
        "actor": BOB_ACTOR,
        "object": NOTE,
    });

    let (stored, deleted) = pod
        .write(|w| {
            let stored = inbox::deliver(
                w,
                BOB_OUTBOX,
                &create(PUBLIC, "short-lived"),
                "2026-08-26T12:00:00Z",
            );
            let deleted = processor::process_member(
                w,
                BOB_INBOX,
                BOB_OUTBOX,
                &delete,
                "2026-08-26T12:00:01Z",
            );
            Ok((stored, deleted))
        })
        .unwrap();
    stored.unwrap();
    deleted.unwrap();

    assert!(
        inbox::read_activity(&pod.read_store(), NOTE).is_none(),
        "the note survived"
    );
    assert!(
        inbox::members(&pod.read_store(), BOB_OUTBOX).is_empty(),
        "the outbox still lists it"
    );
}
