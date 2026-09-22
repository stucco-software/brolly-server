//! Timelines.
//!
//! The home timeline is the single most important thing Phase 6 gets right,
//! because the predecessor got it wrong in a way that was both slow and
//! silently lossy. From the learnings:
//!
//! > `timelines.rs:140-162` reads the viewer's `following` collection, resolves
//! > each followee to a user, opens *that user's* store, and walks *their*
//! > outbox — N stores per request, to reassemble data that is already sitting
//! > in the one store it just closed.
//!
//! And worse than slow: it could only resolve *local* actors, so it dropped
//! every remote followee's posts with a `continue`. Push already put those
//! posts in the viewer's own inbox. Reading them back is one store open.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_mastodon::timeline;
use brolly_store::resources::Pod;
use serde_json::{Value, json};

const ALICE_INBOX: &str = "https://alice.brolly.test/inbox";

fn store() -> (tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = manager.pod(uuid::Uuid::new_v4()).unwrap();
    (dir, store)
}

fn note_id(seed: u8) -> String {
    brolly_mastodon::status_id::new_note_id(1_724_000_000_000 + seed as u64, [seed; 10])
}

/// A Create as the delivery path stores it.
fn create(author_host: &str, note: &str, content: &str) -> Value {
    json!({
        "type": "Create",
        "id": format!("https://{author_host}/~/notes/{note}/activity"),
        "actor": format!("https://{author_host}/actor"),
        "published": "2026-08-26T12:00:00Z",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "object": {
            "type": "Note",
            "id": format!("https://{author_host}/~/notes/{note}"),
            "attributedTo": format!("https://{author_host}/actor"),
            "content": content,
            "published": "2026-08-26T12:00:00Z",
        },
    })
}

fn deliver(store: &Pod, activity: &Value, at: &str) {
    store
        .write(|w| {
            Ok(brolly_activitypub::inbox::deliver(
                w,
                ALICE_INBOX,
                activity,
                at,
            ))
        })
        .expect("write")
        .expect("deliver");
}

// --- the regression that motivates the whole phase ---------------------------

#[test]
fn the_home_timeline_includes_remote_authors() {
    // The predecessor's outbox-walk resolved followees to *local* users and
    // `continue`d past everyone else, so a remote followee's posts silently
    // never appeared. Push already delivered them here; reading the inbox is
    // what makes them visible.
    let (_dir, store) = store();

    deliver(
        &store,
        &create("bob.brolly.test", &note_id(1), "local"),
        "2026-08-26T12:00:01Z",
    );
    deliver(
        &store,
        &create("mastodon.social", &note_id(2), "remote"),
        "2026-08-26T12:00:02Z",
    );

    let page = timeline::home(&store.read_store(), ALICE_INBOX, 20, None);

    assert_eq!(page.len(), 2, "a remote author's post was dropped");
    let contents: Vec<&str> = page
        .iter()
        .map(|e| e.note["content"].as_str().unwrap())
        .collect();
    assert!(contents.contains(&"remote"));
    assert!(contents.contains(&"local"));
}

#[test]
fn the_home_timeline_reads_one_store() {
    // Not an assertion about performance so much as about shape: everything the
    // timeline needs is already in the viewer's own store, so the function
    // signature takes exactly one and cannot fan out even by accident.
    let (_dir, store) = store();
    deliver(
        &store,
        &create("bob.brolly.test", &note_id(1), "hi"),
        "2026-08-26T12:00:01Z",
    );

    let page = timeline::home(&store.read_store(), ALICE_INBOX, 20, None);
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].author_actor, "https://bob.brolly.test/actor");
}

#[test]
fn the_home_timeline_unwraps_the_note_from_its_activity() {
    // Clients want the Note, not the Create that carried it.
    let (_dir, store) = store();
    let id = note_id(1);
    deliver(
        &store,
        &create("bob.brolly.test", &id, "hello"),
        "2026-08-26T12:00:01Z",
    );

    let page = timeline::home(&store.read_store(), ALICE_INBOX, 20, None);
    assert_eq!(page[0].note["type"], "Note");
    assert_eq!(page[0].note["content"], "hello");
    assert_eq!(
        page[0].note["id"],
        format!("https://bob.brolly.test/~/notes/{id}")
    );
}

#[test]
fn the_home_timeline_is_newest_first() {
    let (_dir, store) = store();
    for n in 1..=3u8 {
        deliver(
            &store,
            &create("bob.brolly.test", &note_id(n), &format!("post {n}")),
            &format!("2026-08-26T12:00:0{n}Z"),
        );
    }

    let page = timeline::home(&store.read_store(), ALICE_INBOX, 20, None);
    let contents: Vec<&str> = page
        .iter()
        .map(|e| e.note["content"].as_str().unwrap())
        .collect();
    assert_eq!(contents, vec!["post 3", "post 2", "post 1"]);
}

#[test]
fn the_home_timeline_shows_posts_and_boosts_but_not_follows() {
    // A Follow belongs in notifications. Rendering it as a status shows an
    // empty post in the timeline.
    let (_dir, store) = store();
    deliver(
        &store,
        &create("bob.brolly.test", &note_id(1), "a post"),
        "2026-08-26T12:00:01Z",
    );
    deliver(
        &store,
        &json!({
            "type": "Follow",
            "id": "https://bob.brolly.test/~/follows/1",
            "actor": "https://bob.brolly.test/actor",
            "object": "https://alice.brolly.test/actor",
        }),
        "2026-08-26T12:00:02Z",
    );
    deliver(
        &store,
        &json!({
            "type": "Announce",
            "id": "https://bob.brolly.test/~/announces/1",
            "actor": "https://bob.brolly.test/actor",
            "object": {
                "type": "Note",
                "id": format!("https://carol.brolly.test/~/notes/{}", note_id(9)),
                "attributedTo": "https://carol.brolly.test/actor",
                "content": "boosted",
                "published": "2026-08-26T12:00:00Z",
            },
        }),
        "2026-08-26T12:00:03Z",
    );

    let page = timeline::home(&store.read_store(), ALICE_INBOX, 20, None);
    assert_eq!(page.len(), 2, "expected the post and the boost only");
    assert!(
        page.iter().all(|e| e.note["type"] == "Note"),
        "a non-Note leaked into the timeline"
    );
}

#[test]
fn the_home_timeline_paginates_without_repeating_the_boundary() {
    let (_dir, store) = store();
    for n in 1..=5u8 {
        deliver(
            &store,
            &create("bob.brolly.test", &note_id(n), &format!("post {n}")),
            &format!("2026-08-26T12:00:0{n}Z"),
        );
    }

    let first = timeline::home(&store.read_store(), ALICE_INBOX, 2, None);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].note["content"], "post 5");

    let second = timeline::home(&store.read_store(), ALICE_INBOX, 2, Some(&first[1].cursor));
    assert_eq!(second.len(), 2);
    assert_eq!(
        second[0].note["content"], "post 3",
        "the page boundary was repeated"
    );
}

#[test]
fn an_empty_inbox_is_an_empty_timeline_not_an_error() {
    let (_dir, store) = store();
    assert!(timeline::home(&store.read_store(), ALICE_INBOX, 20, None).is_empty());
}

#[test]
fn an_activity_whose_object_is_only_a_reference_is_skipped() {
    // A Create carrying a bare IRI rather than an embedded object has nothing
    // to render. Emitting a status with null content would show an empty post.
    let (_dir, store) = store();
    deliver(
        &store,
        &json!({
            "type": "Create",
            "id": "https://bob.brolly.test/~/notes/x/activity",
            "actor": "https://bob.brolly.test/actor",
            "object": "https://bob.brolly.test/~/notes/x",
        }),
        "2026-08-26T12:00:01Z",
    );

    assert!(timeline::home(&store.read_store(), ALICE_INBOX, 20, None).is_empty());
}

// --- public timeline ---------------------------------------------------------

#[test]
fn the_public_timeline_dereferences_only_the_page_it_returns() {
    // D5: the index holds pointers, never content. The cost of a page is the
    // page size, not the size of the instance — which is the entire reason the
    // index is allowed to exist.
    let pointers: Vec<String> = (1..=10)
        .map(|n| format!("https://alice.brolly.test/~/notes/{}", note_id(n)))
        .collect();

    let fetched = std::cell::RefCell::new(Vec::new());
    let page = timeline::public(&pointers[..3], |iri| {
        fetched.borrow_mut().push(iri.to_string());
        Some(json!({
            "type": "Note",
            "id": iri,
            "content": "hello",
            "published": "2026-08-26T12:00:00Z",
        }))
    });

    assert_eq!(page.len(), 3);
    assert_eq!(
        fetched.borrow().len(),
        3,
        "dereferenced more notes than the page contains"
    );
}

#[test]
fn a_dangling_pointer_is_skipped_rather_than_failing_the_page() {
    // D5 again: dangling rows are the correct steady state, because deleting a
    // member is `rm -rf` on one directory and the index sweeps lazily. One
    // deleted note must not blank the whole public timeline.
    let pointers = [
        "https://alice.brolly.test/~/notes/gone".to_string(),
        format!("https://alice.brolly.test/~/notes/{}", note_id(1)),
    ];

    let page = timeline::public(&pointers, |iri| {
        // The pod is gone, so the dereference finds nothing.
        if iri.ends_with("gone") {
            return None;
        }
        Some(json!({
            "type": "Note",
            "id": iri,
            "content": "still here",
            "published": "2026-08-26T12:00:00Z",
        }))
    });

    assert_eq!(page.len(), 1, "a dangling pointer took the page down");
    assert_eq!(page[0].note["content"], "still here");
}
