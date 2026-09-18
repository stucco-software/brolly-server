//! Phase 2 invariants, as tests rather than conventions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_domain::iri::{iris_in, is_canonical};
use brolly_store::index::{self, NotePointer};
use brolly_store::{StoreManager, insert_quads, insert_record};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::json;
use uuid::Uuid;

fn node(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn manager() -> (StoreManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mgr = StoreManager::open(dir.path(), 8, 60).expect("open manager");
    (mgr, dir)
}

// --- the write path canonicalizes ------------------------------------------

#[test]
fn non_canonical_iris_cannot_survive_the_write_path() {
    let (mgr, _dir) = manager();
    let user = Uuid::new_v4();
    let pod = mgr.pod(user).unwrap();
    let graph = node("https://alice.brolly.id/inbox");

    // Exactly what Mastodon sends: the http spelling of AS2.
    let hostile = vec![Quad::new(
        NamedOrBlankNode::NamedNode(node("https://alice.brolly.id/notes/1")),
        node("http://www.w3.org/ns/activitystreams#content"),
        Term::NamedNode(node("http://www.w3.org/ns/activitystreams#Public")),
        GraphName::NamedNode(graph.clone()),
    )];
    insert_quads(&pod, &hostile).unwrap();

    let stored: Vec<Quad> = pod
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(graph.as_ref())),
        )
        .filter_map(Result::ok)
        .collect();

    assert!(!stored.is_empty());
    for quad in &stored {
        for iri in iris_in(quad) {
            assert!(is_canonical(iri), "{iri} reached storage non-canonical");
        }
    }
}

#[test]
fn records_round_trip_through_a_real_store() {
    let (mgr, _dir) = manager();
    let pod = mgr.pod(Uuid::new_v4()).unwrap();
    let subject = node("https://alice.brolly.id/records/1");

    let record = json!({
        "$type": "app.bsky.feed.post",
        "text": "stored and read back",
        "langs": ["en"],
        "reply": {"root": {"uri": "at://x/1"}}
    });
    insert_record(&pod, &record, &subject, &subject, "app.bsky.feed.post").unwrap();

    let quads: Vec<Quad> = pod
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(subject.as_ref())),
        )
        .filter_map(Result::ok)
        .collect();

    let decoded = brolly_domain::faithful::decode(&quads, &subject).unwrap();
    assert_eq!(decoded, record, "storage must not be lossy");
}

// --- pods are isolated ------------------------------------------------------

#[test]
fn pods_are_isolated_and_delete_is_rm_rf() {
    let (mgr, _dir) = manager();
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();
    let subject = node("https://alice.brolly.id/records/1");

    insert_record(
        &mgr.pod(alice).unwrap(),
        &json!({"text": "alice's"}),
        &subject,
        &subject,
        "test.note",
    )
    .unwrap();

    let bob_pod = mgr.pod(bob).unwrap();
    assert_eq!(
        bob_pod.quads_for_pattern(None, None, None, None).count(),
        0,
        "one user's write must not appear in another's pod"
    );

    assert!(mgr.pod_bytes(alice).unwrap() > 0);
    mgr.delete_pod(alice).unwrap();
    assert!(!mgr.pod_exists(alice));
    assert_eq!(mgr.pod_bytes(alice).unwrap(), 0, "delete is rm -rf");
}

// --- the index holds pointers, never content --------------------------------

fn seed_index(store: &oxigraph::store::Store) {
    for (n, when) in [("1", "2026-08-18T10:00:00Z"), ("2", "2026-08-18T11:00:00Z")] {
        index::record_note(
            store,
            &NotePointer {
                note: node(&format!("https://alice.brolly.id/notes/{n}")),
                author: node("https://alice.brolly.id/actor"),
                published: when.to_string(),
                audience: node("https://www.w3.org/ns/activitystreams#Public"),
                in_reply_to: None,
            },
        )
        .unwrap();
    }
}

#[test]
fn the_index_uses_only_allowlisted_predicates() {
    let (mgr, _dir) = manager();
    seed_index(mgr.instance());

    let used: Vec<String> = mgr
        .instance()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(
                node(index::PUBLIC_TIMELINE).as_ref(),
            )),
        )
        .filter_map(Result::ok)
        .map(|q| q.predicate.as_str().to_string())
        .collect();

    assert!(!used.is_empty());
    for predicate in &used {
        assert!(
            index::ALLOWED_PREDICATES.contains(&predicate.as_str()),
            "{predicate} is not a pointer or filter key — the index must never hold content"
        );
    }
    assert!(
        !used
            .iter()
            .any(|p| p.contains("content") || p.contains("#text")),
        "content predicate leaked into the index"
    );
}

#[test]
fn public_timeline_is_ordered_and_paginated() {
    let (mgr, _dir) = manager();
    seed_index(mgr.instance());
    let public = node("https://www.w3.org/ns/activitystreams#Public");

    let page = index::public_timeline(mgr.instance(), &public, 10, None).unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].published, "2026-08-18T11:00:00Z", "newest first");

    let next =
        index::public_timeline(mgr.instance(), &public, 10, Some("2026-08-18T11:00:00Z")).unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].published, "2026-08-18T10:00:00Z");

    let limited = index::public_timeline(mgr.instance(), &public, 1, None).unwrap();
    assert_eq!(limited.len(), 1, "limit is applied in the engine");
}

#[test]
fn dangling_rows_sweep_and_the_index_rebuilds() {
    let (mgr, _dir) = manager();
    seed_index(mgr.instance());
    let public = node("https://www.w3.org/ns/activitystreams#Public");

    // A pod deletes a note; the row is left dangling until dereference sweeps it.
    index::forget_note(mgr.instance(), &node("https://alice.brolly.id/notes/1")).unwrap();
    assert_eq!(
        index::public_timeline(mgr.instance(), &public, 10, None)
            .unwrap()
            .len(),
        1
    );

    index::clear(mgr.instance()).unwrap();
    assert!(
        index::public_timeline(mgr.instance(), &public, 10, None)
            .unwrap()
            .is_empty(),
        "clear is the first half of a rebuild"
    );

    seed_index(mgr.instance());
    assert_eq!(
        index::public_timeline(mgr.instance(), &public, 10, None)
            .unwrap()
            .len(),
        2,
        "replay reproduces the index"
    );
}

#[test]
fn the_index_can_count_its_notes_without_opening_a_pod() {
    // ADR 0005 R8: NodeInfo's post count is a cross-user aggregate, which is
    // precisely what the server agent exists for.
    let dir = tempfile::tempdir().unwrap();
    let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    let index = manager.instance();

    assert_eq!(brolly_store::index::count_notes(index).unwrap(), 0);

    for n in 1..=3 {
        brolly_store::index::record_note(
            index,
            &brolly_store::index::NotePointer {
                note: oxigraph::model::NamedNode::new_unchecked(format!(
                    "https://alice.brolly.test/~/notes/{n}"
                )),
                author: oxigraph::model::NamedNode::new_unchecked(
                    "https://alice.brolly.test/actor",
                ),
                published: format!("2026-08-26T0{n}:00:00Z"),
                audience: oxigraph::model::NamedNode::new_unchecked(
                    "https://www.w3.org/ns/activitystreams#Public",
                ),
                // A reply carries an extra predicate; the count must not move
                // with the number of triples a row happens to have.
                in_reply_to: (n == 2).then(|| {
                    oxigraph::model::NamedNode::new_unchecked("https://alice.brolly.test/~/notes/1")
                }),
            },
        )
        .unwrap();
    }

    assert_eq!(brolly_store::index::count_notes(index).unwrap(), 3);
}

#[test]
fn a_pointer_keeps_what_it_was_first_recorded_with() {
    // A later record of the same note, such as a replayed Create, must not add
    // a second author (anyone who boosts a post could claim it) or a second
    // published time (the note would be listed twice, at the later time).
    let (mgr, _dir) = manager();
    let note = "https://alice.brolly.id/~/notes/1";
    let pointer = |author: &str, published: &str| NotePointer {
        note: node(note),
        author: node(author),
        published: published.to_string(),
        audience: node("https://www.w3.org/ns/activitystreams#Public"),
        in_reply_to: None,
    };

    assert!(!index::is_indexed(mgr.instance(), &node(note)).unwrap());
    index::record_note(
        mgr.instance(),
        &pointer("https://alice.brolly.id/actor", "2026-09-17T10:00:00Z"),
    )
    .unwrap();
    assert!(index::is_indexed(mgr.instance(), &node(note)).unwrap());

    index::record_note(
        mgr.instance(),
        &pointer("https://mallory.brolly.id/actor", "2026-09-17T11:00:00Z"),
    )
    .unwrap();

    let values = |predicate: &str| -> Vec<String> {
        mgr.instance()
            .quads_for_pattern(None, Some(node(predicate).as_ref()), None, None)
            .filter_map(Result::ok)
            .map(|quad| quad.object.to_string())
            .collect()
    };
    assert_eq!(
        values(index::P_AUTHOR),
        vec!["<https://alice.brolly.id/actor>".to_string()]
    );
    assert_eq!(
        values(index::P_PUBLISHED),
        vec!["\"2026-09-17T10:00:00Z\"".to_string()],
        "a second published literal lists the note twice"
    );
    assert_eq!(index::count_notes(mgr.instance()).unwrap(), 1);
}

#[test]
fn concurrent_first_records_of_one_note_write_one_pointer() {
    // A redelivered Create can race its original. Both see the note unindexed
    // unless check-then-write is atomic, and the pointer gets two authors.
    let (stores, _dir) = manager();
    let instance = std::sync::Arc::clone(stores.instance());
    let note = node("https://alice.brolly.test/~/notes/01J8Z0000000000000000000A1");

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let writers: Vec<_> = (0..8)
        .map(|i| {
            let instance = std::sync::Arc::clone(&instance);
            let barrier = std::sync::Arc::clone(&barrier);
            let note = note.clone();
            std::thread::spawn(move || {
                barrier.wait();
                index::record_note(
                    &instance,
                    &NotePointer {
                        note,
                        author: node(&format!("https://member{i}.brolly.test/actor")),
                        published: format!("2026-09-18T12:00:0{i}Z"),
                        audience: node("https://www.w3.org/ns/activitystreams#Public"),
                        in_reply_to: None,
                    },
                )
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap().unwrap();
    }

    assert_eq!(index::count_notes(&instance).unwrap(), 1);
}
