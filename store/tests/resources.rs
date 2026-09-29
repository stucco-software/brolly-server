//! The pod handle: one read interface, one way to write.
//!
//! Spec: `docs/specs/2026-09-22-solid-resource-metadata.md`, Testing →
//! `store/tests/resources.rs`. The upgrade arrives, with its tests, in rollout
//! commit 2.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use brolly_store::resources::{container_triples, modified_ms};
use brolly_store::{
    BlobMeta, Content, Kind, METADATA_GRAPH, Pod, PodRead, StoreError, StoreManager,
};
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use oxigraph::sparql::QueryResults;
use uuid::Uuid;

const SAYS: &str = "https://example.test/says";
const OUTBOX: &str = "https://alice.brolly.test/outbox";
const PROFILE: &str = "https://alice.brolly.test/profile";

fn node(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn manager(idle_secs: u64) -> (tempfile::TempDir, StoreManager) {
    let dir = tempfile::tempdir().unwrap();
    let stores = StoreManager::open(dir.path(), 8, idle_secs).unwrap();
    (dir, stores)
}

/// `<graph> ex:says "value"`, in `graph`.
fn says(graph: &str, value: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(node(graph)),
        node(SAYS),
        Term::Literal(Literal::new_simple_literal(value)),
        GraphName::NamedNode(node(graph)),
    )
}

/// Every quad in one graph, through any reader.
fn graph(read: &impl PodRead, name: &str) -> Vec<Quad> {
    read.quads_for_pattern(
        None,
        None,
        None,
        Some(GraphNameRef::NamedNode(node(name).as_ref())),
    )
    .map(Result::unwrap)
    .collect()
}

/// What `graph` says, if anything.
fn said(read: &impl PodRead, name: &str) -> Option<String> {
    graph(read, name).into_iter().find_map(|q| match q.object {
        Term::Literal(l) if q.predicate.as_str() == SAYS => Some(l.value().to_string()),
        _ => None,
    })
}

// --- outside the root ------------------------------------------------------------

#[test]
fn the_outside_root_methods_refuse_the_metadata_graph() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    let forged = says(METADATA_GRAPH, "forged");

    let attempts: [(&str, Result<(), StoreError>); 5] = [
        (
            "insert",
            pod.write(|w| w.insert(std::slice::from_ref(&forged))),
        ),
        (
            "remove_quads",
            pod.write(|w| w.remove_quads(std::slice::from_ref(&forged))),
        ),
        (
            "replace_graph",
            pod.write(|w| w.replace_graph(METADATA_GRAPH, std::slice::from_ref(&forged))),
        ),
        ("clear_graph", pod.write(|w| w.clear_graph(METADATA_GRAPH))),
        ("graph", pod.write(|w| w.graph(METADATA_GRAPH).map(|_| ()))),
    ];
    for (method, result) in attempts {
        assert!(
            matches!(result, Err(StoreError::UnderRoot)),
            "{method}: {result:?}"
        );
    }
    // A new pod's metadata holds its layout mark, and nothing forged.
    assert!(!graph(&pod.read_store(), METADATA_GRAPH).contains(&forged));
}

/// `inbox` decides per IRI which family of methods to use, so it needs the
/// same test `put` and the outside-root methods apply, and they must agree.
#[test]
fn under_root_is_the_test_put_and_the_outside_root_methods_apply() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    let root = "https://alice.brolly.test/~/";
    let note = "https://alice.brolly.test/~/notes/1";
    let foreign = "https://bob.brolly.test/~/notes/1";

    pod.write(|w| {
        assert!(
            !w.under_root(note)?,
            "a pod with no root has nothing under it"
        );
        w.create_root(root)?;
        assert!(w.under_root(note)?);
        assert!(w.under_root(root)?);
        assert!(!w.under_root("https://alice.brolly.test/inbox")?);
        assert!(!w.under_root(foreign)?);

        assert!(matches!(
            w.replace_graph(note, &[]),
            Err(StoreError::UnderRoot)
        ));
        assert!(matches!(
            w.put(foreign, Content::Rdf(&[])),
            Err(StoreError::NotUnderRoot)
        ));
        Ok(())
    })
    .unwrap();
}

#[test]
fn writes_in_one_closure_commit_together_and_roll_back_together() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();

    pod.write(|w| {
        w.insert(&[says(PROFILE, "alice")])?;
        w.insert(&[says(OUTBOX, "first")])
    })
    .unwrap();

    let failed: Result<(), StoreError> = pod.write(|w| {
        w.replace_graph(PROFILE, &[says(PROFILE, "mallory")])?;
        w.clear_graph(OUTBOX)?;
        Err(StoreError::Backend("the closure gave up".into()))
    });
    assert!(failed.is_err());

    let read = pod.read_store();
    assert_eq!(said(&read, PROFILE).as_deref(), Some("alice"));
    assert_eq!(said(&read, OUTBOX).as_deref(), Some("first"));
}

// --- reads -------------------------------------------------------------------------

#[test]
fn a_read_inside_a_write_sees_that_writes_earlier_changes() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();

    pod.write(|w| {
        w.insert(&[says(OUTBOX, "first")])?;
        assert_eq!(said(w, OUTBOX).as_deref(), Some("first"));
        assert_eq!(w.graph(OUTBOX)?.len(), 1);
        w.insert(&[says(OUTBOX, "second")])?;
        assert_eq!(graph(w, OUTBOX).len(), 2);
        Ok(())
    })
    .unwrap();
}

/// The same questions through any reader.
fn answers(read: &impl PodRead, name: &str) -> (usize, bool) {
    let asked = read
        .query_with(
            "ASK { GRAPH ?g { ?s ?p ?o } }",
            &[("g", Term::NamedNode(node(name)))],
        )
        .unwrap();
    let QueryResults::Boolean(present) = asked else {
        panic!("ASK didn't answer a boolean");
    };
    (graph(read, name).len(), present)
}

#[test]
fn pod_read_works_the_same_over_a_store_a_snapshot_and_a_transaction() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    pod.write(|w| w.insert(&[says(OUTBOX, "hi")])).unwrap();

    let expected = (1, true);
    assert_eq!(answers(&pod.read_store(), OUTBOX), expected);
    assert_eq!(pod.read(|r| Ok(answers(r, OUTBOX))).unwrap(), expected);
    assert_eq!(pod.write(|w| Ok(answers(w, OUTBOX))).unwrap(), expected);
}

#[test]
fn query_runs_select_and_ask_only() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    let read = pod.read_store();

    assert!(matches!(
        read.query("SELECT ?s WHERE { ?s ?p ?o }"),
        Ok(QueryResults::Solutions(_))
    ));
    assert!(
        read.query("CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }")
            .is_err()
    );
    assert!(
        read.query("INSERT DATA { <urn:a> <urn:b> <urn:c> }")
            .is_err(),
        "an update parsed as a query"
    );
}

// --- concurrency -------------------------------------------------------------------

/// Read a counter, pause, write it back plus one. Without the lock two
/// writers read the same value and one increment is lost.
fn increment(pod: &Pod) {
    pod.write(|w| {
        let current: u32 = w
            .graph(OUTBOX)?
            .first()
            .and_then(|q| match &q.object {
                Term::Literal(l) => l.value().parse().ok(),
                _ => None,
            })
            .unwrap_or(0);
        std::thread::sleep(Duration::from_millis(5));
        w.replace_graph(OUTBOX, &[says(OUTBOX, &(current + 1).to_string())])
    })
    .unwrap();
}

#[test]
fn writers_to_one_pod_are_serialised() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();

    let barrier = Arc::new(Barrier::new(4));
    let writers: Vec<_> = (0..4)
        .map(|_| {
            let pod = Arc::clone(&pod);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..10 {
                    increment(&pod);
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }

    assert_eq!(said(&pod.read_store(), OUTBOX).as_deref(), Some("40"));
}

#[test]
fn writers_to_different_pods_do_not_block_each_other() {
    let (_dir, stores) = manager(60);
    let alice = stores.pod(Uuid::new_v4()).unwrap();
    let bob = stores.pod(Uuid::new_v4()).unwrap();

    let (entered, wait_entered) = mpsc::channel();
    let (release, wait_release) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        alice
            .write(|_| {
                entered.send(()).unwrap();
                wait_release.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    wait_entered.recv().unwrap();

    let (done, wait_done) = mpsc::channel();
    let other = std::thread::spawn(move || {
        bob.write(|w| w.insert(&[says(OUTBOX, "bob")])).unwrap();
        done.send(()).unwrap();
    });
    let finished = wait_done.recv_timeout(Duration::from_secs(5));
    release.send(()).unwrap();
    holder.join().unwrap();
    other.join().unwrap();
    assert!(finished.is_ok(), "bob's write waited on alice's lock");
}

#[test]
fn a_pod_refetched_after_eviction_while_a_writer_holds_it_gives_the_same_lock() {
    let (_dir, stores) = manager(1);
    let alice = Uuid::new_v4();
    let held = stores.pod(alice).unwrap();

    let (entered, wait_entered) = mpsc::channel();
    let (release, wait_release) = mpsc::channel::<()>();
    let writer = {
        let held = Arc::clone(&held);
        std::thread::spawn(move || {
            held.write(|_| {
                entered.send(()).unwrap();
                wait_release.recv().unwrap();
                Ok(())
            })
            .unwrap();
        })
    };
    wait_entered.recv().unwrap();

    // Let the cache evict alice while the writer is still inside its closure.
    // Idle expiry, not capacity: see `tests/pod_lifecycle.rs`.
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(stores.open_pods(), 0, "setup: the cache still holds a pod");
    let again = stores.pod(alice).unwrap();
    assert!(Arc::ptr_eq(&held, &again), "two pods over one database");

    let (done, wait_done) = mpsc::channel();
    let second = std::thread::spawn(move || {
        again.write(|_| Ok(())).unwrap();
        done.send(()).unwrap();
    });
    assert!(
        wait_done.recv_timeout(Duration::from_millis(300)).is_err(),
        "the re-fetched pod's writer didn't wait for the first"
    );
    release.send(()).unwrap();
    writer.join().unwrap();
    wait_done.recv_timeout(Duration::from_secs(5)).unwrap();
    second.join().unwrap();
}

// --- released blobs ----------------------------------------------------------------

#[test]
fn a_released_blob_goes_after_commit_and_a_failed_write_deletes_nothing() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    let digest = pod.blobs().put(b"transient").unwrap();

    let failed: Result<(), StoreError> = pod.write(|w| {
        w.release_blob(&digest);
        Err(StoreError::Backend("gave up after releasing".into()))
    });
    assert!(failed.is_err());
    assert!(
        pod.blobs().contains(&digest),
        "a failed write deleted bytes"
    );

    pod.write(|w| {
        w.release_blob(&digest);
        assert!(pod.blobs().contains(&digest), "deleted before the commit");
        Ok(())
    })
    .unwrap();
    assert!(!pod.blobs().contains(&digest), "nothing references it");
}

// --- resources under the storage root ----------------------------------------------

const ROOT: &str = "https://alice.brolly.test/~/";

fn at(path: &str) -> String {
    format!("{ROOT}{path}")
}

/// A pod with its storage root recorded, as provisioning will leave it.
fn provisioned(stores: &StoreManager) -> Arc<Pod> {
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    pod.write(|w| w.create_root(ROOT)).unwrap();
    pod
}

fn version(pod: &Pod, resource: &str) -> String {
    pod.read_store().meta(resource).unwrap().unwrap().version
}

/// Bytes into the pod's blob store, as a caller does before `write`.
fn blob(pod: &Pod, bytes: &[u8]) -> BlobMeta {
    BlobMeta {
        digest: pod.blobs().put(bytes).unwrap(),
        media_type: "image/png".into(),
        byte_size: bytes.len() as u64,
    }
}

#[test]
fn an_empty_document_and_an_empty_container_exist_after_put() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);

    pod.write(|w| {
        w.put(&at("empty"), Content::Rdf(&[]))?;
        w.put(&at("box/"), Content::Container(&[]))
    })
    .unwrap();

    let read = pod.read_store();
    let doc = read
        .meta(&at("empty"))
        .unwrap()
        .expect("the empty document");
    assert_eq!(doc.kind, Kind::RdfSource);
    assert_eq!(doc.version.len(), 26, "a ULID: {}", doc.version);
    assert!(graph(&read, &at("empty")).is_empty());

    let container = read
        .meta(&at("box/"))
        .unwrap()
        .expect("the empty container");
    assert_eq!(container.kind, Kind::Container);
    assert!(read.members(&at("box/")).unwrap().is_empty());
    assert_eq!(
        read.members(ROOT).unwrap(),
        vec![at("box/"), at("empty")],
        "both are listed in the root"
    );
}

#[test]
fn containment_and_intermediate_containers_are_recorded_each_with_a_version() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);

    pod.write(|w| w.put(&at("a/b/c"), Content::Rdf(&[says(&at("a/b/c"), "hi")])))
        .unwrap();

    let read = pod.read_store();
    assert_eq!(read.members(ROOT).unwrap(), vec![at("a/")]);
    assert_eq!(read.members(&at("a/")).unwrap(), vec![at("a/b/")]);
    assert_eq!(read.members(&at("a/b/")).unwrap(), vec![at("a/b/c")]);
    let a = read.meta(&at("a/")).unwrap().unwrap();
    let b = read.meta(&at("a/b/")).unwrap().unwrap();
    assert_eq!((a.kind, b.kind), (Kind::Container, Kind::Container));
    assert_eq!(a.version.len(), 26);
    assert_eq!(b.version.len(), 26);
    assert_ne!(
        a.version, b.version,
        "each intermediate has its own version"
    );

    // Containment lives in the metadata graph only, never in a content graph.
    for container in [ROOT, at("a/").as_str(), at("a/b/").as_str()] {
        assert!(
            graph(&read, container)
                .iter()
                .all(|q| q.predicate.as_str() != brolly_domain::vocab::LDP_CONTAINS),
            "{container}'s own graph lists members"
        );
    }
}

#[test]
fn an_acl_is_recorded_but_never_contained() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);

    pod.write(|w| {
        w.put(&at("doc"), Content::Rdf(&[]))?;
        w.put(&at("doc.acl"), Content::Auxiliary(&[]))
    })
    .unwrap();

    let read = pod.read_store();
    let acl = read.meta(&at("doc.acl")).unwrap().expect("the ACL exists");
    assert_eq!(acl.kind, Kind::Auxiliary);
    assert_eq!(read.members(ROOT).unwrap(), vec![at("doc")]);
}

#[test]
fn a_container_with_members_is_not_removed_and_a_missing_resource_is_a_no_op() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("box/item"), Content::Rdf(&[])))
        .unwrap();

    let refused = pod.write(|w| w.remove(&at("box/")));
    assert!(
        matches!(refused, Err(StoreError::ContainerNotEmpty)),
        "got {refused:?}"
    );
    assert!(pod.read_store().meta(&at("box/")).unwrap().is_some());

    assert!(!pod.write(|w| w.remove(&at("never-was"))).unwrap());

    // Emptied, it goes.
    assert!(pod.write(|w| w.remove(&at("box/item"))).unwrap());
    assert!(pod.write(|w| w.remove(&at("box/"))).unwrap());
    assert!(pod.read_store().meta(&at("box/")).unwrap().is_none());
    assert!(pod.read_store().members(ROOT).unwrap().is_empty());
}

#[test]
fn removing_a_resource_removes_its_acl_graph_and_metadata() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| {
        w.put(&at("doc"), Content::Rdf(&[says(&at("doc"), "hi")]))?;
        w.put(
            &at("doc.acl"),
            Content::Auxiliary(&[says(&at("doc.acl"), "rules")]),
        )
    })
    .unwrap();

    assert!(pod.write(|w| w.remove(&at("doc"))).unwrap());

    let read = pod.read_store();
    assert!(read.meta(&at("doc")).unwrap().is_none());
    assert!(read.meta(&at("doc.acl")).unwrap().is_none());
    assert!(graph(&read, &at("doc")).is_empty());
    assert!(graph(&read, &at("doc.acl")).is_empty());
}

#[test]
fn a_container_put_keeps_its_members() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("box/item"), Content::Rdf(&[])))
        .unwrap();

    pod.write(|w| {
        w.put(
            &at("box/"),
            Content::Container(&[says(&at("box/"), "a label")]),
        )
    })
    .unwrap();

    let read = pod.read_store();
    assert_eq!(read.members(&at("box/")).unwrap(), vec![at("box/item")]);
    assert_eq!(said(&read, &at("box/")).as_deref(), Some("a label"));
}

#[test]
fn put_needs_a_root_and_stays_under_it() {
    let (_dir, stores) = manager(60);
    let bare = stores.pod(Uuid::new_v4()).unwrap();
    let no_root = bare.write(|w| w.put(&at("doc"), Content::Rdf(&[])));
    assert!(
        matches!(no_root, Err(StoreError::NoRoot)),
        "got {no_root:?}"
    );

    let pod = provisioned(&stores);
    let outside = pod.write(|w| w.put(PROFILE, Content::Rdf(&[])));
    assert!(
        matches!(outside, Err(StoreError::NotUnderRoot)),
        "got {outside:?}"
    );
    let removed_root = pod.write(|w| w.remove(ROOT));
    assert!(
        matches!(removed_root, Err(StoreError::Invalid(_))),
        "got {removed_root:?}"
    );
}

#[test]
fn content_must_fit_its_iri_and_its_graph() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    for (resource, content) in [
        (at("doc"), Content::Container(&[])),
        (at("box/"), Content::Rdf(&[])),
        (at("doc.acl"), Content::Rdf(&[])),
        (at("doc"), Content::Auxiliary(&[])),
    ] {
        let result = pod.write(|w| w.put(&resource, content.clone()));
        assert!(
            matches!(result, Err(StoreError::Invalid(_))),
            "{resource} took {content:?}: {result:?}"
        );
    }

    // A body for one resource can't write into another's graph.
    let stray = [says(&at("other"), "smuggled")];
    let result = pod.write(|w| w.put(&at("doc"), Content::Rdf(&stray)));
    assert!(
        matches!(result, Err(StoreError::Invalid(_))),
        "got {result:?}"
    );
    assert!(graph(&pod.read_store(), &at("other")).is_empty());
}

#[test]
fn the_outside_root_methods_refuse_graphs_under_the_root() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let doc = at("doc");
    pod.write(|w| w.put(&doc, Content::Rdf(&[says(&doc, "mine")])))
        .unwrap();
    let before = graph(&pod.read_store(), &doc);
    let forged = says(&doc, "forged");

    let attempts: [(&str, Result<(), StoreError>); 5] = [
        (
            "insert",
            pod.write(|w| w.insert(std::slice::from_ref(&forged))),
        ),
        (
            "remove_quads",
            pod.write(|w| w.remove_quads(std::slice::from_ref(&forged))),
        ),
        (
            "replace_graph",
            pod.write(|w| w.replace_graph(&doc, std::slice::from_ref(&forged))),
        ),
        ("clear_graph", pod.write(|w| w.clear_graph(&doc))),
        ("graph", pod.write(|w| w.graph(&doc).map(|_| ()))),
    ];
    for (method, result) in attempts {
        assert!(
            matches!(result, Err(StoreError::UnderRoot)),
            "{method}: {result:?}"
        );
    }
    assert_eq!(graph(&pod.read_store(), &doc), before);
    assert!(pod.read_store().meta(&doc).unwrap().is_some());
}

#[test]
fn a_post_and_its_outbox_entry_commit_together_and_roll_back_together() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let note = at("notes/1");
    let entry = says(OUTBOX, &note);

    pod.write(|w| {
        w.put(&note, Content::Rdf(&[says(&note, "hello")]))?;
        w.insert(std::slice::from_ref(&entry))
    })
    .unwrap();
    assert!(pod.read_store().meta(&note).unwrap().is_some());
    assert_eq!(graph(&pod.read_store(), OUTBOX), vec![entry]);

    let second = at("notes/2");
    let failed: Result<(), StoreError> = pod.write(|w| {
        w.put(&second, Content::Rdf(&[says(&second, "lost")]))?;
        w.insert(&[says(OUTBOX, &second)])?;
        Err(StoreError::Backend("the closure gave up".into()))
    });
    assert!(failed.is_err());
    let read = pod.read_store();
    assert!(read.meta(&second).unwrap().is_none(), "the post committed");
    assert!(graph(&read, &second).is_empty());
    assert_eq!(graph(&read, OUTBOX).len(), 1, "the outbox entry committed");
    assert_eq!(read.members(&at("notes/")).unwrap(), vec![note]);
}

#[test]
fn a_put_inside_a_write_is_visible_to_the_rest_of_it() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let doc = at("doc");

    pod.write(|w| {
        w.put(&doc, Content::Rdf(&[says(&doc, "first")]))?;
        assert!(w.meta(&doc)?.is_some(), "put, then meta in the same write");
        assert_eq!(w.members(ROOT)?, vec![doc.clone()]);
        w.append(&doc, &[says(&doc, "second")])?;
        assert_eq!(graph(w, &doc).len(), 2, "append after put");
        Ok(())
    })
    .unwrap();
}

// --- versions ----------------------------------------------------------------------

#[test]
fn a_containers_version_follows_its_direct_members_and_not_its_grandchildren() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("a/b/one"), Content::Rdf(&[])))
        .unwrap();
    let parent = || version(&pod, &at("a/b/"));
    let grandparent = || version(&pod, &at("a/"));

    let (p0, g0) = (parent(), grandparent());
    pod.write(|w| w.put(&at("a/b/two"), Content::Rdf(&[])))
        .unwrap();
    let (p1, g1) = (parent(), grandparent());
    assert_ne!(p1, p0, "a member was added");
    assert_eq!(g1, g0, "the grandparent moved on an add");

    pod.write(|w| w.put(&at("a/b/one"), Content::Rdf(&[says(&at("a/b/one"), "x")])))
        .unwrap();
    let (p2, g2) = (parent(), grandparent());
    assert_ne!(p2, p1, "a member changed");
    assert_eq!(g2, g1, "the grandparent moved on a change");

    pod.write(|w| w.remove(&at("a/b/two"))).unwrap();
    let (p3, g3) = (parent(), grandparent());
    assert_ne!(p3, p2, "a member was removed");
    assert_eq!(g3, g2, "the grandparent moved on a remove");
}

#[test]
fn modified_is_strictly_increasing_within_one_millisecond() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let doc = at("doc");

    // Twenty puts in one closure land in the same millisecond or close to it.
    let stamps = pod
        .write(|w| {
            (0..20)
                .map(|n| w.put(&doc, Content::Rdf(&[says(&doc, &n.to_string())])))
                .map(|meta| meta.map(|m| (m.modified, m.version)))
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap();

    for pair in stamps.windows(2) {
        assert!(pair[0].0 < pair[1].0, "{} then {}", pair[0].0, pair[1].0);
        assert_ne!(pair[0].1, pair[1].1, "a change without a new version");
    }
    let stored = pod.read_store().meta(&doc).unwrap().unwrap();
    assert_eq!(stored.modified, stamps[19].0);
    assert_eq!(stored.version, stamps[19].1);
}

#[test]
fn read_sees_one_consistent_version_during_a_commit() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let doc = at("doc");
    let first = pod
        .write(|w| w.put(&doc, Content::Rdf(&[says(&doc, "0")])))
        .unwrap();

    let writer = {
        let pod = Arc::clone(&pod);
        let doc = doc.clone();
        std::thread::spawn(move || {
            (1..200)
                .map(|n| {
                    let n = n.to_string();
                    let meta = pod
                        .write(|w| w.put(&doc, Content::Rdf(&[says(&doc, &n)])))
                        .unwrap();
                    (meta.version, n)
                })
                .collect::<Vec<_>>()
        })
    };

    let mut seen = Vec::new();
    while !writer.is_finished() {
        seen.push(
            pod.read(|r| {
                let meta = r.meta(&doc)?.expect("the document exists throughout");
                Ok((meta.version, said(r, &doc).expect("content throughout")))
            })
            .unwrap(),
        );
    }
    let mut written: std::collections::HashMap<String, String> =
        writer.join().unwrap().into_iter().collect();
    written.insert(first.version, "0".into());

    assert!(!seen.is_empty());
    for (version, content) in seen {
        assert_eq!(
            written.get(&version),
            Some(&content),
            "version {version} was read with another write's content"
        );
    }
}

// --- blobs -------------------------------------------------------------------------

#[test]
fn a_binary_records_its_blob_and_removing_it_deletes_the_bytes_after_commit() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let image = at("image.png");
    let meta = blob(&pod, b"png bytes");

    let recorded = pod
        .write(|w| w.put(&image, Content::Binary(meta.clone())))
        .unwrap();
    assert_eq!(recorded.kind, Kind::NonRdfSource);
    assert_eq!(recorded.blob.as_ref(), Some(&meta));
    assert_eq!(
        pod.read_store().meta(&image).unwrap().unwrap().blob,
        Some(meta.clone())
    );

    pod.write(|w| w.remove(&image)).unwrap();
    assert!(
        !pod.blobs().contains(&meta.digest),
        "the bytes outlived the resource"
    );
}

#[test]
fn a_binary_put_refuses_bytes_that_are_not_there() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let absent = BlobMeta {
        digest: "0".repeat(64),
        media_type: "image/png".into(),
        byte_size: 1,
    };

    let result = pod.write(|w| w.put(&at("image.png"), Content::Binary(absent)));
    assert!(
        matches!(result, Err(StoreError::BlobMissing)),
        "got {result:?}"
    );
    assert!(pod.read_store().meta(&at("image.png")).unwrap().is_none());
}

#[test]
fn a_remove_that_fails_to_commit_deletes_no_blob() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let image = at("image.png");
    let meta = blob(&pod, b"keep me");
    pod.write(|w| w.put(&image, Content::Binary(meta.clone())))
        .unwrap();

    let failed: Result<(), StoreError> = pod.write(|w| {
        w.remove(&image)?;
        Err(StoreError::Backend("gave up after releasing".into()))
    });
    assert!(failed.is_err());
    assert!(
        pod.blobs().contains(&meta.digest),
        "a failed write deleted bytes"
    );
    assert!(pod.read_store().meta(&image).unwrap().is_some());
}

#[test]
fn an_upload_committed_before_a_release_keeps_the_blob() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let meta = blob(&pod, b"shared bytes");
    pod.write(|w| w.put(&at("one.png"), Content::Binary(meta.clone())))
        .unwrap();

    // Identical bytes, uploaded and committed first.
    let again = blob(&pod, b"shared bytes");
    pod.write(|w| w.put(&at("two.png"), Content::Binary(again)))
        .unwrap();
    pod.write(|w| w.remove(&at("one.png"))).unwrap();

    assert!(
        pod.blobs().contains(&meta.digest),
        "a referenced blob was swept"
    );
}

#[test]
fn an_upload_that_loses_the_race_gets_blob_missing_and_succeeds_on_retry() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let meta = blob(&pod, b"racing bytes");
    pod.write(|w| w.put(&at("one.png"), Content::Binary(meta.clone())))
        .unwrap();

    // The second upload writes its bytes (already there, so a no-op)...
    let upload = blob(&pod, b"racing bytes");
    // ...then the release commits first and sweeps them.
    pod.write(|w| w.remove(&at("one.png"))).unwrap();
    assert!(!pod.blobs().contains(&meta.digest));

    let lost = pod.write(|w| w.put(&at("two.png"), Content::Binary(upload.clone())));
    assert!(matches!(lost, Err(StoreError::BlobMissing)), "got {lost:?}");

    // The caller writes the bytes again and retries once.
    let retry = blob(&pod, b"racing bytes");
    pod.write(|w| w.put(&at("two.png"), Content::Binary(retry)))
        .unwrap();

    // Never a reference to a missing file.
    let read = pod.read_store();
    for quad in read.quads_for_pattern(
        None,
        Some(node(brolly_domain::vocab::BROLLY_BLOB_DIGEST).as_ref()),
        None,
        None,
    ) {
        let Term::Literal(digest) = quad.unwrap().object else {
            panic!("a digest that isn't a literal");
        };
        assert!(pod.blobs().contains(digest.value()), "{digest} has no file");
    }
}

#[test]
fn the_raw_store_fixture_sees_what_readers_see() {
    // `test-fixtures` is how other crates' tests will seed old layouts.
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("doc"), Content::Rdf(&[says(&at("doc"), "hi")])))
        .unwrap();
    assert_eq!(
        pod.raw_store()
            .quads_for_pattern(None, None, None, None)
            .count(),
        pod.read_store()
            .quads_for_pattern(None, None, None, None)
            .count()
    );
}

#[test]
fn a_description_replaces_the_one_before_it() {
    // Mastodon alt text: a second description must replace the first, not sit
    // beside it, and the binary keeps its bytes.
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let meta = blob(&pod, b"a small dog");
    pod.write(|w| w.put(&at("dog.png"), Content::Binary(meta.clone())))
        .unwrap();
    let first = pod
        .write(|w| w.set_description(&at("dog.png"), &[says(&at("dog.png"), "a dog")]))
        .unwrap();
    let second = pod
        .write(|w| w.set_description(&at("dog.png"), &[says(&at("dog.png"), "a small dog")]))
        .unwrap();

    assert_ne!(first.version, second.version, "the version didn't move");
    assert_eq!(second.blob.as_ref().map(|b| &b.digest), Some(&meta.digest));
    let described = pod
        .read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(node(&at("dog.png")).as_ref())),
        )
        .count();
    assert_eq!(described, 1, "the old description is still there");

    // Only a binary has a description.
    pod.write(|w| w.put(&at("doc"), Content::Rdf(&[]))).unwrap();
    let refused = pod.write(|w| w.set_description(&at("doc"), &[says(&at("doc"), "x")]));
    assert!(
        matches!(refused, Err(StoreError::Invalid(_))),
        "got {refused:?}"
    );
}

#[test]
fn modified_moves_past_a_stored_time_oxigraph_shortened() {
    // Oxigraph normalises an xsd:dateTime on the way in: `.750Z` reads back as
    // `.75Z`, `.000Z` as `Z`. The floor that keeps `modified` increasing has to
    // read those forms, and what `meta` returns has to be fixed width again.
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("doc"), Content::Rdf(&[]))).unwrap();

    // Plant a far-future modified time in the shortened form, so the floor,
    // not the clock, decides the next value.
    let subject = NamedOrBlankNode::NamedNode(node(&at("doc")));
    let predicate = node(brolly_domain::vocab::DCTERMS_MODIFIED);
    let graph = GraphName::NamedNode(node(METADATA_GRAPH));
    let raw = pod.raw_store();
    let stale: Vec<Quad> = raw
        .quads_for_pattern(
            Some((&subject).into()),
            Some(predicate.as_ref()),
            None,
            Some(graph.as_ref()),
        )
        .map(Result::unwrap)
        .collect();
    for quad in &stale {
        raw.remove(quad).unwrap();
    }
    raw.insert(&Quad::new(
        subject.clone(),
        predicate.clone(),
        Term::Literal(Literal::new_typed_literal(
            "2999-01-01T00:00:00.750Z",
            node("http://www.w3.org/2001/XMLSchema#dateTime"),
        )),
        graph,
    ))
    .unwrap();
    let planted = pod.read_store().meta(&at("doc")).unwrap().unwrap().modified;
    assert_eq!(planted, "2999-01-01T00:00:00.750Z", "read back fixed width");

    let next = pod.write(|w| w.put(&at("doc"), Content::Rdf(&[]))).unwrap();
    assert_eq!(next.modified, "2999-01-01T00:00:00.751Z");
}

// --- a container's listing (5b, H13) -------------------------------------------

/// The object of `<member> <predicate>` in `container`'s listing, as served.
fn listed(pod: &Pod, container: &str, member: &str, predicate: &str) -> Option<Term> {
    container_triples(&pod.read_store(), container)
        .unwrap()
        .into_iter()
        .find(|q| {
            q.subject.to_string() == format!("<{member}>") && q.predicate.as_str() == predicate
        })
        .map(|q| q.object)
}

/// Solid Protocol §4.2.1: a file manager draws a listing without a `HEAD` per
/// member. Without this it has to make one request per row, and a container of
/// a hundred notes costs a hundred round trips.
#[test]
fn a_listing_carries_each_members_modified_time_and_mtime() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("c/m"), Content::Rdf(&[]))).unwrap();

    let own = pod.read_store().meta(&at("c/m")).unwrap().unwrap();
    assert_eq!(
        listed(
            &pod,
            &at("c/"),
            &at("c/m"),
            brolly_domain::vocab::DCTERMS_MODIFIED
        ),
        Some(Term::Literal(Literal::new_typed_literal(
            own.modified.clone(),
            node(brolly_domain::vocab::XSD_DATE_TIME),
        ))),
        "the listing must agree with the member's own modified time",
    );
    let ms = modified_ms(&own.modified).unwrap();
    assert_eq!(
        listed(
            &pod,
            &at("c/"),
            &at("c/m"),
            brolly_domain::vocab::STAT_MTIME
        ),
        Some(Term::Literal(Literal::new_typed_literal(
            (ms / 1000).to_string(),
            node(brolly_domain::vocab::XSD_INTEGER),
        ))),
        "stat:mtime is the same instant in seconds",
    );
}

/// §4.2.1 excuses inapplicable metadata. An RDF source's serialized length
/// changes with the `Accept` header, so a `stat:size` on one would be a number
/// that contradicts `Content-Length` on most reads.
#[test]
fn only_a_binary_member_is_listed_with_a_size() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let blob = blob(&pod, b"0123456789");
    pod.write(|w| {
        w.put(&at("c/doc"), Content::Rdf(&[]))?;
        w.put(&at("c/pic.png"), Content::Binary(blob.clone()))?;
        Ok(())
    })
    .unwrap();

    assert_eq!(
        listed(
            &pod,
            &at("c/"),
            &at("c/pic.png"),
            brolly_domain::vocab::STAT_SIZE
        ),
        Some(Term::Literal(Literal::new_typed_literal(
            "10",
            node(brolly_domain::vocab::XSD_INTEGER),
        ))),
    );
    assert_eq!(
        listed(
            &pod,
            &at("c/"),
            &at("c/doc"),
            brolly_domain::vocab::STAT_SIZE
        ),
        None,
        "an RDF source has no one length to report",
    );
}

/// Oxigraph normalises an `xsd:dateTime` on the way in, so a listing built
/// from the raw quads would say `.75Z` where the member's own `Last-Modified`
/// says `.750Z` — about one write in ten (commit 9d58082). The listing has to
/// go through the same `meta()` path every other reader does.
#[test]
fn a_listed_modified_time_is_the_fixed_width_one_meta_returns() {
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    pod.write(|w| w.put(&at("c/m"), Content::Rdf(&[]))).unwrap();

    // Plant the shortened form Oxigraph produces, in place of what was stored.
    let subject = NamedOrBlankNode::NamedNode(node(&at("c/m")));
    let predicate = node(brolly_domain::vocab::DCTERMS_MODIFIED);
    let graph = GraphName::NamedNode(node(METADATA_GRAPH));
    let raw = pod.raw_store();
    let stale: Vec<Quad> = raw
        .quads_for_pattern(
            Some((&subject).into()),
            Some(predicate.as_ref()),
            None,
            Some(graph.as_ref()),
        )
        .map(Result::unwrap)
        .collect();
    for quad in &stale {
        raw.remove(quad).unwrap();
    }
    raw.insert(&Quad::new(
        subject,
        predicate,
        Term::Literal(Literal::new_typed_literal(
            "2999-01-01T00:00:00.75Z",
            node(brolly_domain::vocab::XSD_DATE_TIME),
        )),
        graph,
    ))
    .unwrap();

    let listed = listed(
        &pod,
        &at("c/"),
        &at("c/m"),
        brolly_domain::vocab::DCTERMS_MODIFIED,
    );
    let Some(Term::Literal(value)) = listed else {
        panic!("no modified time in the listing: {listed:?}");
    };
    assert_eq!(
        value.value(),
        "2999-01-01T00:00:00.750Z",
        "the listing must not serve the shortened form",
    );
    assert_eq!(
        value.value(),
        pod.read_store().meta(&at("c/m")).unwrap().unwrap().modified,
        "the listing and meta() must not disagree",
    );
}

// --- large containers --------------------------------------------------------------

/// A container's record is read and rewritten by the predicates it holds, not
/// by everything about the container. Its `ldp:contains` triples aren't part
/// of the record, so reading its metadata and putting one more member leaves
/// every other member listed, whatever the container's size.
#[test]
fn a_put_into_a_large_container_keeps_every_member() {
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    let root = "https://alice.brolly.test/~/";
    let folder = format!("{root}big/");
    let member = |i: usize| format!("{folder}m{i:04}");
    const MEMBERS: usize = 500;

    pod.write(|w| {
        w.create_root(root)?;
        for i in 0..MEMBERS {
            w.put(&member(i), Content::Rdf(&[says(&member(i), "hi")]))?;
        }
        Ok(())
    })
    .unwrap();

    let before = pod.read(|r| r.meta(&folder)).unwrap().unwrap();
    assert_eq!(before.kind, Kind::Container);
    assert!(before.blob.is_none());

    let last = member(MEMBERS);
    pod.write(|w| w.put(&last, Content::Rdf(&[])).map(|_| ()))
        .unwrap();

    let after = pod.read(|r| r.meta(&folder)).unwrap().unwrap();
    assert_eq!(after.kind, Kind::Container);
    assert_ne!(after.version, before.version, "the parent's version moves");
    let members = pod.read(|r| r.members(&folder)).unwrap();
    let expected: Vec<String> = (0..=MEMBERS).map(member).collect();
    assert_eq!(members, expected);

    // Re-putting and appending to the container rewrite its record, and keep
    // its members too.
    pod.write(|w| {
        w.put(&folder, Content::Container(&[says(&folder, "a folder")]))?;
        w.append(&folder, &[says(&folder, "still")])
    })
    .unwrap();
    assert_eq!(pod.read(|r| r.members(&folder)).unwrap(), expected);
    assert_eq!(
        pod.read(|r| r.meta(&folder)).unwrap().unwrap().kind,
        Kind::Container
    );
}
