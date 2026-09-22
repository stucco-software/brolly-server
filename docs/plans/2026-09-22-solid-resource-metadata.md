# Stage 5a: Server-Managed Resource Metadata — Implementation Plan

<!-- doc-paths: skip -->
<!-- A plan cites the files it is about to create, so the paths it names
     are not expected to resolve until it has been executed. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Existence, containment, versions and binary metadata move into a
per-pod metadata graph that only the server writes. Every pod read and write
goes through a `Pod` handle whose one write path is locked and transactional.
Existing pods upgrade themselves on first open.

**Architecture:** A new `store::resources` module owns `urn:brolly:resources`
and provides:
- `Pod`, with `read`, `read_store` and `write`
- the `PodRead` trait, implemented by `ReadStore`, `ResourceRead` and `PodWrite`
- `PodWrite`, with under-root resource methods and outside-root
  protocol-graph methods
- `InstanceStore` for the index

LDP, ActivityPub, Mastodon, ATProto ingest, provisioning and WAC all move onto
it. Commit 2 upgrades pods forward-only.

**Tech Stack:** Rust, oxigraph 0.5.9 transactions, moka, axum 0.8, sqlx and
testcontainers.

**Spec:** [`docs/specs/2026-09-22-solid-resource-metadata.md`](../specs/2026-09-22-solid-resource-metadata.md)
**Roadmap:** [`docs/specs/2026-09-17-interop-roadmap.md`](../specs/2026-09-17-interop-roadmap.md), stage 5a.

---

## Commits

| Commit | Chunks | Contents |
|---|---|---|
| 1 | 1 and 2 | The pod handle and resource API, and every reader and writer moved onto it, with no behaviour change. The workspace doesn't build between chunk 1's Task 2 and the end of chunk 2, so chunk 1 gates on `-p brolly-domain -p brolly-store` only. |
| 2 | 3 and 4 | The switch: the upgrade on open, and LDP, WAC, posts, media and provisioning on metadata. Removes `legacy_under_root`, `maintenance.rs` and `acl-uncontain`. Forward-only. |
| 3 | 5 | Conditional requests, `ETag` and `Last-Modified`. |

Each commit is verified from a clean checkout (the stage 0 procedure). Clean
checkouts run one at a time, never alongside another test run, because
parallel Docker runs cause false failures.

## Reconciling the chunks

The five chunks were written in parallel against fixed interfaces. Chunk 1's
code is authoritative for the `store` API: it was compiled and tested in a
scratch copy of the repo. Where a later chunk names something differently, use
chunk 1's name and keep the later chunk's behaviour. Known points:

- **`PodRead`:**
  - It has `query_with(sparql, bindings)` as well as `query`.
  - `meta`, `members` and `storage_root` are `PodRead` methods, so callers need
    `use brolly_store::PodRead`.
  - Chunk 2's WAC code has been reconciled: it keeps today's SELECT with
    substituted bindings, through `query_with`.
- **`InstanceStore`:** chunk 1 gives it no `store()` accessor, and the `index`
  functions take `&InstanceStore` directly. Chunk 2's Task 1 is a
  reconciliation checklist over chunk 1's store work: skip anything chunk 1 has
  already done, and route index writes through the functions chunk 1 changed.
- **`LegacyWriter`:** its methods are `insert`, `remove`, `replace_graph` and
  `clear_graph`, as chunk 2 assumes. It refuses only the metadata graph.
- **The outside-root methods** refuse graphs under the root only once a root is
  recorded, so commit 1 writes profiles, follows and inbox entries as today.
- **`StoreError`:** chunk 1 adds `Invalid(String)` as well as the five listed
  variants.
- **`set_description`** (the spec's alt-text replacement) is in chunk 1's
  Task 3, and chunk 4's media code calls it.
- **`ldp::prepare`, `ldp::put_in` and `LdpError::BlobMissing`,** which chunk 4
  calls: match chunk 3's actual names.
- **Weak comparison for `If-None-Match`** (chunk 5) is in the spec.

## Chunk 1: The pod handle and the resource API (commit 1, part A)

Spec sections **The metadata graph**, **The pod handle: reads, and one way to
write**, and the store half of **Testing → `store/tests/resources.rs`**
(everything except the upgrade bullets, which are chunk 3). This chunk is the
first half of rollout commit 1; chunk 2 moves every caller onto the new API and
its last task commits both.

**The workspace doesn't build between Task 2 and the end of chunk 2.** Task 2
removes the `Deref`-shaped access every caller relies on (`StoreManager::pod`
returns `Arc<Pod>`, not `Arc<Store>`), makes the free write helpers
crate-private, and gives `StoreManager::instance` and the `index` functions an
`InstanceStore`. Every adapter and the server stop compiling until chunk 2
updates them. So in this chunk:

- **Gates are scoped to the two crates that change:**
  `cargo test -p brolly-domain -p brolly-store` and
  `cargo clippy -p brolly-domain -p brolly-store --all-targets -- -D warnings`,
  plus `cargo fmt --all -- --check` (rustfmt doesn't need the workspace to
  compile) and, in Task 2, `cargo deny check`.
- **Stage, don't commit.** Every task ends with `git add`. Chunk 2's last task
  runs the workspace gates and commits chunks 1 and 2 as one commit.

**What changes:**

| File | Change |
|---|---|
| `domain/src/vocab.rs` | the stage 5a terms, plus tests |
| `store/Cargo.toml` | `rand`, `time`, `tracing`; the `test-fixtures` feature; a self dev-dependency that turns it on for this crate's own tests |
| `store/src/manager.rs` | new `StoreError` variants; caches `Arc<Pod>`, live map of `Weak<Pod>`; `instance()` returns `&InstanceStore` |
| `store/src/resources.rs` (new) | `METADATA_GRAPH`, `PodRead`, `ReadStore`, `ResourceRead`, `Pod`, `PodWrite`, `LegacyWriter`, `Content`, `Kind`, `BlobMeta`, `ResourceMeta` |
| `store/src/index.rs` | `InstanceStore`; every function takes `&InstanceStore` |
| `store/src/write.rs` | transaction variants; the helpers become `pub(crate)`; `insert_record` and `replace_graph` go |
| `store/src/collection.rs` | readers take `&impl PodRead` |
| `store/src/lib.rs` | new modules and re-exports; `insert_quads`/`insert_record` no longer re-exported |
| `store/examples/store_budget.rs` | writes through `Pod::write` |
| `store/tests/storage_invariants.rs` | writes through `Pod::write`, reads through `PodRead`, the index through `InstanceStore` |
| `store/tests/resources.rs` (new) | the spec's store tests |

`store/tests/pod_lifecycle.rs` and `store/tests/blobs.rs` don't change. The
stage 0 behaviour they pin (an evicted-but-live pod is handed back, concurrent
first opens share one handle) is kept, now for `Arc<Pod>`, and Task 2's tests
add that the handed-back pod has the same write lock.

**Interfaces this chunk delivers.** Chunks 2 to 5 use exactly these. Where they
differ from the plan's fixed interfaces, the reason is in the reviewer notes.

- `brolly_store::{Pod, PodRead, ReadStore, ResourceRead, PodWrite, LegacyWriter, Content, Kind, BlobMeta, ResourceMeta, METADATA_GRAPH, InstanceStore}`, all re-exported at the crate root from `store::resources` (and `store::index` for `InstanceStore`).
- `trait PodRead` (sealed):
  - required: `quads_for_pattern(&self, Option<NamedOrBlankNodeRef<'_>>, Option<NamedNodeRef<'_>>, Option<TermRef<'_>>, Option<GraphNameRef<'_>>) -> QuadIter<'_>` and `evaluate(&self, PreparedSparqlQuery) -> Result<QueryResults<'_>, StoreError>`
  - provided: `query(&self, &str)`, `query_with(&self, &str, &[(&str, Term)])` (both `-> Result<QueryResults<'_>, StoreError>`, SELECT and ASK only), `meta(&self, &str) -> Result<Option<ResourceMeta>, StoreError>`, `members(&self, &str) -> Result<Vec<String>, StoreError>` (sorted), `storage_root(&self) -> Result<Option<String>, StoreError>`
  - implemented by `ReadStore<'_>`, `ResourceRead<'_>`, `PodWrite<'_>` and `InstanceStore`. A caller of `w.meta(..)` or `w.members(..)` on a `PodWrite` needs `use brolly_store::PodRead`.
- `Pod::{read_store, read, write, blobs}`, and `raw_store` behind `feature = "test-fixtures"`. `Pod::open` is `pub(crate)`.
- `PodWrite` under the root: `put(&mut self, &str, Content<'_>) -> Result<ResourceMeta, _>`, `append(&mut self, &str, &[Quad]) -> Result<ResourceMeta, _>`, `remove(&mut self, &str) -> Result<bool, _>`, `create_root(&mut self, &str) -> Result<(), _>`, `release_blob(&mut self, &str)`.
- `PodWrite` outside the root: `graph`, `insert`, `remove_quads`, `replace_graph`, `clear_graph`, with the fixed signatures.
- `PodWrite::legacy_under_root(&mut self) -> LegacyWriter<'_, 'a>`, with `insert(&[Quad])`, `remove(&[Quad])`, `replace_graph(&str, &[Quad])`, `clear_graph(&str)`, all `-> Result<(), StoreError>`. **Temporary**: chunk 3 deletes it.
- `enum Content<'a> { Rdf(&'a [Quad]), Container(&'a [Quad]), Binary(BlobMeta), Auxiliary(&'a [Quad]) }` (`Clone`, not `Copy`).
- `StoreError` gains `UnderRoot`, `NotUnderRoot`, `NoRoot`, `ContainerNotEmpty`, `BlobMissing`, and `Invalid(String)`.
- `StoreManager::pod(user) -> Result<Arc<Pod>, StoreError>` and `StoreManager::instance() -> &InstanceStore`. `StoreManager::blobs(user)` is unchanged.
- `index::{record_note, is_indexed, forget_note, public_note_iris, count_notes, clear, public_timeline}` take `&InstanceStore`.
- `collection::{members, received_at, literal_in, literal, read_record, record_type, timeline}` take `&impl PodRead`.
- Not public any more: `insert_quads` (now `pub(crate)`). Gone: `insert_record`, `write::replace_graph`. `write::WriteError` stays public.
- For chunk 3's `upgrade`, private items in `resources.rs` that a child module (`resources/upgrade.rs`, declared with `mod upgrade;`) can call: `PodWrite::{record, contain, forget}`, `meta_quad`, `containment`, `parent_container`, `is_acl`, `check_graph`, `iri`, `metadata_graph`, `next_modified`, `new_version`, and the `transaction`/`blobs` fields.

---

### Task 1: The vocabulary

**Files:**
- Modify: `domain/src/vocab.rs` (append after the last line, `:71`)

- [ ] **Step 1: Write the failing test**

Append to `domain/src/vocab.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_terms_live_in_their_namespaces() {
        for term in [
            LDP_RESOURCE,
            LDP_CONTAINER,
            LDP_BASIC_CONTAINER,
            LDP_RDF_SOURCE,
            LDP_NON_RDF_SOURCE,
            LDP_CONTAINS,
        ] {
            assert!(term.starts_with(LDP), "{term}");
        }
        assert!(PIM_STORAGE.starts_with(SPACE));
        assert!(DCTERMS_MODIFIED.starts_with(DCTERMS));
        assert!(XSD_DATE_TIME.starts_with(XSD));
        for term in [
            BROLLY_AUXILIARY,
            BROLLY_VERSION,
            BROLLY_LAYOUT,
            BROLLY_BLOB_DIGEST,
            BROLLY_MEDIA_TYPE,
            BROLLY_BYTE_SIZE,
        ] {
            assert!(term.starts_with(BROLLY), "{term}");
        }
    }

    #[test]
    fn the_blob_terms_keep_the_iris_already_stored() {
        // ADR 0013 pods already hold triples with these IRIs; the upgrade reads
        // them back, so moving the constants must not rename them.
        assert_eq!(BROLLY_BLOB_DIGEST, "https://brolly.id/ns#blobDigest");
        assert_eq!(BROLLY_MEDIA_TYPE, "https://brolly.id/ns#mediaType");
        assert_eq!(BROLLY_BYTE_SIZE, "https://brolly.id/ns#byteSize");
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-domain vocab`

Expected: the build fails with `error[E0425]: cannot find value `LDP_RESOURCE` in this scope`
(and the same for each new constant).

- [ ] **Step 3: Add the terms**

Insert this into `domain/src/vocab.rs` between `SPACE_STORAGE` (`:71`) and the
`#[cfg(test)]` module you just added:

```rust
// --- LDP resources and server-managed metadata (stage 5a) -------------------
//
// `store::resources` writes these into each pod's `urn:brolly:resources`
// graph. They describe resources the server manages, so no client write can
// reach them there.

/// `r` exists. In the metadata graph this triple *is* existence.
pub const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#RDFSource";
pub const LDP_NON_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#NonRDFSource";
pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
/// The class of a storage root. The same namespace as [`SPACE`]; Solid calls
/// it `pim:`.
pub const PIM_STORAGE: &str = "http://www.w3.org/ns/pim/space#Storage";

pub const DCTERMS: &str = "http://purl.org/dc/terms/";
pub const DCTERMS_MODIFIED: &str = "http://purl.org/dc/terms/modified";
pub const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";

/// An auxiliary resource (today only an `.acl`). Recorded, never contained.
pub const BROLLY_AUXILIARY: &str = "https://brolly.id/ns#Auxiliary";
/// A resource's version: a new ULID on every change, served as its `ETag`.
pub const BROLLY_VERSION: &str = "https://brolly.id/ns#version";
/// The pod's metadata layout version.
pub const BROLLY_LAYOUT: &str = "https://brolly.id/ns#layout";
/// Binary metadata (ADR 0013). No standard vocabulary names a
/// content-addressed blob; the digest is the join to the blob store.
pub const BROLLY_BLOB_DIGEST: &str = "https://brolly.id/ns#blobDigest";
pub const BROLLY_MEDIA_TYPE: &str = "https://brolly.id/ns#mediaType";
pub const BROLLY_BYTE_SIZE: &str = "https://brolly.id/ns#byteSize";
```

The three blob IRIs are the ones `adapters/solid/src/ldp.rs:70-72` already
stores (`BLOB_DIGEST`, `BLOB_MEDIA_TYPE`, `BLOB_SIZE`). Leave those copies in
place: chunk 2 points `ldp.rs` at these.

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-domain vocab`

Expected: `test result: ok. 2 passed`.

- [ ] **Step 5: Format**

Run: `cargo fmt --all`

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check
cargo clippy -p brolly-domain -p brolly-store --all-targets -- -D warnings
cargo test -p brolly-domain -p brolly-store
```

The workspace still builds after this task (the change is additive), but the
chunk's gates are the scoped ones throughout.

- [ ] **Step 7: Stage, don't commit**

```bash
git add domain/src/vocab.rs
```

---

### Task 2: The pod handle: `Pod`, `PodRead`, one way to write

**Files:**
- Create: `store/tests/resources.rs`
- Create: `store/src/resources.rs`
- Modify: `store/Cargo.toml` (whole file)
- Modify: `store/src/manager.rs` (whole file: `StoreError` `:21-43`, the struct `:57-71`, `open` `:89`, `pod` `:123`, `open_pod` `:134-151`, `live_handles` `:157`, `instance` `:161-164`)
- Modify: `store/src/write.rs` (whole file)
- Modify: `store/src/index.rs` (imports `:22-28`; `record_note` `:74`, `:118`; `is_indexed` `:127`; `forget_note` `:142-157`; `public_note_iris` `:168-172`; `count_notes` `:190`; `clear` `:203-206`; `public_timeline` `:223-228`, `:259`)
- Modify: `store/src/collection.rs` (imports `:16-19`; the seven readers at `:52`, `:70`, `:90`, `:110`, `:127`, `:149`, `:178-179`)
- Modify: `store/src/lib.rs` (whole file)
- Modify: `store/examples/store_budget.rs` (`:12`, `:29-40`)
- Modify: `store/tests/storage_invariants.rs` (`:6`, `:37-40`, `:69-71`, `:94-106`, `:118`, `:309-338`)

This task has no resources yet: the tests cover the read interface, the
outside-root methods, the legacy writer, the lock, and released blobs. Task 3
adds `put`, `append`, `remove` and `create_root`.

- [ ] **Step 1: Write the failing tests**

Create `store/tests/resources.rs`:

```rust
//! The pod handle: one read interface, one way to write.
//!
//! Spec: `docs/specs/2026-09-22-solid-resource-metadata.md`, Testing →
//! `store/tests/resources.rs`. The upgrade arrives, with its tests, in rollout
//! commit 2.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use brolly_store::{METADATA_GRAPH, Pod, PodRead, StoreError, StoreManager};
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
    assert!(graph(&pod.read_store(), METADATA_GRAPH).is_empty());
}

#[test]
fn the_legacy_writer_writes_without_metadata_and_never_into_it() {
    // Rollout commit 1 only: today's behaviour for resources under the root.
    let (_dir, stores) = manager(60);
    let pod = stores.pod(Uuid::new_v4()).unwrap();
    let old = "https://alice.brolly.test/~/old";

    pod.write(|w| w.legacy_under_root().insert(&[says(old, "raw")]))
        .unwrap();
    let read = pod.read_store();
    assert_eq!(said(&read, old).as_deref(), Some("raw"));
    assert!(read.meta(old).unwrap().is_none());

    let result = pod.write(|w| {
        w.legacy_under_root()
            .insert(&[says(METADATA_GRAPH, "forged")])
    });
    assert!(
        matches!(result, Err(StoreError::UnderRoot)),
        "got {result:?}"
    );
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-store --test resources`

Expected: the build fails with
`error[E0432]: unresolved imports `brolly_store::METADATA_GRAPH`, `brolly_store::Pod`, `brolly_store::PodRead``.

- [ ] **Step 3: Dependencies and the fixture feature**

Replace `store/Cargo.toml` with:

```toml
[package]
name = "brolly-store"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true
description = "Per-user pod stores, the server-agent store, and query helpers."

[features]
# `Pod::raw_store`, for tests that seed an old-layout pod. Enabled only from
# `[dev-dependencies]`: `cfg(test)` doesn't reach another crate's integration
# tests, and nothing outside `tests/` may name a raw store.
test-fixtures = []

[dependencies]
brolly-domain.workspace = true
moka = { version = "0.12.16", features = ["sync"] }
oxigraph = "0.5.9"
rand = "0.10.2"
serde_json = "1.0.151"
time = { version = "0.3.55", features = ["formatting", "parsing", "macros"] }
tracing.workspace = true
uuid = { version = "1.24.1", features = ["v4", "serde"] }

sha2 = "0.11.0"

[lints]
workspace = true

[dev-dependencies]
# Itself, with the fixtures, so this crate's own integration tests can seed
# old layouts the same way every other crate's do.
brolly-store = { path = ".", features = ["test-fixtures"] }
tempfile = "3.27.0"
```

No crate is new to `Cargo.lock`: `rand` 0.10.2, `time` 0.3.55 (with
`time-macros` 0.2.32) and `tracing` are already there for other members. The
self dev-dependency is how this crate's own integration tests get
`Pod::raw_store` (chunk 3's upgrade tests use it); `cargo test` builds
`brolly-store` once, with the feature on.

- [ ] **Step 4: `StoreError` and the manager**

Replace `store/src/manager.rs` with:

```rust
//! Store lifecycle: one on-disk Oxigraph database per user, plus the
//! instance's own.
//!
//! Pods are opened lazily and cached in an LRU, so an idle subdomain does not
//! keep its store mapped forever. Eviction drops the in-memory handle only; the
//! on-disk data stays.
//!
//! The LRU ceiling is a real budget line at thousands of users — each open
//! store carries its own memtables and file handles. `benches/` measures it;
//! the predecessor shipped 500/1h defaults that were never validated against a
//! number.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use moka::sync::Cache;
use uuid::Uuid;

use crate::index::InstanceStore;
use crate::resources::Pod;

#[derive(Debug, Clone)]
pub enum StoreError {
    Io(String),
    Backend(String),
    NotFound,
    /// An outside-root write named a graph under the storage root, or the
    /// metadata graph itself. Those change only through `put` and `remove`.
    UnderRoot,
    /// `put` named a resource outside the pod's storage root.
    NotUnderRoot,
    /// The pod has no storage root recorded, so there is nothing to put under.
    NoRoot,
    /// `remove` of a container that still has members.
    ContainerNotEmpty,
    /// `Content::Binary` named a digest whose bytes aren't in the blob store.
    /// Write the bytes again and retry once.
    BlobMissing,
    /// A write the store refuses as malformed: content that doesn't fit its
    /// IRI, a quad outside the resource's graph, removing the storage root.
    Invalid(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Backend(e) => write!(f, "store backend: {e}"),
            StoreError::NotFound => write!(f, "store not found"),
            StoreError::UnderRoot => write!(f, "graph is under the storage root"),
            StoreError::NotUnderRoot => write!(f, "resource is outside the storage root"),
            StoreError::NoRoot => write!(f, "pod has no storage root"),
            StoreError::ContainerNotEmpty => write!(f, "container is not empty"),
            StoreError::BlobMissing => write!(f, "blob bytes are missing"),
            StoreError::Invalid(e) => write!(f, "invalid write: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

impl From<oxigraph::store::StorageError> for StoreError {
    fn from(e: oxigraph::store::StorageError) -> Self {
        StoreError::Backend(e.to_string())
    }
}

impl From<oxigraph::store::LoaderError> for StoreError {
    fn from(e: oxigraph::store::LoaderError) -> Self {
        StoreError::Backend(e.to_string())
    }
}

/// Opens and caches per-user pods, and owns the instance store.
pub struct StoreManager {
    base: PathBuf,
    pods: Cache<Uuid, Arc<Pod>>,
    /// Every pod handle still alive anywhere, cached or not.
    ///
    /// RocksDB lets a process open a directory once. The cache can evict a pod
    /// while a request still holds its `Arc`, and a second `Store::open` on
    /// that directory is then refused by the lock. So a cache miss looks here
    /// first and hands back the live handle. The lock covers only the map;
    /// concurrent opens of one pod are deduplicated by the cache itself.
    ///
    /// Handing back the same `Pod` also hands back the same write lock (R6):
    /// two `Pod`s over one database would each serialise their own writers and
    /// not each other's.
    live: Mutex<HashMap<Uuid, Weak<Pod>>>,
    instance: InstanceStore,
}

impl StoreManager {
    /// Open (or create) the store tree under `base`.
    ///
    /// `max_open` bounds resident pods; `idle_secs` evicts handles that have
    /// gone quiet. Both are budget numbers — see `benches/store_open.rs`.
    pub fn open(
        base: impl Into<PathBuf>,
        max_open: u64,
        idle_secs: u64,
    ) -> Result<Self, StoreError> {
        let base = base.into();
        std::fs::create_dir_all(base.join("users"))?;
        let instance_dir = base.join("instance");
        std::fs::create_dir_all(&instance_dir)?;

        Ok(Self {
            instance: InstanceStore::open(&instance_dir)?,
            pods: Cache::builder()
                .max_capacity(max_open)
                .time_to_idle(std::time::Duration::from_secs(idle_secs))
                .build(),
            live: Mutex::new(HashMap::new()),
            base,
        })
    }

    fn pod_dir(&self, user: Uuid) -> PathBuf {
        self.base.join("users").join(user.to_string())
    }

    /// The user's blob directory, creating it on first use.
    ///
    /// Under the pod directory, so `delete_pod` takes the bytes with it and
    /// `pod_bytes` counts them — media has to sit inside the same quota and the
    /// same delete as the triples, or neither number means anything.
    pub fn blobs(&self, user: Uuid) -> Result<crate::blobs::BlobStore, StoreError> {
        crate::blobs::BlobStore::open(self.pod_dir(user).join("blobs"))
    }

    /// Content-addressed storage for the member's ATProtocol repo blocks.
    ///
    /// Separate from `blobs` even though both are content-addressed immutable
    /// bytes: media and repo blocks have different lifecycles — a blob is
    /// deleted when its last resource goes, a repo block is history — and
    /// mixing them would make either sweep reason about the other.
    pub fn repo_blocks(&self, user: Uuid) -> Result<crate::blobs::BlobStore, StoreError> {
        crate::blobs::BlobStore::open(self.pod_dir(user).join("repo"))
    }

    /// The user's pod, opening it if necessary. Creates on first use.
    pub fn pod(&self, user: Uuid) -> Result<Arc<Pod>, StoreError> {
        // `try_get_with` runs `open_pod` at most once per user at a time, and
        // concurrent requests for that user wait for its result. Requests for
        // different users open in parallel: opening costs milliseconds (ADR
        // 0006), so one lock across every open would queue members behind each
        // other on a burst of cache misses.
        self.pods
            .try_get_with(user, || self.open_pod(user))
            .map_err(|e| StoreError::clone(&e))
    }

    /// Hand back the live handle if the cache evicted one a request still
    /// holds, and open the database only when nothing does.
    fn open_pod(&self, user: Uuid) -> Result<Arc<Pod>, StoreError> {
        if let Some(pod) = self.live_handles().get(&user).and_then(Weak::upgrade) {
            return Ok(pod);
        }
        let pod = Arc::new(Pod::open(&self.pod_dir(user))?);
        let mut live = self.live_handles();
        // Drop entries whose pods have closed, so the map tracks what is open
        // rather than everyone who was ever served.
        live.retain(|_, handle| handle.strong_count() > 0);
        live.insert(user, Arc::downgrade(&pod));
        Ok(pod)
    }

    /// The live-handle map. A poisoned lock only means another thread panicked
    /// while holding it; the map holds weak handles, so nothing in it can be
    /// half-written.
    fn live_handles(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Weak<Pod>>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The server agent's own store — the cross-user query surface (ADR 0005).
    ///
    /// Not a `Pod`: it has no storage root, is never upgraded, and only
    /// `index` writes it (R15).
    pub fn instance(&self) -> &InstanceStore {
        &self.instance
    }

    /// Delete a user's pod outright.
    ///
    /// This is the whole delete story: content lives in exactly one place, so
    /// removing the directory removes it. The instance index is left holding
    /// dangling pointers, which is the correct steady state — they sweep lazily
    /// on dereference (D5).
    pub fn delete_pod(&self, user: Uuid) -> Result<(), StoreError> {
        self.pods.invalidate(&user);
        self.live_handles().remove(&user);
        let dir = self.pod_dir(user);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    pub fn pod_exists(&self, user: Uuid) -> bool {
        self.pod_dir(user).exists()
    }

    /// Resident pod count. Exposed for the benchmark and for operational
    /// metrics — the LRU ceiling is only meaningful if it can be observed.
    pub fn open_pods(&self) -> u64 {
        self.pods.run_pending_tasks();
        self.pods.entry_count()
    }

    /// Bytes on disk for one user, for quota accounting. Cheap because pods are
    /// physically separate — the property that per-user isolation buys.
    pub fn pod_bytes(&self, user: Uuid) -> std::io::Result<u64> {
        crate::blobs::dir_bytes(&self.pod_dir(user))
    }
}
```

The live map now holds `Weak<Pod>`, so a pod handed back after eviction is the
same `Pod` with the same write lock (R6). `open_pod` no longer builds the
`rdf/` path itself: `Pod::open` takes the pod directory and opens `rdf/` and
`blobs/` under it, which is how `Pod::write` reaches the `BlobStore` it checks
and sweeps.

- [ ] **Step 5: The write path's transaction variants**

Replace `store/src/write.rs` with:

```rust
//! **The** write path. Every quad entering any store passes through here.
//!
//! A canonicalization table is worth nothing if a writer can bypass it. The
//! predecessor had no choke point, so whichever AS2 spelling a sender used got
//! stored, five reader modules had to match both, and a production bug shipped
//! when one of them matched only the `https` form.
//!
//! There is exactly one insert per target in this crate, a store and a
//! transaction, both canonicalize, and `tests/storage_invariants.rs` asserts
//! that non-canonical input cannot survive a round trip through storage.
//!
//! The functions are crate-internal. Everything outside `store` writes a pod
//! through `Pod::write` and the instance through `index`, and both land here.
//! `WriteError` stays public for the adapters' error conversions.

use brolly_domain::faithful::FaithfulError;
use brolly_domain::iri::canonicalize_quad;
use oxigraph::model::Quad;
use oxigraph::store::{Store, Transaction};

use crate::manager::StoreError;

#[derive(Debug)]
pub enum WriteError {
    Store(StoreError),
    Encode(FaithfulError),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Store(e) => write!(f, "{e}"),
            WriteError::Encode(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<StoreError> for WriteError {
    fn from(e: StoreError) -> Self {
        WriteError::Store(e)
    }
}

impl From<FaithfulError> for WriteError {
    fn from(e: FaithfulError) -> Self {
        WriteError::Encode(e)
    }
}

/// Insert quads, normalizing every IRI on the way in.
///
/// The insertion point for a bare store: today only the instance index.
/// Returns the number written.
pub(crate) fn insert_quads(store: &Store, quads: &[Quad]) -> Result<usize, WriteError> {
    for quad in quads {
        store
            .insert(&canonicalize_quad(quad))
            .map_err(|e| WriteError::Store(StoreError::from(e)))?;
    }
    Ok(quads.len())
}

/// Insert quads inside an open transaction, normalizing every IRI on the way
/// in. The pod's insertion point: `PodWrite` and `resources` reach the
/// transaction only through here. Returns the number written.
pub(crate) fn insert_quads_in(transaction: &mut Transaction<'_>, quads: &[Quad]) -> usize {
    for quad in quads {
        transaction.insert(&canonicalize_quad(quad));
    }
    quads.len()
}

/// Remove quads inside an open transaction.
///
/// Canonicalized like an insert, so removing the `http` spelling of a quad
/// removes the `https` one that was actually stored.
pub(crate) fn remove_quads_in(transaction: &mut Transaction<'_>, quads: &[Quad]) {
    for quad in quads {
        transaction.remove(&canonicalize_quad(quad));
    }
}
```

`insert_record` and `replace_graph` go: nothing in `store` uses them, and
outside `store` a record is `faithful::encode` then `PodWrite::insert`.

- [ ] **Step 6: `resources.rs`**

Create `store/src/resources.rs`:

```rust
//! Pods, and the resources under their storage root.
//!
//! A pod stores each LDP resource as the named graph at its IRI, and holds
//! what the *server* knows about those resources (existence, kind,
//! containment, modified time, version, blob metadata) in one more graph,
//! [`METADATA_GRAPH`]. No LDP path names that graph, and this module is the
//! only code that writes it, so no client write can reach server-managed
//! state.
//!
//! **One way to write.** [`Pod`] keeps its `Store` private. Reads go through
//! [`PodRead`]; every write goes through [`Pod::write`], which takes the pod's
//! lock, opens one transaction, and hands the closure a [`PodWrite`]. Under
//! the storage root `PodWrite` offers only `put`/`append`/`remove`, which keep
//! the metadata true; outside it, `insert`/`remove_quads`/`replace_graph`/
//! `clear_graph`, which refuse anything under the root. A write that skips the
//! lock or the metadata doesn't compile (spec R5, R7).
//!
//! **In-memory stores deadlock here.** Oxigraph's in-memory backend serialises
//! every transaction behind one lock, so `Pod::read` inside a `Pod::write`
//! closure would wait on itself. Pods are always RocksDB, which snapshots
//! instead, so this only matters to a test that builds a pod some other way.
//!
//! See `docs/specs/2026-09-22-solid-resource-metadata.md`.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use brolly_domain::vocab;
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, Term, TermRef, Variable,
};
use oxigraph::sparql::{PreparedSparqlQuery, QueryEvaluationError, QueryResults, SparqlEvaluator};
use oxigraph::store::{QuadIter, Store, Transaction};

use crate::blobs::BlobStore;
use crate::manager::StoreError;
use crate::write::{insert_quads_in, remove_quads_in};

/// The graph holding every pod's resource metadata.
///
/// Not an `https` IRI, so no LDP path can name it.
pub const METADATA_GRAPH: &str = "urn:brolly:resources";

// --- the read interface ------------------------------------------------------

mod sealed {
    pub trait Sealed {}
}

/// Everything a reader needs, and nothing that writes (R14).
///
/// Three providers: [`ReadStore`] (the committed store), [`ResourceRead`] (one
/// snapshot) and [`PodWrite`] (the open transaction, so a read inside a write
/// sees that write's own changes). `InstanceStore` implements it too. Sealed:
/// only this crate's types are readers.
pub trait PodRead: sealed::Sealed {
    /// Quads matching a pattern. The same iterator Oxigraph returns for a store
    /// and for a transaction.
    fn quads_for_pattern(
        &self,
        subject: Option<NamedOrBlankNodeRef<'_>>,
        predicate: Option<NamedNodeRef<'_>>,
        object: Option<TermRef<'_>>,
        graph_name: Option<GraphNameRef<'_>>,
    ) -> QuadIter<'_>;

    /// Run a query that is already prepared, for a caller that substitutes
    /// variables itself. SELECT and ASK only: a prepared *query* can't be an
    /// update, and a CONSTRUCT or DESCRIBE is refused.
    fn evaluate(&self, query: PreparedSparqlQuery) -> Result<QueryResults<'_>, StoreError>;

    /// Parse and run a SPARQL SELECT or ASK.
    fn query(&self, sparql: &str) -> Result<QueryResults<'_>, StoreError> {
        self.query_with(sparql, &[])
    }

    /// Parse and run a SPARQL SELECT or ASK, with variables bound by
    /// substitution rather than interpolated into the text.
    fn query_with(
        &self,
        sparql: &str,
        bindings: &[(&str, Term)],
    ) -> Result<QueryResults<'_>, StoreError> {
        let mut prepared = SparqlEvaluator::new()
            .parse_query(sparql)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        for (name, value) in bindings {
            let variable = Variable::new(*name).map_err(|e| StoreError::Backend(e.to_string()))?;
            prepared = prepared.substitute_variable(variable, value.clone());
        }
        self.evaluate(prepared)
    }

    /// The resource's metadata, or `None` when it doesn't exist.
    ///
    /// Existence is one triple, `<r> a ldp:Resource` in [`METADATA_GRAPH`]
    /// (R2), so an empty document or container exists once created.
    fn meta(&self, resource: &str) -> Result<Option<ResourceMeta>, StoreError> {
        read_meta(self, resource)
    }

    /// A container's members, sorted. Read only from the metadata graph, so a
    /// container's own graph can't add or hide one (R3).
    fn members(&self, container: &str) -> Result<Vec<String>, StoreError> {
        let mut members = Vec::new();
        for quad in self.quads_for_pattern(
            Some(iri(container).as_ref().into()),
            Some(iri(vocab::LDP_CONTAINS).as_ref()),
            None,
            Some(metadata_graph().as_ref()),
        ) {
            if let Term::NamedNode(member) = quad?.object {
                members.push(member.into_string());
            }
        }
        members.sort();
        Ok(members)
    }

    /// The pod's storage root, from `<root> a pim:Storage` in the metadata.
    fn storage_root(&self) -> Result<Option<String>, StoreError> {
        let first = self
            .quads_for_pattern(
                None,
                Some(iri(vocab::RDF_TYPE).as_ref()),
                Some(iri(vocab::PIM_STORAGE).as_ref().into()),
                Some(metadata_graph().as_ref()),
            )
            .next()
            .transpose()?;
        Ok(first.and_then(|quad| match quad.subject {
            NamedOrBlankNode::NamedNode(root) => Some(root.into_string()),
            NamedOrBlankNode::BlankNode(_) => None,
        }))
    }
}

/// Refuse a CONSTRUCT or DESCRIBE, and map the engine's error.
pub(crate) fn read_only<'a>(
    results: Result<QueryResults<'a>, QueryEvaluationError>,
) -> Result<QueryResults<'a>, StoreError> {
    match results.map_err(|e| StoreError::Backend(e.to_string()))? {
        QueryResults::Graph(_) => Err(StoreError::Backend(
            "only SELECT and ASK queries are supported".into(),
        )),
        results => Ok(results),
    }
}

/// A plain read of the committed store. Each call sees the latest commit;
/// for several reads that must agree, use [`Pod::read`].
pub struct ReadStore<'a> {
    store: &'a Store,
}

/// One consistent snapshot of a pod, for [`Pod::read`].
///
/// A transaction that is never committed: on RocksDB that is a snapshot plus
/// an empty write batch, and it takes no lock.
pub struct ResourceRead<'a> {
    transaction: Transaction<'a>,
}

impl sealed::Sealed for ReadStore<'_> {}
impl sealed::Sealed for ResourceRead<'_> {}
impl sealed::Sealed for PodWrite<'_> {}
impl sealed::Sealed for crate::index::InstanceStore {}

impl PodRead for ReadStore<'_> {
    fn quads_for_pattern(
        &self,
        subject: Option<NamedOrBlankNodeRef<'_>>,
        predicate: Option<NamedNodeRef<'_>>,
        object: Option<TermRef<'_>>,
        graph_name: Option<GraphNameRef<'_>>,
    ) -> QuadIter<'_> {
        self.store
            .quads_for_pattern(subject, predicate, object, graph_name)
    }

    fn evaluate(&self, query: PreparedSparqlQuery) -> Result<QueryResults<'_>, StoreError> {
        read_only(query.on_store(self.store).execute())
    }
}

impl PodRead for ResourceRead<'_> {
    fn quads_for_pattern(
        &self,
        subject: Option<NamedOrBlankNodeRef<'_>>,
        predicate: Option<NamedNodeRef<'_>>,
        object: Option<TermRef<'_>>,
        graph_name: Option<GraphNameRef<'_>>,
    ) -> QuadIter<'_> {
        self.transaction
            .quads_for_pattern(subject, predicate, object, graph_name)
    }

    fn evaluate(&self, query: PreparedSparqlQuery) -> Result<QueryResults<'_>, StoreError> {
        read_only(query.on_transaction(&self.transaction).execute())
    }
}

impl PodRead for PodWrite<'_> {
    fn quads_for_pattern(
        &self,
        subject: Option<NamedOrBlankNodeRef<'_>>,
        predicate: Option<NamedNodeRef<'_>>,
        object: Option<TermRef<'_>>,
        graph_name: Option<GraphNameRef<'_>>,
    ) -> QuadIter<'_> {
        self.transaction
            .quads_for_pattern(subject, predicate, object, graph_name)
    }

    fn evaluate(&self, query: PreparedSparqlQuery) -> Result<QueryResults<'_>, StoreError> {
        read_only(query.on_transaction(&self.transaction).execute())
    }
}

// --- resource metadata ---------------------------------------------------------

/// What kind of resource the metadata records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Container,
    RdfSource,
    NonRdfSource,
    /// An auxiliary resource: today only an `.acl`. Recorded, never contained.
    Auxiliary,
}

/// A binary's bytes, by digest, in the pod's `BlobStore` (ADR 0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeta {
    pub digest: String,
    pub media_type: String,
    pub byte_size: u64,
}

/// Everything the server records about one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMeta {
    pub kind: Kind,
    /// `xsd:dateTime` lexical form, UTC, millisecond precision: fixed width,
    /// so it also sorts as text.
    pub modified: String,
    /// A ULID, new on every change. The `ETag` (R4).
    pub version: String,
    pub blob: Option<BlobMeta>,
}

/// What `put` stores.
#[derive(Debug, Clone)]
pub enum Content<'a> {
    /// An RDF document, exactly as sent. May be empty.
    Rdf(&'a [Quad]),
    /// A container's extra triples; never its containment. May be empty.
    Container(&'a [Quad]),
    /// A binary whose bytes are already in the pod's `BlobStore`.
    Binary(BlobMeta),
    /// An auxiliary resource: an ACL.
    Auxiliary(&'a [Quad]),
}

// --- the pod -------------------------------------------------------------------

/// One member's pod: its store, its blobs, and the lock every write takes.
///
/// No `Deref` to `Store` (R7). Cached by `StoreManager` as `Arc<Pod>`, with a
/// `Weak<Pod>` in its live map, so a pod re-fetched while any request still
/// holds it is the same `Pod` with the same lock (R6).
pub struct Pod {
    store: Store,
    blobs: BlobStore,
    write_lock: Mutex<()>,
}

impl Pod {
    /// Open the pod under `dir`: the graph in `rdf/`, the bytes in `blobs/`.
    ///
    /// The graph has its own subdirectory because Oxigraph owns that
    /// directory's layout, and `blobs/` inside it would be a stray directory in
    /// a database it manages. Crate-internal: `StoreManager` opens each pod
    /// once, and RocksDB refuses a second open.
    pub(crate) fn open(dir: &Path) -> Result<Self, StoreError> {
        let rdf = dir.join("rdf");
        std::fs::create_dir_all(&rdf)?;
        Ok(Self {
            store: Store::open(&rdf)?,
            blobs: BlobStore::open(dir.join("blobs"))?,
            write_lock: Mutex::new(()),
        })
    }

    /// Everything a reader needs: pattern matching and SPARQL queries. No
    /// writes. Each call reads the latest commit.
    pub fn read_store(&self) -> ReadStore<'_> {
        ReadStore { store: &self.store }
    }

    /// A consistent read: metadata and content from one snapshot, no lock.
    pub fn read<T>(
        &self,
        f: impl FnOnce(&ResourceRead<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let snapshot = ResourceRead {
            transaction: self.store.start_transaction()?,
        };
        f(&snapshot)
    }

    /// The only way to change a pod.
    ///
    /// Takes the write lock, *then* starts one transaction, so it sees every
    /// earlier commit: Oxigraph transactions read a snapshot and commit a blind
    /// batch with no conflict detection. Runs `f`, commits, then deletes the
    /// released blobs nothing references any more, and only then releases the
    /// lock (R12). A closure that errs or a commit that fails writes nothing
    /// and deletes nothing.
    ///
    /// `f` is synchronous, so the lock can't be held across an `.await`. The
    /// mutex isn't reentrant: calling `write` inside `f` deadlocks, so a caller
    /// with several operations does them in one closure.
    pub fn write<T>(
        &self,
        f: impl FnOnce(&mut PodWrite<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        // A poisoned lock means a closure panicked, and a panicking closure
        // never committed: there is nothing half-written to distrust.
        let _held = self
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut writer = PodWrite {
            transaction: self.store.start_transaction()?,
            released: Vec::new(),
        };
        let value = f(&mut writer)?;
        let PodWrite {
            transaction,
            released,
            ..
        } = writer;
        transaction.commit()?;
        self.sweep(released);
        Ok(value)
    }

    /// Delete each released blob that no resource references any more.
    ///
    /// Runs after the commit and under the lock, so a concurrent upload of the
    /// same bytes either committed first (still referenced, kept) or runs after
    /// this and finds the file gone, which `Content::Binary` refuses with
    /// `BlobMissing`. The write has committed by now, so a failed delete is
    /// logged rather than returned: the bytes are orphaned, not lost.
    fn sweep(&self, mut released: Vec<String>) {
        released.sort();
        released.dedup();
        for digest in released {
            match blob_referenced(&self.read_store(), &digest) {
                Ok(true) => {}
                Ok(false) => {
                    if let Err(error) = self.blobs.remove(&digest) {
                        tracing::warn!(%digest, %error, "released blob not deleted");
                    }
                }
                Err(error) => {
                    tracing::warn!(%digest, %error, "released blob not checked; kept");
                }
            }
        }
    }

    /// The pod's blob store. Write bytes here *before* `write` (R12): uploads
    /// shouldn't queue behind the lock on disk I/O.
    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// The raw store, for tests that seed an old layout. Behind the
    /// `test-fixtures` feature, which crates enable only in
    /// `[dev-dependencies]`.
    #[cfg(feature = "test-fixtures")]
    pub fn raw_store(&self) -> &Store {
        &self.store
    }
}

// --- writing -------------------------------------------------------------------

/// One open transaction on a pod, handed to a [`Pod::write`] closure.
///
/// Two families of methods. Under the storage root: [`put`](Self::put),
/// [`append`](Self::append), [`remove`](Self::remove), which keep the metadata
/// true. Outside it: [`insert`](Self::insert), [`remove_quads`](Self::remove_quads),
/// [`replace_graph`](Self::replace_graph), [`clear_graph`](Self::clear_graph),
/// which refuse any graph under the root with `StoreError::UnderRoot`. One
/// transaction covers both, so a post and its outbox entry commit together.
pub struct PodWrite<'a> {
    transaction: Transaction<'a>,
    released: Vec<String>,
}

impl<'a> PodWrite<'a> {
    /// Mark a blob for deletion once this write commits, if nothing references
    /// it by then. Idempotent; a failed write deletes nothing.
    pub fn release_blob(&mut self, digest: &str) {
        self.released.push(digest.to_string());
    }

    // --- outside the storage root ---

    /// Every quad in one outside-root graph.
    pub fn graph(&self, graph: &str) -> Result<Vec<Quad>, StoreError> {
        self.refuse_under_root([&GraphName::NamedNode(iri(graph))])?;
        self.transaction
            .quads_for_pattern(
                None,
                None,
                None,
                Some(GraphNameRef::NamedNode(iri(graph).as_ref())),
            )
            .map(|quad| quad.map_err(StoreError::from))
            .collect()
    }

    /// Insert quads into outside-root graphs.
    pub fn insert(&mut self, quads: &[Quad]) -> Result<(), StoreError> {
        self.refuse_under_root(quads.iter().map(|quad| &quad.graph_name))?;
        insert_quads_in(&mut self.transaction, quads);
        Ok(())
    }

    /// Remove quads from outside-root graphs.
    pub fn remove_quads(&mut self, quads: &[Quad]) -> Result<(), StoreError> {
        self.refuse_under_root(quads.iter().map(|quad| &quad.graph_name))?;
        remove_quads_in(&mut self.transaction, quads);
        Ok(())
    }

    /// Replace an outside-root graph's contents with `quads`, which must all be
    /// in that graph.
    pub fn replace_graph(&mut self, graph: &str, quads: &[Quad]) -> Result<(), StoreError> {
        check_graph(graph, quads)?;
        self.clear_graph(graph)?;
        insert_quads_in(&mut self.transaction, quads);
        Ok(())
    }

    /// Empty an outside-root graph.
    pub fn clear_graph(&mut self, graph: &str) -> Result<(), StoreError> {
        self.refuse_under_root([&GraphName::NamedNode(iri(graph))])?;
        self.transaction
            .clear_graph(GraphNameRef::NamedNode(iri(graph).as_ref()))?;
        Ok(())
    }

    /// TEMPORARY, rollout commit 1 only: raw writes under the storage root,
    /// with no metadata, so that commit changes no behaviour. Removed in
    /// commit 2, when every under-root writer moves to `put` and `remove`.
    pub fn legacy_under_root(&mut self) -> LegacyWriter<'_, 'a> {
        LegacyWriter {
            transaction: &mut self.transaction,
        }
    }

    // --- internals ---

    /// Refuse the metadata graph always, and graphs under the storage root once
    /// a root is recorded. A pod with no root has nothing under it yet.
    fn refuse_under_root<'q>(
        &self,
        graphs: impl IntoIterator<Item = &'q GraphName>,
    ) -> Result<(), StoreError> {
        let root = self.storage_root()?;
        for graph in graphs {
            let GraphName::NamedNode(graph) = graph else {
                continue;
            };
            let under_root = root
                .as_deref()
                .is_some_and(|root| graph.as_str().starts_with(root));
            if under_root || graph.as_str() == METADATA_GRAPH {
                return Err(StoreError::UnderRoot);
            }
        }
        Ok(())
    }
}

/// Raw writes under the storage root, with no metadata. TEMPORARY: rollout
/// commit 1 only. Still refuses the metadata graph.
pub struct LegacyWriter<'w, 'a> {
    transaction: &'w mut Transaction<'a>,
}

impl LegacyWriter<'_, '_> {
    pub fn insert(&mut self, quads: &[Quad]) -> Result<(), StoreError> {
        refuse_metadata(quads)?;
        insert_quads_in(self.transaction, quads);
        Ok(())
    }

    pub fn remove(&mut self, quads: &[Quad]) -> Result<(), StoreError> {
        refuse_metadata(quads)?;
        remove_quads_in(self.transaction, quads);
        Ok(())
    }

    pub fn replace_graph(&mut self, graph: &str, quads: &[Quad]) -> Result<(), StoreError> {
        check_graph(graph, quads)?;
        self.clear_graph(graph)?;
        insert_quads_in(self.transaction, quads);
        Ok(())
    }

    pub fn clear_graph(&mut self, graph: &str) -> Result<(), StoreError> {
        if graph == METADATA_GRAPH {
            return Err(StoreError::UnderRoot);
        }
        self.transaction
            .clear_graph(GraphNameRef::NamedNode(iri(graph).as_ref()))?;
        Ok(())
    }
}

fn refuse_metadata(quads: &[Quad]) -> Result<(), StoreError> {
    let names_metadata = quads.iter().any(
        |quad| matches!(&quad.graph_name, GraphName::NamedNode(g) if g.as_str() == METADATA_GRAPH),
    );
    if names_metadata {
        return Err(StoreError::UnderRoot);
    }
    Ok(())
}

// --- helpers ---------------------------------------------------------------------

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn metadata_graph() -> GraphName {
    GraphName::NamedNode(iri(METADATA_GRAPH))
}

/// Every quad must be in `graph`, or a write to one resource could reach
/// another.
fn check_graph(graph: &str, quads: &[Quad]) -> Result<(), StoreError> {
    let stray = quads
        .iter()
        .any(|quad| !matches!(&quad.graph_name, GraphName::NamedNode(g) if g.as_str() == graph));
    if stray {
        return Err(StoreError::Invalid(format!(
            "a quad for {graph} names another graph"
        )));
    }
    Ok(())
}

/// Read one resource's record.
fn read_meta<R: PodRead + ?Sized>(
    read: &R,
    resource: &str,
) -> Result<Option<ResourceMeta>, StoreError> {
    let mut exists = false;
    let mut kind = Kind::RdfSource;
    let mut modified = String::new();
    let mut version = String::new();
    let mut digest = None;
    let mut media_type = None;
    let mut byte_size = None;
    for quad in read.quads_for_pattern(
        Some(iri(resource).as_ref().into()),
        None,
        None,
        Some(metadata_graph().as_ref()),
    ) {
        let quad = quad?;
        let predicate = quad.predicate.as_str();
        match (predicate, &quad.object) {
            (vocab::RDF_TYPE, Term::NamedNode(class)) => match class.as_str() {
                vocab::LDP_RESOURCE => exists = true,
                vocab::BROLLY_AUXILIARY => kind = Kind::Auxiliary,
                vocab::LDP_CONTAINER if kind != Kind::Auxiliary => kind = Kind::Container,
                vocab::LDP_NON_RDF_SOURCE if kind == Kind::RdfSource => {
                    kind = Kind::NonRdfSource;
                }
                _ => {}
            },
            (vocab::DCTERMS_MODIFIED, Term::Literal(value)) => modified = value.value().into(),
            (vocab::BROLLY_VERSION, Term::Literal(value)) => version = value.value().into(),
            (vocab::BROLLY_BLOB_DIGEST, Term::Literal(value)) => {
                digest = Some(value.value().into())
            }
            (vocab::BROLLY_MEDIA_TYPE, Term::Literal(value)) => {
                media_type = Some(value.value().into());
            }
            (vocab::BROLLY_BYTE_SIZE, Term::Literal(value)) => {
                byte_size = value.value().parse().ok()
            }
            _ => {}
        }
    }
    if !exists {
        return Ok(None);
    }
    let blob = match (digest, media_type, byte_size) {
        (Some(digest), Some(media_type), Some(byte_size)) => Some(BlobMeta {
            digest,
            media_type,
            byte_size,
        }),
        _ => None,
    };
    Ok(Some(ResourceMeta {
        kind,
        modified,
        version,
        blob,
    }))
}

/// Is any resource's record naming this digest?
fn blob_referenced(read: &impl PodRead, digest: &str) -> Result<bool, StoreError> {
    let literal = Term::Literal(Literal::new_simple_literal(digest));
    let first = read
        .quads_for_pattern(
            None,
            Some(iri(vocab::BROLLY_BLOB_DIGEST).as_ref()),
            Some(literal.as_ref()),
            Some(metadata_graph().as_ref()),
        )
        .next()
        .transpose()?;
    Ok(first.is_some())
}
```

`PodWrite` has no `blobs` field yet; Task 3 adds it with `put`, which is its
only reader. `Pod::read` holds a transaction it never commits: on RocksDB that
is a snapshot and an empty write batch, with no lock. `sweep` logs at `warn`
rather than failing, because by then the write has committed.

- [ ] **Step 7: `InstanceStore`**

In `store/src/index.rs`, replace the imports (`:22-28`):

```rust
use oxigraph::model::Variable;
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};
use oxigraph::store::Store;

use crate::manager::StoreError;
use crate::write::{WriteError, insert_quads};
```

with the imports and the new type:

```rust
use std::path::Path;

use oxigraph::model::Variable;
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, Term, TermRef,
};
use oxigraph::sparql::{PreparedSparqlQuery, QueryResults, SparqlEvaluator};
use oxigraph::store::{QuadIter, Store};

use crate::manager::StoreError;
use crate::resources::{PodRead, read_only};
use crate::write::{WriteError, insert_quads};

/// The server agent's own store (ADR 0005).
///
/// Its own type rather than a `Pod` (R15): it has no storage root and no
/// resource metadata, it is never upgraded, and the functions in this module
/// are the only things that write it. Everything else reads it through
/// [`PodRead`].
pub struct InstanceStore {
    store: Store,
}

impl InstanceStore {
    pub(crate) fn open(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            store: Store::open(dir)?,
        })
    }
}

impl PodRead for InstanceStore {
    fn quads_for_pattern(
        &self,
        subject: Option<NamedOrBlankNodeRef<'_>>,
        predicate: Option<NamedNodeRef<'_>>,
        object: Option<TermRef<'_>>,
        graph_name: Option<GraphNameRef<'_>>,
    ) -> QuadIter<'_> {
        self.store
            .quads_for_pattern(subject, predicate, object, graph_name)
    }

    fn evaluate(&self, query: PreparedSparqlQuery) -> Result<QueryResults<'_>, StoreError> {
        read_only(query.on_store(&self.store).execute())
    }
}
```

Then, in the same file:

- `:74`: `pub fn record_note(store: &Store, pointer: &NotePointer) -> Result<(), WriteError> {` becomes `pub fn record_note(store: &InstanceStore, pointer: &NotePointer) -> Result<(), WriteError> {`
- `:118`: `    insert_quads(store, &quads)?;` becomes `    insert_quads(&store.store, &quads)?;`
- `:127`: `pub fn is_indexed(store: &Store, note: &NamedNode) -> Result<bool, StoreError> {` becomes `pub fn is_indexed(store: &InstanceStore, note: &NamedNode) -> Result<bool, StoreError> {` (its body reads through `PodRead::quads_for_pattern` unchanged)
- `forget_note` (`:142-157`) becomes:

```rust
/// Drop a row — used when a dereference 404s, i.e. the pod no longer has it.
pub fn forget_note(store: &InstanceStore, note: &NamedNode) -> Result<(), StoreError> {
    let subject = NamedOrBlankNode::NamedNode(note.clone());
    let stale: Vec<Quad> = store
        .store
        .quads_for_pattern(
            Some((&subject).into()),
            None,
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .filter_map(Result::ok)
        .collect();
    for quad in &stale {
        store.store.remove(quad)?;
    }
    Ok(())
}
```

- `:169` (in `public_note_iris`), `:224` (in `public_timeline`): `    store: &Store,` becomes `    store: &InstanceStore,`
- `:190`: `pub fn count_notes(store: &Store) -> Result<i64, StoreError> {` becomes `pub fn count_notes(store: &InstanceStore) -> Result<i64, StoreError> {`
- `clear` (`:203-206`) becomes:

```rust
pub fn clear(store: &InstanceStore) -> Result<(), StoreError> {
    store
        .store
        .clear_graph(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref()))?;
    Ok(())
}
```

- `:259`: `        .on_store(store)` becomes `        .on_store(&store.store)`

`record_note` keeps its process-wide `RECORDING` mutex: there is one instance
store per process, so moving the lock into `InstanceStore` would change
nothing.

- [ ] **Step 8: Collections read through `PodRead`**

In `store/src/collection.rs`, delete `use oxigraph::store::Store;` (`:18`) and
add after `use serde_json::Value;` (`:19`):

```rust

use crate::resources::PodRead;
```

Then change the `store` parameter of all seven readers from `store: &Store` to
`store: &impl PodRead`: `members` (`:52`), `received_at` (`:70`), `literal_in`
(`:90`), `literal` (`:110`), `read_record` (`:127`), `record_type` (`:149`) and
`timeline` (`:179`). The bodies are unchanged; they call `quads_for_pattern`,
which `PodRead` provides. rustfmt wraps `literal_in`'s signature in Step 12.

- [ ] **Step 9: The crate root**

Replace `store/src/lib.rs` with:

```rust
//! Per-user pod stores, the server-agent store, and the single write path.
//!
//! Two surfaces, and every query resolves to exactly one of them:
//!
//! | Store | Contains | Query scope |
//! |---|---|---|
//! | pod | one user's data, all protocols | cross-*protocol* joins |
//! | server agent | pointers + filter keys for all users | cross-*user* queries |
//!
//! The server-agent store holds **pointers and filter keys only, never
//! content** (decision D5), which is what makes account deletion `rm -rf` on
//! one directory and leaves the index to self-heal.
//!
//! See `docs/greenfield-implementation-plan.md` §3 Phase 2 and ADR 0005.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod blobs;
pub mod collection;
pub mod index;
pub mod manager;
pub mod resources;
pub mod write;

pub use blobs::BlobStore;
pub use index::InstanceStore;
pub use manager::{StoreError, StoreManager};
/// Re-exported so adapters and the server can name a store without taking a
/// direct oxigraph dependency — the engine stays an implementation detail of
/// this crate.
pub use oxigraph::store::Store;
pub use resources::{
    BlobMeta, Content, Kind, LegacyWriter, METADATA_GRAPH, Pod, PodRead, PodWrite, ReadStore,
    ResourceMeta, ResourceRead,
};
```

- [ ] **Step 10: The existing store tests and the example**

In `store/tests/storage_invariants.rs`:

- `:6`: `use brolly_store::{StoreManager, insert_quads, insert_record};` becomes `use brolly_store::{InstanceStore, PodRead, StoreManager};`
- `:37-39`:

```rust
    insert_quads(&pod, &hostile).unwrap();

    let stored: Vec<Quad> = pod
        .quads_for_pattern(
```

becomes

```rust
    pod.write(|w| w.insert(&hostile)).unwrap();

    let stored: Vec<Quad> = pod
        .read_store()
        .quads_for_pattern(
```

- `:69-72`:

```rust
    insert_record(&pod, &record, &subject, &subject, "app.bsky.feed.post").unwrap();

    let quads: Vec<Quad> = pod
        .quads_for_pattern(
```

becomes

```rust
    let encoded =
        brolly_domain::faithful::encode(&record, &subject, &subject, "app.bsky.feed.post").unwrap();
    pod.write(|w| w.insert(&encoded)).unwrap();

    let quads: Vec<Quad> = pod
        .read_store()
        .quads_for_pattern(
```

- `:94-106`:

```rust
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
```

becomes

```rust
    let encoded = brolly_domain::faithful::encode(
        &json!({"text": "alice's"}),
        &subject,
        &subject,
        "test.note",
    )
    .unwrap();
    mgr.pod(alice)
        .unwrap()
        .write(|w| w.insert(&encoded))
        .unwrap();

    let bob_pod = mgr.pod(bob).unwrap();
    assert_eq!(
        bob_pod
            .read_store()
            .quads_for_pattern(None, None, None, None)
            .count(),
```

- `:118`: `fn seed_index(store: &oxigraph::store::Store) {` becomes `fn seed_index(store: &InstanceStore) {`
- In `concurrent_first_records_of_one_note_write_one_pointer` (`:305-339`), the threads can no longer clone an `Arc` of the instance store, so they share the manager. Replace `:310` `    let instance = std::sync::Arc::clone(stores.instance());` with `    let stores = std::sync::Arc::new(stores);`, `:316` `            let instance = std::sync::Arc::clone(&instance);` with `            let stores = std::sync::Arc::clone(&stores);`, `:322` `                    &instance,` with `                    stores.instance(),`, and `:338` `    assert_eq!(index::count_notes(&instance).unwrap(), 1);` with `    assert_eq!(index::count_notes(stores.instance()).unwrap(), 1);`.

The other index tests pass `mgr.instance()` and compile unchanged; the two that
call `mgr.instance().quads_for_pattern(..)` read through `PodRead`, which the
new import brings in.

In `store/examples/store_budget.rs` (`cargo test` builds examples):

- `:12`: `use brolly_store::{StoreManager, insert_record};` becomes `use brolly_store::StoreManager;`
- `:32-39`:

```rust
            insert_record(
                &pod,
                &json!({"$type": "app.bsky.feed.post", "text": "benchmark record", "i": i}),
                &subject,
                &subject,
                "app.bsky.feed.post",
            )
            .expect("write");
```

becomes

```rust
            let quads = brolly_domain::faithful::encode(
                &json!({"$type": "app.bsky.feed.post", "text": "benchmark record", "i": i}),
                &subject,
                &subject,
                "app.bsky.feed.post",
            )
            .expect("encode");
            pod.write(|w| w.insert(&quads)).expect("write");
```

- [ ] **Step 11: Run the store tests and watch them pass**

Run: `cargo test -p brolly-domain -p brolly-store`

Expected, among the results: `resources` 10 passed, `pod_lifecycle` 3 passed,
`storage_invariants` 9 passed, `blobs` 9 passed, and the store's unit tests 2
passed. No failures.

- [ ] **Step 12: Format**

Run: `cargo fmt --all`

- [ ] **Step 13: Gates**

```bash
cargo fmt --all -- --check
cargo clippy -p brolly-domain -p brolly-store --all-targets -- -D warnings
cargo test -p brolly-domain -p brolly-store
cargo deny check
```

`cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`.
Don't run the workspace gates: every other crate fails to compile until chunk 2.

- [ ] **Step 14: Stage, don't commit**

```bash
git add store/Cargo.toml Cargo.lock store/src store/tests store/examples
```

---

### Task 3: Resources under the storage root

**Files:**
- Modify: `store/src/resources.rs` (the `PodWrite` struct and `Pod::write`'s initialiser, then append)
- Modify: `store/tests/resources.rs` (the `brolly_store` import, then append)

The spec's rules, all in one `impl PodWrite` block and its helpers:
- **`put`** replaces the content graph, rewrites the resource's record (types, `modified` = `max(now, previous + 1 ms)`, a new ULID version, blob metadata), and, unless the resource is auxiliary, contains it in its parent. Missing intermediate containers are created, each with its own version. The direct parent's version moves, the grandparent's doesn't. `Content::Binary` checks the blob file exists first (`BlobMissing`). A replaced blob is released.
- **`append`** adds quads, creating the resource (by its IRI's kind) if it's missing, and keeps an existing kind and blob, so alt text can go on a binary.
- **`remove`** is a no-op returning `false` on a missing resource. It refuses a container with members (`ContainerNotEmpty`) and the root (`Invalid`). It drops the content graph and the record, the resource's `.acl` graph and record, its containment (moving the parent's version), and releases its blob.
- **`create_root`** records `pim:Storage` and the root's container record. It's idempotent for the same root, and refuses a second one.
- A container's IRI ends in `/` and nothing else's does; an ACL's ends in `.acl` and nothing else's does. Every quad in a body must be in the resource's own graph.

- [ ] **Step 1: Write the failing tests**

In `store/tests/resources.rs`, replace the import
`use brolly_store::{METADATA_GRAPH, Pod, PodRead, StoreError, StoreManager};`
with:

```rust
use brolly_store::{
    BlobMeta, Content, Kind, METADATA_GRAPH, Pod, PodRead, StoreError, StoreManager,
};
```

Then append to the end of the file:

```rust
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
fn a_description_replaces_the_one_before_it() {
    // Mastodon alt text: a second description must replace the first, not sit
    // beside it, and the binary keeps its bytes.
    let (_dir, stores) = manager(60);
    let pod = provisioned(&stores);
    let meta = blob(&pod, b"a small dog");
    pod.write(|w| w.put(&at("dog.png"), Content::Binary(meta.clone())))
        .unwrap();
    let first = pod.write(|w| w.set_description(&at("dog.png"), &[says(&at("dog.png"), "a dog")]))
        .unwrap();
    let second = pod
        .write(|w| w.set_description(&at("dog.png"), &[says(&at("dog.png"), "a small dog")]))
        .unwrap();

    assert_ne!(first.version, second.version, "the version didn't move");
    assert_eq!(second.blob.as_ref().map(|b| &b.digest), Some(&meta.digest));
    let described = pod
        .read_store()
        .quads_for_pattern(None, None, None, Some(GraphNameRef::NamedNode(node(&at("dog.png")).as_ref())))
        .count();
    assert_eq!(described, 1, "the old description is still there");

    // Only a binary has a description.
    pod.write(|w| w.put(&at("doc"), Content::Rdf(&[]))).unwrap();
    let refused = pod.write(|w| w.set_description(&at("doc"), &[says(&at("doc"), "x")]));
    assert!(matches!(refused, Err(StoreError::Invalid(_))), "got {refused:?}");
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
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-store --test resources`

Expected: the build fails with
`error[E0599]: no method named `put` found for mutable reference `&mut PodWrite<'_>``
(and the same for `create_root`, `remove` and `append`).

- [ ] **Step 3: `PodWrite` gets the pod's blobs**

In `store/src/resources.rs`, replace the `PodWrite` fields

```rust
pub struct PodWrite<'a> {
    transaction: Transaction<'a>,
    released: Vec<String>,
}
```

with

```rust
pub struct PodWrite<'a> {
    transaction: Transaction<'a>,
    blobs: &'a BlobStore,
    released: Vec<String>,
}
```

and, in `Pod::write`, replace

```rust
        let mut writer = PodWrite {
            transaction: self.store.start_transaction()?,
            released: Vec::new(),
        };
```

with

```rust
        let mut writer = PodWrite {
            transaction: self.store.start_transaction()?,
            blobs: &self.blobs,
            released: Vec::new(),
        };
```

- [ ] **Step 4: The resource methods**

Append to the end of `store/src/resources.rs` (after `blob_referenced`):

```rust
// --- resources under the storage root ------------------------------------------

impl PodWrite<'_> {
    /// Store `content` as `resource`, replacing its content graph.
    ///
    /// Records `ldp:Resource` and the kind, sets `modified` to
    /// `max(now, previous + 1 ms)` and a new version, and, unless the resource
    /// is auxiliary, contains it in its parent, creating missing intermediate
    /// containers, each with its own version. The direct parent's version moves
    /// (R9). A binary's previous blob, if it changes, is released.
    pub fn put(
        &mut self,
        resource: &str,
        content: Content<'_>,
    ) -> Result<ResourceMeta, StoreError> {
        let root = self.root_for(resource)?;
        let kind = kind_of(&content);
        check_kind(resource, &root, kind)?;
        let (quads, blob): (&[Quad], _) = match content {
            Content::Rdf(quads) | Content::Container(quads) | Content::Auxiliary(quads) => {
                (quads, None)
            }
            Content::Binary(blob) => (&[], Some(blob)),
        };
        check_graph(resource, quads)?;
        // The bytes went in before the lock (R12). A concurrent release may
        // have swept them since; the caller writes them again and retries.
        if let Some(blob) = &blob
            && !self.blobs.contains(&blob.digest)
        {
            return Err(StoreError::BlobMissing);
        }

        let previous = self.meta(resource)?;
        self.transaction
            .clear_graph(GraphNameRef::NamedNode(iri(resource).as_ref()))?;
        insert_quads_in(&mut self.transaction, quads);
        let meta = self.record(resource, kind, previous.as_ref(), blob)?;
        if let Some(old) = previous.and_then(|p| p.blob)
            && meta
                .blob
                .as_ref()
                .is_none_or(|new| new.digest != old.digest)
        {
            self.release_blob(&old.digest);
        }
        if kind != Kind::Auxiliary {
            self.contain(resource, &root)?;
        }
        Ok(meta)
    }

    /// Add quads to `resource`'s content graph, creating it if it doesn't
    /// exist (as a container, an ACL or an RDF document, by its IRI). Keeps an
    /// existing resource's kind and blob, so alt text can go on a binary.
    pub fn append(&mut self, resource: &str, quads: &[Quad]) -> Result<ResourceMeta, StoreError> {
        let root = self.root_for(resource)?;
        check_graph(resource, quads)?;
        let previous = self.meta(resource)?;
        let (kind, blob) = match &previous {
            Some(meta) => (meta.kind, meta.blob.clone()),
            None => (kind_for_iri(resource), None),
        };
        check_kind(resource, &root, kind)?;
        insert_quads_in(&mut self.transaction, quads);
        let meta = self.record(resource, kind, previous.as_ref(), blob)?;
        if kind != Kind::Auxiliary {
            self.contain(resource, &root)?;
        }
        Ok(meta)
    }

    /// Replace a binary's description triples (today, Mastodon alt text) and
    /// move its version. Replaces rather than appends, so a second description
    /// doesn't sit beside the first. Keeps the bytes and the blob metadata.
    /// Refuses anything that isn't an existing binary.
    pub fn set_description(
        &mut self,
        resource: &str,
        quads: &[Quad],
    ) -> Result<ResourceMeta, StoreError> {
        let previous = self.meta(resource)?;
        let Some(ResourceMeta {
            kind: Kind::NonRdfSource,
            blob: Some(blob),
            ..
        }) = previous.clone()
        else {
            return Err(StoreError::Invalid(format!(
                "{resource} is not a binary, so it has no description"
            )));
        };
        let root = self.root_for(resource)?;
        check_graph(resource, quads)?;
        self.transaction
            .clear_graph(GraphNameRef::NamedNode(iri(resource).as_ref()))?;
        insert_quads_in(&mut self.transaction, quads);
        let meta = self.record(resource, Kind::NonRdfSource, previous.as_ref(), Some(blob))?;
        self.contain(resource, &root)?;
        Ok(meta)
    }

    /// Remove `resource` if present, returning whether it was there: a no-op
    /// on a missing resource, so a Delete that reaches one graph twice doesn't
    /// fail.
    ///
    /// Deletes the content graph, the metadata, and its `.acl` graph and
    /// metadata; takes it out of its container (whose version moves); releases
    /// its blob. Refuses a container that still has members, and the storage
    /// root.
    pub fn remove(&mut self, resource: &str) -> Result<bool, StoreError> {
        let Some(meta) = self.meta(resource)? else {
            return Ok(false);
        };
        let root = self.root_for(resource)?;
        if resource == root {
            return Err(StoreError::Invalid(
                "the storage root can't be removed".into(),
            ));
        }
        if meta.kind == Kind::Container && !self.members(resource)?.is_empty() {
            return Err(StoreError::ContainerNotEmpty);
        }

        self.forget(resource)?;
        if let Some(blob) = &meta.blob {
            self.release_blob(&blob.digest);
        }
        if meta.kind != Kind::Auxiliary {
            // Deleting a resource deletes its ACL (Solid Protocol §5.4), or
            // recreating it would quietly bring the old grants back.
            self.forget(&format!("{resource}.acl"))?;
            if let Some(parent) = parent_container(resource, &root) {
                let contains = containment(&parent, resource);
                remove_quads_in(&mut self.transaction, &[contains]);
                self.touch(&parent)?;
            }
        }
        Ok(true)
    }

    /// Record the storage root. Provisioning only.
    ///
    /// Idempotent for the same root; a pod has one root, so a different one is
    /// refused. Leaves the root's content graph alone.
    pub fn create_root(&mut self, root: &str) -> Result<(), StoreError> {
        if !root.ends_with('/') {
            return Err(StoreError::Invalid(format!("{root} is not a container")));
        }
        match self.storage_root()? {
            Some(existing) if existing == root => return Ok(()),
            Some(existing) => {
                return Err(StoreError::Invalid(format!(
                    "the pod's root is already {existing}"
                )));
            }
            None => {}
        }
        let previous = self.meta(root)?;
        self.record(root, Kind::Container, previous.as_ref(), None)?;
        insert_quads_in(
            &mut self.transaction,
            &[meta_quad(
                root,
                vocab::RDF_TYPE,
                Term::NamedNode(iri(vocab::PIM_STORAGE)),
            )],
        );
        Ok(())
    }

    /// The storage root, if `resource` is under it.
    fn root_for(&self, resource: &str) -> Result<String, StoreError> {
        let root = self.storage_root()?.ok_or(StoreError::NoRoot)?;
        if !resource.starts_with(&root) {
            return Err(StoreError::NotUnderRoot);
        }
        Ok(root)
    }

    /// Rewrite `resource`'s record: types, a new stamp, blob metadata. Keeps
    /// what isn't the record's own: `ldp:contains` and the root's
    /// `pim:Storage`.
    fn record(
        &mut self,
        resource: &str,
        kind: Kind,
        previous: Option<&ResourceMeta>,
        blob: Option<BlobMeta>,
    ) -> Result<ResourceMeta, StoreError> {
        let stale: Vec<Quad> = self
            .transaction
            .quads_for_pattern(
                Some(iri(resource).as_ref().into()),
                None,
                None,
                Some(metadata_graph().as_ref()),
            )
            .filter(|quad| match quad {
                Ok(quad) => is_record_quad(quad),
                Err(_) => true,
            })
            .collect::<Result<_, _>>()?;
        remove_quads_in(&mut self.transaction, &stale);

        let (modified_ms, modified) = next_modified(previous)?;
        let version = new_version(modified_ms);
        let mut quads: Vec<Quad> = types_for(kind)
            .iter()
            .map(|class| meta_quad(resource, vocab::RDF_TYPE, Term::NamedNode(iri(class))))
            .collect();
        quads.push(meta_quad(
            resource,
            vocab::DCTERMS_MODIFIED,
            Term::Literal(Literal::new_typed_literal(
                modified.clone(),
                iri(vocab::XSD_DATE_TIME),
            )),
        ));
        quads.push(meta_quad(
            resource,
            vocab::BROLLY_VERSION,
            Term::Literal(Literal::new_simple_literal(version.clone())),
        ));
        if let Some(blob) = &blob {
            quads.extend(blob_quads(resource, blob));
        }
        insert_quads_in(&mut self.transaction, &quads);
        Ok(ResourceMeta {
            kind,
            modified,
            version,
            blob,
        })
    }

    /// Put `resource` in its parent container, creating missing ancestors, and
    /// move the parent's version. Stops at the root, which has no parent.
    fn contain(&mut self, resource: &str, root: &str) -> Result<(), StoreError> {
        let Some(parent) = parent_container(resource, root) else {
            return Ok(());
        };
        if self.meta(&parent)?.is_none() {
            self.record(&parent, Kind::Container, None, None)?;
            self.contain(&parent, root)?;
        }
        insert_quads_in(&mut self.transaction, &[containment(&parent, resource)]);
        self.touch(&parent)
    }

    /// A new stamp for an existing resource, keeping everything else.
    fn touch(&mut self, resource: &str) -> Result<(), StoreError> {
        if let Some(meta) = self.meta(resource)? {
            let blob = meta.blob.clone();
            self.record(resource, meta.kind, Some(&meta), blob)?;
        }
        Ok(())
    }

    /// Drop a resource's content graph and its whole metadata record,
    /// containment included. Nothing else: the caller decides the rest.
    fn forget(&mut self, resource: &str) -> Result<(), StoreError> {
        let node = iri(resource);
        self.transaction
            .remove_named_graph(NamedOrBlankNodeRef::NamedNode(node.as_ref()))?;
        let record: Vec<Quad> = self
            .transaction
            .quads_for_pattern(
                Some(node.as_ref().into()),
                None,
                None,
                Some(metadata_graph().as_ref()),
            )
            .collect::<Result<_, _>>()?;
        remove_quads_in(&mut self.transaction, &record);
        Ok(())
    }
}

fn meta_quad(subject: &str, predicate: &str, object: Term) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(iri(subject)),
        iri(predicate),
        object,
        metadata_graph(),
    )
}

fn containment(container: &str, member: &str) -> Quad {
    meta_quad(container, vocab::LDP_CONTAINS, Term::NamedNode(iri(member)))
}

fn blob_quads(resource: &str, blob: &BlobMeta) -> [Quad; 3] {
    [
        meta_quad(
            resource,
            vocab::BROLLY_BLOB_DIGEST,
            Term::Literal(Literal::new_simple_literal(&blob.digest)),
        ),
        meta_quad(
            resource,
            vocab::BROLLY_MEDIA_TYPE,
            Term::Literal(Literal::new_simple_literal(&blob.media_type)),
        ),
        meta_quad(
            resource,
            vocab::BROLLY_BYTE_SIZE,
            Term::Literal(Literal::new_typed_literal(
                blob.byte_size.to_string(),
                iri(vocab::XSD_INTEGER),
            )),
        ),
    ]
}

/// The metadata types each kind records.
fn types_for(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Container => &[
            vocab::LDP_RESOURCE,
            vocab::LDP_CONTAINER,
            vocab::LDP_BASIC_CONTAINER,
        ],
        Kind::RdfSource => &[vocab::LDP_RESOURCE, vocab::LDP_RDF_SOURCE],
        Kind::NonRdfSource => &[vocab::LDP_RESOURCE, vocab::LDP_NON_RDF_SOURCE],
        Kind::Auxiliary => &[
            vocab::LDP_RESOURCE,
            vocab::LDP_RDF_SOURCE,
            vocab::BROLLY_AUXILIARY,
        ],
    }
}

/// Is this metadata quad part of a resource's own record, which `record`
/// rewrites? Containment and the root's `pim:Storage` are not.
fn is_record_quad(quad: &Quad) -> bool {
    let predicate = quad.predicate.as_str();
    if predicate == vocab::LDP_CONTAINS {
        return false;
    }
    if predicate == vocab::RDF_TYPE
        && matches!(&quad.object, Term::NamedNode(class) if class.as_str() == vocab::PIM_STORAGE)
    {
        return false;
    }
    true
}

fn kind_of(content: &Content<'_>) -> Kind {
    match content {
        Content::Rdf(_) => Kind::RdfSource,
        Content::Container(_) => Kind::Container,
        Content::Binary(_) => Kind::NonRdfSource,
        Content::Auxiliary(_) => Kind::Auxiliary,
    }
}

/// The kind a new resource gets from its IRI alone, for `append`.
fn kind_for_iri(resource: &str) -> Kind {
    if is_acl(resource) {
        Kind::Auxiliary
    } else if resource.ends_with('/') {
        Kind::Container
    } else {
        Kind::RdfSource
    }
}

fn is_acl(resource: &str) -> bool {
    resource.ends_with(".acl")
}

/// A container's IRI ends in `/` and nothing else's does; an ACL's ends in
/// `.acl` and nothing else's does. The root is a container.
fn check_kind(resource: &str, root: &str, kind: Kind) -> Result<(), StoreError> {
    let fits = match kind {
        Kind::Container => resource.ends_with('/'),
        Kind::Auxiliary => is_acl(resource),
        Kind::RdfSource | Kind::NonRdfSource => !resource.ends_with('/') && !is_acl(resource),
    };
    if !fits || (resource == root && kind != Kind::Container) {
        return Err(StoreError::Invalid(format!(
            "{resource} can't hold {kind:?} content"
        )));
    }
    Ok(())
}

/// The container that directly holds `resource`: `/~/a/b/c` → `/~/a/b/`,
/// `/~/a/` → `/~/`. `None` at the root and outside it.
fn parent_container(resource: &str, root: &str) -> Option<String> {
    if resource == root || !resource.starts_with(root) {
        return None;
    }
    let trimmed = resource.trim_end_matches('/');
    let cut = trimmed.rfind('/')?;
    let parent = &trimmed[..=cut];
    (parent.len() >= root.len()).then(|| parent.to_string())
}

// --- time and versions -----------------------------------------------------------

type Format = &'static [time::format_description::BorrowedFormatItem<'static>];

const MODIFIED_FORMAT: Format = time::macros::format_description!(
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
);

fn now_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

/// `max(now, previous + 1 ms)`: strictly increasing per resource even within
/// one millisecond, and never backwards if the clock steps back.
fn next_modified(previous: Option<&ResourceMeta>) -> Result<(i64, String), StoreError> {
    let floor = previous
        .and_then(|meta| parse_modified(&meta.modified))
        .map_or(i64::MIN, |ms| ms.saturating_add(1));
    let ms = now_ms().max(floor);
    Ok((ms, format_modified(ms)?))
}

fn format_modified(ms: i64) -> Result<String, StoreError> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .format(MODIFIED_FORMAT)
        .map_err(|e| StoreError::Backend(e.to_string()))
}

fn parse_modified(text: &str) -> Option<i64> {
    let at = time::PrimitiveDateTime::parse(text, MODIFIED_FORMAT).ok()?;
    Some((at.assume_utc().unix_timestamp_nanos() / 1_000_000) as i64)
}

/// A ULID over `ms` and fresh randomness: 26 Crockford base32 characters,
/// the timestamp in the high 48 bits.
fn new_version(ms: i64) -> String {
    ulid(u64::try_from(ms).unwrap_or(0), rand::random())
}

fn ulid(ms: u64, randomness: [u8; 10]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bytes = [0u8; 16];
    bytes[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    bytes[6..].copy_from_slice(&randomness);
    let value = u128::from_be_bytes(bytes);
    (0..26)
        .rev()
        .map(|i| char::from(ALPHABET[((value >> (5 * i)) & 0x1f) as usize]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "https://alice.brolly.test/~/";

    #[test]
    fn parents_walk_up_to_the_storage_root_and_stop() {
        assert_eq!(
            parent_container("https://alice.brolly.test/~/a/b/c", ROOT).as_deref(),
            Some("https://alice.brolly.test/~/a/b/")
        );
        assert_eq!(
            parent_container("https://alice.brolly.test/~/a/", ROOT).as_deref(),
            Some(ROOT)
        );
        assert_eq!(parent_container(ROOT, ROOT), None);
        assert_eq!(
            parent_container("https://alice.brolly.test/profile", ROOT),
            None
        );
    }

    #[test]
    fn modified_is_fixed_width_and_round_trips() {
        let text = format_modified(1_758_535_200_007).unwrap();
        assert_eq!(text, "2025-09-22T10:00:00.007Z");
        assert_eq!(parse_modified(&text), Some(1_758_535_200_007));
    }

    #[test]
    fn modified_moves_forward_even_within_a_millisecond() {
        let far_future = format_modified(now_ms() + 60_000).unwrap();
        let previous = ResourceMeta {
            kind: Kind::RdfSource,
            modified: far_future.clone(),
            version: String::new(),
            blob: None,
        };
        let (_, next) = next_modified(Some(&previous)).unwrap();
        assert!(next > far_future, "{next} is not after {far_future}");
    }

    #[test]
    fn a_version_is_a_ulid_ordered_by_time() {
        let early = ulid(1, [0xff; 10]);
        let late = ulid(2, [0x00; 10]);
        assert_eq!(early.len(), 26);
        assert!(early < late, "{early} vs {late}");
        assert_eq!(ulid(0, [0; 10]), "0".repeat(26));
    }

    #[test]
    fn kinds_must_fit_their_iris() {
        let doc = "https://alice.brolly.test/~/doc";
        let dir = "https://alice.brolly.test/~/dir/";
        let acl = "https://alice.brolly.test/~/doc.acl";
        assert!(check_kind(doc, ROOT, Kind::RdfSource).is_ok());
        assert!(check_kind(doc, ROOT, Kind::NonRdfSource).is_ok());
        assert!(check_kind(dir, ROOT, Kind::Container).is_ok());
        assert!(check_kind(acl, ROOT, Kind::Auxiliary).is_ok());
        assert!(check_kind(doc, ROOT, Kind::Container).is_err());
        assert!(check_kind(dir, ROOT, Kind::RdfSource).is_err());
        assert!(check_kind(acl, ROOT, Kind::RdfSource).is_err());
        assert!(check_kind(doc, ROOT, Kind::Auxiliary).is_err());
    }
}
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `cargo test -p brolly-domain -p brolly-store`

Expected: `resources` 30 passed, the store's unit tests 7 passed, and the rest
as in Task 2. No failures.

- [ ] **Step 6: Format**

Run: `cargo fmt --all`

- [ ] **Step 7: Gates**

```bash
cargo fmt --all -- --check
cargo clippy -p brolly-domain -p brolly-store --all-targets -- -D warnings
cargo test -p brolly-domain -p brolly-store
```

- [ ] **Step 8: Stage, don't commit**

```bash
git add store/src/resources.rs store/tests/resources.rs
```

Chunk 2 starts from here, with the workspace not yet compiling.

---

### Notes for the reviewer

**Verified against the code.** All three tasks were run in a scratch copy of
`domain` and `store` at `f564eb6`, in a two-member workspace with the real
`Cargo.lock`. The test code, the expected failures, and the pass counts above
come from those runs, and clippy, rustfmt and `cargo deny check` were clean. A
mutation check (removing the lock from `Pod::write`) makes
`writers_to_one_pod_are_serialised` and the eviction-lock test fail.

**Oxigraph 0.5.9, checked in its source:**
- `Store::quads_for_pattern` returns `QuadIter<'static>` and `Transaction::quads_for_pattern` returns `QuadIter<'_>`. `'static` coerces, so one trait signature, `-> QuadIter<'_>`, fits both.
- `PreparedSparqlQuery::on_store` gives `QueryResults<'static>`, and `on_transaction(&'b Transaction)` gives `QueryResults<'b>`. Both fit `-> QueryResults<'_>`.
- `Store::start_transaction` is a readable transaction: on RocksDB, a snapshot plus a write batch with index, so reads inside it see its own writes. `Transaction::insert` and `remove` are infallible. `clear_graph` and `remove_named_graph` return `Result`.
- `Pod::read` is that transaction, never committed. On RocksDB it takes no lock; on the in-memory backend it would take the global transaction lock, so a `read` inside a `write` would deadlock there. `resources.rs` documents this; pods are always RocksDB.

**Where the code departs from the fixed interfaces:**
1. **`PodRead` has more than two methods.** `query(&str)` is kept, but `authz::wac::select_iris` and `index::public_timeline` bind values with `substitute_variable` rather than interpolating them. So the trait also has a required `evaluate(PreparedSparqlQuery)` and a provided `query_with(&str, &[(&str, Term)])`. A prepared query can't be an update, so updates are refused by the parser. A CONSTRUCT or DESCRIBE is refused by checking the result kind. The trait is sealed.
2. **`meta`, `members` and `storage_root` are provided methods on `PodRead`,** not inherent methods on `PodWrite`. `ResourceRead` and `ReadStore` need them too (chunk 4's `ldp::read`, and the tests). The cost is `use brolly_store::PodRead` at call sites.
3. **A sixth new error, `StoreError::Invalid(String)`.** It covers content that doesn't fit its IRI, a body quad in another graph, removing the root, and a second root. Nothing outside `store` matches on `StoreError` exhaustively today (`grep`-checked), so the new variant breaks no match. Chunk 2 maps it to a 500-class `LdpError`: every case is a server bug, because `ldp` picks the `Content`.
4. **`LegacyWriter` has two lifetimes, `LegacyWriter<'w, 'a>`.** It holds `&'w mut Transaction<'a>`, and `&mut` is invariant. Call sites (`w.legacy_under_root().insert(..)`) don't name the type.
5. **`Content::Binary(BlobMeta)` is owned,** as the interface says, so `Content` is `Clone` but not `Copy`.
6. **`InstanceStore` is in `store/src/index.rs`,** next to the only code that writes it. Its `Store` is private to that module.

**Judgement calls:**
7. **The ULID is hand-rolled** in `resources.rs`, from `rand` 0.10.2 and `time` 0.3.55, which are already in the lock. The version's timestamp is the resource's `modified` millisecond. There's no `ulid` crate in `Cargo.lock`. The cached `ulid` 1.2.1 depends on `rand` 0.9, which would add another duplicate version, and `store` can't depend on `brolly_mastodon::status_id`. It's the same encoding as `status_id::new_note_id`.
8. **The outside-root methods refuse the metadata graph always, and graphs under the root only once a root is recorded.** In commit 1 no pod has a root (provisioning calls `create_root` from commit 2 on), so the outside-root methods then accept every content graph, exactly as today. The protection starts in commit 2, when every provisioned pod has a root. Chunk 2 should still send under-root writes through `legacy_under_root`, so commit 2's switch is a rename at each call site rather than a hunt. The alternative, a `/~/` path heuristic while there's no root, would also refuse a recipient's copies of foreign `/~/` notes in commit 1.
9. **`graph()` refuses under the root too.** It's a read, but the fixed interface lists it with the refusing methods. Under-root reads inside a write go through `PodRead`.
10. **What each kind records.** A container records `ldp:Resource`, `ldp:Container` and `ldp:BasicContainer`, with no `ldp:RDFSource`, following the spec's container representation. An ACL records `ldp:Resource`, `ldp:RDFSource` and `brolly:Auxiliary`. The root keeps `pim:Storage` across rewrites of its record.
11. **`put` releases a replaced blob itself** when the digest changes. The spec has the caller do it; doing it here too is harmless (the sweep dedupes and re-checks references) and stops an RDF PUT over a binary from leaking the bytes.
12. **`append` on a missing resource creates it,** matching stage 0's POST-to-document. It keeps an existing resource's kind and blob, which is what alt text on a binary needs.
13. **`remove` uses `remove_named_graph`, not `clear_graph`,** so the graph disappears from `named_graphs()`. That matters to chunk 3's upgrade, which classifies named graphs. It always forgets `<r>.acl`, whether or not it's recorded. Removing an ACL itself moves no version.
14. **`create_root`** needs a trailing `/`. It's idempotent for the same IRI and refuses a different one. It doesn't write the layout marker (chunk 3's) or touch the root's content graph.
15. **`modified`** is `YYYY-MM-DDTHH:MM:SS.mmmZ`, fixed width, so it also sorts as text.
16. **The spec's "commit failure deletes no blob" test** can't make RocksDB's commit fail, so it tests a closure that errs after releasing, in both tasks. The commit-failure path is the same by construction: `transaction.commit()?` returns before `sweep`.
17. **The blob race tests are deterministic sequences, not threads.** One keeps the blob because the upload committed first. The other gets `BlobMissing` and succeeds on retry, and then checks that every recorded digest has a file.
18. **Readers:** `collection.rs` moves to `&impl PodRead` here, because it's in `store`. `Pod::blobs()` is new, so tests and callers can reach the pod's `BlobStore` without the user id.
19. **Removed items:** `write::insert_record` and `write::replace_graph` are deleted rather than made crate-private, since nothing in `store` uses them. `WriteError` stays public because five adapter error types convert from it. Chunk 2 decides whether they keep doing so.
20. **Deliberately left to chunk 2:**
    - the `server/tests/architecture.rs` rules
    - the Mastodon no-writes lint's mutator list
    - `collection::LDP_CONTAINS`, which duplicates `vocab::LDP_CONTAINS`
    - the blob constants in `adapters/solid/src/ldp.rs`


## Chunk 2: Every reader and writer on the pod handle (commit 1, part B)

Chunk 1 adds `store::resources` and changes `StoreManager::pod` to return an
`Arc<Pod>`, with no `Deref` to `Store`. That breaks every pod reader and writer
in the workspace. This chunk moves each of them onto the new handle.

It's a compile-driven migration with **no behaviour change**:
- **Readers** take `&impl PodRead`.
- **Writers** take `&mut PodWrite` and run inside one `Pod::write`.
- **Protocol graphs outside the storage root** use the outside-root methods.
- **Everything under the root** goes through `legacy_under_root()`, which writes
  exactly what today's code writes.

The on-disk layout doesn't change, and every existing test keeps its
assertions.

Chunks 1 and 2 are one commit (spec, Rollout item 1). Tasks 1–6 run their
crate's tests and gates, then stage. Task 7 runs the workspace gates, commits,
and verifies from a clean checkout. The tree doesn't compile workspace-wide
until Task 6 is done, so the tasks go in dependency order:
store → authz → solid → activitypub → atproto and mastodon → server.

### Interfaces assumed from chunk 1

These come from COMMON.md, with the details a caller needs. If chunk 1 named
something differently, change the call and keep the design.

| # | Assumption | Why this chunk needs it |
|---|---|---|
| A1 | Paths: `brolly_store::resources::{Pod, PodRead, PodWrite, ReadStore, Content}` and `brolly_store::{InstanceStore, StoreError}` | every import below |
| A2 | `PodWrite::legacy_under_root(&mut self) -> LegacyWriter<'_>`, where `LegacyWriter` has `insert(&mut self, &[Quad])`, `remove(&mut self, &[Quad])`, `replace_graph(&mut self, &str, &[Quad])` and `clear_graph(&mut self, &str)`, each returning `Result<(), StoreError>` | every write under `/~/` |
| A3 | `LegacyWriter::insert` and `replace_graph` canonicalise, like `write::insert_quads` and `write::replace_graph` today. `remove` and `clear_graph` don't need to. | `a_patch_cannot_reintroduce_a_non_canonical_namespace` and `non_canonical_iris_cannot_survive_the_write_path` depend on it |
| A4 | `LegacyWriter` polices nothing: it writes any graph | a recipient's copy of another origin's post goes through it in commit 1 |
| A5 | The outside-root methods (`insert`, `remove_quads`, `replace_graph`, `clear_graph`, `graph`) refuse only graphs under a **recorded** root. A pod with no recorded root has nothing under it, so they refuse nothing, and they never return `NoRoot`. | No pod records a root until commit 2 (provisioning calls `create_root` then). If they refused every write to a pod with no root, commit 1 couldn't write a profile. |
| A6 | `PodRead::quads_for_pattern` has `Store::quads_for_pattern`'s signature, and `query(&self, &str) -> Result<QueryResults<'_>, StoreError>` runs SELECT and ASK | readers keep their bodies |
| A7 | `ReadStore` reads the committed store on each call, like `&Store` today | a reader never holds one across a write it must see |
| A8 | `InstanceStore: PodRead + Send + Sync`, with a crate-internal `fn store(&self) -> &Store` | index functions (Task 1) and tests that read the index |
| A9 | `store/Cargo.toml` has `[features] test-fixtures = []`, and `Pod::raw_store(&self) -> &Store` sits behind it | seeding in tests |
| A10 | `create_root`, `put(.., Content::Auxiliary(..))` and the outside-root `insert` work in commit 1 | two new tests use them |

### Conversion rules

Every edit below follows one of these rules. The per-task tables cite them by
number.

- **R1: reader signature.** `store: &Store` becomes `store: &impl PodRead`. The
  body doesn't change, and the file imports `brolly_store::resources::PodRead`.
- **R2: reader call outside a write.** `f(&pod, …)` becomes
  `f(&pod.read_store(), …)`, where `pod: Arc<Pod>` or `&Pod`.
- **R3: reader call inside a write.** `f(&*w, …)`, where `w: &mut PodWrite<'_>`.
  If clippy flags a needless reborrow, pass `w`.
- **R4: writer signature.** `store: &Store` becomes `w: &mut PodWrite<'_>`. The
  error type becomes `StoreError` wherever it was `WriteError` or
  `StorageError`, so writers compose with `?` inside a closure. Adapters then
  name no `brolly_store::write` item.
- **R5: where a graph is written.**
  - **Protocol state outside `/~/`** uses `w.insert`, `w.remove_quads` and the
    other outside-root methods: the profile document, `…/actor#social`, the
    `/inbox` and `/outbox` collection graphs, and `at://` records.
  - **Anything that is, or may be, under `/~/`** uses
    `w.legacy_under_root()`: LDP resources, the storage root, ACLs, media, and
    activity or note records. Records can be the author's own post under their
    root.
  - Commit 2 replaces exactly the `legacy_under_root` sites. The other sites
    already use their final method.
- **R6: writer call site.**
  - A writer that returns `StoreError` is called as `pod.write(|w| f(w, …))`.
  - A writer with its own error type `E` is called as
    `pod.write(|w| Ok(f(w, …))).map_err(E::from).flatten()`, or with two
    `unwrap`s in tests.
  - `Result::flatten` is stable on the pinned 1.90 toolchain.
- **R7: no `.await` under a pod handle.**
  - A `Pod::write` closure is synchronous, so it can't contain an `.await`.
  - A `ReadStore` temporary never sits in a `for` header or a `match` scrutinee
    whose body awaits: bind the result with `let` first.
- **R8: old-layout seeding in tests.** Quads that a test puts under `/~/`
  directly, as setup that doesn't depend on the code under test, go through
  each file's `seed` helper:

  ```rust
  /// Setup straight into the store, bypassing `Pod::write` (`test-fixtures`),
  /// so it doesn't depend on the code under test.
  fn seed(target: &Pod, quads: &[Quad]) {
      let store = target.raw_store();
      for quad in quads {
          store.insert(quad).unwrap();
      }
  }
  ```

  Seeding never canonicalises. Every seeded IRI is already canonical (ACL, FOAF
  and example IRIs), so nothing changes.
- **R9: `&Pod` entry points.** `ldp::{read, put, append, delete}` and
  `provision::pod` take `&Pod`. A caller that passes `&arc` (`Arc<Pod>`) stays
  as it is, through deref coercion.

**Refusals inside a write.** Where an adapter returns its own error from inside
a closure (R6, second form), the closure returns `Ok(Err(e))`, and whatever the
adapter wrote before refusing still commits. That's today's behaviour: each of
these was a series of separate, non-transactional store calls. Every refusal
path that exists today refuses before writing, except `inbox::deliver`, which
can fail to encode an embedded object after storing its activity, as it can
today. Store failures inside a closure propagate with `?` and roll the
transaction back. Nothing observable changes, because today they'd have
returned an error anyway.

### Files changed by this chunk

- `store/src/collection.rs`, `store/src/index.rs`, `store/tests/storage_invariants.rs` (Task 1, only what chunk 1 hasn't done)
- `authz/Cargo.toml`, `authz/src/wac.rs`, `authz/tests/conformance_matrix.rs`
- `adapters/solid/Cargo.toml`, `adapters/solid/src/{ldp,storage,patch,profile}.rs`, `adapters/solid/tests/{acl_control,ldp_conformance,ldp_nonrdf,patch_conformance,publication_boundary}.rs`
- `adapters/activitypub/Cargo.toml`, `adapters/activitypub/src/{inbox,follows,processor}.rs`, `adapters/activitypub/tests/{inbox,processor}.rs`
- `adapters/atproto/src/ingest.rs`
- `adapters/mastodon/src/timeline.rs`, `adapters/mastodon/tests/timeline.rs`
- `server/Cargo.toml`, `server/src/{pod,outbox,mastodon_api,profile,xrpc,activitypub,account,provision,maintenance}.rs`
- `server/tests/{activitypub_discovery,admin_cli,architecture,dashboard,federation_flows,harmonization,maintenance,mastodon_compose,mastodon_profile_flags,pod_http,solid_token_access,xrpc}.rs`

Unchanged, checked:
- `server/src/auth.rs:330-333`: `provision::pod(&pod, …)` coerces (R9)
- `server/src/bin/admin.rs`
- `identity/**`, `test-support/**`, `adapters/atproto/src/{blocks,repo}.rs`
- `adapters/atproto/tests/*`, `adapters/mastodon/tests/{oauth_persistence,status_id,translate}.rs`
- `server/tests/{admin,atproto_oauth,auth_flow,mastodon_api,mastodon_oauth_flow,solid_oidc_flow,ui_invariants}.rs`: they only call `StoreManager::open`
- `store/tests/{pod_lifecycle,blobs}.rs`: `Arc::ptr_eq` works on `Arc<Pod>`

---

### Task 1: The store crate's readers and the index

Chunk 1 may already have done some or all of this. Do only what's missing, so
that by the end of this task the store crate exposes exactly these signatures:

| Item | Signature at the end of this task |
|---|---|
| `collection::members` | `pub fn members(store: &impl PodRead, collection: &str) -> Vec<String>` |
| `collection::received_at` | `pub fn received_at(store: &impl PodRead, collection: &str, activity: &str) -> Option<String>` |
| `collection::literal_in` | `pub fn literal_in(store: &impl PodRead, subject: &str, predicate: &str, graph: &str) -> Option<String>` |
| `collection::literal` | `pub fn literal(store: &impl PodRead, subject: &str, predicate: &str) -> Option<String>` |
| `collection::read_record` | `pub fn read_record(store: &impl PodRead, id: &str) -> Option<Value>` |
| `collection::record_type` | `pub fn record_type(store: &impl PodRead, activity: &str) -> Option<String>` |
| `collection::timeline` | `pub fn timeline(store: &impl PodRead, collection: &str, types: &[&str], limit: usize, before: Option<&str>) -> Vec<Entry>` |
| `index::record_note` | `pub fn record_note(instance: &InstanceStore, pointer: &NotePointer) -> Result<(), StoreError>` |
| `index::is_indexed` | `pub fn is_indexed(instance: &InstanceStore, note: &NamedNode) -> Result<bool, StoreError>` |
| `index::forget_note` | `pub fn forget_note(instance: &InstanceStore, note: &NamedNode) -> Result<(), StoreError>` |
| `index::public_note_iris` | `pub fn public_note_iris(instance: &InstanceStore, limit: usize, before: Option<&str>) -> Result<Vec<String>, StoreError>` |
| `index::count_notes` | `pub fn count_notes(instance: &InstanceStore) -> Result<i64, StoreError>` |
| `index::clear` | `pub fn clear(instance: &InstanceStore) -> Result<(), StoreError>` |
| `index::public_timeline` | `pub fn public_timeline(instance: &InstanceStore, audience: &NamedNode, limit: usize, before: Option<&str>) -> Result<Vec<NotePointer>, StoreError>` |

`record_note` returns `StoreError` rather than `WriteError`. That lets the
processor drop its `From<WriteError>` impl (Task 4), so no adapter names
`brolly_store::write` whatever chunk 1 does with it.

**Files:**
- Modify: `store/src/collection.rs:16-19` (imports), `:52`, `:70`, `:90`, `:110`, `:127`, `:149`, `:178-184` (signatures)
- Modify: `store/src/index.rs:22-28` (imports), `:74-120`, `:127-139`, `:142-157`, `:168-179`, `:190-200`, `:203-206`, `:223-261`
- Modify: `store/tests/storage_invariants.rs:4-6`, `:23-114`, `:118-132`, `:137-141`, `:305-339`

- [ ] **Step 1: See what chunk 1 left**

```bash
grep -n 'store: &Store' store/src/collection.rs store/src/index.rs
grep -n 'insert_quads\|insert_record\|Arc::clone(stores.instance' store/tests/storage_invariants.rs
cargo test -p brolly-store --no-run 2>&1 | tail -20
```

If the first two print nothing and the build succeeds, the store side is done.
Check the table's signatures against the source, and fix any `record_note`
that still returns `WriteError` (Step 4's code). Then go to Step 6.

- [ ] **Step 2: Move `storage_invariants.rs` onto the pod handle and the `InstanceStore`**

Replace the imports at `:4-6`:

```rust
use brolly_domain::iri::{iris_in, is_canonical};
use brolly_store::StoreManager;
use brolly_store::index::{self, NotePointer};
use brolly_store::resources::PodRead;
```

Replace `non_canonical_iris_cannot_survive_the_write_path`,
`records_round_trip_through_a_real_store` and
`pods_are_isolated_and_delete_is_rm_rf` (`:23-114`):

```rust
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
    pod.write(|w| w.insert(&hostile)).unwrap();

    let stored: Vec<Quad> = pod
        .read_store()
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
    let encoded =
        brolly_domain::faithful::encode(&record, &subject, &subject, "app.bsky.feed.post")
            .unwrap();
    pod.write(|w| w.insert(&encoded)).unwrap();

    let quads: Vec<Quad> = pod
        .read_store()
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

    let encoded =
        brolly_domain::faithful::encode(&json!({"text": "alice's"}), &subject, &subject, "test.note")
            .unwrap();
    mgr.pod(alice)
        .unwrap()
        .write(|w| w.insert(&encoded))
        .unwrap();

    let bob_pod = mgr.pod(bob).unwrap();
    assert_eq!(
        bob_pod
            .read_store()
            .quads_for_pattern(None, None, None, None)
            .count(),
        0,
        "one user's write must not appear in another's pod"
    );

    assert!(mgr.pod_bytes(alice).unwrap() > 0);
    mgr.delete_pod(alice).unwrap();
    assert!(!mgr.pod_exists(alice));
    assert_eq!(mgr.pod_bytes(alice).unwrap(), 0, "delete is rm -rf");
}
```

`seed_index` (`:118`) takes the instance store:

```rust
fn seed_index(instance: &brolly_store::InstanceStore) {
    for (n, when) in [("1", "2026-08-18T10:00:00Z"), ("2", "2026-08-18T11:00:00Z")] {
        index::record_note(
            instance,
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
```

`mgr.instance().quads_for_pattern(..)` (`:137-141`, `:287-288`) is unchanged:
it now resolves through `InstanceStore`'s `PodRead` impl (A8), which the new
import brings into scope.

`concurrent_first_records_of_one_note_write_one_pointer` (`:305-339`) can't
`Arc::clone` a `&InstanceStore`, so it uses scoped threads:

```rust
#[test]
fn concurrent_first_records_of_one_note_write_one_pointer() {
    // A redelivered Create can race its original. Both see the note unindexed
    // unless check-then-write is atomic, and the pointer gets two authors.
    let (stores, _dir) = manager();
    let instance = stores.instance();
    let note = node("https://alice.brolly.test/~/notes/01J8Z0000000000000000000A1");

    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        let writers: Vec<_> = (0..8)
            .map(|i| {
                let barrier = &barrier;
                let note = note.clone();
                scope.spawn(move || {
                    barrier.wait();
                    index::record_note(
                        instance,
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
    });

    assert_eq!(index::count_notes(instance).unwrap(), 1);
}
```

The other index tests pass `mgr.instance()` or `manager.instance()` already
(`:171-212`, `:225-254`, `:272-302`) and don't change.

- [ ] **Step 3: Run it and watch it fail**

Run: `cargo test -p brolly-store --test storage_invariants`
Expected: FAIL to compile. If chunk 1 left the index on `&Store`, the error is
`error[E0308]: mismatched types … expected `&Store`, found `&InstanceStore``
at `index::record_note(instance, …)`.

- [ ] **Step 4: Move the readers and the index**

In `store/src/collection.rs`, replace the imports at `:16-19`:

```rust
use brolly_domain::faithful;
use oxigraph::model::{GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::Value;

use crate::resources::PodRead;
```

Then apply R1 to the seven signatures, exactly as in the table above: `:52`,
`:70`, `:90`, `:110`, `:127`, `:149` and `:178-184`. The bodies stay as they
are, because `PodRead::quads_for_pattern` has `Store`'s signature (A6).
`timeline` passes its `store` straight through to `members`, `received_at` and
`record_type`.

In `store/src/index.rs`, replace the imports at `:22-28`, naming
`InstanceStore` by wherever chunk 1 defined it:

```rust
use oxigraph::model::Variable;
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use oxigraph::sparql::{QueryResults, SparqlEvaluator};

use crate::InstanceStore;
use crate::manager::StoreError;
use crate::write::insert_quads;
```

Replace `record_note` through `clear` (`:67-206`) with the following. The doc
comments stay as they are, apart from the first line of each signature:

```rust
/// Record a note in the public timeline index.
///
/// **The first record wins.** If the note is already indexed, nothing is
/// written. A pointer names one author and one published time. A second author
/// triple would let anyone who boosts a post claim it, and `count_notes` would
/// count it twice. A second `published` literal would list the note twice in
/// [`public_timeline`], once at the later time.
pub fn record_note(instance: &InstanceStore, pointer: &NotePointer) -> Result<(), StoreError> {
    // Check-then-write has to be atomic, or two first records of one note (a
    // redelivered Create racing its original) would both write. A process-wide
    // lock is enough: RocksDB lets only one process open the instance store.
    // A poisoned lock only means a writer panicked; the check below re-reads
    // the store, so there is no state to distrust.
    static RECORDING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _recording = RECORDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if is_indexed(instance, &pointer.note)? {
        return Ok(());
    }

    let subject = NamedOrBlankNode::NamedNode(pointer.note.clone());
    let mut quads = vec![
        Quad::new(
            subject.clone(),
            iri(P_AUTHOR),
            Term::NamedNode(pointer.author.clone()),
            graph(),
        ),
        Quad::new(
            subject.clone(),
            iri(P_PUBLISHED),
            Term::Literal(Literal::new_simple_literal(&pointer.published)),
            graph(),
        ),
        Quad::new(
            subject.clone(),
            iri(P_AUDIENCE),
            Term::NamedNode(pointer.audience.clone()),
            graph(),
        ),
    ];
    if let Some(parent) = &pointer.in_reply_to {
        quads.push(Quad::new(
            subject,
            iri(P_IN_REPLY_TO),
            Term::NamedNode(parent.clone()),
            graph(),
        ));
    }
    // A pointer carries no faithful record, so the only failure left is the
    // store's.
    insert_quads(instance.store(), &quads).map_err(|e| StoreError::Backend(e.to_string()))?;
    Ok(())
}

/// Is this note on the public timeline?
///
/// A pointer always has exactly one author triple, so that is what's checked.
/// A read, not a write: the ActivityPub processor asks before it lets an
/// `Announce` touch the index.
pub fn is_indexed(instance: &InstanceStore, note: &NamedNode) -> Result<bool, StoreError> {
    let subject = NamedOrBlankNode::NamedNode(note.clone());
    let first = instance
        .store()
        .quads_for_pattern(
            Some((&subject).into()),
            Some(iri(P_AUTHOR).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .next()
        .transpose()?;
    Ok(first.is_some())
}

/// Drop a row — used when a dereference 404s, i.e. the pod no longer has it.
pub fn forget_note(instance: &InstanceStore, note: &NamedNode) -> Result<(), StoreError> {
    let store = instance.store();
    let subject = NamedOrBlankNode::NamedNode(note.clone());
    let stale: Vec<Quad> = store
        .quads_for_pattern(
            Some((&subject).into()),
            None,
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .filter_map(Result::ok)
        .collect();
    for quad in &stale {
        store.remove(quad)?;
    }
    Ok(())
}

/// The AS2 public collection — the audience a public post is addressed to.
pub const PUBLIC_AUDIENCE: &str = "https://www.w3.org/ns/activitystreams#Public";

/// Note IRIs on the public timeline, newest first.
///
/// A convenience over [`public_timeline`] that takes and returns plain strings,
/// so a caller can page the public timeline without depending on oxigraph. The
/// engine stays an implementation detail of this crate, which is the same
/// reason callers name an `InstanceStore` rather than an oxigraph `Store`.
pub fn public_note_iris(
    instance: &InstanceStore,
    limit: usize,
    before: Option<&str>,
) -> Result<Vec<String>, StoreError> {
    Ok(
        public_timeline(instance, &iri(PUBLIC_AUDIENCE), limit, before)?
            .into_iter()
            .map(|pointer| pointer.note.as_str().to_string())
            .collect(),
    )
}

/// How many notes the index knows about.
///
/// Counted here rather than by opening every pod — this is exactly the
/// cross-user question the server agent exists to answer (ADR 0005 R8), and it
/// is the only number NodeInfo publishes beyond the member count.
///
/// Counts rows, not triples: `P_AUTHOR` appears exactly once per note, where a
/// bare graph count would inflate by however many optional predicates each row
/// happened to carry.
pub fn count_notes(instance: &InstanceStore) -> Result<i64, StoreError> {
    Ok(instance
        .store()
        .quads_for_pattern(
            None,
            Some(iri(P_AUTHOR).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref())),
        )
        .filter_map(Result::ok)
        .count() as i64)
}

/// Wipe the index. The first half of a rebuild.
pub fn clear(instance: &InstanceStore) -> Result<(), StoreError> {
    instance
        .store()
        .clear_graph(GraphNameRef::NamedNode(iri(PUBLIC_TIMELINE).as_ref()))?;
    Ok(())
}
```

In `public_timeline` (`:223-261`), the first parameter becomes
`instance: &InstanceStore`, and `.on_store(store)` becomes
`.on_store(instance.store())`. Nothing else changes. `substitute_variable` has
to bind an oxigraph `Store`, which is why the index keeps the raw handle
internally rather than going through `PodRead::query`.

If chunk 1 renamed `write::insert_quads` or changed its error type, call the
crate-internal equivalent, and keep the `StoreError` mapping.

- [ ] **Step 5: Run it and watch it pass**

Run: `cargo test -p brolly-store`
Expected: PASS, every test in `blobs`, `pod_lifecycle`, `storage_invariants`
and chunk 1's `resources`.

- [ ] **Step 6: Format**

Run: `cargo fmt --all`

- [ ] **Step 7: The crate's gates**

Run: `cargo clippy -p brolly-store --all-targets -- -D warnings && cargo test -p brolly-store`
Expected: clean. The workspace doesn't build yet; Tasks 2–6 fix it.

- [ ] **Step 8: Stage, don't commit**

```bash
git add store/src/collection.rs store/src/index.rs store/tests/storage_invariants.rs
```

---

### Task 2: WAC reads through `PodRead`

`effective_acl` and `authorize` run outside a write (`ldp::read`) and, from
commit 2, inside one (`put_in`). Both take `&impl PodRead`. `authorize` keeps
its SELECT and its substituted `?agent`/`?target` exactly as today, and runs
it through chunk 1's `PodRead::query_with`, so no IRI is ever written into the
query text.

**Files:**
- Modify: `authz/Cargo.toml` (`[dev-dependencies]`)
- Modify: `authz/src/wac.rs:1-6`, `:111-133`, `:159-222`, `:224-258`
- Modify: `authz/tests/conformance_matrix.rs:15-16`, `:61-72`, `:74-82`, `:180-181`, `:295`, `:322`, `:334`, `:351`; add one test

| Site | Before | After | Rule |
|---|---|---|---|
| `wac.rs:111` `effective_acl` | `store: &Store` | `store: &impl PodRead` | R1 |
| `wac.rs:159` `authorize` | `store: &Store`, SELECT with substitutions | `store: &impl PodRead`, the same SELECT with substitutions via `PodRead::query_with` | R1, full code |
| `wac.rs:225` `select_iris` | prepared query with bindings | `store.query(query)`, no bindings | full code |
| `conformance_matrix.rs:63` | `store: &oxigraph::store::Store` | `store: &impl PodRead` | R1 |
| `conformance_matrix.rs:77` | `Arc<oxigraph::store::Store>` | `Arc<Pod>` | |
| `conformance_matrix.rs:180` | `insert_quads(&store, &quads).expect("seed acls")` | `seed(&store, &quads)` | R8 |
| `conformance_matrix.rs:295` | `surface_allows(*s, &store, …)` | `surface_allows(*s, &store.read_store(), …)` | R2 |
| `conformance_matrix.rs:322`, `:334` | `effective_acl(&store, …)` | `effective_acl(&store.read_store(), …)` | R2 |
| `conformance_matrix.rs:351` | `authorize(&store, …)` | `authorize(&store.read_store(), …)` | R2 |

- [ ] **Step 1: Enable the fixtures for the tests**

In `authz/Cargo.toml`, add to `[dev-dependencies]`:

```toml
brolly-store = { workspace = true, features = ["test-fixtures"] }
```

- [ ] **Step 2: Move the matrix onto `Pod`, and add a test of a read inside a write**

In `authz/tests/conformance_matrix.rs`, replace the imports at `:15-16`:

```rust
use brolly_authz::{AccessMode, Agent, EffectiveAcl, authorize, effective_acl};
use brolly_store::StoreManager;
use brolly_store::resources::{Content, Pod, PodRead};
```

Replace `surface_allows` and the head of `fixture` (`:61-82`):

```rust
fn surface_allows(
    _surface: Surface,
    store: &impl PodRead,
    path: &str,
    agent: &Agent,
    mode: AccessMode,
) -> bool {
    let Some(acl) = effective_acl(store, BASE, path).expect("effective acl") else {
        return false; // no ACL anywhere means no grant
    };
    authorize(store, &acl, agent, mode).expect("authorize")
}

/// Setup straight into the store, bypassing `Pod::write` (`test-fixtures`),
/// so it doesn't depend on the code under test.
fn seed(target: &Pod, quads: &[Quad]) {
    let store = target.raw_store();
    for quad in quads {
        store.insert(quad).unwrap();
    }
}

fn fixture() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mgr = StoreManager::open(dir.path(), 4, 60).expect("manager");
    let store = mgr.pod(Uuid::new_v4()).expect("pod");
```

At `:180`, `insert_quads(&store, &quads).expect("seed acls");` becomes
`seed(&store, &quads);`. Then apply the R2 rows in the table (`:295`, `:322`,
`:334`, `:351`).

Append this test:

```rust
/// A reader inside a write sees that write's own changes. Commit 2 checks WAC
/// inside the transaction a PUT is about to change, so this is what it relies
/// on. The ACL goes in as a resource, not raw quads, so the test holds once
/// ACLs exist by metadata too.
#[test]
fn an_acl_written_earlier_in_the_same_write_governs() {
    const ROOT: &str = "https://alice.brolly.id/~/";
    let dir = tempfile::tempdir().expect("tempdir");
    let mgr = StoreManager::open(dir.path(), 4, 60).expect("manager");
    let pod = mgr.pod(Uuid::new_v4()).expect("pod");

    let g = format!("{ROOT}draft.acl");
    let a = format!("{g}#public");
    let acl = [
        t(&g, &a, &format!("{ACL}accessTo"), &format!("{ROOT}draft")),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &a, &format!("{ACL}agentClass"), &format!("{FOAF}Agent")),
    ];

    let (found, allowed) = pod
        .write(|w| {
            w.create_root(ROOT)?;
            w.put(&g, Content::Auxiliary(&acl))?;
            let governing = effective_acl(&*w, BASE, "/~/draft")
                .expect("effective acl")
                .expect("an ACL governs /~/draft");
            let allowed = authorize(&*w, &governing, &Agent::Anonymous, AccessMode::Read)
                .expect("authorize");
            Ok((governing.graph.as_str().to_string(), allowed))
        })
        .expect("write");

    assert_eq!(found, g, "the reader missed the write's own ACL");
    assert!(allowed, "the ACL written in this write didn't grant");
}
```

- [ ] **Step 3: Run it and watch it fail**

Run: `cargo test -p brolly-authz`
Expected: FAIL to compile. The error is `error[E0277]: the trait bound
`ReadStore<'_>: …` is not satisfied`, or `error[E0308]: mismatched types …
expected `&Store`, found `&ReadStore<'_>``, at `surface_allows`'s call to
`effective_acl` and at the new test's `effective_acl(&*w, …)`.

- [ ] **Step 4: Read through `PodRead`**

In `authz/src/wac.rs`, replace the imports at `:1-6`:

```rust
//! WAC evaluation.

use brolly_domain::vocab;
use brolly_store::resources::PodRead;
use oxigraph::model::NamedNode;
use oxigraph::sparql::QueryResults;
```

In `effective_acl` (`:111-133`), the first parameter becomes
`store: &impl PodRead`. The call at `:133` becomes:

```rust
    let existing = select_iris(store, &query, "acl", &[])?;
```

Replace `authorize` and `select_iris` (`:150-258`):

```rust
pub fn authorize(
    store: &impl PodRead,
    acl: &EffectiveAcl,
    agent: &Agent,
    mode: AccessMode,
) -> Result<bool, AuthzError> {
    // Unchanged from today down to the query text: the same SELECT, with
    // `?agent` and `?target` bound by substitution, never written into the
    // text. Only the store type changes, and `select_iris` goes through
    // `PodRead::query_with`.
    let scope = if acl.direct {
        "http://www.w3.org/ns/auth/acl#accessTo"
    } else {
        "http://www.w3.org/ns/auth/acl#default"
    };
    let modes = mode
        .satisfying()
        .iter()
        .map(|m| format!("<{m}>"))
        .collect::<Vec<_>>()
        .join(" ");

    let acl_iri = acl.graph.as_str();
    let foaf_agent = format!("{}Agent", vocab::FOAF);
    let acl_ns = vocab::ACL;
    let vcard_member = format!("{}hasMember", vocab::VCARD);

    let agent_branches = match agent {
        Agent::Anonymous => String::new(),
        Agent::Authenticated(_) => format!(
            r#"
            UNION {{ ?auth <{acl_ns}agentClass> <{acl_ns}AuthenticatedAgent> }}
            UNION {{ ?auth <{acl_ns}agent> ?agent }}
            UNION {{
              ?auth <{acl_ns}agentGroup> ?group .
              GRAPH ?groupDoc {{ ?group <{vcard_member}> ?agent }}
            }}
            "#
        ),
    };

    let query = format!(
        r#"
        SELECT ?agent ?target WHERE {{
          VALUES ?mode {{ {modes} }}
          GRAPH <{acl_iri}> {{
            ?auth <{scope}> ?target ;
                  <{acl_ns}mode> ?mode .
            {{ ?auth <{acl_ns}agentClass> <{foaf_agent}> }}
            {agent_branches}
          }}
        }}
        LIMIT 1
        "#
    );

    let mut bindings: Vec<(&str, Term)> = vec![("target", Term::NamedNode(acl.scope.clone()))];
    if let Agent::Authenticated(webid) = agent {
        bindings.push(("agent", Term::NamedNode(NamedNode::new_unchecked(webid))));
    }

    let rows = select_iris(store, &query, "target", &bindings)?;
    Ok(!rows.is_empty())
}

/// Run a SELECT with substituted bindings, returning one projected column.
fn select_iris(
    store: &impl PodRead,
    query: &str,
    column: &str,
    bindings: &[(&str, Term)],
) -> Result<Vec<String>, AuthzError> {
    let results = store
        .query_with(query, bindings)
        .map_err(|e| AuthzError::Query(e.to_string()))?;

    let QueryResults::Solutions(solutions) = results else {
        return Err(AuthzError::Query("expected SELECT solutions".into()));
    };

    let mut out = Vec::new();
    for solution in solutions {
        let solution = solution.map_err(|e| AuthzError::Query(e.to_string()))?;
        match solution.get(column) {
            Some(oxigraph::model::Term::NamedNode(n)) => out.push(n.as_str().to_string()),
            _ => out.push(String::new()),
        }
    }
    Ok(out)
}
```

The query text and the substitutions are exactly today's; only the store type and the call into `PodRead::query_with` change. `effective_acl`'s callers of `select_iris` pass `&[]`. The `#[cfg(test)]` module doesn't change.

- [ ] **Step 5: Run it and watch it pass**

Run: `cargo test -p brolly-authz`
Expected: PASS. That's the whole matrix (every surface agrees),
`direct_acl_wins_over_inherited`,
`an_accessto_grant_does_not_leak_through_inheritance`, the three unit tests,
and `an_acl_written_earlier_in_the_same_write_governs`.

- [ ] **Step 6: Format**

Run: `cargo fmt --all`

- [ ] **Step 7: The crate's gates**

Run: `cargo clippy -p brolly-authz --all-targets -- -D warnings && cargo test -p brolly-authz`
Expected: clean.

- [ ] **Step 8: Stage, don't commit**

```bash
git add authz/Cargo.toml authz/src/wac.rs authz/tests/conformance_matrix.rs
```

---
### Task 3: The Solid adapter

`ldp`'s entry points take `&Pod` (R9). Each one does four things in order:
1. checks WAC through `read_store()`
2. writes any blob bytes
3. runs one `Pod::write`
4. releases replaced bytes after the commit

The WAC check stays outside the write in commit 1, as it is today. Commit 2
splits these into the `&Pod` layer and `_in(&mut PodWrite)` layer and moves
the check inside. The readers (`blob_digest`, `granted_modes`, `may_write`,
`storage::{exists, members}`) take `&impl PodRead`. `storage`'s writers and
`patch`'s appliers take `&mut PodWrite`. `profile::write` uses the
outside-root methods, since the profile document is outside `/~/`.

**Files:**
- Modify: `adapters/solid/Cargo.toml` (`[dev-dependencies]`)
- Modify: `adapters/solid/src/storage.rs:1-186` (everything above `mod tests`)
- Modify: `adapters/solid/src/ldp.rs:11-19`, `:53-63`, `:79-112`, `:153-201`, `:208-221`, `:271-336`, `:396-508`
- Modify: `adapters/solid/src/patch.rs:19-22`, `:193-247`, `:306-321`
- Modify: `adapters/solid/src/profile.rs:12-15`, `:50`, `:66`, `:75`, `:97-169`, `:189-195`
- Modify: `adapters/solid/tests/acl_control.rs`, `ldp_conformance.rs`, `ldp_nonrdf.rs`, `patch_conformance.rs`, `publication_boundary.rs` (sites in the table)

**Source sites:**

| Site | Before | After | Rule |
|---|---|---|---|
| `storage.rs:21` `init_storage_root` | `(store: &Store, root) -> Result<(), WriteError>`, `insert_quads` | `(w: &mut PodWrite<'_>, root) -> Result<(), StoreError>`, `w.legacy_under_root().insert` | R4, R5 |
| `storage.rs:66` `add_containment` | `&Store`, `insert_quads` per level | `&mut PodWrite`, `legacy_under_root().insert` per level | R4, R5 |
| `storage.rs:93` `remove_containment` | `&Store`, `store.remove` | `&mut PodWrite`, `legacy_under_root().remove` | R4, R5 |
| `storage.rs:113` `members` | `&Store` | `&impl PodRead` | R1 |
| `storage.rs:136` `uncontain_acls` | `&Store`, `store.remove` loop | `&mut PodWrite`, read through `w`, one `legacy_under_root().remove` | R4, R5 |
| `storage.rs:170` `exists` | `&Store` | `&impl PodRead` | R1 |
| `ldp.rs:79` `blob_digest`, `:83` `literal_object`, `:103` `digest_still_referenced` | `&Store` | `&impl PodRead` | R1 |
| `ldp.rs:153` `check`, `:180` `granted_modes`, `:447` `may_write` | `&Store` | `&impl PodRead` | R1 |
| `ldp.rs:208` `read` | `store: &Store` | `pod: &Pod`, reads through one `ReadStore` | R9 |
| `ldp.rs:271` `put` | `&Store`, `replace_graph` + `contain` + blob release | `&Pod`, one `Pod::write`, release after commit | full code |
| `ldp.rs:330` `contain` | `&Store` → `LdpError` | `&mut PodWrite` → `StoreError` | R4 |
| `ldp.rs:396` `append` | `&Store`, `insert_quads` + `contain` | `&Pod`, one `Pod::write` | full code |
| `ldp.rs:457` `delete` | `&Store`, exists/members checks, two `clear_graph`s, `remove_containment`, blob release | `&Pod`, checks and writes in one `Pod::write`, release after commit | full code |
| `patch.rs:210` `apply_scoped` | `&Store`, `replace_graph` | `&mut PodWrite`, `legacy_under_root().replace_graph` | R4, R5 |
| `patch.rs:307`, `:316` `apply_n3_patch`, `apply_sparql_update` | `&Store` | `&mut PodWrite<'_>` | R4 |
| `profile.rs:50` `read`, `:66` `flag`, `:75` `literal`, `:189` `document` | `&Store` | `&impl PodRead` | R1 |
| `profile.rs:97` `write` | `&Store`, `store.remove` per quad + `insert_quads` → `WriteError` | `&mut PodWrite`, `remove_quads` + `insert` → `StoreError` | R4, R5 |

**Test sites:**

| File | Lines | Before | After | Rule |
|---|---|---|---|---|
| all five | imports | `use brolly_store::{StoreManager, insert_quads};`, `oxigraph::store::Store` | `use brolly_store::StoreManager;` and `use brolly_store::resources::{Pod, PodRead};`, dropping `PodRead` where no method is called on a provider | |
| `acl_control.rs` | 70-74, 102-106 | `std::sync::Arc<oxigraph::store::Store>` | `std::sync::Arc<Pod>` | |
| `acl_control.rs` | 78 | `storage::init_storage_root(&store, ROOT).unwrap();` | `store.write(\|w\| storage::init_storage_root(w, ROOT)).unwrap();` | R6 |
| `acl_control.rs` | 82, 112, 360 | `insert_quads(&store, &[…]).unwrap();` | `seed(&store, &[…]);` | R8 |
| `acl_control.rs` | 183, 291 | `ldp::may_write(&store, …)` | `ldp::may_write(&store.read_store(), …)` | R2 |
| `acl_control.rs` | 193, 376, 532, 551 | `ldp::granted_modes(&store, …)` | `ldp::granted_modes(&store.read_store(), …)` | R2 |
| `acl_control.rs` | 234, 334, 455, 456, 491, 492, 537, 586, 587 | `storage::exists(&store, …)` | `storage::exists(&store.read_store(), …)` | R2 |
| `acl_control.rs` | 421, 457, 578, 581 | `storage::members(&store, …)` | `storage::members(&store.read_store(), …)` | R2 |
| `acl_control.rs` | 573-574 | two `storage::add_containment(&store, …).unwrap();` | one write (code below) | R6 |
| `acl_control.rs` | 576, 589 | `storage::uncontain_acls(&store).unwrap()` | `store.write(storage::uncontain_acls).unwrap()` | R6 |
| `ldp_conformance.rs` | 65-69 | `Arc<oxigraph::store::Store>` | `Arc<Pod>` | |
| `ldp_conformance.rs` | 74 | `storage::init_storage_root(&store, ROOT).unwrap();` | `store.write(\|w\| storage::init_storage_root(w, ROOT)).unwrap();` | R6 |
| `ldp_conformance.rs` | 91, 346, 418 | `insert_quads(&store, …).unwrap();` | `seed(&store, …);` | R8 |
| `ldp_conformance.rs` | 137, 251, 254, 310, 313 | `storage::exists(&store, …)` | `storage::exists(&store.read_store(), …)` | R2 |
| `ldp_conformance.rs` | 272, 273, 274, 293, 314 | `storage::members(&store, …)` | `storage::members(&store.read_store(), …)` | R2 |
| `ldp_nonrdf.rs` | 11, 36 | `use brolly_store::{BlobStore, Store, insert_quads};`, `store: std::sync::Arc<Store>` | `use brolly_store::BlobStore; use brolly_store::resources::PodRead;`, `store: std::sync::Arc<brolly_store::resources::Pod>` (the file has its own `struct Pod`) | |
| `ldp_nonrdf.rs` | 48 | `storage::init_storage_root(&store, ROOT).unwrap();` | `store.write(\|w\| storage::init_storage_root(w, ROOT)).unwrap();` | R6 |
| `ldp_nonrdf.rs` | 51 | `insert_quads(&store, &[…]).unwrap();` | `seed(&store, &[…]);` | R8 |
| `ldp_nonrdf.rs` | 139-141 | `pod.store.quads_for_pattern(` | `pod.store.read_store().quads_for_pattern(` | R2 |
| `ldp_nonrdf.rs` | 175, 401 | `storage::members(&pod.store, …)` | `storage::members(&pod.store.read_store(), …)` | R2 |
| `ldp_nonrdf.rs` | 270, 370 | `ldp::blob_digest(&pod.store, …)` | `ldp::blob_digest(&pod.store.read_store(), …)` | R2 |
| `patch_conformance.rs` | 11, 20 | `use oxigraph::store::Store;`, `Arc<Store>` | removed, `Arc<Pod>` | |
| `patch_conformance.rs` | 25 | `insert_quads(&store, &[…]).unwrap();` | `seed(&store, &[…]);` | R8 |
| `patch_conformance.rs` | 38 | `fn triples(store: &Store)` | `fn triples(store: &Pod)`, reading through `store.read_store()`; call sites unchanged | R2 |
| `patch_conformance.rs` | 60, 72, 87, 104, 119, 136, 195, 202 | `patch::apply_n3_patch(&X, RESOURCE, B)` | `n3(&X, B)` | R6 |
| `patch_conformance.rs` | 137, 154, 170 | `patch::apply_sparql_update(&X, RESOURCE, S)` | `sparql(&X, S)` | R6 |
| `publication_boundary.rs` | 12-14, 48 | `index, insert_quads`, `oxigraph::store::Store`, `pod: Arc<Store>` | `use brolly_store::{StoreManager, index}; use brolly_store::resources::{Pod, PodRead};`, `pod: Arc<Pod>` | |
| `publication_boundary.rs` | 56 | `storage::init_storage_root(&pod, ROOT).unwrap();` | `pod.write(\|w\| storage::init_storage_root(w, ROOT)).unwrap();` | R6 |
| `publication_boundary.rs` | 59 | `insert_quads(&pod, &[…]).unwrap();` | `seed(&pod, &[…]);` | R8 |
| `publication_boundary.rs` | 83-85 | `manager.instance().quads_for_pattern(` | unchanged: `InstanceStore: PodRead`, imported above | A8 |

Unchanged: all 79 `ldp::{read, put, append, delete}(&store | &pod.store | &f.pod, …)` calls (R9). Unchanged: `oidc_persistence.rs`.

- [ ] **Step 1: Enable the fixtures for the tests**

In `adapters/solid/Cargo.toml`, add to `[dev-dependencies]`:

```toml
brolly-store = { workspace = true, features = ["test-fixtures"] }
```

- [ ] **Step 2: Move the Solid tests onto `Pod`**

Apply the test-site table. Each of the five files that seeds gets the R8
`seed` helper. `ldp_nonrdf.rs` names the type
`&brolly_store::resources::Pod`, because it defines its own `struct Pod`. The
fixtures read like this. `acl_control.rs`'s `pod()` (`:69-99`):

```rust
/// A pod whose root ACL gives Alice Read, Write and Control over everything.
fn pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();
    store
        .write(|w| storage::init_storage_root(w, ROOT))
        .unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    seed(
        &store,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &a, &format!("{ACL}agent"), ALICE),
        ],
    );
    (mgr, dir, store)
}
```

`ldp_conformance.rs`'s `pod()`, `ldp_nonrdf.rs`'s `pod()` and
`publication_boundary.rs`'s `fixture()` change the same way: the write for
`init_storage_root`, then `seed` for the ACL. `patch_conformance.rs`:

```rust
use brolly_solid::patch::{self, PatchError};
use brolly_store::StoreManager;
use brolly_store::resources::{Pod, PodRead};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const RESOURCE: &str = "https://alice.brolly.id/~/note";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// Setup straight into the store, bypassing `Pod::write` (`test-fixtures`),
/// so it doesn't depend on the code under test.
fn seed(target: &Pod, quads: &[Quad]) {
    let store = target.raw_store();
    for quad in quads {
        store.insert(quad).unwrap();
    }
}

fn pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();

    seed(
        &store,
        &[Quad::new(
            NamedOrBlankNode::NamedNode(n(RESOURCE)),
            n("https://example.org/title"),
            Term::Literal(oxigraph::model::Literal::new_simple_literal("Original")),
            GraphName::NamedNode(n(RESOURCE)),
        )],
    );
    (mgr, dir, store)
}

/// Apply an N3 Patch in one write, as `pod.rs` does.
fn n3(store: &Pod, body: &[u8]) -> Result<(), PatchError> {
    store
        .write(|w| Ok(patch::apply_n3_patch(w, RESOURCE, body)))
        .map_err(|e| PatchError::Store(e.to_string()))
        .flatten()
}

/// Apply a SPARQL Update in one write, as `pod.rs` does.
fn sparql(store: &Pod, update: &str) -> Result<(), PatchError> {
    store
        .write(|w| Ok(patch::apply_sparql_update(w, RESOURCE, update)))
        .map_err(|e| PatchError::Store(e.to_string()))
        .flatten()
}

fn triples(store: &Pod) -> Vec<String> {
    store
        .read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(n(RESOURCE).as_ref())),
        )
        .filter_map(Result::ok)
        .map(|q| format!("{} {} {}", q.subject, q.predicate, q.object))
        .collect()
}
```

`acl_control.rs:573-576` and `:589` become:

```rust
    // The triples an old `put` of each ACL would have left behind.
    store
        .write(|w| {
            storage::add_containment(w, &format!("{ROOT}.acl"), ROOT)?;
            storage::add_containment(w, &format!("{ROOT}shared/.acl"), ROOT)
        })
        .unwrap();

    assert_eq!(store.write(storage::uncontain_acls).unwrap(), 2);
```

```rust
    assert_eq!(
        store.write(storage::uncontain_acls).unwrap(),
        0,
        "idempotent"
    );
```

- [ ] **Step 3: Run them and watch them fail**

Run: `cargo test -p brolly-solid --tests`
Expected: FAIL to compile. The errors include `error[E0308]: mismatched types …
expected `&Store`, found `&mut PodWrite<'_>`` at
`storage::init_storage_root(w, ROOT)`, and at the patch helpers'
`patch::apply_n3_patch(w, …)`.

- [ ] **Step 4: `storage.rs`**

Replace everything above `#[cfg(test)]` (`:1-186`) with the following. The
tests module doesn't change.

```rust
//! The storage root and container bookkeeping.
//!
//! Everything here is under the storage root, so it writes through
//! `legacy_under_root`, exactly as it always has, until the pod keeps its own
//! resource metadata (stage 5a).

use brolly_domain::vocab;
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};

pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
pub const LDP_NON_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#NonRDFSource";
pub const PIM_STORAGE: &str = "http://www.w3.org/ns/pim/space#Storage";

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// Create the user's storage root: an `ldp:BasicContainer` that is also a
/// `pim:Storage`, which is what makes it discoverable as *the* pod root rather
/// than just another container.
pub fn init_storage_root(w: &mut PodWrite<'_>, root: &str) -> Result<(), StoreError> {
    let node = iri(root);
    let quads = vec![
        Quad::new(
            NamedOrBlankNode::NamedNode(node.clone()),
            iri(vocab::RDF_TYPE),
            Term::NamedNode(iri(LDP_BASIC_CONTAINER)),
            GraphName::NamedNode(node.clone()),
        ),
        Quad::new(
            NamedOrBlankNode::NamedNode(node.clone()),
            iri(vocab::RDF_TYPE),
            Term::NamedNode(iri(LDP_RESOURCE)),
            GraphName::NamedNode(node.clone()),
        ),
        Quad::new(
            NamedOrBlankNode::NamedNode(node.clone()),
            iri(vocab::RDF_TYPE),
            Term::NamedNode(iri(PIM_STORAGE)),
            GraphName::NamedNode(node),
        ),
    ];
    w.legacy_under_root().insert(&quads)
}

/// The container that directly holds `resource`.
///
/// `/~/a/b/c` → `/~/a/b/`, `/~/a/` → `/~/`. Returns `None` at the storage root,
/// which has no parent inside the pod.
pub fn parent_container(resource: &str, root: &str) -> Option<String> {
    if resource == root || !resource.starts_with(root) {
        return None;
    }
    let trimmed = resource.trim_end_matches('/');
    let cut = trimmed.rfind('/')?;
    let parent = &trimmed[..cut + 1];
    (parent.len() >= root.len()).then(|| parent.to_string())
}

/// Record `resource` as contained by its parent, all the way up.
///
/// Containment is maintained on write rather than derived on read, because an
/// LDP `GET` on a container must list its members and walking the whole pod to
/// find them would be the outbox-walking mistake in another costume.
pub fn add_containment(w: &mut PodWrite<'_>, resource: &str, root: &str) -> Result<(), StoreError> {
    let mut child = resource.to_string();
    while let Some(parent) = parent_container(&child, root) {
        let parent_node = iri(&parent);
        w.legacy_under_root().insert(&[
            Quad::new(
                NamedOrBlankNode::NamedNode(parent_node.clone()),
                iri(LDP_CONTAINS),
                Term::NamedNode(iri(&child)),
                GraphName::NamedNode(parent_node.clone()),
            ),
            Quad::new(
                NamedOrBlankNode::NamedNode(parent_node.clone()),
                iri(vocab::RDF_TYPE),
                Term::NamedNode(iri(LDP_BASIC_CONTAINER)),
                GraphName::NamedNode(parent_node),
            ),
        ])?;
        child = parent;
    }
    Ok(())
}

/// Remove a containment triple when a resource is deleted.
pub fn remove_containment(
    w: &mut PodWrite<'_>,
    resource: &str,
    root: &str,
) -> Result<(), StoreError> {
    let Some(parent) = parent_container(resource, root) else {
        return Ok(());
    };
    let parent_node = iri(&parent);
    w.legacy_under_root().remove(&[Quad::new(
        NamedOrBlankNode::NamedNode(parent_node.clone()),
        iri(LDP_CONTAINS),
        Term::NamedNode(iri(resource)),
        GraphName::NamedNode(parent_node),
    )])
}

/// Members of a container.
pub fn members(store: &impl PodRead, container: &str) -> Vec<String> {
    let node = iri(container);
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(node.clone())).into()),
            Some(iri(LDP_CONTAINS).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            Term::NamedNode(n) => Some(n.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// Remove every `ldp:contains` triple that names an ACL resource.
///
/// ACL resources are auxiliary and aren't members of their container (Solid
/// Protocol §4.3), but `ldp::put` recorded them as members until stage 0. This
/// is the repair `brolly-admin acl-uncontain` runs on each pod. It returns how
/// many triples it removed, so a second run reports zero.
pub fn uncontain_acls(w: &mut PodWrite<'_>) -> Result<usize, StoreError> {
    let stale = w
        .quads_for_pattern(None, Some(iri(LDP_CONTAINS).as_ref()), None, None)
        .filter_map(|quad| match quad {
            Ok(quad) => is_acl_containment(&quad).then_some(Ok(quad)),
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<Quad>, _>>()?;
    w.legacy_under_root().remove(&stale)?;
    Ok(stale.len())
}

/// The shape [`add_containment`] writes, naming an ACL: a container's own
/// graph saying it contains an `.acl` resource.
///
/// Matching the graph as well as the predicate leaves a member's own documents
/// alone, even if they happen to use `ldp:contains`.
fn is_acl_containment(quad: &Quad) -> bool {
    let (
        NamedOrBlankNode::NamedNode(container),
        Term::NamedNode(member),
        GraphName::NamedNode(graph),
    ) = (&quad.subject, &quad.object, &quad.graph_name)
    else {
        return false;
    };
    container == graph
        && is_container(container.as_str())
        && crate::ldp::governed(member.as_str()).is_some()
}

/// Does a resource exist, as a graph with any triples?
pub fn exists(store: &impl PodRead, resource: &str) -> bool {
    let node = iri(resource);
    store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .next()
        .is_some()
}

/// True when the IRI names a container by LDP convention.
pub fn is_container(resource: &str) -> bool {
    resource.ends_with('/')
}
```

- [ ] **Step 5: `ldp.rs`**

Replace the imports (`:11-19`):

```rust
use brolly_authz::{AccessMode, authorize, effective_acl};
use brolly_domain::syntax::{self, ReadFormat, SyntaxError, WriteFormat};
use brolly_identity::Subject;
use brolly_store::resources::{Pod, PodRead, PodWrite};
use brolly_store::{BlobStore, StoreError};
use oxigraph::model::{GraphNameRef, NamedNode, Quad};

use crate::storage;
```

Replace `impl From<WriteError> for LdpError` (`:53-57`) with the following,
keeping the `StorageError` impl below it:

```rust
impl From<StoreError> for LdpError {
    fn from(e: StoreError) -> Self {
        LdpError::Store(e.to_string())
    }
}
```

Apply R1 to `blob_digest` (`:79`), `literal_object` (`:83`),
`digest_still_referenced` (`:103`), `check` (`:153-159`), `granted_modes`
(`:180`) and `may_write` (`:447-452`). Only the `store` parameter's type
changes, to `&impl PodRead`, and the bodies don't. `check` passes `store`
through to `effective_acl` and `authorize`, which take `&impl PodRead` since
Task 2.

`read` (`:208-221`): rename the first parameter and read through one
`ReadStore`. Only the head changes, and the rest of the body keeps using
`store`:

```rust
pub fn read(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    accept: Option<&str>,
) -> Result<LdpOutcome, LdpError> {
    let store = &pod.read_store();
    let resource = format!("{base}{path}");

    if !check(store, base, path, subject, AccessMode::Read)? {
        return Err(LdpError::NotFound);
    }
    if !storage::exists(store, &resource) {
        return Err(LdpError::NotFound);
    }
```

From `:225` to the end of `read`, the body is unchanged. `blob_digest(store,
…)`, `literal_object(store, …)`, `granted_modes(store, …)` and
`store.quads_for_pattern(…)` all resolve through `PodRead`.

Replace `put` and `contain` (`:267-336`):

```rust
/// `PUT` — create or replace a resource.
///
/// Requires Write. Replacing is not Append: a client that may only add triples
/// must not be able to erase the ones already there.
pub fn put(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
) -> Result<(), LdpError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&pod.read_store(), base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Forbidden);
    }

    // ADR 0007: RDF/XML is refused rather than falling through to blob
    // storage. Every *other* unparseable type is a legitimate binary, so this
    // has to name RDF/XML specifically — `read_format` errors for all of them.
    refuse_rdf_xml(content_type)?;

    if syntax::is_parseable_rdf(content_type) {
        let quads = parse_into_graph(body, syntax::read_format(content_type)?, &resource)?;
        pod.write(|w| {
            w.legacy_under_root().replace_graph(&resource, &quads)?;
            contain(w, &resource, storage_root)
        })?;
        return Ok(());
    }

    let blobs = blobs.ok_or_else(|| LdpError::Store("no blob store for this pod".into()))?;
    // The new bytes land before the write, and the previous bytes are released
    // only after it commits, so a failed write leaves the old resource intact.
    let digest = blobs
        .put(body)
        .map_err(|e| LdpError::Store(e.to_string()))?;
    let quads = blob_quads(&resource, &digest, content_type, body.len());
    let released = pod.write(|w| {
        let previous = blob_digest(&*w, &resource);
        w.legacy_under_root().replace_graph(&resource, &quads)?;
        contain(w, &resource, storage_root)?;
        Ok(previous.filter(|previous| {
            *previous != digest && !digest_still_referenced(&*w, previous, &resource)
        }))
    })?;
    if let Some(previous) = released {
        blobs
            .remove(&previous)
            .map_err(|e| LdpError::Store(e.to_string()))?;
    }
    Ok(())
}

/// Record `resource` as a member of its container, unless it is an ACL.
///
/// ACL resources are auxiliary resources and aren't contained (Solid Protocol
/// §4.3). Skipping the whole walk up the tree, not just the last step, is what
/// stops a write to `/~/newdir/.acl` from creating `/~/newdir/` as a side
/// effect. The ACL may exist before the resource it governs, and WAC applies it
/// once that resource does.
fn contain(w: &mut PodWrite<'_>, resource: &str, storage_root: &str) -> Result<(), StoreError> {
    if governed(resource).is_some() {
        return Ok(());
    }
    storage::add_containment(w, resource, storage_root)
}
```

Replace `append` (`:393-441`):

```rust
/// `POST` — append triples to a resource, or create a member of a container.
///
/// Requires Append, which Write satisfies (`acl:Write` implies `acl:Append`).
pub fn append(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
) -> Result<String, LdpError> {
    let container = format!("{base}{path}");
    if !container.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&pod.read_store(), base, path, subject, AccessMode::Append)? {
        return Err(LdpError::Forbidden);
    }

    // POST to a container mints a new member; POST to a resource appends.
    let target = if storage::is_container(&container) {
        format!("{container}{}", uuid::Uuid::new_v4())
    } else {
        container.clone()
    };

    // A binary member is created rather than appended to: there are no triples
    // to merge into.
    refuse_rdf_xml(content_type)?;
    let quads = if syntax::is_parseable_rdf(content_type) {
        parse_into_graph(body, syntax::read_format(content_type)?, &target)?
    } else {
        let blobs = blobs.ok_or_else(|| LdpError::Store("no blob store for this pod".into()))?;
        let digest = blobs
            .put(body)
            .map_err(|e| LdpError::Store(e.to_string()))?;
        blob_quads(&target, &digest, content_type, body.len())
    };

    pod.write(|w| {
        w.legacy_under_root().insert(&quads)?;
        contain(w, &target, storage_root)
    })?;
    Ok(target)
}
```

`may_write` (`:443-454`) keeps its doc comment and body. Its first parameter
becomes `store: &impl PodRead`.

Replace `delete` (`:456-508`):

```rust
/// `DELETE`.
pub fn delete(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    storage_root: &str,
) -> Result<(), LdpError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&pod.read_store(), base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Forbidden);
    }

    let released = pod.write(|w| {
        if !storage::exists(&*w, &resource) {
            return Ok(Err(LdpError::NotFound));
        }

        // Refusing to delete a non-empty container is LDP's rule, and it is the
        // difference between removing a resource and silently orphaning a
        // subtree.
        if storage::is_container(&resource) && !storage::members(&*w, &resource).is_empty() {
            return Ok(Err(LdpError::Forbidden));
        }

        // Read the digest before the graph goes, then release the bytes only if
        // no other resource still names them — content addressing means two
        // resources can share one blob.
        let digest = blob_digest(&*w, &resource);
        w.legacy_under_root().clear_graph(&resource)?;
        storage::remove_containment(w, &resource, storage_root)?;

        // Deleting a resource deletes its ACL (Solid Protocol §5.4). Now that an
        // ACL isn't a member, a container that has one can be deleted, and
        // recreating it would otherwise quietly bring the old grants back. Both
        // go in one transaction, so a failure leaves both.
        w.legacy_under_root()
            .clear_graph(&format!("{resource}.acl"))?;

        Ok(Ok(digest.filter(|digest| {
            !digest_still_referenced(&*w, digest, &resource)
        })))
    })??;

    if let Some(digest) = released
        && let Some(blobs) = blobs
    {
        blobs
            .remove(&digest)
            .map_err(|e| LdpError::Store(e.to_string()))?;
    }
    Ok(())
}
```

- [ ] **Step 6: `patch.rs`**

Replace the imports (`:19-22`). The scratch store is still an oxigraph
in-memory `Store`: it's a separate database with its own transaction lock,
never a pod.

```rust
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphNameRef, NamedNode, Quad};
use oxigraph::sparql::SparqlEvaluator;
use oxigraph::store::Store;
```

Replace `apply_scoped` (`:193-247`):

```rust
/// Run an update against one resource, in isolation.
///
/// The resource's triples are copied into a scratch in-memory store as its
/// **default graph**, the update runs there verbatim, and the result replaces
/// the resource's named graph inside the caller's write.
///
/// This avoids rewriting the client's SPARQL. Wrapping text in `WITH <g>` only
/// works for the `DELETE/INSERT … WHERE` form — `INSERT DATA`, which is what
/// most Solid clients actually send, needs `GRAPH <g> { … }` inside the braces
/// instead. Doing that by string surgery on a user-supplied query is exactly
/// the kind of parser-by-regex this codebase should not contain.
///
/// Two properties fall out for free: the result goes through the pod's
/// canonicalising write path, so IRIs are canonicalized like any other write
/// rather than needing a fix-up pass afterwards; and the swap is computed
/// before it is applied, so a failing update leaves the resource untouched.
fn apply_scoped(
    w: &mut PodWrite<'_>,
    resource: &str,
    update: &str,
    precondition: impl Fn(&Store) -> Result<(), PatchError>,
) -> Result<(), PatchError> {
    let graph = NamedNode::new_unchecked(resource);

    let scratch = Store::new().map_err(|e| PatchError::Store(e.to_string()))?;
    for quad in w.quads_for_pattern(
        None,
        None,
        None,
        Some(GraphNameRef::NamedNode(graph.as_ref())),
    ) {
        let quad = quad.map_err(|e| PatchError::Store(e.to_string()))?;
        scratch
            .insert(&Quad::new(
                quad.subject,
                quad.predicate,
                quad.object,
                oxigraph::model::GraphName::DefaultGraph,
            ))
            .map_err(|e| PatchError::Store(e.to_string()))?;
    }

    precondition(&scratch)?;
    run_update(&scratch, update)?;

    let patched: Vec<Quad> = scratch
        .quads_for_pattern(None, None, None, Some(GraphNameRef::DefaultGraph))
        .filter_map(Result::ok)
        .map(|q| Quad::new(q.subject, q.predicate, q.object, graph.clone()))
        .collect();

    // Every PATCH target is under the storage root (`pod.rs` refuses the rest).
    w.legacy_under_root()
        .replace_graph(resource, &patched)
        .map_err(|e| PatchError::Store(e.to_string()))?;
    Ok(())
}
```

Replace `apply_n3_patch` and `apply_sparql_update` (`:306-321`):

```rust
/// Apply an N3 Patch to a resource, inside the caller's write.
pub fn apply_n3_patch(
    w: &mut PodWrite<'_>,
    resource: &str,
    body: &[u8],
) -> Result<(), PatchError> {
    let patch = parse_n3_patch(body, resource)?;
    let update = n3_patch_to_sparql(&patch);
    apply_scoped(w, resource, &update, |scratch| {
        check_preconditions(scratch, &patch)
    })
}

/// Apply a SPARQL Update to a resource, inside the caller's write.
pub fn apply_sparql_update(
    w: &mut PodWrite<'_>,
    resource: &str,
    sparql: &str,
) -> Result<(), PatchError> {
    if !is_graph_safe(sparql) {
        return Err(PatchError::EscapesGraph);
    }
    apply_scoped(w, resource, sparql, |_| Ok(()))
}
```

`check_preconditions`, `ask_query` and `run_update` keep `&Store`, because
they only ever run on the scratch store.

- [ ] **Step 7: `profile.rs`**

Replace the imports (`:12-15`):

```rust
use brolly_domain::vocab;
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
```

Apply R1 to `read` (`:50`), `flag` (`:66`), `literal` (`:75`) and `document`
(`:189-195`). Only the `store` parameter's type changes.

Replace `write` (`:92-169`):

```rust
/// Write the profile, replacing the predicates it owns.
///
/// Only `foaf:name` and `vcard:note` are touched: the profile document also
/// holds `space:storage`, keys and type triples that this form knows nothing
/// about, so clearing the graph would delete them.
///
/// The profile document is protocol state outside the storage root, so it is
/// written with `PodWrite`'s outside-root methods.
pub fn write(
    w: &mut PodWrite<'_>,
    webid: &str,
    document: &str,
    profile: &Profile,
) -> Result<(), StoreError> {
    let graph = iri(document);
    let subject = NamedOrBlankNode::NamedNode(iri(webid));

    let mut existing: Vec<Quad> = Vec::new();
    for predicate in [
        vocab::FOAF_NAME,
        vocab::VCARD_NOTE,
        vocab::AS2_MANUALLY_APPROVES,
        vocab::MASTODON_BOT,
        vocab::MASTODON_DISCOVERABLE,
    ] {
        existing.extend(
            w.quads_for_pattern(
                Some((&subject).into()),
                Some(iri(predicate).as_ref()),
                None,
                Some(GraphNameRef::NamedNode(graph.as_ref())),
            )
            .filter_map(Result::ok),
        );
    }
    w.remove_quads(&existing)?;

    // An empty field means "no value", not an empty string: a blank
    // `foaf:name` reads as a person literally named "".
    let mut quads = Vec::new();
    for (predicate, value) in [
        (vocab::FOAF_NAME, &profile.display_name),
        (vocab::VCARD_NOTE, &profile.bio),
    ] {
        if value.trim().is_empty() {
            continue;
        }
        quads.push(Quad::new(
            subject.clone(),
            iri(predicate),
            Term::Literal(Literal::new_simple_literal(value.trim())),
            GraphName::NamedNode(graph.clone()),
        ));
    }
    // Flags are written always, including when false. Unlike a name, absence
    // is meaningful here — `discoverable` absent means *true* — so omitting a
    // false value would read back as the opposite of what was set.
    for (predicate, value) in [
        (vocab::AS2_MANUALLY_APPROVES, profile.locked),
        (vocab::MASTODON_BOT, profile.bot),
        (vocab::MASTODON_DISCOVERABLE, profile.discoverable),
    ] {
        quads.push(Quad::new(
            subject.clone(),
            iri(predicate),
            Term::Literal(Literal::new_typed_literal(
                if value { "true" } else { "false" },
                iri(vocab::XSD_BOOLEAN),
            )),
            GraphName::NamedNode(graph.clone()),
        ));
    }

    if !quads.is_empty() {
        w.insert(&quads)?;
    }
    Ok(())
}
```

- [ ] **Step 8: Run them and watch them pass**

Run: `cargo test -p brolly-solid`
Expected: PASS. That's every test in `acl_control`, `ldp_conformance`,
`ldp_nonrdf`, `oidc_persistence`, `patch_conformance` and
`publication_boundary`, and the unit tests. `oidc_persistence` needs Docker, as
it does today.

- [ ] **Step 9: Format**

Run: `cargo fmt --all`

- [ ] **Step 10: The crate's gates**

Run: `cargo clippy -p brolly-solid --all-targets -- -D warnings && cargo test -p brolly-solid`
Expected: clean.

- [ ] **Step 11: Stage, don't commit**

```bash
git add adapters/solid/Cargo.toml adapters/solid/src/ldp.rs adapters/solid/src/storage.rs \
        adapters/solid/src/patch.rs adapters/solid/src/profile.rs \
        adapters/solid/tests/acl_control.rs adapters/solid/tests/ldp_conformance.rs \
        adapters/solid/tests/ldp_nonrdf.rs adapters/solid/tests/patch_conformance.rs \
        adapters/solid/tests/publication_boundary.rs
```

---
### Task 4: The ActivityPub adapter

`inbox` and `follows` writers take `&mut PodWrite`. Their readers take
`&impl PodRead`. `processor::process` splits in two:
- `process_member(&mut PodWrite, inbox, outbox, activity, received_at)`
- `process_instance(&InstanceStore, activity)`

`Recipient` goes, because each half already names its recipient. The graphs are
routed by R5:
- **The `/inbox` and `/outbox` collection graphs and `#social`** use the
  outside-root methods.
- **Activity and object records** use `legacy_under_root`. A record can be the
  author's own post under `/~/`, or a recipient's copy on another origin.
  Commit 2 decides between them from the IRI.

**Files:**
- Modify: `adapters/activitypub/Cargo.toml` (`[dev-dependencies]`)
- Modify: `adapters/activitypub/src/inbox.rs:14-177`
- Modify: `adapters/activitypub/src/follows.rs:14-188` and the tests module `:190-241`
- Modify: `adapters/activitypub/src/processor.rs:21-247`
- Modify: `adapters/activitypub/tests/inbox.rs`, `adapters/activitypub/tests/processor.rs` (sites in the table)

**Source sites:**

| Site | Before | After | Rule |
|---|---|---|---|
| `inbox.rs:83` `deliver` | `&Store`, `insert_quads` | `&mut PodWrite`; records `legacy_under_root().replace_graph`, collection `w.insert` | R4, R5 |
| `inbox.rs:134` `write_record` | `clear_graph` + `insert_quads` | `legacy_under_root().replace_graph` | R5 |
| `inbox.rs:144` `clear_received_at` | read + `store.remove` loop | read through `w`, `w.remove_quads` | R3, R5 |
| `inbox.rs:164` `remove` | `store.remove`, `clear_graph` | `w.remove_quads` (collection), `legacy_under_root().clear_graph` (record) | R5 |
| `inbox.rs:61-65` | `From<WriteError> for InboxError` | `From<StoreError> for InboxError` | R4 |
| `follows.rs:41`, `:56`, `:76` `record*` | `&Store` → `WriteError` | `&mut PodWrite` → `StoreError`, `w.insert` | R4, R5 |
| `follows.rs:99`, `:105`, `:109` `approve`, `reject`, `drop_request` | `&Store` → `WriteError` | `&mut PodWrite` → `StoreError`, `w.remove_quads` | R4, R5 |
| `follows.rs:91`, `:124`, `:129`, `:133` `pending`, `followers`, `following`, `objects` | `&Store` | `&impl PodRead` | R1 |
| `follows.rs:156` `remove` | `&Store` → `StorageError` | `&mut PodWrite` → `StoreError` | R4 |
| `processor.rs:33-40` `Recipient` | enum | removed | |
| `processor.rs:78-82` | `From<WriteError> for ProcessError` | removed (`index` returns `StoreError`, Task 1) | |
| `processor.rs:93` `process` | dispatch on `Recipient` | `process_member` and `process_instance` | full code |
| `processor.rs:153` `carriers` | `&Store` | `&impl PodRead`, called with `&*w` | R1, R3 |
| `processor.rs:165`, `:211` `process_for_instance`, `index_note` | `&Store` | `&InstanceStore` | |

- [ ] **Step 1: Enable the fixtures for the tests**

In `adapters/activitypub/Cargo.toml`, add to `[dev-dependencies]`:

```toml
brolly-store = { workspace = true, features = ["test-fixtures"] }
```

- [ ] **Step 2: Move the tests onto `Pod`, and add a read-inside-a-write test**

**`tests/inbox.rs`.** Replace the imports and `store()` (`:14-26`):

```rust
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
```

Then:
- **`inbox::deliver(&store, …)` becomes `deliver(&store, …)`** at `:52, 66, 93,
  107, 108, 123, 135, 147, 177, 179, 197, 204, 233, 268, 275, 297`.
- **`:299` becomes:**
  `store.write(|w| Ok(inbox::remove(w, ALICE_INBOX, &id))).unwrap().expect("remove");`
- **R2 at `:55, 68, 76, 95, 110, 111, 126, 137, 156, 187, 218, 222, 226, 242,
  249, 283, 284, 286, 287, 301, 302, 303`.** `inbox::{members, received_at,
  read_activity, timeline}(&store, …)` becomes `(&store.read_store(), …)`. At
  `:68` the `&store` is on `:69`, and at `:249` it's on `:250`.

**`tests/processor.rs`.** Replace the imports and helpers (`:14-100`), keeping
the `const`s and `create` as they are:

```rust
use brolly_activitypub::inbox::{self, InboxError};
use brolly_activitypub::processor::{self, ProcessError};
use brolly_store::resources::{Pod, PodRead};
use brolly_store::{StoreManager, index};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::{Value, json};
```

```rust
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
```

Then:
- **Member sites.** `processor::process(&pod, Recipient::Member { inbox: X,
  outbox: Y }, A, T)` becomes `member(&pod, X, Y, A, T)` at `:109, 233, 503,
  564, 611, 649, 722, 754, 800, 825, 861`.
- **Instance sites.** `processor::process(index_store, Recipient::Instance, A,
  T)` becomes `processor::process_instance(index_store, A)` at `:136, 161, 206,
  243, 270, 285, 326, 350, 375, 387, 422, 432, 513, 543, 683, 691`. The site at
  `:777` becomes `processor::process_instance(manager.instance(), &attack)`.
- **The loop at `:483-494`** becomes:

  ```rust
      member(&pod, ALICE_INBOX, ALICE_OUTBOX, &activity, "2026-08-26T12:00:01Z").unwrap();
      processor::process_instance(index_store, &activity).unwrap();
  ```
- **`inbox::deliver(&pod, …)` becomes `deliver(&pod, …)`** at `:597`, `:641`.
- **R2 at `:120, 125, 253, 527, 531, 666, 670, 674, 773, 873`.**
  `inbox::…(&pod, …)` becomes `(&pod.read_store(), …)`.
- **`graph(&pod, X)` becomes `graph(&pod.read_store(), X)`** at `:562, 581,
  594, 628, 749, 768, 795, 813`.
- **Unchanged:**
  - `graph(index_store, …)` at `:383`, `:403`
  - `literals(index_store)` at `:169`
  - `index_store.quads_for_pattern` at `:178`, through `InstanceStore: PodRead`
  - the `seed(&pod, …)` calls

Append:

```rust
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
            let deleted =
                processor::process_member(w, BOB_INBOX, BOB_OUTBOX, &delete, "2026-08-26T12:00:01Z");
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
```

**`src/follows.rs` tests module.** `store()` returns
`(tempfile::TempDir, std::sync::Arc<Pod>)`, and the module adds
`use brolly_store::resources::Pod;`. Then:
- **Writes at `:193, 201, 202, 209, 222, 223, 236, 237`.** `record(&store, A,
  B).expect(m)` becomes `store.write(|w| record(w, A, B)).expect(m)`, and the
  same for `record_following`.
- **`:225`** becomes `store.write(|w| remove(w, BOB, ALICE)).expect("remove");`.
- **R2 at `:194, 203, 211, 213, 216, 227, 228, 239, 240`.**
  `followers|following(&store, …)` becomes `(&store.read_store(), …)`.

- [ ] **Step 3: Run them and watch them fail**

Run: `cargo test -p brolly-activitypub`
Expected: FAIL to compile. The errors are `error[E0425]: cannot find function
`process_member` in module `processor``, and `error[E0308]: mismatched types …
expected `&Store`, found `&mut PodWrite<'_>`` at `inbox::deliver(w, …)` and
`record(w, …)`.

- [ ] **Step 4: `inbox.rs`**

Replace `:14-18` (imports) and `:61-65`:

```rust
use brolly_domain::faithful;
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::Value;
```

```rust
impl From<StoreError> for InboxError {
    fn from(e: StoreError) -> Self {
        InboxError::Store(e.to_string())
    }
}
```

Replace `deliver` through `remove` (`:77-177`):

```rust
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
```

- [ ] **Step 5: `follows.rs`**

Replace `:14-16`:

```rust
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
```

Add a sentence to the module doc, after its last paragraph: "`#social` is
protocol state outside the storage root, so it is written with `PodWrite`'s
outside-root methods."

Then apply these to `:41-174`. The doc comments stay:
- **`record`, `record_following`, `record_request`.** Signature `(w: &mut
  PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError>`.
  The body is `w.insert(&[Quad::new(...)])`, with the same quad as today, and
  no `?; Ok(())` tail.
- **`pending`, `followers`, `following`, `objects`.** The first parameter
  becomes `store: &impl PodRead`.
- **`approve` and `reject`.** Same signature as `record`. Their bodies are
  `drop_request(w, follower, followee)?; record(w, follower, followee)` and
  `drop_request(w, follower, followee)`.
- **`drop_request`:**

```rust
fn drop_request(w: &mut PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError> {
    let graph = graph_for(followee);
    w.remove_quads(&[Quad::new(
        NamedOrBlankNode::NamedNode(iri(followee)),
        iri(PENDING),
        Term::NamedNode(iri(follower)),
        GraphName::NamedNode(graph),
    )])
}
```

- **`remove`:**

```rust
/// Undo a follow.
pub fn remove(w: &mut PodWrite<'_>, follower: &str, followee: &str) -> Result<(), StoreError> {
    w.remove_quads(&[
        Quad::new(
            NamedOrBlankNode::NamedNode(iri(followee)),
            iri(AS_FOLLOWERS),
            Term::NamedNode(iri(follower)),
            GraphName::NamedNode(graph_for(followee)),
        ),
        Quad::new(
            NamedOrBlankNode::NamedNode(iri(follower)),
            iri(AS_FOLLOWING),
            Term::NamedNode(iri(followee)),
            GraphName::NamedNode(graph_for(follower)),
        ),
    ])
}
```

- [ ] **Step 6: `processor.rs`**

Replace `:21-26`:

```rust
use brolly_store::index::{self, NotePointer};
use brolly_store::resources::{PodRead, PodWrite};
use brolly_store::{InstanceStore, StoreError};
use oxigraph::model::NamedNode;
use serde_json::Value;

use crate::inbox::{self, InboxError};
```

Delete `Recipient` (`:32-40`) and `impl From<brolly_store::write::WriteError>
for ProcessError` (`:78-82`). Replace `process`, `process_for_member`,
`carriers`, `process_for_instance` and `index_note` (`:84-247`). The comment
bodies marked "unchanged" are copied verbatim from `:117-124`, `:167-169`,
`:175-183`, `:193-197`, `:205-206` and `:212-213`, `:222-223`:

```rust
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
        // (unchanged comment, :117-124)
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
    match activity["type"].as_str() {
        // (unchanged comment, :167-169)
        Some("Create") => match object_id(activity) {
            Some(note) if same_origin(note, actor) => index_note(instance, activity),
            _ => Ok(()),
        },
        // (unchanged comment, :175-183)
        Some("Announce") => {
            if let Some(note) = object_id(activity)
                && index::is_indexed(instance, &NamedNode::new_unchecked(note))?
            {
                index_note(instance, activity)?;
            }
            Ok(())
        }
        Some("Delete") => {
            // (unchanged comment, :193-197)
            if let Some(target) = object_id(activity)
                && same_origin(target, actor)
            {
                index::forget_note(instance, &NamedNode::new_unchecked(target))?;
            }
            Ok(())
        }
        // (unchanged comment, :205-206)
        _ => Ok(()),
    }
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

fn index_note(instance: &InstanceStore, activity: &Value) -> Result<(), ProcessError> {
    // (unchanged body of :212-246, with `index::record_note(instance, …)`
    // in place of `index::record_note(store, …)`)
}
```

Write out `index_note`'s body in full from `:212-246`. The only change is the
first argument of `index::record_note`. The module doc's table, and the
`owning_actor`, `same_origin`, `addressed_publicly` and `mentions_public`
functions and unit tests, don't change. `ProcessError` keeps
`From<InboxError>` and `From<StoreError>`.

- [ ] **Step 7: Run them and watch them pass**

Run: `cargo test -p brolly-activitypub`
Expected: PASS. That's every test in `tests/inbox.rs` and `tests/processor.rs`,
including `a_reader_inside_a_write_sees_that_writes_own_changes`, and the
`follows` and `processor` unit tests.

- [ ] **Step 8: Format**

Run: `cargo fmt --all`

- [ ] **Step 9: The crate's gates**

Run: `cargo clippy -p brolly-activitypub --all-targets -- -D warnings && cargo test -p brolly-activitypub`
Expected: clean.

- [ ] **Step 10: Stage, don't commit**

```bash
git add adapters/activitypub/Cargo.toml adapters/activitypub/src/inbox.rs \
        adapters/activitypub/src/follows.rs adapters/activitypub/src/processor.rs \
        adapters/activitypub/tests/inbox.rs adapters/activitypub/tests/processor.rs
```

---
### Task 5: The ATProto ingest and the Mastodon home timeline

`ingest::ingest` writes an `at://` graph and canonical triples into the profile
document. Both are outside the root, so it uses `w.insert` (R5).
`ingest::read` and `timeline::home` are readers (R1).

**Files:**
- Modify: `adapters/atproto/src/ingest.rs:20-24`, `:26-57`, `:88-118`, and the tests module `:120-317`
- Modify: `adapters/mastodon/src/timeline.rs:19-20`, `:53`
- Modify: `adapters/mastodon/tests/timeline.rs:18`, `:23-27`, `:52-54`, and the `timeline::home` sites

| Site | Before | After | Rule |
|---|---|---|---|
| `ingest.rs:32` `IngestError::Store` | `Store(WriteError)` | `Store(StoreError)` | R4 |
| `ingest.rs:53-57` | `From<WriteError>` | `From<StoreError>` | R4 |
| `ingest.rs:88` `ingest` | `&Store`, `insert_quads` | `&mut PodWrite`, `w.insert`, returns `quads.len()` | R4, R5 |
| `ingest.rs:116` `read` | `&Store` | `&impl PodRead` | R1 |
| `timeline.rs:53` `home` | `&Store` | `&impl PodRead` | R1 |
| ingest unit tests: `ingest(&store, R, U, WEBID, PROFILE)` at `:148, 162, 170, 207, 219, 235, 257, 297, 305` | | `put(&store, R, U)` | R6 |
| ingest unit tests: `read(&store, …)` at `:150, 179, 180, 208, 314, 315`; `literal_in(&store, …)` at `:241`, `:268` | | `&store.read_store()` | R2 |
| `mastodon/tests/timeline.rs` `timeline::home(&store, …)` at `:77, 100, 116, 136, 181, 200, 204, 215, 234` | | `timeline::home(&store.read_store(), …)` | R2 |

The `deliver(&store, …)` calls in `mastodon/tests/timeline.rs` (`:66, 71, 94,
110, 129, 149, 154, 164, 193, 223`) are unchanged, because only the helper
changes. The Mastodon crate still has no write path of its own: its tests
write through `brolly-activitypub`, a dev-dependency.

- [ ] **Step 1: Move the tests**

In `adapters/atproto/src/ingest.rs`'s tests module, replace `store()`
(`:129-134`), adding `use brolly_store::resources::Pod;` after
`use serde_json::json;`:

```rust
    fn store() -> (tempfile::TempDir, std::sync::Arc<Pod>) {
        let dir = tempfile::tempdir().unwrap();
        let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
        let store = manager.pod(uuid::Uuid::new_v4()).unwrap();
        (dir, store)
    }

    /// Ingest in one write, as `xrpc.rs` does.
    fn put(store: &Pod, record: &Value, uri: &str) -> Result<usize, IngestError> {
        store
            .write(|w| Ok(ingest(w, record, uri, WEBID, PROFILE)))
            .map_err(IngestError::from)
            .flatten()
    }
```

Then apply the table's two test rows. For example, `:148` becomes
`let written = put(&store, &record, &uri).expect("ingest");`, and `:219`
becomes `put(&store, &json!({"text": "orphan"}), &uri),` inside the
`matches!`.

In `adapters/mastodon/tests/timeline.rs`, replace `:18` and `:23-27`, and
`deliver` (`:52-54`):

```rust
use brolly_store::resources::Pod;
```

```rust
fn store() -> (tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = manager.pod(uuid::Uuid::new_v4()).unwrap();
    (dir, store)
}
```

```rust
fn deliver(store: &Pod, activity: &Value, at: &str) {
    store
        .write(|w| Ok(brolly_activitypub::inbox::deliver(w, ALICE_INBOX, activity, at)))
        .expect("write")
        .expect("deliver");
}
```

Then apply the R2 row to the nine `timeline::home` sites.

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-atproto --lib ingest && cargo test -p brolly-mastodon --test timeline`
Expected: FAIL to compile. `ingest(w, …)` gives `error[E0308]: mismatched types
… expected `&Store`, found `&mut PodWrite<'_>``, and `timeline::home(&store.read_store(), …)`
gives the same mismatch the other way.

- [ ] **Step 3: `ingest.rs`**

Replace `:20-24`, and change `IngestError::Store`'s field and the second
`From` impl:

```rust
use brolly_domain::{canonical, faithful};
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::NamedNode;
use serde_json::Value;
```

```rust
    Store(StoreError),
```

```rust
impl From<StoreError> for IngestError {
    fn from(e: StoreError) -> Self {
        IngestError::Store(e)
    }
}
```

Replace `ingest`'s signature and last line, and `read`. The doc comments and
the middle of `ingest` don't change:

```rust
pub fn ingest(
    w: &mut PodWrite<'_>,
    record: &Value,
    at_uri: &str,
    webid: &str,
    profile_document: &str,
) -> Result<usize, IngestError> {
```

```rust
    // Both graphs are protocol state outside the storage root: the record's
    // `at://` graph and the profile document.
    w.insert(&quads)?;
    Ok(quads.len())
}

/// Read a record back out of the pod, as the wire format it arrived in.
pub fn read(store: &impl PodRead, at_uri: &str) -> Option<Value> {
    brolly_store::collection::read_record(store, at_uri)
}
```

- [ ] **Step 4: `timeline.rs`**

Replace `:19-20`, and apply R1 to `home` at `:53`:

```rust
use brolly_store::collection;
use brolly_store::resources::PodRead;
use serde_json::Value;
```

```rust
pub fn home(store: &impl PodRead, inbox: &str, limit: usize, before: Option<&str>) -> Vec<Row> {
```

- [ ] **Step 5: Run them and watch them pass**

Run: `cargo test -p brolly-atproto && cargo test -p brolly-mastodon`
Expected: PASS. The Postgres-backed tests need Docker, as today.

- [ ] **Step 6: Format**

Run: `cargo fmt --all`

- [ ] **Step 7: The crates' gates**

Run: `cargo clippy -p brolly-atproto -p brolly-mastodon --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 8: Stage, don't commit**

```bash
git add adapters/atproto/src/ingest.rs adapters/mastodon/src/timeline.rs \
        adapters/mastodon/tests/timeline.rs
```

---
### Task 6: The server

Each handler takes the pod, reads through `read_store()`, and writes in one
`Pod::write` whose closure has no `.await` (R7). Three spots needed care:
- **`outbox::deliver`** stores the author's copy, and a Follow's bookkeeping,
  in one write. That write closes before the recipient loop's awaits. Each
  recipient then gets its own writes in `deliver_locally`.
- **`upload_media`** writes after its multipart awaits have finished, as
  today.
- **`follow_requests` and `deliver`** bind their reads before a loop that
  awaits.

**Files:**
- Modify: `server/Cargo.toml` (`[dev-dependencies]` `brolly-store` line)
- Modify: `server/src/pod.rs:15-31`, `:61-67`, `:79-86`, `:262-263`, `:307-308`, `:339-340`, `:372`, `:383-390`, `:429-430`; add `patch_in`
- Modify: `server/src/outbox.rs:18-19`, `:268-331`, `:333-356`, `:397-447`
- Modify: `server/src/mastodon_api.rs:15-27`, `:86-90`, `:309`, `:320`, `:389`, `:420`, `:546`, `:562-578`, `:621-636`, `:663-673`, `:742-756`, `:871-899`, `:913-924`, `:955-963`
- Modify: `server/src/profile.rs:100`, `:103-104`, `:119-126`
- Modify: `server/src/xrpc.rs:505-517`
- Modify: `server/src/activitypub.rs:103-107`, `:248`, `:252`, `:299`
- Modify: `server/src/account.rs:11-25`, `:178`, `:211-231`, `:438-441`
- Modify: `server/src/provision.rs:12-18`, `:35-70`
- Modify: `server/src/maintenance.rs:46-51`
- Modify: `server/tests/{activitypub_discovery,admin_cli,architecture,dashboard,federation_flows,harmonization,maintenance,mastodon_compose,mastodon_profile_flags,pod_http,solid_token_access,xrpc}.rs`

**Test sites:**

| File | Lines | Before | After | Rule |
|---|---|---|---|---|
| `activitypub_discovery.rs` | 44 | `storage::init_storage_root(&pod, ALICE_ROOT).unwrap();` | `pod.write(\|w\| storage::init_storage_root(w, ALICE_ROOT)).unwrap();` | R6 |
| `activitypub_discovery.rs` | 198-208 | `brolly_solid::profile::write(&pod, A, B, &P).unwrap();` | `pod.write(\|w\| brolly_solid::profile::write(w, A, B, &P)).unwrap();` | R6 |
| `admin_cli.rs` | 46 | `storage::add_containment(&pod, &acl, &root).unwrap();` | `pod.write(\|w\| storage::add_containment(w, &acl, &root)).unwrap();` | R6 |
| `admin_cli.rs` | 59, 60 | `storage::members(&pod, …)`, `storage::exists(&pod, …)` | `(&pod.read_store(), …)` | R2 |
| `dashboard.rs` | 49 | `storage::init_storage_root(&pod, ROOT).unwrap();` | `pod.write(\|w\| storage::init_storage_root(w, ROOT)).unwrap();` | R6 |
| `dashboard.rs` | 248-249 | `pod\n.quads_for_pattern(` | `pod\n.read_store()\n.quads_for_pattern(`; add `use brolly_store::resources::PodRead;` | R2 |
| `federation_flows.rs` | 11 | `processor::{self, ProcessError, Recipient}` | `processor::{self, ProcessError}`; add `use brolly_store::resources::PodRead;` | |
| `federation_flows.rs` | 153 | `-> std::sync::Arc<brolly_store::Store>` | `-> std::sync::Arc<brolly_store::resources::Pod>` | |
| `federation_flows.rs` | 164-165 | `self.pod(username)\n.quads_for_pattern(` | `self.pod(username)\n.read_store()\n.quads_for_pattern(` | R2 |
| `federation_flows.rs` | 234, 239, 245, 284, 287, 317, 349, 382, 423, 427, 579, 653, 654, 656, 671, 675, 679, 683, 687, 823, 893, 973, 974, 975, 976, 1007, 1009, 1052, 1140, 1161, 1193, 1197, 1229 | `inbox::…(&h.pod(X), …)`, `follows::…(&h.pod(X), …)` | `(&h.pod(X).read_store(), …)` | R2 |
| `federation_flows.rs` | 540-545 | `follows::record(&h.pod("alice"), C, &actor("alice")).unwrap();` | `h.pod("alice").write(\|w\| follows::record(w, C, &actor("alice"))).unwrap();` | R6 |
| `federation_flows.rs` | 1057-1065 | `processor::process(&h.pod("alice"), Recipient::Member {…}, &attack, T)` | code below | R6 |
| `harmonization.rs` | 106-117, 177-188 | `brolly_atproto::ingest::ingest(&pod, R, U, W, D).expect(m);` | `pod.write(\|w\| Ok(brolly_atproto::ingest::ingest(w, R, U, W, D))).unwrap().expect(m);` | R6 |
| `harmonization.rs` | 136-146, 165-174 | `brolly_solid::profile::write(&pod, …).unwrap();` | `pod.write(\|w\| brolly_solid::profile::write(w, …)).unwrap();` | R6 |
| `harmonization.rs` | 196-197 | `brolly_atproto::ingest::read(&pod, …)` | `brolly_atproto::ingest::read(&pod.read_store(), …)` | R2 |
| `maintenance.rs` | 29 | `storage::add_containment(&pod, &format!("{root}.acl"), &root).unwrap();` | `pod.write(\|w\| storage::add_containment(w, &format!("{root}.acl"), &root)).unwrap();` | R6 |
| `maintenance.rs` | 58, 60 | `storage::members(&pod, …)`, `storage::exists(&pod, …)` | `(&pod.read_store(), …)` | R2 |
| `mastodon_compose.rs` | 362-367 | `brolly_activitypub::follows::record(&alice_pod, B, A).unwrap();` | `alice_pod.write(\|w\| brolly_activitypub::follows::record(w, B, A)).unwrap();` | R6 |
| `mastodon_compose.rs` | 379 | `collection::members(&bob_pod, &bob_inbox)` | `collection::members(&bob_pod.read_store(), &bob_inbox)` | R2 |
| `mastodon_profile_flags.rs` | 359, 362, 387, 391, 440, 445, 480, 481, 504 | `follows::{followers,pending}(&alice_pod, …)` | `(&alice_pod.read_store(), …)` | R2 |
| `pod_http.rs` | 9 | `use brolly_store::{StoreManager, insert_quads};` | `use brolly_store::StoreManager;` and `use brolly_store::resources::{Pod, PodRead};` | |
| `pod_http.rs` | 58 | `storage::init_storage_root(&pod, ROOT).unwrap();` | `pod.write(\|w\| storage::init_storage_root(w, ROOT)).unwrap();` | R6 |
| `pod_http.rs` | 61, 753 | `insert_quads(&pod, &[…]).unwrap();` | `seed(&pod, &[…]);` | R8 |
| `pod_http.rs` | 509-519 | `brolly_solid::profile::write(&pod, …).unwrap();` | `pod.write(\|w\| brolly_solid::profile::write(w, …)).unwrap();` | R6 |
| `pod_http.rs` | 796-804 | `pod\n.contains(&t(…))\n.unwrap()` | `holds(&pod, &t(…))` | R2 |
| `pod_http.rs` | 834-841 | `pod.contains(&t(…)).unwrap()` in `control` | `holds(&pod, &t(…))` | R2 |
| `pod_http.rs` | 861 | `storage::exists(&pod, …)` | `storage::exists(&pod.read_store(), …)` | R2 |
| `solid_token_access.rs` | 19 | `use brolly_store::{StoreManager, insert_quads};` | `use brolly_store::StoreManager;` and `use brolly_store::resources::Pod;` | |
| `solid_token_access.rs` | 65 | `storage::init_storage_root(&pod, ROOT).unwrap();` | `pod.write(\|w\| storage::init_storage_root(w, ROOT)).unwrap();` | R6 |
| `solid_token_access.rs` | 68 | `insert_quads(&pod, &[…]).unwrap();` | `seed(&pod, &[…]);` | R8 |
| `xrpc.rs` | 239, 263, 290 | `brolly_atproto::ingest::read(&pod, &uri)` | `brolly_atproto::ingest::read(&pod.read_store(), &uri)` | R2 |
| `architecture.rs` | 236-259 | `MUTATORS: [&str; 11]` | `[&str; 14]`, adding `.write(\|`, `legacy_under_root` and `raw_store` (code below) | |

Unchanged: every `brolly_server::provision::pod(&pod, …)` call (R9), every
`ldp::put(&pod, …)` call, and every `index::…(h.stores.instance(), …)` call.

- [ ] **Step 1: Enable the fixtures for the server's tests**

In `server/Cargo.toml` `[dev-dependencies]`, replace `brolly-store.workspace = true` with:

```toml
brolly-store = { workspace = true, features = ["test-fixtures"] }
```

- [ ] **Step 2: Move the harnesses onto `Pod`**

Apply the test-site table. `pod_http.rs` and `solid_token_access.rs` each get
the R8 `seed` helper. `pod_http.rs` also gets:

```rust
/// Does the pod hold exactly this quad?
fn holds(pod: &Pod, quad: &Quad) -> bool {
    pod.read_store()
        .quads_for_pattern(
            Some(quad.subject.as_ref()),
            Some(quad.predicate.as_ref()),
            Some(quad.object.as_ref()),
            Some(quad.graph_name.as_ref()),
        )
        .next()
        .is_some()
}
```

`pod_http.rs:796-804` becomes:

```rust
    let pod = h.stores.pod(h.user).unwrap();
    let granted = holds(
        &pod,
        &t(
            &format!("{ROOT}shared/.acl"),
            &bob_auth,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ),
    );
    assert!(!granted, "the refused PATCH must not have landed");
```

`pod_http.rs:834-841` becomes:

```rust
    let control = |auth: &str| {
        holds(
            &pod,
            &t(&g, auth, &format!("{ACL}mode"), &format!("{ACL}Control")),
        )
    };
```

`federation_flows.rs:1057-1065` becomes:

```rust
    // ...and so does the processor, for the day it arrives from another server.
    let processed = h
        .pod("alice")
        .write(|w| {
            Ok(processor::process_member(
                w,
                &inbox_of("alice"),
                &outbox_of("alice"),
                &attack,
                "2026-09-17T12:00:00Z",
            ))
        })
        .unwrap();
```

In `architecture.rs`, `the_mastodon_crate_never_writes_to_a_store`'s doc and
list (`:236-259`) become:

```rust
/// A pure lint rather than a type-level guarantee. Writes need a `PodWrite`,
/// which only `Pod::write` hands out, so a `.write(|` call is what to look
/// for, alongside the index writers and raw oxigraph calls.
#[test]
fn the_mastodon_crate_never_writes_to_a_store() {
    /// Every mutation entry point in `brolly-store`, plus the raw oxigraph
    /// calls that would bypass it. Kept in sync by hand — but a *new* store
    /// mutator that this list misses is a `brolly-store` review question, and
    /// `store::write`'s own docs say there is exactly one insert.
    const MUTATORS: [&str; 14] = [
        // brolly-store's write path.
        "insert_quads",
        "insert_record",
        "replace_graph",
        "record_note",
        "forget_note",
        "index::clear",
        // The pod handle's only way in, and its escape hatches.
        ".write(|",
        "legacy_under_root",
        "raw_store",
        // Raw oxigraph, which would sidestep canonicalization entirely.
        ".insert(",
        ".remove(",
        "clear_graph",
        ".transaction(",
        "bulk_loader",
    ];
```

Keep the paragraph above the `/// A pure lint` line, from "Mastodon is a
**projection**" to "Postgres with a backfill job…". Only the last paragraph
changes.

- [ ] **Step 3: Run them and watch them fail**

Run: `cargo test -p brolly-server --no-run`
Expected: FAIL to compile, in `server/src` first:
- `error[E0308]: mismatched types … expected `&Store`, found `&Pod`` at
  `pod.rs:61-67`'s `PodRequest { store, .. }`
- `error[E0425]: cannot find function `process``, and `error[E0432]: unresolved
  import … `Recipient``, in `outbox.rs`

- [ ] **Step 4: `pod.rs`**

**Source sites:**

| Site | Before | After |
|---|---|---|
| `:26` `PodRequest::store` | `pub store: Arc<brolly_store::Store>` | `pub pod: Arc<Pod>` |
| `:61-67`, `:84` | `let store = …`, `store,` | `let pod = …`, `pod,` |
| `:263`, `:308`, `:340`, `:430` | `&request.store` | `&request.pod` (R9) |
| `:372` | `ldp::may_write(&request.store, …)` | `ldp::may_write(&request.pod.read_store(), …)` (R2) |
| `:384`, `:386` | `patch::apply_*(&request.store, …)` | `patch_in(&request.pod, \|w\| patch::apply_*(w, …))` (R6) |

Add `use brolly_store::resources::{Pod, PodWrite};` after `:17`. Replace
`:24-26` and `:61-67`:

```rust
    pub user: User,
    pub subject: Subject,
    pub pod: Arc<Pod>,
```

```rust
    let pod = match state.stores.pod(user.id) {
        Ok(pod) => pod,
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "pod store unavailable");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };
```

`:84` becomes `pod,`. Replace `:371-398`:

```rust
    // A patch mutates, so it needs Write.
    match ldp::may_write(
        &request.pod.read_store(),
        &request.base,
        &path,
        &request.subject,
    ) {
        Ok(true) => {}
        Ok(false) => return ldp_error(LdpError::Forbidden),
        Err(e) => return ldp_error(e),
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let result = match content_type.split(';').next().unwrap_or_default().trim() {
        "text/n3" => patch_in(&request.pod, |w| {
            patch::apply_n3_patch(w, &resource, &body)
        }),
        "application/sparql-update" => match std::str::from_utf8(&body) {
            Ok(sparql) => patch_in(&request.pod, |w| {
                patch::apply_sparql_update(w, &resource, sparql)
            }),
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "body is not UTF-8").into_response();
            }
        },
        other => {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("PATCH accepts text/n3 or application/sparql-update, not {other}"),
            )
                .into_response();
        }
    };
```

Add after `patch`:

```rust
/// Apply a patch in one `Pod::write`.
///
/// A refused patch comes back inside `Ok`, so the transaction commits, but
/// every refusal happens before the patch writes anything.
fn patch_in(
    pod: &Pod,
    apply: impl FnOnce(&mut PodWrite<'_>) -> Result<(), patch::PatchError>,
) -> Result<(), patch::PatchError> {
    pod.write(|w| Ok(apply(w)))
        .map_err(|e| patch::PatchError::Store(e.to_string()))
        .flatten()
}
```

- [ ] **Step 5: `outbox.rs`**

Replace `:19`, and add the `PodRead` import:

```rust
use brolly_activitypub::processor::{self, ProcessError};
use brolly_store::resources::PodRead;
```

Replace `deliver`'s body from `let received = now();` (`:268`) to the end
(`:331`):

```rust
    let received = now();
    let Ok(author_pod) = state.stores.pod(author.id) else {
        return Err(DeliverError::Failed);
    };
    let author_inbox = webid::inbox(&author.username, &state.base_domain);
    let author_outbox = webid::outbox(&author.username, &state.base_domain);

    // The author's copy, and a Follow's bookkeeping, in one write. It closes
    // before the recipient loop awaits anything: the write holds the pod's
    // lock, and every other writer to this pod waits on it.
    let stored = author_pod.write(|w| {
        // The author holds their own post — content lives in exactly one place
        // (D2) and this is it. A Delete removes rather than stores.
        if activity["type"] == "Delete" {
            if let Err(e) =
                processor::process_member(w, &author_inbox, &author_outbox, activity, &received)
            {
                tracing::error!(error = %e, "removing the author's copy failed");
                return Ok(false);
            }
        } else if let Err(e) =
            brolly_activitypub::inbox::deliver(w, &author_outbox, activity, &received)
        {
            tracing::error!(error = %e, "storing the author's copy failed");
            return Ok(false);
        }

        // A Follow is also a relationship, not only a notification.
        if activity["type"] == "Follow"
            && let Some(target) = activity["object"].as_str()
        {
            let _ = follows::record_following(w, actor, target);
        }
        Ok(true)
    });
    match stored {
        Ok(true) => {}
        Ok(false) => return Err(DeliverError::Failed),
        Err(e) => {
            tracing::error!(error = %e, "storing the author's copy failed");
            return Err(DeliverError::Failed);
        }
    }

    // Bound before the loop, so no read of the pod is held across its awaits.
    let inboxes = recipients(state, &author_pod.read_store(), actor, activity);
    for inbox in inboxes {
        let Ok(url) = url::Url::parse(&inbox) else {
            continue;
        };
        // D12: the switch runs on every delivery, local or not.
        if !brolly_activitypub::should_deliver(&url, &state.base_domain) {
            tracing::debug!(%inbox, "remote delivery suppressed; federation is off");
            continue;
        }
        deliver_locally(state, &inbox, actor, activity, &received).await;
    }

    // The instance is a recipient like any other (D4), and its processor writes
    // the pointer row. This is the only way anything reaches the public index.
    match processor::process_instance(state.stores.instance(), activity) {
        Ok(()) => {}
        Err(e @ ProcessError::ForeignObject) => tracing::warn!(error = %e, "indexing refused"),
        Err(e) => tracing::error!(error = %e, "indexing failed"),
    }

    Ok(())
}
```

`recipients` (`:334-343`): the second parameter becomes
`author_pod: &impl PodRead`, and the body doesn't change.

Replace `deliver_locally` from `let Ok(pod) = …` (`:397`) to the end
(`:447`):

```rust
    let Ok(pod) = state.stores.pod(user.id) else {
        return;
    };

    // A Follow arriving establishes the relationship in the recipient's pod,
    // which is what delivery reads to resolve recipients next time — *unless*
    // the account is locked, in which case it waits for approval instead.
    //
    // This is the whole of what "locked" means, and the predecessor recorded
    // the follow unconditionally, so the flag did nothing. It did nothing
    // invisibly, too: the profile still rendered the lock.
    //
    // FEDERATION: this writes before `processor::process_member` applies its
    // origin check (stage 0, A1). That is only safe while every activity here
    // came through `outbox::deliver` with an actor the server set. Revisit when
    // federation is enabled (ADR 0016): an inbound Follow's `actor` must be
    // verified before it is recorded as a follower.
    if activity["type"] == "Follow"
        && let Some(target) = activity["object"].as_str()
        && let Some(follower) = activity["actor"].as_str()
    {
        let webid = webid::webid(&user.username, &state.base_domain);
        let document = webid::profile_document(&user.username, &state.base_domain);
        // The lock is read in the same write that records the follow, so the
        // two can't disagree.
        let _ = pod.write(|w| {
            if brolly_solid::profile::read(&*w, &webid, &document).locked {
                follows::record_request(w, follower, target)
            } else {
                follows::record(w, follower, target)
            }
        });
    }

    // A refusal isn't a failure: the activity named a graph its actor doesn't
    // own. Delivery to every other recipient carries on either way.
    let outbox = webid::outbox(&user.username, &state.base_domain);
    match pod
        .write(|w| {
            Ok(processor::process_member(
                w, inbox, &outbox, activity, received,
            ))
        })
        .map_err(ProcessError::from)
        .flatten()
    {
        Ok(()) => {}
        Err(e @ ProcessError::ForeignObject) => {
            tracing::warn!(error = %e, %inbox, "local delivery refused");
        }
        Err(e) => tracing::error!(error = %e, %inbox, "local delivery failed"),
    }
}
```

The `// FEDERATION:` comment's function name changes from
`processor::process` to `processor::process_member`. It's otherwise
verbatim.

- [ ] **Step 6: `mastodon_api.rs`**

Add `use brolly_store::resources::{Pod, PodRead};` after `:23`.

| Site | Before | After | Rule |
|---|---|---|---|
| `:86-90` `author_for` | `profile::read(&pod, …)` | `profile::read(&pod.read_store(), …)` | R2 |
| `:136` `counts` | `count_notes(state.stores.instance())` | unchanged (`&InstanceStore`) | |
| `:309`, `:320` `home_timeline` | `timeline::home(&pod, …)` | `timeline::home(&pod.read_store(), …)` | R2 |
| `:343-347` `public_timeline` | `public_note_iris(state.stores.instance(), …)` | unchanged | |
| `:389` `fetch_note`, `:420` `status` | `collection::read_record(&pod, …)` | `collection::read_record(&pod.read_store(), …)` | R2 |
| `:530-539` `upload_media` | `ldp::put(&pod, …)` | unchanged (R9); the write follows the multipart awaits | R7 |
| `:546`, `:626` | `set_alt_text(&pod, &iri, text)` | unchanged call; new body below | |
| `:562` `set_alt_text` | `&brolly_store::Store`, `insert_quads` | `&Pod`, `legacy_under_root().insert` | R5, R6 |
| `:576` `alt_text` | `&brolly_store::Store` | `&impl PodRead` | R1 |
| `:621`, `:663`, `:742` | `ldp::blob_digest(&pod, &iri)` | `ldp::blob_digest(&pod.read_store(), &iri)` | R2 |
| `:630`, `:667`, `:749-753` | `collection::literal(&pod, …)` | `collection::literal(&pod.read_store(), …)` | R2 |
| `:636`, `:673`, `:755` | `alt_text(&pod, &iri)` | `alt_text(&pod.read_store(), &iri)` | R2 |
| `:879-899` `update_credentials` | read, then `profile::write(&pod, …)` | read and write in one `Pod::write` | R3, R6 |
| `:919` `follow_requests` | `for follower in pending(&pod, &actor) { … .await … }` | bind first, then loop | R2, R7 |
| `:955` `resolve_request` | `pending(&pod, &actor)` | `pending(&pod.read_store(), &actor)` | R2 |
| `:959-963` | `approve(&pod, …)` / `reject(&pod, …)` | one `Pod::write` | R6 |

Replace `set_alt_text` and `alt_text` (`:562-578`):

```rust
fn set_alt_text(pod: &Pod, iri: &str, text: &str) {
    use oxigraph_model::{Literal, NamedNode, NamedOrBlankNode, Quad, Term};
    let node = NamedNode::new_unchecked(iri);
    let quad = Quad::new(
        NamedOrBlankNode::NamedNode(node.clone()),
        NamedNode::new_unchecked(ALT_TEXT),
        Term::Literal(Literal::new_simple_literal(text)),
        oxigraph_model::GraphName::NamedNode(node),
    );
    // The media resource is under the storage root, so this is written the
    // way it always was until the pod keeps resource metadata.
    if let Err(e) = pod.write(|w| w.legacy_under_root().insert(&[quad])) {
        tracing::warn!(error = %e, "storing alt text failed");
    }
}

fn alt_text(pod: &impl PodRead, iri: &str) -> Option<String> {
    brolly_store::collection::literal(pod, iri, ALT_TEXT)
}
```

Replace `update_credentials`'s `:877-899`, from the "Merge onto…" comment to
the error return:

```rust
    let written = pod.write(|w| {
        // Merge onto what is stored, so an absent field is untouched rather
        // than reset. The predecessor's version of this is where `locked` went
        // to die. Read in the same write, so nothing lands in between.
        let mut profile = brolly_solid::profile::read(&*w, &id, &document);
        if let Some(name) = update.display_name {
            profile.display_name = name;
        }
        if let Some(note) = update.note {
            profile.bio = note;
        }
        if let Some(locked) = update.locked {
            profile.locked = locked;
        }
        if let Some(bot) = update.bot {
            profile.bot = bot;
        }
        if let Some(discoverable) = update.discoverable {
            profile.discoverable = discoverable;
        }
        brolly_solid::profile::write(w, &id, &document, &profile)
    });
    if let Err(e) = written {
        tracing::error!(error = %e, "profile update failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Update failed");
    }
```

In `follow_requests` (`:917-923`):

```rust
    let actor = webid::actor(&user.username, &state.base_domain);
    // Bound before the loop, so no read of the pod is held across its awaits.
    let pending = brolly_activitypub::follows::pending(&pod.read_store(), &actor);
    let mut accounts = Vec::new();
    for follower in pending {
```

In `resolve_request` (`:955-963`):

```rust
    if !brolly_activitypub::follows::pending(&pod.read_store(), &actor).contains(&follower) {
        return not_found();
    }

    let outcome = pod.write(|w| {
        if approve {
            brolly_activitypub::follows::approve(w, &follower, &actor)
        } else {
            brolly_activitypub::follows::reject(w, &follower, &actor)
        }
    });
```

- [ ] **Step 7: `profile.rs`, `xrpc.rs` and `activitypub.rs`**

In `server/src/profile.rs`:
- **`:103-104`** becomes
  `brolly_solid::profile::document(&pod.read_store(), &id.webid, &id.document, &id.storage_root, &issuer);`.
- **`html` (`:119-126`).** Its last parameter becomes
  `pod: &brolly_store::resources::Pod`, and `:126` becomes
  `let profile = brolly_solid::profile::read(&pod.read_store(), &id.webid, &id.document);`.
- **The call at `:100`** doesn't change.

In `server/src/xrpc.rs`, replace `:505-517`:

```rust
    // And into the pod, faithfully, so the other protocols can see it.
    let uri = ingest::at_uri(&did_of(&user, &state), &input.collection, &rkey);
    let webid = webid::webid(&user.username, &state.base_domain);
    let document = webid::profile_document(&user.username, &state.base_domain);
    if let Ok(pod) = state.stores.pod(user.id)
        && let Err(e) = pod
            .write(|w| Ok(ingest::ingest(w, &record, &uri, &webid, &document)))
            .map_err(ingest::IngestError::from)
            .flatten()
    {
        tracing::error!(error = %e, "faithful ingest failed after a repo write");
    }
```

In `server/src/activitypub.rs`, apply R2 in four places:
- `:104` `&pod` becomes `&pod.read_store()`
- `:248` becomes `follows::followers(&pod.read_store(), &actor)`
- `:252` becomes `follows::following(&pod.read_store(), &actor)`
- `:299` becomes `brolly_store::collection::members(&pod.read_store(), &inbox)`

- [ ] **Step 8: `account.rs`, `provision.rs` and `maintenance.rs`**

In `server/src/account.rs`:
- **Imports.** Add `use brolly_store::resources::PodRead;`.
- **`:178`** becomes `let current = profile::read(&pod.read_store(), &id, &document);`.
- **`:211-231`.** Replace from the "Read before writing" comment to the end of
  the `match` with:

```rust
    // Read before writing, in the same write, so this form edits only the two
    // fields it owns. `profile::write` replaces every predicate it manages, so
    // passing defaults for the flags would silently unlock a locked account
    // from a page that never mentions locking.
    let written = pod.write(|w| {
        let existing = profile::read(&*w, &id, &document);
        profile::write(
            w,
            &id,
            &document,
            &Profile {
                display_name: form.display_name,
                bio: form.bio,
                ..existing
            },
        )
    });
    match written {
        Ok(()) => Redirect::to("/account/profile?saved=true").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "profile write failed");
            server_error()
        }
    }
```

- **`:438-441`**, in the export, becomes:

```rust
    // Every graph in the pod, through a read of the committed store.
    let quads: Vec<_> = pod
        .read_store()
        .quads_for_pattern(None, None, None, None)
        .filter_map(Result::ok)
        .collect();
```

In `server/src/provision.rs`, replace `:14-18` and `pod` (`:35-70`):

```rust
use brolly_solid::storage;
use brolly_store::StoreError;
use brolly_store::resources::Pod;
use oxigraph_model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use sqlx::PgPool;
use uuid::Uuid;
```

```rust
/// Create a member's storage root and the ACL that makes it theirs.
///
/// The grant carries **both** `acl:accessTo` and `acl:default`: the first
/// governs the container itself, the second governs everything inside it. They
/// are distinct scopes, and conflating them is how an ACL silently grants more
/// or less than intended.
pub fn pod(pod: &Pod, username: &str, base_domain: &str) -> Result<(), StoreError> {
    let root = routing::storage_root(username, base_domain);
    let acl = format!("{root}.acl");
    let owner = format!("{acl}#owner");
    let member = webid::webid(username, base_domain);
    let grant = [
        triple(&acl, &owner, &format!("{ACL}accessTo"), &root),
        triple(&acl, &owner, &format!("{ACL}default"), &root),
        triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        triple(
            &acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ),
        triple(&acl, &owner, &format!("{ACL}agent"), &member),
    ];

    // The root and its ACL in one write, so a pod never has a root its owner
    // can't write to. Both are under the storage root and are written the way
    // they always were until the pod keeps resource metadata.
    pod.write(|w| {
        storage::init_storage_root(w, &root)?;
        w.legacy_under_root().insert(&grant)
    })
}
```

In `server/src/maintenance.rs`, `:49-51` becomes:

```rust
                .and_then(|pod| {
                    pod.write(brolly_solid::storage::uncontain_acls)
                        .map_err(|e| e.to_string())
                });
```

- [ ] **Step 9: Run them and watch them pass**

Run: `cargo test -p brolly-server`
Expected: PASS. That's every test, including `architecture`, `federation_flows`,
`pod_http`, `admin_cli` and `maintenance`, and the Docker-backed ones.

- [ ] **Step 10: Format**

Run: `cargo fmt --all`

- [ ] **Step 11: The crate's gates**

Run: `cargo clippy -p brolly-server --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 12: Stage, don't commit**

```bash
git add server/Cargo.toml \
        server/src/pod.rs server/src/outbox.rs server/src/mastodon_api.rs \
        server/src/profile.rs server/src/xrpc.rs server/src/activitypub.rs \
        server/src/account.rs server/src/provision.rs server/src/maintenance.rs \
        server/tests/activitypub_discovery.rs server/tests/admin_cli.rs \
        server/tests/architecture.rs server/tests/dashboard.rs \
        server/tests/federation_flows.rs server/tests/harmonization.rs \
        server/tests/maintenance.rs server/tests/mastodon_compose.rs \
        server/tests/mastodon_profile_flags.rs server/tests/pod_http.rs \
        server/tests/solid_token_access.rs server/tests/xrpc.rs
```

---
### Task 7: The workspace gates, then commit 1

**Files:** none new. This task commits chunk 1's staged files and Tasks 1–6.

- [ ] **Step 1: Nothing reaches a pod the old way**

```bash
grep -rn 'brolly_store::Store\b\|oxigraph::store::Store\|insert_quads\|insert_record\|write::replace_graph' \
  --include='*.rs' authz adapters server identity | grep -v '^adapters/solid/src/patch.rs'
grep -rn 'Recipient' --include='*.rs' adapters server
grep -rn 'raw_store' --include='*.rs' authz/src adapters/*/src server/src identity/src
```

Expected: no output. `patch.rs` keeps `oxigraph::store::Store` for its scratch
store only. `store/src` isn't searched, because only `store` may name the raw
write path.

- [ ] **Step 2: No `.await` inside a write**

```bash
grep -rn -A25 '\.write(|' --include='*.rs' server/src | grep '\.await'
```

Expected: no output.

- [ ] **Step 3: Format**

Run: `cargo fmt --all`

- [ ] **Step 4: The gates**

```bash
cargo fmt --all -- --check \
  && cargo clippy --workspace --all-targets -- -D warnings \
  && cargo test --workspace \
  && cargo deny check
```

Expected: all green. `cargo deny check` runs because four `Cargo.toml`s gained
a dev-dependency feature. Chunk 1's `store/Cargo.toml` gained a feature too. No
new crate enters the lock.

- [ ] **Step 5: Commit**

Chunk 1's files are already staged. Check that nothing is left unstaged, then
commit:

```bash
git status --short          # every changed file shows in the first column
git commit -m "refactor(store): every pod read and write goes through the pod handle

StoreManager hands out a Pod instead of a bare Store, and a Pod doesn't
deref to one. A reader takes &impl PodRead, which a plain read of the
store, a snapshot and an open write all implement, so WAC, the
collection readers, the processor's carrier check and profile::read work
the same inside a write as outside one. The only way to change a pod is
Pod::write: a synchronous closure, run under the pod's lock in one
transaction, so no handler can hold it across an .await.

Protocol graphs outside the storage root (the profile, #social, the
inbox and outbox collections, at:// records) go through PodWrite's
outside-root methods. Everything under the root still goes through a
temporary raw writer, legacy_under_root, so nothing on disk changes. The
next commit replaces that writer with resources that keep their own
metadata. store::resources, its tests and the new vocabulary land here
too.

processor::process splits into process_member, which runs inside the
member pod's write, and process_instance, which takes the InstanceStore.
The index takes the InstanceStore as well.

No behaviour change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Verify the commit from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo fmt --all -- --check && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd - && git worktree remove /tmp/verify --force
```

It has to be green there, or the commit isn't done. A clean checkout catches
files that were changed but never staged. It also catches the `test-fixtures`
feature, which unifies differently when the store crate is built from scratch.
The first compile takes several minutes, so run it in the background rather
than skipping it.

---

### Notes for the reviewer

1. **Overlap with chunk 1.** COMMON.md gives this chunk "index functions take
   `&InstanceStore`" and "store/tests". Chunk 1 owns the store crate and may do
   the same work. Task 1 is written as a reconciliation:
   - it states the signatures the crate must end with
   - it does only what's missing
   - it makes `index::record_note` return `StoreError` rather than
     `WriteError`, so no adapter names `brolly_store::write`

   Check it against chunk 1 before running either.
2. **Assumed interfaces (A1–A10).** A2, A4, A5 and A8 are the ones to confirm.
   - **A2: the method names.** `LegacyWriter::{insert, remove, replace_graph,
     clear_graph}`, and `InstanceStore::store()`, are my names. COMMON.md only
     says "raw insert/remove/replace_graph/clear_graph".
   - **A4: `LegacyWriter` must police nothing.** A recipient's copy of Bob's
     post (`https://bob…/~/notes/…`) goes through it into Alice's pod.
   - **A5: the outside-root methods must accept writes to a pod with no
     recorded root.** No pod has one in commit 1. If they return `NoRoot`
     instead, commit 1 can't write a profile, a follow or an inbox entry.
3. **`PodRead::query` has no variable bindings, so WAC changed shape.**
   `authorize` used `substitute_variable` for the target and the WebID. It now
   writes both into an `ASK`.
   - **The target** comes from `effective_acl`'s server-generated candidates,
     the same trust as the ACL graph IRI, which was already written in.
   - **The WebID** is written in only if `NamedNode::new` parses it. An
     unparseable one gets only the `acl:AuthenticatedAgent` branch, which is
     all a substituted unparseable IRI could ever match.
   - **Alternative.** Chunk 1 could add a bindings-taking query method to
     `PodRead`. That's a trait change across three implementations, so I
     didn't assume it.
   - **Pre-existing, not introduced here.** `effective_acl` already writes
     path-derived candidates into its query unescaped. A request path
     containing `>` makes the query fail to parse, which becomes a 500. That's
     worth a look in 5b.
4. **Refusals inside a write commit whatever came before them.** An adapter
   error comes back as `Ok(Err(e))`, and a store error aborts. That keeps
   today's non-transactional behaviour exactly:
   - Every refusal that exists today happens before any write.
   - The one exception is `inbox::deliver` failing to encode an embedded
     object after storing the activity, which also leaves the activity today.

   Commit 2 may prefer to roll back on any refusal. Changing `Ok(Err(e))` to
   an abort would be the place to do it.
5. **Several writes became atomic where they were separate calls.** None of
   this is test-visible, and none of it is a behaviour change on a single
   thread:
   - `provision::pod` writes the root and its ACL together.
   - `ldp::delete` removes the resource and its ACL together, so the "after
     the resource, not before" ordering comment is rewritten.
   - `update_credentials`, `profile_submit` and `deliver_locally`'s Follow
     bookkeeping each read the profile and write in one transaction.
   - `outbox::deliver` folds `record_following` into the author-copy write.
     That's equivalent, because a failed author copy returned before recording
     the follow today too.
6. **Blob release moved.** In `ldp::put`, replaced bytes are deleted after the
   write commits, and containment is now inside that write. If deleting the
   file fails, the new resource and its containment have already committed and
   the call returns an error. Today containment would have been skipped. It
   deliberately doesn't use `PodWrite::release_blob`. In commit 1 that checks
   references in metadata, where there are none yet, so it would delete bytes
   an old-layout resource still names.
7. **The WAC check stays outside the write** in `ldp::{put, append, delete}`,
   as today. Commit 2's `_in` layer moves it inside. The `&Pod` signatures are
   already the spec's final outer layer, so no caller changes then.
8. **`Recipient` is gone.** `process_instance` drops the unused `received_at`.
   The processor tests use a `member()` helper instead.
9. **Public error types changed.**
   - `IngestError::Store` holds a `StoreError`.
   - `follows::*`, `profile::write`, `storage::*` and `provision::pod` return
     `StoreError`.
   - `InboxError` and `LdpError` gain `From<StoreError>` and lose
     `From<WriteError>`.
   - `PodRequest.store` is renamed `pod`.
10. **`ReadStore` is never held across an `.await`.** `outbox::deliver`'s
    recipient list and `follow_requests`' pending list are bound before their
    loops, where a temporary in the `for` header would otherwise live through
    every await.
11. **Tests that seed through `raw_store()` will need commit 2's attention.**
    From commit 2, existence, containment and ACL governance come from
    metadata. These files seed raw quads that the metadata won't know about:
    - `conformance_matrix.rs`
    - the Solid `acl_control`, `ldp_conformance`, `ldp_nonrdf`,
      `patch_conformance` and `publication_boundary` tests
    - `processor.rs`
    - `pod_http.rs` and `solid_token_access.rs`

    The tests that call `storage::init_storage_root`, `add_containment` or
    `uncontain_acls` stop compiling in commit 2, when those go. The two new
    tests use `create_root`, `put` and the outside-root methods, so they
    survive commit 2 unchanged.
12. **The architecture lint** for the Mastodon crate gains `.write(|`,
    `legacy_under_root` and `raw_store`. The two new rules the spec asks for
    are commit 2's: nothing but `resources.rs` names `urn:brolly:resources`,
    and nothing outside `store` names `oxigraph::store::Store` in a write
    position.
13. **Account export** needed no special case. It reads every quad through
    `read_store()`, so it will include `urn:brolly:resources` once commit 2
    writes it, as the spec requires.
14. **Placeholders.** `processor.rs`'s `index_note` body and five comments are
    given as "unchanged, copy from `:NN-MM`" rather than retyped, because only
    one argument changes. `ldp::read` gives only its changed head.


## Chunk 3: The upgrade, and LDP on metadata (commit 2, part A)

Spec sections: *Upgrading existing pods*, *Reading a resource*, *Writing*,
*ACLs exist by metadata*, and their tests under *Testing*. This chunk and
chunk 4 are **rollout commit 2, one commit**. Tasks 1–5 here stage their work
and don't commit. Chunk 4's last task commits.

**Build, not green, between tasks.** After every task in this chunk the
workspace **builds** (`cargo clippy --workspace --all-targets -- -D warnings`
is clean), and the store, authz and Solid adapter tests pass. The server's
integration tests (`pod_http`, `solid_token_access`, `federation_flows`,
`mastodon_*`, `dashboard`, `activitypub_discovery`, `admin_cli`,
`maintenance`) are **expected to fail from Task 4 on** until chunk 4: their
harnesses and `provision::pod` still seed pods through `legacy_under_root`,
which records no metadata, and `inbox` and the Mastodon media reads are still
chunk 2's. Don't fix them here. Each task's gate therefore runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p brolly-store -p brolly-authz -p brolly-solid
```

and `cargo deny check` when a `Cargo.toml` changes. The full
`cargo test --workspace` is chunk 4's gate.

**What changes, in one place:**

| File | Change |
|---|---|
| `store/Cargo.toml` | `tracing`; a `[[bench]]` with `harness = false` |
| `store/src/resources.rs` | `mod upgrade;` and its re-exports; `container_triples` |
| `store/src/resources/upgrade.rs` (new) | `upgrade`, `UpgradeOutcome`, `UpgradeReport` |
| `store/src/manager.rs` | `open_pod` upgrades before the pod joins the live map |
| `store/tests/upgrade.rs` (new) | every *Upgrade* test bullet in the spec |
| `store/benches/upgrade.rs` (new) | the spec's upgrade benchmark |
| `adapters/solid/src/ldp.rs` | two layers on metadata; `Body`, `prepare`; `LdpError::{NotRdf, ContainmentChange, BlobMissing}`; `patch`/`patch_in` |
| `adapters/solid/src/patch.rs` | writes through `ldp::store_patched`; `PatchError::Ldp` |
| `adapters/solid/src/storage.rs` | path helpers, plus a fenced section chunk 4 deletes |
| `adapters/solid/tests/*.rs` | fixtures record the root and ACLs; `storage::exists`/`members` become metadata reads; the spec's Solid tests |
| `authz/src/wac.rs` | `effective_acl` picks candidates by metadata existence |
| `authz/tests/conformance_matrix.rs` | the fixture moves under `/~/` and records its ACLs |
| `server/src/pod.rs` | `NotRdf` → 415, `ContainmentChange` → 409, `BlobMissing` → 500; `delete` and `patch` call the new `ldp` functions |

### Interfaces this chunk provides

Chunk 4 (Mastodon upload) and chunk 5 (preconditions) build on these. The
names are the ones chunk 4 assumes.

```rust
// brolly_store::resources
pub fn upgrade(pod: &Pod) -> Result<UpgradeOutcome, StoreError>;
pub enum UpgradeOutcome { Fresh, Current, Upgraded(UpgradeReport), NoRoot { candidates: Vec<String> } }
pub struct UpgradeReport { pub root: String, pub resources: usize, pub dropped_containment: usize, pub not_binaries: usize }
pub fn container_triples(r: &impl PodRead, container: &str) -> Result<Vec<Quad>, StoreError>;

// brolly_solid::ldp
pub enum Body { Rdf { bytes: Vec<u8>, format: ReadFormat }, Binary(BlobMeta) }
pub enum PatchBody<'a> { N3(&'a [u8]), SparqlUpdate(&'a str) }
pub fn prepare(blobs: Option<&BlobStore>, body: &[u8], content_type: &str) -> Result<Body, LdpError>;
pub fn read(pod: &Pod, blobs: Option<&BlobStore>, base: &str, path: &str, subject: &Subject, accept: Option<&str>) -> Result<LdpOutcome, LdpError>;
pub fn read_in(r: &ResourceRead<'_>, blobs: Option<&BlobStore>, base: &str, path: &str, subject: &Subject, accept: Option<&str>) -> Result<LdpOutcome, LdpError>;
pub fn put(pod: &Pod, blobs: Option<&BlobStore>, base: &str, path: &str, subject: &Subject, body: &[u8], content_type: &str, storage_root: &str) -> Result<(), LdpError>;
pub fn put_in(w: &mut PodWrite<'_>, base: &str, path: &str, subject: &Subject, body: &Body, storage_root: &str) -> Result<(), LdpError>;
pub fn append(pod: &Pod, blobs: Option<&BlobStore>, base: &str, path: &str, subject: &Subject, body: &[u8], content_type: &str, storage_root: &str) -> Result<String, LdpError>;
pub fn append_in(w: &mut PodWrite<'_>, base: &str, path: &str, subject: &Subject, body: &Body, storage_root: &str) -> Result<String, LdpError>;
pub fn delete(pod: &Pod, base: &str, path: &str, subject: &Subject, storage_root: &str) -> Result<(), LdpError>;
pub fn delete_in(w: &mut PodWrite<'_>, base: &str, path: &str, subject: &Subject, storage_root: &str) -> Result<(), LdpError>;
pub fn patch(pod: &Pod, base: &str, path: &str, subject: &Subject, body: PatchBody<'_>, storage_root: &str) -> Result<(), PatchError>;
pub fn patch_in(w: &mut PodWrite<'_>, base: &str, path: &str, subject: &Subject, body: PatchBody<'_>, storage_root: &str) -> Result<(), PatchError>;
pub fn blob_digest(pod: &Pod, resource: &str) -> Option<String>;
pub fn may_write / granted_modes(r: &impl PodRead, …);   // unchanged from chunk 2
// LdpError gains NotRdf, ContainmentChange, BlobMissing.
```

`ldp::delete` loses chunk 2's `blobs` argument: `PodWrite::remove` releases
the blob and `Pod::write` deletes it.

### Assumed from chunks 1 and 2

From COMMON.md, used as written: `Pod::{read, read_store, write, raw_store}`,
`PodWrite::{meta, members, put, append, remove, create_root, release_blob}`,
`PodRead`, `ResourceRead`, `Content`, `BlobMeta`, `ResourceMeta`, `Kind`,
`METADATA_GRAPH`, `StoreError::{NotUnderRoot, NoRoot, ContainerNotEmpty,
BlobMissing}`, and the `vocab` constants (`LDP_CONTAINS`, `LDP_RESOURCE`,
`LDP_CONTAINER`, `LDP_BASIC_CONTAINER`, `LDP_NON_RDF_SOURCE`, `PIM_STORAGE`,
`BROLLY_AUXILIARY`, `BROLLY_LAYOUT`, `BROLLY_BLOB_DIGEST`, `BROLLY_MEDIA_TYPE`,
`BROLLY_BYTE_SIZE`). **If chunk 1 named one differently, substitute its name
and keep the structure shown here.** Not in the fixed list:

| Assumed | Why |
|---|---|
| `ResourceRead::meta(&self, &str) -> Result<Option<ResourceMeta>, StoreError>` | chunk 1 (chunk 4 assumes it too); `ldp::read_in` needs existence from the snapshot |
| `Pod` holds its pod's `BlobStore` in a private field, written `blobs` below | `Content::Binary` checks the file and `write` deletes released blobs, so chunk 1's `Pod` must have one. The upgrade (a child module of `resources`) reads it |
| a private `PodWrite` method that inserts quads into `METADATA_GRAPH`, written `insert_metadata(&mut self, &[Quad]) -> Result<(), StoreError>` below | `put` needs one. The upgrade uses it for the layout mark only |
| `PodWrite::put(r, Content::Binary(_))` leaves `r`'s content graph empty, and `append` on a binary adds to its content graph | spec *PUT of a binary* ("description triples are dropped") and chunk 4's alt text |
| `PodWrite::append` on a missing resource creates it (auxiliary for `.acl`, else an RDF document) and contains it | stage 0's POST-to-a-document, which creates |
| `Pod::write` commits only when the closure returns `Ok` | spec *Pod::write* |
| chunk 2's test helpers `seed` (raw, via `raw_store`), `n3`, `sparql`; fixtures of the shape `(StoreManager, TempDir, Arc<Pod>)` | chunk 2, Task 3 |

---

### Task 1: The upgrade on first open

**Files:**
- Create: `store/tests/upgrade.rs`
- Create: `store/src/resources/upgrade.rs`
- Modify: `store/src/resources.rs` (top: `mod upgrade;` and a `pub use`; end: `container_triples`)
- Modify: `store/src/manager.rs` (`open_pod`, `:118-135` at f564eb6, as chunk 1 left it)
- Modify: `store/Cargo.toml` (`[dependencies]`)

- [ ] **Step 1: Write the failing tests**

Create `store/tests/upgrade.rs`. The pods are written in the old layout with a
raw `Store` before any `StoreManager` has opened them, then opened through
the manager, which upgrades them. Reads go through the public API, so the
tests don't depend on how metadata is spelled.

```rust
//! Old-layout pods upgrade themselves on first open (spec 5a, *Upgrading
//! existing pods*).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use brolly_domain::vocab;
use brolly_store::resources::{
    self, Kind, METADATA_GRAPH, Pod, PodRead, ResourceMeta, UpgradeOutcome,
};
use brolly_store::{Store, StoreManager};
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, Term, TermRef,
};
use uuid::Uuid;

const ROOT: &str = "https://alice.brolly.test/~/";
const MALLORY_ROOT: &str = "https://mallory.brolly.test/~/";
const PROFILE: &str = "https://alice.brolly.test/profile";
const TITLE: &str = "https://example.org/title";
const ALT: &str = "https://www.w3.org/ns/activitystreams#name";
const ACL_MODE: &str = "http://www.w3.org/ns/auth/acl#mode";
const ACL_READ: &str = "http://www.w3.org/ns/auth/acl#Read";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n pretend this is an image";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// `<s> <p> <o>` in graph `g`.
fn iri(g: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(n(s), n(p), n(o), GraphName::NamedNode(n(g)))
}

/// `<s> <p> "o"` in graph `g`.
fn lit(g: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(n(s), n(p), Literal::new_simple_literal(o), GraphName::NamedNode(n(g)))
}

/// The root as `init_storage_root` wrote it before layout 2.
fn old_root(root: &str) -> Vec<Quad> {
    vec![
        iri(root, root, vocab::RDF_TYPE, vocab::LDP_BASIC_CONTAINER),
        iri(root, root, vocab::RDF_TYPE, vocab::LDP_RESOURCE),
        iri(root, root, vocab::RDF_TYPE, vocab::PIM_STORAGE),
    ]
}

/// A data directory holding one member's pod, written in the old layout
/// before any `StoreManager` opens it.
struct OldPod {
    dir: tempfile::TempDir,
    user: Uuid,
}

impl OldPod {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            user: Uuid::new_v4(),
        }
    }

    /// Where `StoreManager` keeps this member's graph (`users/<id>/rdf`). If
    /// that moved, these pods would open empty and every test here fails.
    fn rdf_dir(&self) -> PathBuf {
        self.dir.path().join("users").join(self.user.to_string()).join("rdf")
    }

    /// Write quads straight into the store, the way the old code left them.
    /// The raw store is dropped at the end, releasing RocksDB's lock.
    fn seed(&self, quads: &[Quad]) {
        std::fs::create_dir_all(self.rdf_dir()).unwrap();
        Store::open(self.rdf_dir())
            .unwrap()
            .extend(quads.iter().cloned())
            .unwrap();
    }

    /// Put bytes in this member's blob store, returning their digest.
    fn blob(&self, bytes: &[u8]) -> String {
        let stores = StoreManager::open(self.dir.path(), 4, 60).unwrap();
        stores.blobs(self.user).unwrap().put(bytes).unwrap()
    }

    /// Open the pod through a fresh manager, which upgrades it.
    fn open(&self) -> (StoreManager, Arc<Pod>) {
        let stores = StoreManager::open(self.dir.path(), 4, 60).unwrap();
        let pod = stores.pod(self.user).unwrap();
        (stores, pod)
    }
}

fn meta(pod: &Pod, resource: &str) -> Option<ResourceMeta> {
    pod.read(|r| r.meta(resource)).unwrap()
}

fn members(pod: &Pod, container: &str) -> Vec<String> {
    let mut members = pod.write(|w| w.members(container)).unwrap();
    members.sort();
    members
}

/// One graph's quads, through the public read path.
fn content(pod: &Pod, graph: &str) -> Vec<Quad> {
    pod.read_store()
        .quads_for_pattern(None, None, None, Some(GraphNameRef::NamedNode(n(graph).as_ref())))
        .map(Result::unwrap)
        .collect()
}

/// Every quad in the pod, as sorted text, so "unchanged" compares content.
fn dump(pod: &Pod) -> Vec<String> {
    let mut all: Vec<String> = pod
        .read_store()
        .quads_for_pattern(None, None, None, None)
        .map(|q| q.unwrap().to_string())
        .collect();
    all.sort();
    all
}

fn is_marked(pod: &Pod) -> bool {
    let graph = NamedNodeRef::new_unchecked(METADATA_GRAPH);
    pod.read_store()
        .quads_for_pattern(
            Some(NamedOrBlankNodeRef::NamedNode(graph)),
            Some(NamedNodeRef::new_unchecked(vocab::BROLLY_LAYOUT)),
            None,
            Some(GraphNameRef::NamedNode(graph)),
        )
        .next()
        .is_some()
}

fn about(quad: &Quad, subject: &str) -> bool {
    matches!(&quad.subject, NamedOrBlankNode::NamedNode(s) if s.as_str() == subject)
}

fn names(quad: &Quad, object: &str) -> bool {
    matches!(&quad.object, Term::NamedNode(o) if o.as_str() == object)
}
```

Then the tests, one per bullet under *Testing → Upgrade*:

```rust
// --- which pods it touches ------------------------------------------------

#[test]
fn an_empty_store_is_marked_at_once() {
    let old = OldPod::new();
    let (_stores, pod) = old.open();

    assert!(is_marked(&pod), "a new pod is layout 2 before provisioning");
    assert_eq!(resources::upgrade(&pod).unwrap(), UpgradeOutcome::Current);
    assert!(
        meta(&pod, ROOT).is_none(),
        "provisioning records the root, not the upgrade"
    );
}

#[test]
fn a_layout_2_pod_is_not_rescanned() {
    let old = OldPod::new();
    {
        let (_stores, pod) = old.open();
        pod.write(|w| w.create_root(ROOT)).unwrap();
    }
    // What an upgrade would record if it ran: a graph under the root that
    // nothing wrote through `put`.
    let stray = format!("{ROOT}stray");
    old.seed(&[lit(&stray, &stray, TITLE, "stray")]);

    let (_stores, pod) = old.open();
    assert_eq!(resources::upgrade(&pod).unwrap(), UpgradeOutcome::Current);
    assert!(meta(&pod, &stray).is_none(), "a layout 2 pod was rescanned");
    assert!(!members(&pod, ROOT).contains(&stray));
}

// --- a whole old-layout pod ---------------------------------------------------

/// Every shape the upgrade has to handle, in one pod. Returns the pod and the
/// digest of its one real blob.
fn old_layout_pod() -> (OldPod, String) {
    let old = OldPod::new();
    let digest = old.blob(PNG);
    let root_acl = format!("{ROOT}.acl");
    let notes = format!("{ROOT}notes/");
    let first = format!("{notes}first");
    let empty = format!("{notes}empty");
    let deep = format!("{ROOT}unlisted/deep/doc");
    let pic = format!("{ROOT}media/pic.png");

    let mut quads = old_root(ROOT);
    quads.extend([
        // The root lists a container and, from before stage 0, its own ACL.
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &notes),
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &root_acl),
        // A member's own triple about something else, in the root's graph.
        iri(ROOT, "https://example.org/a", vocab::LDP_CONTAINS, "https://example.org/b"),
        iri(&root_acl, &format!("{root_acl}#owner"), ACL_MODE, ACL_READ),
        // A container with a title, listing a document and one whose graph is
        // empty (today's empty resources).
        iri(&notes, &notes, vocab::RDF_TYPE, vocab::LDP_BASIC_CONTAINER),
        iri(&notes, &notes, vocab::LDP_CONTAINS, &first),
        iri(&notes, &notes, vocab::LDP_CONTAINS, &empty),
        lit(&notes, &notes, TITLE, "Notes"),
        lit(&first, &first, TITLE, "First"),
        // Nobody lists this one, nor its two containers.
        lit(&deep, &deep, TITLE, "Deep"),
        // A binary as `ldp::put` wrote it, with alt text. Not listed either.
        iri(&pic, &pic, vocab::RDF_TYPE, vocab::LDP_NON_RDF_SOURCE),
        iri(&pic, &pic, vocab::RDF_TYPE, vocab::LDP_RESOURCE),
        lit(&pic, &pic, vocab::BROLLY_BLOB_DIGEST, &digest),
        lit(&pic, &pic, vocab::BROLLY_MEDIA_TYPE, "image/png"),
        Quad::new(
            n(&pic),
            n(vocab::BROLLY_BYTE_SIZE),
            Literal::new_typed_literal(PNG.len().to_string(), n(vocab::XSD_INTEGER)),
            GraphName::NamedNode(n(&pic)),
        ),
        lit(&pic, &pic, ALT, "a cat"),
        // Protocol state outside the root.
        lit(PROFILE, &format!("{PROFILE}#me"), TITLE, "Alice"),
    ]);
    old.seed(&quads);
    (old, digest)
}

#[test]
fn every_step_runs_on_an_old_layout_pod() {
    let (old, digest) = old_layout_pod();
    let (_stores, pod) = old.open();
    let root_acl = format!("{ROOT}.acl");
    let notes = format!("{ROOT}notes/");
    let pic = format!("{ROOT}media/pic.png");

    // The root, and what it contains: never its ACL.
    assert!(matches!(meta(&pod, ROOT).unwrap().kind, Kind::Container));
    assert_eq!(
        members(&pod, ROOT),
        vec![format!("{ROOT}media/"), notes.clone(), format!("{ROOT}unlisted/")]
    );
    assert!(matches!(meta(&pod, &root_acl).unwrap().kind, Kind::Auxiliary));

    // Listed members, including one rescued from an empty graph.
    assert_eq!(
        members(&pod, &notes),
        vec![format!("{notes}empty"), format!("{notes}first")]
    );
    let empty = meta(&pod, &format!("{notes}empty")).expect("the empty document exists");
    assert!(matches!(empty.kind, Kind::RdfSource));
    assert!(content(&pod, &format!("{notes}empty")).is_empty());

    // Unlisted resources, with their missing containers created.
    assert_eq!(
        members(&pod, &format!("{ROOT}unlisted/deep/")),
        vec![format!("{ROOT}unlisted/deep/doc")]
    );
    assert_eq!(
        members(&pod, &format!("{ROOT}unlisted/")),
        vec![format!("{ROOT}unlisted/deep/")]
    );

    // The binary: metadata, containment, and a graph holding only its alt text
    // (and the old type triples, which aren't blob triples).
    let pic_meta = meta(&pod, &pic).unwrap();
    assert!(matches!(pic_meta.kind, Kind::NonRdfSource));
    let blob = pic_meta.blob.expect("blob metadata");
    assert_eq!(blob.digest, digest);
    assert_eq!(blob.media_type, "image/png");
    assert_eq!(blob.byte_size, PNG.len() as u64);
    assert_eq!(members(&pod, &format!("{ROOT}media/")), vec![pic.clone()]);
    let pic_graph = content(&pod, &pic);
    assert!(pic_graph.iter().any(|q| q.predicate.as_str() == ALT), "alt text lost");
    for blob_term in [
        vocab::BROLLY_BLOB_DIGEST,
        vocab::BROLLY_MEDIA_TYPE,
        vocab::BROLLY_BYTE_SIZE,
    ] {
        assert!(
            !pic_graph.iter().any(|q| q.predicate.as_str() == blob_term),
            "{blob_term} left in the binary's graph"
        );
    }

    // Stripping is subject-scoped: the server's triples about the container go,
    // a member's triple about something else stays.
    let root_graph = content(&pod, ROOT);
    assert!(!root_graph.iter().any(|q| about(q, ROOT)
        && (q.predicate.as_str() == vocab::LDP_CONTAINS
            || names(q, vocab::LDP_BASIC_CONTAINER)
            || names(q, vocab::PIM_STORAGE))));
    assert!(root_graph.iter().any(|q| about(q, "https://example.org/a")));
    let notes_graph = content(&pod, &notes);
    assert_eq!(notes_graph.len(), 1, "only the title stays: {notes_graph:?}");

    // Everything recorded has a version and a modified time.
    for resource in [
        ROOT.to_string(),
        root_acl,
        notes.clone(),
        format!("{notes}first"),
        format!("{ROOT}unlisted/"),
        format!("{ROOT}unlisted/deep/"),
        format!("{ROOT}unlisted/deep/doc"),
        pic,
    ] {
        let m = meta(&pod, &resource).unwrap_or_else(|| panic!("{resource} not recorded"));
        assert!(!m.version.is_empty(), "{resource} has no version");
        assert!(!m.modified.is_empty(), "{resource} has no modified time");
    }

    // Outside the root: skipped, and untouched.
    assert!(meta(&pod, PROFILE).is_none());
    assert_eq!(content(&pod, PROFILE).len(), 1);
    assert!(is_marked(&pod));
}

#[test]
fn after_the_upgrade_no_container_graph_holds_ldp_contains() {
    let (old, _) = old_layout_pod();
    let (_stores, pod) = old.open();
    let leftovers: Vec<Quad> = pod
        .read_store()
        .quads_for_pattern(None, Some(n(vocab::LDP_CONTAINS).as_ref()), None, None)
        .map(Result::unwrap)
        .filter(|q| {
            matches!((&q.subject, &q.graph_name),
                (NamedOrBlankNode::NamedNode(s), GraphName::NamedNode(g)) if s == g)
        })
        .collect();
    assert!(leftovers.is_empty(), "containment left in content: {leftovers:?}");
}

#[test]
fn a_second_run_changes_nothing() {
    let (old, _) = old_layout_pod();
    let before = {
        let (_stores, pod) = old.open();
        let before = dump(&pod);
        assert_eq!(resources::upgrade(&pod).unwrap(), UpgradeOutcome::Current);
        assert_eq!(dump(&pod), before, "a second run in the same process");
        before
    };
    let (_stores, pod) = old.open();
    assert_eq!(dump(&pod), before, "a reopen upgraded again");
}
```

```rust
// --- forgeries ------------------------------------------------------------------

#[test]
fn forged_containment_is_dropped() {
    let old = OldPod::new();
    let a = format!("{ROOT}a/");
    let mut quads = old_root(ROOT);
    quads.extend([
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, "https://mallory.example/x"), // foreign
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &format!("{ROOT}a/b")),        // a grandchild
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &a),                           // fine
        iri(&a, &a, vocab::LDP_CONTAINS, &format!("{ROOT}sibling")),        // not a's child
        iri(&a, &a, vocab::LDP_CONTAINS, &format!("{ROOT}a/.acl")),         // an ACL
    ]);
    old.seed(&quads);

    let (_stores, pod) = old.open();
    assert_eq!(members(&pod, ROOT), vec![a.clone()]);
    assert!(members(&pod, &a).is_empty());
    for forged in [
        "https://mallory.example/x".to_string(),
        format!("{ROOT}a/b"),
        format!("{ROOT}sibling"),
        format!("{ROOT}a/.acl"),
    ] {
        assert!(meta(&pod, &forged).is_none(), "{forged} was recorded");
    }
}

#[test]
fn forged_blob_digests_are_not_binaries() {
    let old = OldPod::new();
    let real = old.blob(PNG);
    let elsewhere = format!("{ROOT}elsewhere");
    let not_a_digest = format!("{ROOT}not-a-digest");
    let no_file = format!("{ROOT}no-file");
    let mut quads = old_root(ROOT);
    quads.extend([
        // A real digest, but about another subject than the graph.
        lit(&elsewhere, "https://example.org/x", vocab::BROLLY_BLOB_DIGEST, &real),
        lit(&not_a_digest, &not_a_digest, vocab::BROLLY_BLOB_DIGEST, "../../../etc/passwd"),
        lit(&no_file, &no_file, vocab::BROLLY_BLOB_DIGEST, &"ab".repeat(32)),
    ]);
    old.seed(&quads);

    let (_stores, pod) = old.open();
    for doc in [&elsewhere, &not_a_digest, &no_file] {
        let m = meta(&pod, doc).unwrap_or_else(|| panic!("{doc} not recorded"));
        assert!(matches!(m.kind, Kind::RdfSource), "{doc} became a binary");
        assert!(m.blob.is_none());
        assert!(
            content(&pod, doc)
                .iter()
                .any(|q| q.predicate.as_str() == vocab::BROLLY_BLOB_DIGEST),
            "{doc}'s digest triple should stay, as data"
        );
    }
}

#[test]
fn a_planted_storage_type_is_not_a_second_root() {
    let old = OldPod::new();
    let doc = format!("{ROOT}app/doc");
    let mut quads = old_root(ROOT);
    quads.push(iri(&doc, &doc, vocab::RDF_TYPE, vocab::PIM_STORAGE));
    old.seed(&quads);

    let (_stores, pod) = old.open();
    assert!(matches!(meta(&pod, &doc).unwrap().kind, Kind::RdfSource));
    let roots: Vec<String> = pod
        .read_store()
        .quads_for_pattern(
            None,
            Some(n(vocab::RDF_TYPE).as_ref()),
            Some(TermRef::NamedNode(n(vocab::PIM_STORAGE).as_ref())),
            Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(METADATA_GRAPH))),
        )
        .map(|q| q.unwrap().subject.to_string())
        .collect();
    assert_eq!(roots, vec![format!("<{ROOT}>")]);
    assert_eq!(content(&pod, &doc).len(), 1, "the member's triple stays as data");
}

#[test]
fn a_pod_with_no_root_is_left_unmarked() {
    let old = OldPod::new();
    let doc = format!("{ROOT}orphan");
    old.seed(&[lit(&doc, &doc, TITLE, "orphan")]);
    let (_stores, pod) = old.open();
    assert!(!is_marked(&pod));
    assert!(meta(&pod, &doc).is_none());
    assert_eq!(
        resources::upgrade(&pod).unwrap(),
        UpgradeOutcome::NoRoot { candidates: Vec::new() }
    );

    // Two candidates, on different hosts: no root either.
    let old = OldPod::new();
    old.seed(&[old_root(ROOT), old_root(MALLORY_ROOT)].concat());
    let (_stores, pod) = old.open();
    assert!(!is_marked(&pod));
    assert_eq!(
        resources::upgrade(&pod).unwrap(),
        UpgradeOutcome::NoRoot {
            candidates: vec![ROOT.to_string(), MALLORY_ROOT.to_string()]
        }
    );
}
```

(`ROOT` sorts before `MALLORY_ROOT`: `a` < `m`.)

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-store --test upgrade`
Expected: FAIL to compile: `error[E0432]: unresolved imports
`brolly_store::resources::UpgradeOutcome``, and `cannot find function
`upgrade` in module `resources``.

- [ ] **Step 3: Add `tracing` to the store**

In `store/Cargo.toml`, under `[dependencies]` (skip if chunk 1 added it):

```toml
tracing.workspace = true
```

- [ ] **Step 4: Write `store/src/resources/upgrade.rs`**

`resources.rs` stays a single file with a child module beside it
(`store/src/resources/upgrade.rs`). A child module sees the parent's private
items (`Pod`'s blob store, `PodWrite`'s metadata insert) without widening them,
and brings its own imports, so nothing clashes with chunk 1's.

```rust
//! Upgrading an old-layout pod to layout 2, once, when it's first opened.
//!
//! Before layout 2 a pod kept what the server knew about a resource in the
//! resource's own graph: its types, its container's `ldp:contains`, and a
//! binary's blob pointer. This records all of it in the metadata graph in one
//! transaction, and strips it from the content graphs so the two can't
//! disagree. It's forward-only (spec 5a, *No rollback*).
//!
//! It records through `PodWrite::put`, so each resource is recorded exactly as
//! a write would record it: its kind, a modified time and a fresh version,
//! containment in its parent, and missing intermediate containers. And because
//! `put` replaces the content graph, putting the stripped content is what
//! strips it.

use std::collections::{BTreeMap, BTreeSet};

use brolly_domain::vocab;
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, Term, TermRef,
};

use super::{BlobMeta, Content, METADATA_GRAPH, Pod, PodRead, PodWrite};
use crate::blobs::BlobStore;
use crate::manager::StoreError;

/// The layout this code writes and reads.
const LAYOUT: &str = "2";

/// What opening a pod found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeOutcome {
    /// The store held nothing: a new pod. Marked layout 2; provisioning
    /// records the root with `create_root`.
    Fresh,
    /// Already layout 2. Only the mark was read.
    Current,
    /// An old-layout pod, now layout 2.
    Upgraded(UpgradeReport),
    /// No single storage root at `/~/`. Nothing was written and the pod stays
    /// unmarked, so every open tries again. `candidates` is what was found,
    /// sorted: empty, or more than one.
    NoRoot { candidates: Vec<String> },
}

/// What an upgrade did, for the log line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpgradeReport {
    pub root: String,
    /// Resources recorded, the root included. Intermediate containers that
    /// `put` created on the way are not counted.
    pub resources: usize,
    /// `ldp:contains` triples naming something their container can't hold.
    pub dropped_containment: usize,
    /// `brolly:blobDigest` triples that failed the binary test and stayed data.
    pub not_binaries: usize,
}

```rust
/// Bring `pod` to layout 2 if it isn't already. `StoreManager` calls this once
/// per open, before the pod is reachable by anyone else.
///
/// - A pod already marked is left alone: its root is read from metadata.
/// - A store with no quads at all is marked straight away.
/// - Otherwise it's an old-layout pod. Its root must be the one IRI whose path
///   is exactly `/~/` and whose own graph says it's a `pim:Storage`. With no
///   such IRI, or two (on different hosts), nothing is written and the pod is
///   left unmarked; the caller logs it.
///
/// One `Pod::write`, so a failure leaves the pod exactly as it was and the
/// next open retries.
pub fn upgrade(pod: &Pod) -> Result<UpgradeOutcome, StoreError> {
    pod.write(|w| {
        if is_marked(&*w)? {
            return Ok(UpgradeOutcome::Current);
        }
        if w.quads_for_pattern(None, None, None, None).next().is_none() {
            mark(w)?;
            return Ok(UpgradeOutcome::Fresh);
        }
        let root = match <[String; 1]>::try_from(root_candidates(&*w)?) {
            Ok([root]) => root,
            Err(candidates) => return Ok(UpgradeOutcome::NoRoot { candidates }),
        };
        // `blobs` is chunk 1's private field holding this pod's `BlobStore`.
        let report = record(w, &pod.blobs, &root)?;
        mark(w)?;
        Ok(UpgradeOutcome::Upgraded(report))
    })
}

/// Is the pod at layout 2? A layout this code doesn't know is an error rather
/// than a rescan: a newer server wrote it.
fn is_marked(r: &impl PodRead) -> Result<bool, StoreError> {
    let graph = NamedNodeRef::new_unchecked(METADATA_GRAPH);
    let Some(quad) = r
        .quads_for_pattern(
            Some(NamedOrBlankNodeRef::NamedNode(graph)),
            Some(NamedNodeRef::new_unchecked(vocab::BROLLY_LAYOUT)),
            None,
            Some(GraphNameRef::NamedNode(graph)),
        )
        .next()
    else {
        return Ok(false);
    };
    match quad?.object {
        Term::Literal(layout) if layout.value() == LAYOUT => Ok(true),
        other => Err(StoreError::Backend(format!(
            "this pod is at layout {other}, which this server doesn't know"
        ))),
    }
}

/// `<urn:brolly:resources> brolly:layout 2`, in the metadata graph.
fn mark(w: &mut PodWrite<'_>) -> Result<(), StoreError> {
    let graph = NamedNode::new_unchecked(METADATA_GRAPH);
    // `insert_metadata` is the crate-private metadata write `put` uses; if
    // chunk 1 named it differently, call that.
    w.insert_metadata(&[Quad::new(
        graph.clone(),
        NamedNode::new_unchecked(vocab::BROLLY_LAYOUT),
        Literal::new_typed_literal(LAYOUT, NamedNode::new_unchecked(vocab::XSD_INTEGER)),
        GraphName::NamedNode(graph),
    )])
}

/// Every IRI `r` at path `/~/` with `<r> a pim:Storage` in `r`'s own graph,
/// sorted. A member can write `<> a pim:Storage` into their own document, but
/// its path isn't `/~/`.
fn root_candidates(r: &impl PodRead) -> Result<Vec<String>, StoreError> {
    let mut found = BTreeSet::new();
    for quad in r.quads_for_pattern(
        None,
        Some(NamedNodeRef::new_unchecked(vocab::RDF_TYPE)),
        Some(TermRef::NamedNode(NamedNodeRef::new_unchecked(vocab::PIM_STORAGE))),
        None,
    ) {
        let quad = quad?;
        if let (NamedOrBlankNode::NamedNode(subject), GraphName::NamedNode(graph)) =
            (&quad.subject, &quad.graph_name)
            && subject == graph
            && at_storage_path(subject.as_str())
        {
            found.insert(subject.as_str().to_string());
        }
    }
    Ok(found.into_iter().collect())
}

/// Is `iri`'s path exactly `/~/` (ADR 0010)?
fn at_storage_path(iri: &str) -> bool {
    let Some((_, rest)) = iri.split_once("://") else {
        return false;
    };
    rest.find('/').is_some_and(|cut| &rest[cut..] == "/~/")
}

/// A named graph under the root, classified.
enum Found {
    Container(Vec<Quad>),
    Document(Vec<Quad>),
    Auxiliary(Vec<Quad>),
    /// `rest` is the graph without the three blob triples.
    Binary { blob: BlobMeta, rest: Vec<Quad> },
}

/// Steps 1–5 of the spec's upgrade, for a pod whose root is `root`.
fn record(
    w: &mut PodWrite<'_>,
    blobs: &BlobStore,
    root: &str,
) -> Result<UpgradeReport, StoreError> {
    let mut report = UpgradeReport {
        root: root.to_string(),
        ..UpgradeReport::default()
    };

    // 1. Classify every named graph under the root, once.
    let mut found = BTreeMap::new();
    for (graph, quads) in graphs_under(&*w, root)? {
        let kind = classify(&graph, root, quads, blobs, &mut report);
        found.insert(graph, kind);
    }

    // 3. Members a container lists, if it may hold them. One whose graph is
    //    empty is recorded empty, which rescues today's empty resources.
    for member in listed_members(&found, root, &mut report) {
        found.entry(member).or_insert_with_key(|member| {
            if member.ends_with('/') {
                Found::Container(Vec::new())
            } else {
                Found::Document(Vec::new())
            }
        });
    }

    // 2, 4 and 5. The root first, then each resource through `put`, which
    //    contains it (step 4) and replaces its graph with the stripped one
    //    (step 5). Parents sort before children, but `put` doesn't need them to.
    w.create_root(root)?;
    for (resource, kind) in found {
        match kind {
            Found::Container(quads) => {
                w.put(&resource, Content::Container(&strip_container(&resource, quads)))?;
            }
            Found::Document(quads) => {
                w.put(&resource, Content::Rdf(&quads))?;
            }
            Found::Auxiliary(quads) => {
                w.put(&resource, Content::Auxiliary(&quads))?;
            }
            Found::Binary { blob, rest } => {
                w.put(&resource, Content::Binary(blob))?;
                if !rest.is_empty() {
                    w.append(&resource, &rest)?;
                }
            }
        }
        report.resources += 1;
    }
    Ok(report)
}

/// The quads of every named graph under `root`, grouped by graph, in one pass.
/// The metadata graph and everything outside the root (the profile, the inbox
/// and outbox collections, `at://` records) are skipped.
fn graphs_under(
    r: &impl PodRead,
    root: &str,
) -> Result<BTreeMap<String, Vec<Quad>>, StoreError> {
    let mut graphs: BTreeMap<String, Vec<Quad>> = BTreeMap::new();
    for quad in r.quads_for_pattern(None, None, None, None) {
        let quad = quad?;
        let GraphName::NamedNode(graph) = &quad.graph_name else {
            continue;
        };
        if graph.as_str() == METADATA_GRAPH || !graph.as_str().starts_with(root) {
            continue;
        }
        let key = graph.as_str().to_string();
        graphs.entry(key).or_default().push(quad);
    }
    Ok(graphs)
}

/// The spec's order: an `.acl` IRI is auxiliary; a graph passing the binary
/// test is a binary; an IRI ending in `/` is a container; anything else is an
/// RDF document. Every graph here has quads. The root is always a container,
/// whatever its graph claims.
fn classify(
    graph: &str,
    root: &str,
    quads: Vec<Quad>,
    blobs: &BlobStore,
    report: &mut UpgradeReport,
) -> Found {
    if graph.ends_with(".acl") {
        return Found::Auxiliary(quads);
    }
    if graph != root
        && let Some(blob) = binary(graph, &quads, blobs, report)
    {
        let rest = quads
            .into_iter()
            .filter(|q| !(is_about(q, graph) && is_blob_term(q.predicate.as_str())))
            .collect();
        return Found::Binary { blob, rest };
    }
    if graph.ends_with('/') {
        Found::Container(quads)
    } else {
        Found::Document(quads)
    }
}

```rust
/// The blob `graph` describes, if it passes the binary test: a
/// `<graph> brolly:blobDigest "<64 hex>"` triple naming a file this pod holds
/// (`BlobStore::contains` checks both). Every digest triple that fails it is
/// logged and stays as ordinary data.
fn binary(
    graph: &str,
    quads: &[Quad],
    blobs: &BlobStore,
    report: &mut UpgradeReport,
) -> Option<BlobMeta> {
    let mut digest = None;
    for quad in quads
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::BROLLY_BLOB_DIGEST)
    {
        match &quad.object {
            Term::Literal(d)
                if digest.is_none() && is_about(quad, graph) && blobs.contains(d.value()) =>
            {
                digest = Some(d.value().to_string());
            }
            _ => {
                tracing::warn!(
                    graph,
                    triple = %quad,
                    "upgrade: a blobDigest triple failed the binary test; left as data"
                );
                report.not_binaries += 1;
            }
        }
    }
    let digest = digest?;
    let media_type = literal(quads, graph, vocab::BROLLY_MEDIA_TYPE)
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let byte_size = literal(quads, graph, vocab::BROLLY_BYTE_SIZE)
        .and_then(|size| size.parse().ok())
        .or_else(|| {
            let bytes = blobs.get(&digest).ok().flatten()?;
            u64::try_from(bytes.len()).ok()
        })
        .unwrap_or(0);
    Some(BlobMeta {
        digest,
        media_type,
        byte_size,
    })
}

/// The first literal `<subject> <predicate> "…"` in `quads`.
fn literal(quads: &[Quad], subject: &str, predicate: &str) -> Option<String> {
    quads
        .iter()
        .filter(|q| is_about(q, subject) && q.predicate.as_str() == predicate)
        .find_map(|q| match &q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
}

fn is_about(quad: &Quad, subject: &str) -> bool {
    matches!(&quad.subject, NamedOrBlankNode::NamedNode(s) if s.as_str() == subject)
}

fn is_blob_term(predicate: &str) -> bool {
    matches!(
        predicate,
        vocab::BROLLY_BLOB_DIGEST | vocab::BROLLY_MEDIA_TYPE | vocab::BROLLY_BYTE_SIZE
    )
}

/// Every `<c> ldp:contains <m>` in a container `c`'s own graph whose member
/// `c` may hold. The rest are logged and dropped.
fn listed_members(
    found: &BTreeMap<String, Found>,
    root: &str,
    report: &mut UpgradeReport,
) -> BTreeSet<String> {
    let mut listed = BTreeSet::new();
    for (container, kind) in found {
        let Found::Container(quads) = kind else {
            continue;
        };
        for quad in quads
            .iter()
            .filter(|q| is_about(q, container) && q.predicate.as_str() == vocab::LDP_CONTAINS)
        {
            match &quad.object {
                Term::NamedNode(member) if may_hold(container, member.as_str(), root) => {
                    listed.insert(member.as_str().to_string());
                }
                _ => {
                    tracing::warn!(
                        container = %container,
                        triple = %quad,
                        "upgrade: dropped a containment triple naming something this container can't hold"
                    );
                    report.dropped_containment += 1;
                }
            }
        }
    }
    listed
}

/// May `container` list `member`? Only a direct child, under the root, and
/// never an ACL: ACLs are auxiliary and aren't contained (Solid Protocol §4.3).
fn may_hold(container: &str, member: &str, root: &str) -> bool {
    member.starts_with(root)
        && member != root
        && !member.ends_with(".acl")
        && parent(member) == Some(container)
}

/// The container directly above `resource`: `…/a/b` and `…/a/b/` both give
/// `…/a/`.
fn parent(resource: &str) -> Option<&str> {
    let trimmed = resource.strip_suffix('/').unwrap_or(resource);
    trimmed.rfind('/').map(|cut| &resource[..=cut])
}

/// A container's graph without the server's triples about it: its
/// `ldp:contains`, and its `ldp:BasicContainer`, `ldp:Container` and
/// `pim:Storage` types. Subject-scoped, so a member's triples about other
/// subjects stay.
fn strip_container(container: &str, quads: Vec<Quad>) -> Vec<Quad> {
    quads
        .into_iter()
        .filter(|q| !(is_about(q, container) && is_server_container_triple(q)))
        .collect()
}

fn is_server_container_triple(quad: &Quad) -> bool {
    match quad.predicate.as_str() {
        vocab::LDP_CONTAINS => true,
        vocab::RDF_TYPE => matches!(
            &quad.object,
            Term::NamedNode(t) if matches!(
                t.as_str(),
                vocab::LDP_BASIC_CONTAINER | vocab::LDP_CONTAINER | vocab::PIM_STORAGE
            )
        ),
        _ => false,
    }
}
```

- [ ] **Step 5: Wire it into `resources.rs`, and add `container_triples`**

At the top of `store/src/resources.rs`, after its module doc and imports:

```rust
mod upgrade;

pub use upgrade::{UpgradeOutcome, UpgradeReport, upgrade};
```

At the end of `store/src/resources.rs` (before any `#[cfg(test)] mod tests`),
add the reader `ldp` merges into a container's representation. It lives here
because nothing outside this file reads the metadata graph by name. The
imports are local to the function so they can't clash with chunk 1's:

```rust
/// What a GET of `container` serves from metadata, in the container's own
/// graph: its types (`ldp:Resource`, `ldp:Container`, `ldp:BasicContainer`,
/// and `pim:Storage` at the root) and one `ldp:contains` per member.
///
/// `ldp::read_in` adds these to the container's content graph, and a container
/// PUT is checked against them, so the echo of a GET round-trips.
pub fn container_triples(
    r: &impl PodRead,
    container: &str,
) -> Result<Vec<oxigraph::model::Quad>, StoreError> {
    use brolly_domain::vocab;
    use oxigraph::model::{
        GraphName, GraphNameRef, NamedNode, NamedNodeRef, NamedOrBlankNodeRef, Quad, Term,
    };

    const SERVED_TYPES: [&str; 4] = [
        vocab::LDP_RESOURCE,
        vocab::LDP_CONTAINER,
        vocab::LDP_BASIC_CONTAINER,
        vocab::PIM_STORAGE,
    ];

    let node = NamedNode::new_unchecked(container);
    let graph = GraphName::NamedNode(node.clone());
    let metadata = GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(METADATA_GRAPH));
    let subject = NamedOrBlankNodeRef::NamedNode(node.as_ref());
    let mut out = Vec::new();

    for predicate in [vocab::RDF_TYPE, vocab::LDP_CONTAINS] {
        for quad in r.quads_for_pattern(
            Some(subject),
            Some(NamedNodeRef::new_unchecked(predicate)),
            None,
            Some(metadata),
        ) {
            let quad = quad?;
            let served = predicate == vocab::LDP_CONTAINS
                || matches!(&quad.object, Term::NamedNode(t) if SERVED_TYPES.contains(&t.as_str()));
            if served {
                out.push(Quad::new(node.clone(), quad.predicate, quad.object, graph.clone()));
            }
        }
    }
    Ok(out)
}
```

The metadata's `ldp:contains` triples are exactly `members`' answer (spec
table: containment is `<c> ldp:contains <r>` in the metadata graph), so this
reads them directly rather than going through `PodWrite::members`, which a
`ResourceRead` may not have.

- [ ] **Step 6: Upgrade on open**

In `store/src/manager.rs`, add to the imports:

```rust
use crate::resources::UpgradeOutcome;
```

In `open_pod`, between the line that builds the `Arc<Pod>` and the line that
takes the live-handle map (`let mut live = self.live_handles();`), insert:

```rust
        // Upgrade before publishing. Until this returns no other thread can
        // reach the pod, so its lock is uncontended; concurrent requests for
        // it wait on the cache. A failed upgrade returns here, leaving nothing
        // in the live map or the cache, and the next open retries. This never
        // calls `pod()`, so it can't re-enter the cache's initialiser.
        match crate::resources::upgrade(&pod)? {
            UpgradeOutcome::NoRoot { candidates } => tracing::error!(
                %user,
                ?candidates,
                "pod has no single storage root at /~/; it's served without metadata and its LDP reads answer 404"
            ),
            UpgradeOutcome::Upgraded(report) => tracing::info!(
                %user,
                root = %report.root,
                resources = report.resources,
                dropped_containment = report.dropped_containment,
                not_binaries = report.not_binaries,
                "pod upgraded to layout 2"
            ),
            UpgradeOutcome::Fresh | UpgradeOutcome::Current => {}
        }
```

`pod` is the `Arc<Pod>` chunk 1 builds there; use its name if different. The
early return that hands back a live handle stays *above* this: a live handle
has already been upgraded. The instance store is opened in `open` and never
passes through here.

- [ ] **Step 7: Run the tests and watch them pass**

Run: `cargo test -p brolly-store --test upgrade`
Expected: 9 passed.

Run: `cargo test -p brolly-store -p brolly-authz -p brolly-solid`
Expected: PASS. Nothing else changes yet: every existing fixture opens its pod
first, so the pod is empty, gets marked `Fresh`, and is then seeded as
chunk 2 left it.

- [ ] **Step 8: Format**

```bash
cargo fmt --all
```

- [ ] **Step 9: Gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Expected: all pass (this task changes no behaviour an existing test sees),
and `advisories ok, bans ok, licenses ok, sources ok`.

- [ ] **Step 10: Stage, don't commit**

```bash
git add store/Cargo.toml store/src/resources.rs store/src/resources/upgrade.rs \
        store/src/manager.rs store/tests/upgrade.rs Cargo.lock
```

Commit 2 lands at the end of chunk 4.

---

### Task 2: The upgrade benchmark

The spec's *Cost* paragraph: `store/benches/` gains an upgrade case. There is
no `store/benches/` yet and no benchmark framework in the workspace, so this is
a `harness = false` binary on `std::time::Instant`, with no new dependency.

**Files:**
- Create: `store/benches/upgrade.rs`
- Modify: `store/Cargo.toml` (append a `[[bench]]` table)

- [ ] **Step 1: Declare the bench**

Append to `store/Cargo.toml`:

```toml
[[bench]]
name = "upgrade"
harness = false
```

- [ ] **Step 2: Write it**

```rust
//! How long the layout-2 upgrade holds a pod's first open (spec 5a, *Cost*).
//!
//! `cargo bench -p brolly-store --bench upgrade`. Builds old-layout pods of
//! growing size, then times the first `StoreManager::pod`, which upgrades, and
//! a reopen, which only reads the layout mark. A report, not a gate: nothing
//! here fails on a number.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::time::{Duration, Instant};

use brolly_domain::vocab;
use brolly_store::{Store, StoreManager};
use oxigraph::model::{GraphName, Literal, NamedNode, Quad};
use uuid::Uuid;

const ROOT: &str = "https://alice.brolly.test/~/";
const CONTAINERS: usize = 10;
const TRIPLES_PER_DOCUMENT: usize = 5;

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// An old-layout pod: the root, `CONTAINERS` listed containers, and
/// `documents` listed documents spread across them.
fn old_pod(documents: usize) -> Vec<Quad> {
    let g = |iri: &str| GraphName::NamedNode(n(iri));
    let mut quads = vec![
        Quad::new(n(ROOT), n(vocab::RDF_TYPE), n(vocab::LDP_BASIC_CONTAINER), g(ROOT)),
        Quad::new(n(ROOT), n(vocab::RDF_TYPE), n(vocab::PIM_STORAGE), g(ROOT)),
    ];
    for c in 0..CONTAINERS {
        let container = format!("{ROOT}c{c}/");
        quads.push(Quad::new(n(ROOT), n(vocab::LDP_CONTAINS), n(&container), g(ROOT)));
        quads.push(Quad::new(
            n(&container),
            n(vocab::RDF_TYPE),
            n(vocab::LDP_BASIC_CONTAINER),
            g(&container),
        ));
    }
    for d in 0..documents {
        let container = format!("{ROOT}c{}/", d % CONTAINERS);
        let doc = format!("{container}d{d}");
        quads.push(Quad::new(n(&container), n(vocab::LDP_CONTAINS), n(&doc), g(&container)));
        for t in 0..TRIPLES_PER_DOCUMENT {
            quads.push(Quad::new(
                n(&doc),
                n(&format!("https://example.org/p{t}")),
                Literal::new_simple_literal(format!("value {t}")),
                g(&doc),
            ));
        }
    }
    quads
}

/// Open the pod through a fresh manager and time it.
fn timed_open(dir: &std::path::Path, user: Uuid) -> Duration {
    let stores = StoreManager::open(dir, 4, 60).unwrap();
    let started = Instant::now();
    stores.pod(user).unwrap();
    started.elapsed()
}

fn main() {
    println!("{:>10} {:>14} {:>14}", "documents", "first open", "reopen");
    for documents in [100, 1_000, 10_000] {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let rdf = dir.path().join("users").join(user.to_string()).join("rdf");
        std::fs::create_dir_all(&rdf).unwrap();
        Store::open(&rdf).unwrap().extend(old_pod(documents)).unwrap();

        let first = timed_open(dir.path(), user);
        let reopen = timed_open(dir.path(), user);
        println!("{documents:>10} {first:>14.2?} {reopen:>14.2?}");
    }
}
```

`print_stdout` is allowed because printing is this binary's output. The
workspace lint exists to keep `println!` out of library code.

- [ ] **Step 3: Run it**

Run: `cargo bench -p brolly-store --bench upgrade`
Expected: a three-row table. `first open` grows with the document count and
`reopen` stays near the ~8 ms open cost ADR 0006 measured. Put the numbers in
the commit message body (chunk 4's commit).

- [ ] **Step 4: Format**

```bash
cargo fmt --all
```

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p brolly-store -p brolly-authz -p brolly-solid
cargo deny check
```

`--all-targets` compiles the bench, so clippy covers it.

- [ ] **Step 6: Stage, don't commit**

```bash
git add store/Cargo.toml store/benches/upgrade.rs
```

---

### Task 3: The new `LdpError` variants, and their status codes

**Files:**
- Modify: `adapters/solid/src/ldp.rs` (`LdpError` and its `Display`, `:21-43` at f564eb6)
- Modify: `server/src/pod.rs` (`ldp_error`, `:216-233`; a test module at the end)

- [ ] **Step 1: Write the failing test**

Append to `server/src/pod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// 5a uses the codes `pod.rs` already has; 5b revisits them.
    #[test]
    fn the_new_ldp_refusals_have_status_codes() {
        assert_eq!(
            ldp_error(LdpError::NotRdf).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            ldp_error(LdpError::ContainmentChange).status(),
            StatusCode::CONFLICT,
            "Solid Protocol §5.3"
        );
        assert_eq!(
            ldp_error(LdpError::BlobMissing).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-server --lib pod::tests`
Expected: FAIL to compile: `error[E0599]: no variant or associated item named
`NotRdf` found for enum `LdpError``.

- [ ] **Step 3: Add the variants**

In `adapters/solid/src/ldp.rs`, replace the `LdpError` enum and its `Display`
impl:

```rust
#[derive(Debug)]
pub enum LdpError {
    /// No grant. Deliberately distinct from `NotFound` only *after* the ACL
    /// says the caller may know the resource exists — see [`read`].
    Forbidden,
    NotFound,
    Syntax(SyntaxError),
    Store(String),
    /// A write inside `/~/` that is not addressed to the storage root.
    OutsideStorage,
    /// The target takes RDF only: a container, an ACL, a PATCH of a binary,
    /// or a POST appending to a document.
    NotRdf,
    /// A container PUT whose `ldp:contains` triples don't name exactly the
    /// container's current members. Membership changes only by creating or
    /// deleting members (Solid Protocol §5.3).
    ContainmentChange,
    /// A binary's bytes vanished between `prepare` and the write: a
    /// concurrent delete released identical bytes. Prepare again and retry
    /// once (spec 5a, R12).
    BlobMissing,
}

impl std::fmt::Display for LdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdpError::Forbidden => write!(f, "forbidden"),
            LdpError::NotFound => write!(f, "not found"),
            LdpError::Syntax(e) => write!(f, "{e}"),
            LdpError::Store(e) => write!(f, "storage: {e}"),
            LdpError::OutsideStorage => write!(f, "path is outside the storage root"),
            LdpError::NotRdf => write!(f, "this resource takes an RDF body"),
            LdpError::ContainmentChange => write!(
                f,
                "a container's members change only by creating or deleting them"
            ),
            LdpError::BlobMissing => write!(f, "the blob was released before it was recorded"),
        }
    }
}
```

- [ ] **Step 4: Map them**

In `server/src/pod.rs`, add three arms to `ldp_error`'s `match`, after the
`LdpError::Syntax` arm:

```rust
        LdpError::NotRdf => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "this resource takes an RDF body",
        )
            .into_response(),
        LdpError::ContainmentChange => (
            StatusCode::CONFLICT,
            "a container's members change only by creating or deleting them",
        )
            .into_response(),
        LdpError::BlobMissing => {
            tracing::error!("a blob was released under a write that still needed it");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
```

- [ ] **Step 5: Run it and watch it pass**

Run: `cargo test -p brolly-server --lib pod::tests`
Expected: 1 passed.

- [ ] **Step 6: Format**

```bash
cargo fmt --all
```

- [ ] **Step 7: Gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p brolly-store -p brolly-authz -p brolly-solid
```

The variants are public, so they aren't dead code before Task 4 constructs
them.

- [ ] **Step 8: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs server/src/pod.rs
```

---

### Task 4: LDP on metadata

The switch for the Solid adapter. Existence, kind, containment and blobs come
from `urn:brolly:resources`; writes go through `put`/`append`/`remove`; the
`legacy_under_root` calls in `ldp.rs`, `patch.rs` and `storage.rs` go.

**Files:**
- Modify: `adapters/solid/src/ldp.rs` (everything from the imports to `parse_into_graph`, as chunk 2 left it; `LdpError` from Task 3, `governed`, `refuse_rdf_xml`, `parse_into_graph`, `accepted_write_types`, `served_types` and the tests module stay)
- Modify: `adapters/solid/src/patch.rs` (imports, `PatchError`, `apply_scoped`)
- Modify: `adapters/solid/src/storage.rs`
- Modify: `server/src/pod.rs` (`patch`, `:354-416`; `delete`, `:418-440`)
- Modify: `adapters/solid/tests/ldp_conformance.rs`, `ldp_nonrdf.rs`, `acl_control.rs`, `publication_boundary.rs`, `patch_conformance.rs`

Line numbers below are at f564eb6. Chunk 2 changed the argument forms at the
call sites (`&store.read_store()`, `seed`, `n3`/`sparql`); each step names its
anchor, so go by the anchor.

- [ ] **Step 1: Shared test helpers**

Each of `ldp_conformance.rs`, `acl_control.rs` and `ldp_nonrdf.rs` gets these
three helpers, after chunk 2's `seed`. They go through the pod, not through
`ldp`, so the setup and the checks don't depend on the code under test.

```rust
/// Add `quads` to the ACL at `acl`, recording it as an auxiliary resource if
/// it's new. Metadata is what makes an ACL exist, so a raw `seed` isn't enough.
fn grant(pod: &Pod, acl: &str, quads: &[Quad]) {
    pod.write(|w| {
        let mut all = w
            .quads_for_pattern(None, None, None, Some(GraphNameRef::NamedNode(n(acl).as_ref())))
            .collect::<Result<Vec<_>, _>>()?;
        all.extend_from_slice(quads);
        w.put(acl, Content::Auxiliary(&all))?;
        Ok(())
    })
    .unwrap();
}

/// What the metadata records about `resource`: `Some` is existence.
fn meta(pod: &Pod, resource: &str) -> Option<ResourceMeta> {
    pod.read(|r| r.meta(resource)).unwrap()
}

/// A container's members, sorted, from metadata.
fn members(pod: &Pod, container: &str) -> Vec<String> {
    let mut members = pod.write(|w| w.members(container)).unwrap();
    members.sort();
    members
}
```

Each file's imports gain what these name: `brolly_store::resources::{Content,
Kind, Pod, PodRead, ResourceMeta}` and `oxigraph::model::GraphNameRef`
(`ldp_nonrdf.rs` already has `PodRead` from chunk 2, and names its own fixture
struct, so see Step 4). Import `Kind` only where a test below uses it; clippy
fails on an unused import. `brolly_solid::storage` and chunk 2's `seed` go from
a file once nothing in it uses them.

- [ ] **Step 2: `ldp_conformance.rs`: the fixture and the rewrites**

Replace `pod()` (`:64-93`) with:

```rust
/// A pod whose root ACL grants Alice full control and nothing to anyone else.
fn pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();
    store.write(|w| w.create_root(ROOT)).unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    grant(
        &store,
        &g,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &a, &format!("{ACL}agent"), "https://alice.brolly.id/profile#me"),
        ],
    );
    (mgr, dir, store)
}
```

Then, by anchor:

| Test | Was (chunk 2) | Becomes |
|---|---|---|
| `rdf_xml_is_refused_on_write_and_not_stored_as_a_blob` | `!storage::exists(&store.read_store(), &format!("{ROOT}note"))` | `meta(&store, &format!("{ROOT}note")).is_none()` |
| `a_body_cannot_write_into_another_resources_graph` | `!storage::exists(…other)`, `storage::exists(…note)` | `meta(&store, &format!("{ROOT}other")).is_none()`, `meta(&store, &format!("{ROOT}note")).is_some()` |
| `containment_is_maintained_up_the_tree` | `storage::members(&store.read_store(), X)` ×3 | `members(&store, X)` |
| `posting_to_a_container_mints_a_member` | `storage::members(&store.read_store(), ROOT)` | `members(&store, ROOT)` |
| `delete_removes_the_resource_and_its_containment` | `storage::exists(…)` ×2, `storage::members(…)`, `ldp::delete(&store, None, BASE, …)` | `meta(&store, …).is_some()` / `.is_none()`, `members(&store, ROOT)`, `ldp::delete(&store, BASE, …)` |
| `a_non_empty_container_cannot_be_deleted` | `ldp::delete(&store, None, BASE, "/~/a/", …)` | `ldp::delete(&store, BASE, "/~/a/", …)` |
| `append_permission_does_not_confer_replace` | `seed(&store, &[…bob…])` | `grant(&store, &g, &[…bob…])` |
| `public_read_works_for_anonymous_callers` | `seed(&store, &[…public…])` | `grant(&store, &g, &[…public…])` |

- [ ] **Step 3: `ldp_conformance.rs`: the spec's new tests**

Add `use brolly_domain::vocab;`, and `Kind` to the `brolly_store::resources`
import. Append:

```rust
// --- stage 5a: server-managed metadata ---------------------------------------

/// Every quad in one resource's own graph, through the pod.
fn own_graph(pod: &Pod, resource: &str) -> Vec<Quad> {
    pod.read_store()
        .quads_for_pattern(None, None, None, Some(GraphNameRef::NamedNode(n(resource).as_ref())))
        .map(Result::unwrap)
        .collect()
}

fn put_turtle(store: &Pod, path: &str, body: &[u8]) -> Result<(), LdpError> {
    ldp::put(store, None, BASE, path, &alice(), body, "text/turtle", ROOT)
}

fn ntriples(store: &Pod, path: &str) -> String {
    let out = ldp::read(store, None, BASE, path, &alice(), Some("application/n-triples")).unwrap();
    String::from_utf8(out.body).unwrap()
}

#[test]
fn an_empty_document_exists() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/empty", b"").unwrap();

    assert!(ntriples(&store, "/~/empty").trim().is_empty(), "GET is 200, and empty");
    assert!(matches!(meta(&store, &format!("{ROOT}empty")).unwrap().kind, Kind::RdfSource));
    assert!(members(&store, ROOT).contains(&format!("{ROOT}empty")));

    // It can be deleted, so its listing can be removed too.
    ldp::delete(&store, BASE, "/~/empty", &alice(), ROOT).unwrap();
    assert!(!members(&store, ROOT).contains(&format!("{ROOT}empty")));
}

#[test]
fn an_empty_container_has_its_types_and_no_members() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/", b"").unwrap();

    let body = ntriples(&store, "/~/c/");
    assert!(body.contains("ldp#BasicContainer"), "{body}");
    assert!(body.contains("ldp#Container>"), "{body}");
    assert!(body.contains("ldp#Resource"), "{body}");
    assert!(!body.contains("ldp#contains"), "{body}");
    assert!(!body.contains("space#Storage"), "only the root is a pim:Storage: {body}");
    assert!(matches!(meta(&store, &format!("{ROOT}c/")).unwrap().kind, Kind::Container));
}

#[test]
fn a_container_put_with_an_extra_triple_keeps_its_members() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    put_turtle(&store, "/~/c/", br#"<> <https://example.org/title> "C" ."#).unwrap();

    assert_eq!(members(&store, &format!("{ROOT}c/")), vec![format!("{ROOT}c/m")]);
    let body = ntriples(&store, "/~/c/");
    assert!(body.contains("\"C\""), "{body}");
    assert!(body.contains(&format!("<{ROOT}c/m>")), "{body}");
}

#[test]
fn a_container_put_naming_a_non_member_is_a_containment_change() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let body = format!(
        "<> <{}> <{ROOT}c/m>, <{ROOT}c/ghost> .",
        vocab::LDP_CONTAINS
    );

    let err = put_turtle(&store, "/~/c/", body.as_bytes()).unwrap_err();
    assert!(matches!(err, LdpError::ContainmentChange), "got {err:?}");
    assert_eq!(members(&store, &format!("{ROOT}c/")), vec![format!("{ROOT}c/m")]);
    assert!(meta(&store, &format!("{ROOT}c/ghost")).is_none(), "a member was invented");
}

#[test]
fn a_container_put_echoing_its_listing_succeeds() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();
    let got = ldp::read(&store, None, BASE, "/~/c/", &alice(), Some("text/turtle")).unwrap();

    put_turtle(&store, "/~/c/", &got.body).unwrap();

    assert_eq!(members(&store, &format!("{ROOT}c/")), vec![format!("{ROOT}c/m")]);
    let own = own_graph(&store, &format!("{ROOT}c/"));
    assert!(
        own.is_empty(),
        "the echoed types and containment are the server's, not stored: {own:?}"
    );
}

#[test]
fn a_container_put_with_a_non_rdf_body_is_not_rdf() {
    let (_m, _d, store) = pod();
    let err = ldp::put(&store, None, BASE, "/~/c/", &alice(), b"\x89PNG", "image/png", ROOT)
        .unwrap_err();
    assert!(matches!(err, LdpError::NotRdf), "got {err:?}");
    assert!(meta(&store, &format!("{ROOT}c/")).is_none());
}

#[test]
fn an_ordinary_document_serves_containment_and_digest_triples_as_data() {
    let (_m, _d, store) = pod();
    let digest = "ab".repeat(32);
    let body = format!(
        "<> <{}> <{ROOT}secret> ;\n   <{}> \"{digest}\" .",
        vocab::LDP_CONTAINS,
        vocab::BROLLY_BLOB_DIGEST
    );
    put_turtle(&store, "/~/doc", body.as_bytes()).unwrap();

    let served = ntriples(&store, "/~/doc");
    assert!(served.contains("ldp#contains"), "{served}");
    assert!(served.contains(&digest), "{served}");
    assert!(matches!(meta(&store, &format!("{ROOT}doc")).unwrap().kind, Kind::RdfSource));
    assert!(ldp::blob_digest(&store, &format!("{ROOT}doc")).is_none());
    assert!(meta(&store, &format!("{ROOT}secret")).is_none(), "inert data made a member");
    assert_eq!(members(&store, ROOT), vec![format!("{ROOT}doc")]);
}

#[test]
fn a_patch_that_creates_a_resource_lists_it() {
    let (_m, _d, store) = pod();
    let update = format!(r#"INSERT DATA {{ <{ROOT}made/new> <https://example.org/title> "x" }}"#);
    ldp::patch(
        &store,
        BASE,
        "/~/made/new",
        &alice(),
        ldp::PatchBody::SparqlUpdate(&update),
        ROOT,
    )
    .unwrap();

    assert_eq!(members(&store, &format!("{ROOT}made/")), vec![format!("{ROOT}made/new")]);
    assert!(members(&store, ROOT).contains(&format!("{ROOT}made/")));
    assert!(matches!(meta(&store, &format!("{ROOT}made/new")).unwrap().kind, Kind::RdfSource));
}

#[test]
fn a_container_with_members_cannot_be_emptied_by_put_and_then_deleted() {
    let (_m, _d, store) = pod();
    put_turtle(&store, "/~/c/m", NOTE).unwrap();

    // Before 5a this PUT wiped the listing, and the DELETE then removed the
    // container over a live member.
    put_turtle(&store, "/~/c/", b"").unwrap();
    assert_eq!(members(&store, &format!("{ROOT}c/")), vec![format!("{ROOT}c/m")]);
    assert!(matches!(
        ldp::delete(&store, BASE, "/~/c/", &alice(), ROOT),
        Err(LdpError::Forbidden)
    ));
    assert!(ldp::read(&store, None, BASE, "/~/c/m", &alice(), None).is_ok());
}

#[test]
fn the_storage_root_cannot_be_deleted() {
    let (_m, _d, store) = pod();
    assert!(matches!(
        ldp::delete(&store, BASE, "/~/", &alice(), ROOT),
        Err(LdpError::Forbidden)
    ));
    assert!(meta(&store, ROOT).is_some());
}
```

`put_turtle(&store, …)` passes `&Arc<Pod>` where `&Pod` is expected, which
deref coercion handles, as everywhere else in these files.

- [ ] **Step 4: `ldp_nonrdf.rs`**

The file's own fixture struct is called `Pod` (`:34-38`), which would clash
with `brolly_store::resources::Pod` in the helpers. Rename it to `Fixture` and
keep its fields' names, so every `pod.store` / `pod.blobs` call site stays:

```rust
struct Fixture {
    store: std::sync::Arc<Pod>,
    blobs: BlobStore,
    _stores: brolly_store::StoreManager,
    _dir: tempfile::TempDir,
}

/// A pod whose root ACL grants Alice read and write.
fn pod() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let stores = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    let user = Uuid::new_v4();
    let store = stores.pod(user).unwrap();
    let blobs = stores.blobs(user).unwrap();

    store.write(|w| w.create_root(ROOT)).unwrap();
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    grant(
        &store,
        &g,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}agent"), WEBID),
        ],
    );

    Fixture {
        store,
        blobs,
        _stores: stores,
        _dir: dir,
    }
}
```

The imports become:

```rust
use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp::{self, LdpError, PatchBody};
use brolly_solid::patch::PatchError;
use brolly_store::BlobStore;
use brolly_store::resources::{Content, Kind, Pod, PodRead, ResourceMeta};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;
```

Then, by anchor:

- **`a_binary_is_typed_as_a_non_rdf_source`**: replace everything after the
  `put` with:

  ```rust
      let resource = format!("{BASE}/~/avatar.png");
      let recorded = meta(&pod.store, &resource).expect("the binary exists");
      assert!(matches!(recorded.kind, Kind::NonRdfSource));
      let own: Vec<Quad> = pod
          .store
          .read_store()
          .quads_for_pattern(None, None, None, Some(GraphNameRef::NamedNode(n(&resource).as_ref())))
          .map(Result::unwrap)
          .collect();
      assert!(own.is_empty(), "the blob pointer is the server's, not in the graph: {own:?}");
  ```

- **`a_binary_is_listed_by_its_container`**, **`posting_a_binary_to_a_container_mints_a_member`**:
  `storage::members(&pod.store.read_store(), X)` → `members(&pod.store, X)`.
- **`deleting_a_binary_removes_its_bytes`**, **`turtle_still_goes_to_the_graph_and_not_the_blob_store`**:
  `ldp::blob_digest(&pod.store.read_store(), X)` → `ldp::blob_digest(&pod.store, X)`.
- **Every `ldp::delete(&pod.store, Some(&pod.blobs), BASE, …)`**: drop the
  `Some(&pod.blobs),` argument.
- **`replacing_a_binary_replaces_the_bytes`**: after the first `put(PNG);`
  add

  ```rust
      let old = ldp::blob_digest(&pod.store, &format!("{BASE}/~/avatar.png")).unwrap();
  ```

  and after the final `assert_eq!` add

  ```rust
      assert!(
          !pod.blobs.contains(&old),
          "the replaced bytes are released once nothing names them"
      );
  ```

Append two tests:

```rust
#[test]
fn a_binary_cannot_be_patched() {
    let pod = pod();
    ldp::put(&pod.store, Some(&pod.blobs), BASE, "/~/avatar.png", &alice(), PNG, "image/png", ROOT)
        .unwrap();
    let err = ldp::patch(
        &pod.store,
        BASE,
        "/~/avatar.png",
        &alice(),
        PatchBody::SparqlUpdate("INSERT DATA { <a:b> <a:c> <a:d> }"),
        ROOT,
    )
    .unwrap_err();
    assert!(matches!(err, PatchError::Ldp(LdpError::NotRdf)), "got {err:?}");
}

#[test]
fn a_non_rdf_post_to_a_document_is_not_rdf() {
    let pod = pod();
    ldp::put(&pod.store, Some(&pod.blobs), BASE, "/~/note", &alice(), b"<#it> <https://example.org/p> <https://example.org/o> .", "text/turtle", ROOT)
        .unwrap();
    let err = ldp::append(&pod.store, Some(&pod.blobs), BASE, "/~/note", &alice(), PNG, "image/png", ROOT)
        .unwrap_err();
    assert!(matches!(err, LdpError::NotRdf), "got {err:?}");
}
```

`grant`, `meta` and `members` come from Step 1. `ResourceMeta` is named by
`meta`'s signature, `Content` by `grant`.

- [ ] **Step 5: `acl_control.rs`**

`pod()` (`:69-99`): replace chunk 2's
`store.write(|w| storage::init_storage_root(w, ROOT)).unwrap();` with
`store.write(|w| w.create_root(ROOT)).unwrap();`, and its `seed(&store, &[…])`
with `grant(&store, &g, &[…])`. In `shared_pod()` (`:102-129`) and
`wac_allow_on_an_acl_is_all_or_nothing` (`:360`), `seed(&store, &[…])` becomes
`grant(&store, &g, &[…])`.

By anchor:

| Test | Was (chunk 2) | Becomes |
|---|---|---|
| `bob_cannot_read_rewrite_or_delete_the_containers_acl` | `ldp::delete(&store, None, BASE, …)` | `ldp::delete(&store, BASE, …)` |
| `bob_cannot_create_the_acl_of_a_document_he_can_write` | `!storage::exists(&store.read_store(), X)` | `meta(&store, X).is_none()` |
| `the_owner_can_do_all_of_it` | `ldp::delete(&store, None, BASE, …)` ×3; `!storage::exists(…)` | drop `None,`; `meta(&store, X).is_none()` |
| `an_acl_is_not_a_member_of_its_container` | `storage::members(&store.read_store(), X)` | `members(&store, X)` |
| `an_acl_does_not_create_the_container_it_governs` | `storage::exists(…acl)`, `!storage::exists(…newdir)`, `storage::members(…ROOT)` | `matches!(meta(&store, X).unwrap().kind, Kind::Auxiliary)`, `meta(&store, &newdir).is_none()`, `members(&store, ROOT)` |
| `deleting_a_resource_deletes_its_acl` | `ldp::delete(&store, None, …)`; `!storage::exists(…)` ×2 | drop `None,`; `meta(&store, X).is_none()` |
| `a_recreated_container_does_not_get_its_old_grants_back` | `ldp::delete(&store, None, …)`; `!storage::exists(…)` | drop `None,`; `meta(&store, X).is_none()` |

Delete `stale_acl_containment_is_swept_and_a_rerun_removes_nothing`
(`:556-590`). It plants old-layout containment with `add_containment` and
sweeps it with `uncontain_acls`; the upgrade drops that containment now
(Task 1's `forged_containment_is_dropped`), and chunk 4 removes the sweep.

Append:

```rust
/// An ACL is a resource: it exists, has a version, and goes with what it
/// governs.
#[test]
fn an_acl_exists_has_a_version_and_goes_with_its_resource() {
    let (_m, _d, store) = shared_pod();
    let doc = format!("{ROOT}shared/doc");
    ldp::put(&store, None, BASE, "/~/shared/doc", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        acl_granting(ALICE, &doc).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let acl = meta(&store, &format!("{doc}.acl")).expect("the ACL exists");
    assert!(matches!(acl.kind, Kind::Auxiliary));
    assert!(!acl.version.is_empty());

    ldp::delete(&store, BASE, "/~/shared/doc", &alice(), ROOT).unwrap();
    assert!(meta(&store, &format!("{doc}.acl")).is_none());
}

#[test]
fn an_acl_takes_an_rdf_body_only() {
    let (_m, _d, store) = shared_pod();
    let err = ldp::put(&store, None, BASE, "/~/shared/.acl", &alice(), b"\x89PNG", "image/png", ROOT)
        .unwrap_err();
    assert!(matches!(err, LdpError::NotRdf), "got {err:?}");
}
```

`storage` leaves the imports, and so does chunk 2's `seed` if nothing else
calls it.

- [ ] **Step 6: `publication_boundary.rs` and `patch_conformance.rs`**

`publication_boundary.rs`, `fixture()` (`:51-80`): replace chunk 2's
`init_storage_root` write and `seed(&pod, &[…])` with one write that records
the root and its ACL:

```rust
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    let grants = [
        t(&g, &a, &format!("{ACL}default"), ROOT),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(&g, &a, &format!("{ACL}agent"), "https://alice.brolly.id/profile#me"),
    ];
    pod.write(|w| {
        w.create_root(ROOT)?;
        w.put(&g, Content::Auxiliary(&grants))?;
        Ok(())
    })
    .unwrap();
```

Imports: `use brolly_solid::{ldp, storage};` → `use brolly_solid::ldp;`; add
`Content` to the `brolly_store::resources` import; drop `seed` if unused. In
`deleting_pod_content_also_publishes_nothing`,
`ldp::delete(&f.pod, None, BASE, …)` → `ldp::delete(&f.pod, BASE, …)`.

`patch_conformance.rs`: the resource under patch must exist in metadata, so
`pod()` (`:20-36`) records the root and the document instead of seeding them:

```rust
const ROOT: &str = "https://alice.brolly.id/~/";

fn pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();

    let original = [Quad::new(
        NamedOrBlankNode::NamedNode(n(RESOURCE)),
        n("https://example.org/title"),
        Term::Literal(oxigraph::model::Literal::new_simple_literal("Original")),
        GraphName::NamedNode(n(RESOURCE)),
    )];
    store
        .write(|w| {
            w.create_root(ROOT)?;
            w.put(RESOURCE, Content::Rdf(&original))?;
            Ok(())
        })
        .unwrap();
    (mgr, dir, store)
}
```

Add `Content` to its `brolly_store::resources` import and drop `seed`.
Chunk 2's `n3`/`sparql` helpers call `patch::apply_n3_patch(w, RESOURCE, …)`
and `apply_sparql_update` inside `store.write`, and stay as they are. Their
signatures don't change in this task.

- [ ] **Step 7: Run the Solid tests and watch them fail**

Run: `cargo test -p brolly-solid`
Expected: FAIL to compile. `error[E0061]: this function takes 6 arguments but
5 arguments were supplied` at every `ldp::delete`, and `error[E0425]: cannot
find function `patch` in module `ldp`` / `cannot find type `PatchBody``.

- [ ] **Step 8: `ldp.rs`: imports, conversions, and the blob and read side**

Replace `ldp.rs`'s imports (chunk 2's, at `:11-19`):

```rust
use std::collections::BTreeSet;

use brolly_authz::{AccessMode, authorize, effective_acl};
use brolly_domain::syntax::{self, ReadFormat, SyntaxError, WriteFormat};
use brolly_domain::vocab;
use brolly_identity::Subject;
use brolly_store::resources::{
    self, BlobMeta, Content, Kind, Pod, PodRead, PodWrite, ResourceRead,
};
use brolly_store::{BlobStore, StoreError};
use oxigraph::model::{GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};

use crate::patch::{self, PatchError};
use crate::storage;
```

Update the module doc (`:1-9`) by appending:

```rust
//!
//! **Two layers.** The outer functions ([`read`], [`put`], [`append`],
//! [`delete`], [`patch`]) take a [`Pod`]. Each checks WAC, writes any blob
//! bytes, and runs one `Pod::write` (or reads one `Pod::read` snapshot). The
//! `_in` functions take the open [`PodWrite`] and check WAC against its
//! snapshot, for callers composing several operations in one transaction
//! (Mastodon's upload and its alt text).
//!
//! **Server-managed state comes from metadata** (`store::resources`):
//! existence, kind, containment and a binary's blob. None of it is read from
//! the graph a client writes, so an `ldp:contains` or `brolly:blobDigest`
//! triple in an ordinary document is inert data.
```

Replace chunk 2's `impl From<StoreError> for LdpError` with one that keeps the
refusals `PodWrite` makes:

```rust
impl From<StoreError> for LdpError {
    fn from(e: StoreError) -> Self {
        match e {
            // `put` refuses an IRI outside the pod's root. The outer functions
            // check first, so this is the same refusal reached another way.
            StoreError::NotUnderRoot => LdpError::OutsideStorage,
            // Stage 0's answer to a populated container, until 5b's 409.
            StoreError::ContainerNotEmpty => LdpError::Forbidden,
            StoreError::BlobMissing => LdpError::BlobMissing,
            other => LdpError::Store(other.to_string()),
        }
    }
}
```

Keep the `From<SyntaxError>` and `From<oxigraph::store::StorageError>` impls.

Replace the blob constants, `blob_digest`, `literal_object` and
`digest_still_referenced` (`:65-112`) with:

```rust
/// The blob terms live in `vocab` now. Re-exported under their old names only
/// until chunk 4 moves Mastodon's blob reads onto metadata.
pub use brolly_domain::vocab::{
    BROLLY_BLOB_DIGEST as BLOB_DIGEST, BROLLY_BYTE_SIZE as BLOB_SIZE,
    BROLLY_MEDIA_TYPE as BLOB_MEDIA_TYPE,
};

/// The digest recorded for `resource`, if it is a binary. From metadata only.
pub fn blob_digest(pod: &Pod, resource: &str) -> Option<String> {
    pod.read(|r| r.meta(resource))
        .ok()
        .flatten()
        .and_then(|meta| meta.blob)
        .map(|blob| blob.digest)
}
```

(If chunk 1 or 2 already removed the old constant names, leave the `pub use`
out.)

`LdpOutcome`, `iri`, `governed`, `check`, `granted_modes` and `may_write` stay
as chunk 2 left them (`&impl PodRead`). Replace `read` (`:203-265`) with:

```rust
/// `GET` / `HEAD` an LDP resource, from one snapshot.
///
/// A caller without Read gets `NotFound`, not `Forbidden`: telling an
/// unauthorized caller that a resource exists is itself a disclosure, and the
/// predecessor's WAC leaked existence this way.
pub fn read(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    accept: Option<&str>,
) -> Result<LdpOutcome, LdpError> {
    pod.read(|r| Ok(read_in(r, blobs, base, path, subject, accept)))?
}

/// [`read`] against a snapshot the caller holds.
pub fn read_in(
    r: &ResourceRead<'_>,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    accept: Option<&str>,
) -> Result<LdpOutcome, LdpError> {
    let resource = format!("{base}{path}");
    if !check(r, base, path, subject, AccessMode::Read)? {
        return Err(LdpError::NotFound);
    }
    let Some(meta) = r.meta(&resource)? else {
        return Err(LdpError::NotFound);
    };
    let granted = granted_modes(r, base, path, subject);

    // A binary answers with its bytes. The ACL check above already ran, so
    // there is no path to the blob store that skips authorization.
    if matches!(meta.kind, Kind::NonRdfSource) {
        let blob = meta
            .blob
            .ok_or_else(|| LdpError::Store(format!("{resource} has no blob recorded")))?;
        let bytes = blob_store(blobs)?
            .get(&blob.digest)?
            // The metadata says there are bytes and there are not. That is a
            // broken pod, not a missing resource.
            .ok_or_else(|| LdpError::Store(format!("blob {} is missing", blob.digest)))?;
        return Ok(LdpOutcome {
            body: bytes,
            media_type: blob.media_type,
            granted,
            is_container: false,
        });
    }

    let node = iri(&resource);
    let mut quads = r
        .quads_for_pattern(None, None, None, Some(GraphNameRef::NamedNode(node.as_ref())))
        .collect::<Result<Vec<Quad>, _>>()?;
    let is_container = matches!(meta.kind, Kind::Container);
    if is_container {
        // Its types and its listing come from metadata, never from its graph.
        quads.extend(resources::container_triples(r, &resource)?);
    }

    let format = syntax::negotiate(accept);
    Ok(LdpOutcome {
        body: syntax::serialize(&quads, format)?,
        media_type: format.media_type().to_string(),
        granted,
        is_container,
    })
}
```

- [ ] **Step 9: `ldp.rs`: bodies, and `put`**

Replace `put` and `contain` (chunk 2's, `:267-336` at f564eb6) with:

```rust
/// A request body, ready to write: parsed later against its target's IRI, or
/// already in the blob store.
pub enum Body {
    /// RDF. Parsed in `put_in`/`append_in`, because the base IRI is the target.
    Rdf { bytes: Vec<u8>, format: ReadFormat },
    /// A binary whose bytes [`prepare`] has already written to the blob store.
    Binary(BlobMeta),
}

/// Get a body ready to write.
///
/// A non-RDF body's bytes go into the blob store here, **before** the pod's
/// write lock is taken, so an upload doesn't queue other writers behind its
/// disk I/O. Content addressing makes this idempotent. RDF/XML is refused
/// rather than stored as a blob (ADR 0007): storing it defers the parse rather
/// than avoiding it, and the two live `quick-xml` advisories are reachable
/// either way.
pub fn prepare(
    blobs: Option<&BlobStore>,
    body: &[u8],
    content_type: &str,
) -> Result<Body, LdpError> {
    refuse_rdf_xml(content_type)?;
    if syntax::is_parseable_rdf(content_type) {
        return Ok(Body::Rdf {
            bytes: body.to_vec(),
            format: syntax::read_format(content_type)?,
        });
    }
    Ok(Body::Binary(BlobMeta {
        digest: blob_store(blobs)?.put(body)?,
        media_type: syntax::media_type_of(content_type).to_string(),
        byte_size: u64::try_from(body.len()).unwrap_or(u64::MAX),
    }))
}

fn blob_store(blobs: Option<&BlobStore>) -> Result<&BlobStore, LdpError> {
    blobs.ok_or_else(|| LdpError::Store("no blob store for this pod".into()))
}
```

The checks an outer write makes before it takes the lock, shared by `put`
and `append`:

```rust
/// What an outer write function checks before it takes the lock.
struct Target<'a> {
    pod: &'a Pod,
    base: &'a str,
    path: &'a str,
    subject: &'a Subject,
    storage_root: &'a str,
}

impl Target<'_> {
    /// Refuse what can be refused without the lock, then [`prepare`] the body.
    ///
    /// - Outside the root is refused first, as before.
    /// - `rdf_only` targets (a container or an ACL for PUT, a document for
    ///   POST) refuse a binary body here, before its bytes reach the disk.
    ///   `put_in`/`append_in` refuse it too, for callers that skip this.
    /// - WAC is checked against the committed store *before* any bytes land,
    ///   so a caller who may not write leaves nothing in the blob store.
    ///   `put_in`/`append_in` check again inside the transaction.
    fn prepare(
        &self,
        blobs: Option<&BlobStore>,
        rdf_only: bool,
        mode: AccessMode,
        body: &[u8],
        content_type: &str,
    ) -> Result<Body, LdpError> {
        let resource = format!("{}{}", self.base, self.path);
        if !resource.starts_with(self.storage_root) {
            return Err(LdpError::OutsideStorage);
        }
        refuse_rdf_xml(content_type)?;
        let rdf = syntax::is_parseable_rdf(content_type);
        if !rdf && rdf_only {
            return Err(LdpError::NotRdf);
        }
        if !rdf
            && !check(&self.pod.read_store(), self.base, self.path, self.subject, mode)?
        {
            return Err(LdpError::Forbidden);
        }
        prepare(blobs, body, content_type)
    }
}
```

Then `put`:

```rust
/// `PUT` — create or replace a resource.
///
/// Requires Write. Replacing is not Append: a client that may only add triples
/// must not be able to erase the ones already there.
pub fn put(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
) -> Result<(), LdpError> {
    let resource = format!("{base}{path}");
    let rdf_only = storage::is_container(&resource) || governed(&resource).is_some();
    let target = Target { pod, base, path, subject, storage_root };
    let attempt = || -> Result<(), LdpError> {
        let body = target.prepare(blobs, rdf_only, AccessMode::Write, body, content_type)?;
        in_write(pod, |w| put_in(w, base, path, subject, &body, storage_root))
    };
    // Identical bytes released by a concurrent delete between `prepare` and
    // the write: write them again and retry, once (spec 5a, R12).
    match attempt() {
        Err(LdpError::BlobMissing) => attempt(),
        other => other,
    }
}
```

(The WAC pre-check runs only for a binary body, the only case that writes
before the lock. An RDF body's check happens once, in `put_in`.)

- [ ] **Step 10: `ldp.rs`: `put_in` and the container rule**

Directly after `put`:

```rust
/// [`put`] inside the caller's write. Checks WAC against the transaction's
/// snapshot, then writes with the `Content` the target calls for:
///
/// - an ACL: `Content::Auxiliary`, RDF only (stage 0's Control rule is in
///   `check`);
/// - a container (the path ends in `/`): RDF only, under [`container_body`]'s
///   rule, as `Content::Container`; its members are untouched;
/// - a document: `Content::Rdf`, stored exactly as sent;
/// - a binary: `Content::Binary`, then the previous blob, if any, is released.
///
/// Every refusal comes before the first write.
pub fn put_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &Body,
    storage_root: &str,
) -> Result<(), LdpError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Forbidden);
    }

    if governed(&resource).is_some() {
        let quads = rdf_quads(body, &resource)?;
        w.put(&resource, Content::Auxiliary(&quads))?;
        return Ok(());
    }
    if storage::is_container(&resource) {
        let quads = rdf_quads(body, &resource)?;
        let kept = container_body(&*w, &resource, quads)?;
        w.put(&resource, Content::Container(&kept))?;
        return Ok(());
    }

    let previous = w.meta(&resource)?.and_then(|meta| meta.blob).map(|blob| blob.digest);
    let current = match body {
        Body::Rdf { .. } => {
            let quads = rdf_quads(body, &resource)?;
            w.put(&resource, Content::Rdf(&quads))?;
            None
        }
        Body::Binary(blob) => {
            w.put(
                &resource,
                Content::Binary(BlobMeta {
                    digest: blob.digest.clone(),
                    media_type: blob.media_type.clone(),
                    byte_size: blob.byte_size,
                }),
            )?;
            Some(blob.digest.as_str())
        }
    };
    // Released, not deleted: `Pod::write` deletes it after the commit, and
    // only if nothing else in the pod still names it.
    if let Some(previous) = previous
        && current != Some(previous.as_str())
    {
        w.release_blob(&previous);
    }
    Ok(())
}

/// Parse an RDF body into `resource`'s own graph, or refuse a binary.
fn rdf_quads(body: &Body, resource: &str) -> Result<Vec<Quad>, LdpError> {
    match body {
        Body::Rdf { bytes, format } => parse_into_graph(bytes, *format, resource),
        Body::Binary(_) => Err(LdpError::NotRdf),
    }
}

/// The part of a container's body that is the client's to store.
///
/// - **Containment.** `<container> ldp:contains ?x` triples must name exactly
///   the current members, so a GET-edit-PUT round trip works. A body with none
///   leaves membership alone. Any other set is `ContainmentChange` (Solid
///   Protocol §5.3). Either way none of them is stored: containment lives in
///   metadata.
/// - **Echoed server types** are dropped: `ldp:Resource`, `ldp:Container`,
///   `ldp:BasicContainer`, and `pim:Storage` at the root.
/// - **The rest** is kept.
fn container_body(
    r: &impl PodRead,
    container: &str,
    quads: Vec<Quad>,
) -> Result<Vec<Quad>, LdpError> {
    let node = NamedOrBlankNode::NamedNode(iri(container));
    // What a GET serves from metadata: the types and the listing.
    let served = resources::container_triples(r, container)?;
    let members: BTreeSet<String> = served
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::LDP_CONTAINS)
        .map(|q| q.object.to_string())
        .collect();
    let is_root = served
        .iter()
        .any(|q| matches!(&q.object, Term::NamedNode(t) if t.as_str() == vocab::PIM_STORAGE));

    let mut named = BTreeSet::new();
    let mut kept = Vec::new();
    for quad in quads {
        let about_it = quad.subject == node;
        if about_it && quad.predicate.as_str() == vocab::LDP_CONTAINS {
            named.insert(quad.object.to_string());
            continue;
        }
        // An echo of a type the server serves isn't the client's to store.
        let echoed = about_it
            && quad.predicate.as_str() == vocab::RDF_TYPE
            && is_served_type(&quad.object, is_root);
        if !echoed {
            kept.push(quad);
        }
    }
    if !named.is_empty() && named != members {
        return Err(LdpError::ContainmentChange);
    }
    Ok(kept)
}

fn is_served_type(object: &Term, is_root: bool) -> bool {
    let Term::NamedNode(t) = object else {
        return false;
    };
    matches!(
        t.as_str(),
        vocab::LDP_RESOURCE | vocab::LDP_CONTAINER | vocab::LDP_BASIC_CONTAINER
    ) || (is_root && t.as_str() == vocab::PIM_STORAGE)
}

/// Run `f` in one `Pod::write`, keeping its own error type.
///
/// `Pod::write` speaks `StoreError`. When `f` refuses, the closure returns an
/// `Err`, so the transaction rolls back, and the refusal is handed back as it
/// was.
fn in_write<T, E: From<StoreError>>(
    pod: &Pod,
    f: impl FnOnce(&mut PodWrite<'_>) -> Result<T, E>,
) -> Result<T, E> {
    let mut refusal = None;
    let written = pod.write(|w| {
        f(w).map_err(|e| {
            refusal = Some(e);
            StoreError::Backend("refused, and rolled back".into())
        })
    });
    match (written, refusal) {
        (Ok(value), _) => Ok(value),
        (Err(_), Some(refusal)) => Err(refusal),
        (Err(e), None) => Err(E::from(e)),
    }
}
```


- [ ] **Step 11: `ldp.rs`: `append`, `delete` and `patch`**

Delete `blob_quads` (`:348-391`); nothing writes blob triples into a graph any
more. Replace chunk 2's `append` with:

```rust
/// `POST` — create a member of a container, or append triples to a document.
///
/// Requires Append, which Write satisfies (`acl:Write` implies `acl:Append`).
pub fn append(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
) -> Result<String, LdpError> {
    // Appending to a document takes RDF; a container's new member may be a
    // binary.
    let rdf_only = !storage::is_container(&format!("{base}{path}"));
    let target = Target { pod, base, path, subject, storage_root };
    let attempt = || -> Result<String, LdpError> {
        let body = target.prepare(blobs, rdf_only, AccessMode::Append, body, content_type)?;
        in_write(pod, |w| append_in(w, base, path, subject, &body, storage_root))
    };
    match attempt() {
        Err(LdpError::BlobMissing) => attempt(),
        other => other,
    }
}

/// [`append`] inside the caller's write.
///
/// POST to a container is a `put` of the minted member. POST to a document is
/// stage 0's append, unchanged until 5c, and takes RDF only.
pub fn append_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &Body,
    storage_root: &str,
) -> Result<String, LdpError> {
    let target = format!("{base}{path}");
    if !target.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Append)? {
        return Err(LdpError::Forbidden);
    }

    if storage::is_container(&target) {
        let member = format!("{target}{}", uuid::Uuid::new_v4());
        match body {
            Body::Rdf { .. } => {
                let quads = rdf_quads(body, &member)?;
                w.put(&member, Content::Rdf(&quads))?;
            }
            Body::Binary(blob) => {
                w.put(
                    &member,
                    Content::Binary(BlobMeta {
                        digest: blob.digest.clone(),
                        media_type: blob.media_type.clone(),
                        byte_size: blob.byte_size,
                    }),
                )?;
            }
        }
        return Ok(member);
    }

    let quads = rdf_quads(body, &target)?;
    w.append(&target, &quads)?;
    Ok(target)
}
```

Replace chunk 2's `delete` with:

```rust
/// `DELETE`.
pub fn delete(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
    storage_root: &str,
) -> Result<(), LdpError> {
    in_write(pod, |w| delete_in(w, base, path, subject, storage_root))
}

/// [`delete`] inside the caller's write.
///
/// `remove` takes the resource's `.acl` with it (Solid Protocol §5.4), so a
/// recreated resource can't quietly get its old grants back, and releases its
/// blob. Content addressing means two resources can name one blob, which is
/// why the blob is released rather than deleted here.
pub fn delete_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    storage_root: &str,
) -> Result<(), LdpError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Forbidden);
    }
    let Some(meta) = w.meta(&resource)? else {
        return Err(LdpError::NotFound);
    };
    // Without its root a pod has nowhere to put anything, and only
    // provisioning records one. 5b answers 405 here.
    if resource == storage_root {
        return Err(LdpError::Forbidden);
    }
    // Refusing to delete a non-empty container is LDP's rule, and it is the
    // difference between removing a resource and silently orphaning a subtree.
    if matches!(meta.kind, Kind::Container) && !w.members(&resource)?.is_empty() {
        return Err(LdpError::Forbidden);
    }
    w.remove(&resource)?;
    Ok(())
}
```

Replace `may_write`'s doc comment (`:443-446`) with "May this subject write
to `path`? For callers outside a write; `patch_in` checks inside one." (the
body stays). Then add, after `delete_in`:

```rust
/// A PATCH body, by its content type.
pub enum PatchBody<'a> {
    /// `text/n3`: an N3 Patch.
    N3(&'a [u8]),
    /// `application/sparql-update`.
    SparqlUpdate(&'a str),
}

/// `PATCH`: WAC, the patch, and the write, in one transaction.
pub fn patch(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
    body: PatchBody<'_>,
    storage_root: &str,
) -> Result<(), PatchError> {
    in_write(pod, |w| patch_in(w, base, path, subject, body, storage_root))
}

/// [`patch`] inside the caller's write. A patch mutates, so it needs Write
/// (Control, on an ACL). A binary has no triples to patch.
pub fn patch_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: PatchBody<'_>,
    storage_root: &str,
) -> Result<(), PatchError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(PatchError::Ldp(LdpError::OutsideStorage));
    }
    if !check(&*w, base, path, subject, AccessMode::Write).map_err(PatchError::Ldp)? {
        return Err(PatchError::Ldp(LdpError::Forbidden));
    }
    if w.meta(&resource)?
        .is_some_and(|meta| matches!(meta.kind, Kind::NonRdfSource))
    {
        return Err(PatchError::Ldp(LdpError::NotRdf));
    }
    match body {
        PatchBody::N3(body) => patch::apply_n3_patch(w, &resource, body),
        PatchBody::SparqlUpdate(sparql) => patch::apply_sparql_update(w, &resource, sparql),
    }
}

/// Write a patched graph with the `Content` its target calls for: an ACL as
/// `Auxiliary`, a container under [`container_body`]'s rule, anything else as
/// an RDF document. A patch that creates a resource contains it, because `put`
/// does.
///
/// A patch's `solid:where` can't match a container's `ldp:contains`, because
/// containment isn't in the content graph (a known limitation; 5c revisits it).
pub(crate) fn store_patched(
    w: &mut PodWrite<'_>,
    resource: &str,
    patched: Vec<Quad>,
) -> Result<(), LdpError> {
    if governed(resource).is_some() {
        w.put(resource, Content::Auxiliary(&patched))?;
    } else if storage::is_container(resource) {
        let kept = container_body(&*w, resource, patched)?;
        w.put(resource, Content::Container(&kept))?;
    } else {
        w.put(resource, Content::Rdf(&patched))?;
    }
    Ok(())
}
```

`refuse_rdf_xml`, `parse_into_graph`, `accepted_write_types`, `served_types`
and the tests module stay.

- [ ] **Step 12: `patch.rs` writes through `ldp::store_patched`**

Replace the imports (chunk 2's, `:19-24`):

```rust
use brolly_store::StoreError;
use brolly_store::resources::{PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, Quad};
use oxigraph::sparql::SparqlEvaluator;
use oxigraph::store::Store;
use oxttl::N3Parser;
use oxttl::n3::{N3Quad, N3Term};

use crate::ldp::{self, LdpError};
```

Add a variant to `PatchError` (after `Store(String)`) and its `Display` arm,
and a conversion:

```rust
    /// Refused by the LDP layer: WAC, the containment rule, a binary target,
    /// or the root.
    Ldp(LdpError),
```

```rust
            PatchError::Ldp(e) => write!(f, "{e}"),
```

```rust
impl From<StoreError> for PatchError {
    fn from(e: StoreError) -> Self {
        PatchError::Ldp(LdpError::from(e))
    }
}
```

In `apply_scoped`, replace chunk 2's final write

```rust
    // Every PATCH target is under the storage root (`pod.rs` refuses the rest).
    w.legacy_under_root()
        .replace_graph(resource, &patched)
        .map_err(|e| PatchError::Store(e.to_string()))?;
    Ok(())
```

with

```rust
    // The target's kind decides the `Content`, and a container's body is held
    // to the containment rule, exactly as a PUT would be.
    ldp::store_patched(w, resource, patched).map_err(PatchError::Ldp)
```

and in the same function change `oxigraph::model::GraphName::DefaultGraph` to
`GraphName::DefaultGraph` (now imported). Update `apply_scoped`'s doc: the
sentence "the write goes through `brolly_store::write::replace_graph`" becomes
"the write goes through `PodWrite::put`". The scratch store stays an
in-memory `Store`: it's a separate store, not the pod, so it can't deadlock
with the pod's transaction.

- [ ] **Step 13: `storage.rs` shrinks to path helpers**

Replace the module doc and everything above `parent_container` with:

```rust
//! Path helpers for the storage root.
//!
//! Existence, containment and the root itself live in the pod's metadata
//! (`brolly_store::resources`); this module only reads IRIs.
```

Keep `parent_container`, `is_container` and the tests module as they are.
Delete `remove_containment`. Move the remaining old-layout items below a fence
at the end of the file (above `#[cfg(test)]`), because server code and tests
that chunk 4 converts still call them:

```rust
// --- Old layout: chunk 4 deletes this section with its last callers --------
//
// `provision::pod`, `maintenance.rs` and the server test harnesses still call
// these until chunk 4 converts or removes them. Nothing in this crate does.
```

The section holds, as chunk 2 left them: the five `LDP_*`/`PIM_STORAGE`
constants, `add_containment`, `members`, `uncontain_acls`,
`is_acl_containment` and `exists`, plus the `use` lines only they need. One
change: `init_storage_root` becomes a shim onto metadata, so it no longer uses
`legacy_under_root`:

```rust
/// Record `root` as the pod's storage root. A shim until chunk 4 moves its
/// callers to `PodWrite::create_root`.
pub fn init_storage_root(w: &mut PodWrite<'_>, root: &str) -> Result<(), StoreError> {
    w.create_root(root)
}
```

`add_containment` and `uncontain_acls` still use `legacy_under_root`. Chunk 4
must delete them before (or in) its Task 5, which deletes that method; see the
notes for the reviewer.

- [ ] **Step 14: `pod.rs` calls the new `delete` and `patch`**

`delete` (`:418-440`): drop the `Some(&request.blobs),` argument.

`patch` (`:354-416`): replace everything after the `resolve` block with:

```rust
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let patch_body = match content_type.split(';').next().unwrap_or_default().trim() {
        "text/n3" => ldp::PatchBody::N3(&body),
        "application/sparql-update" => match std::str::from_utf8(&body) {
            Ok(sparql) => ldp::PatchBody::SparqlUpdate(sparql),
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "body is not UTF-8").into_response();
            }
        },
        other => {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("PATCH accepts text/n3 or application/sparql-update, not {other}"),
            )
                .into_response();
        }
    };

    // WAC, the patch and the write, in one transaction.
    match ldp::patch(
        &request.pod,
        &request.base,
        &path,
        &request.subject,
        patch_body,
        &request.storage_root,
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(patch::PatchError::Ldp(e)) => ldp_error(e),
        Err(patch::PatchError::Precondition(m)) => (StatusCode::CONFLICT, m).into_response(),
        Err(patch::PatchError::EscapesGraph) => (
            StatusCode::FORBIDDEN,
            "a PATCH may not name a GRAPH or WITH",
        )
            .into_response(),
        Err(patch::PatchError::Malformed(m) | patch::PatchError::NotAPatch(m)) => {
            (StatusCode::BAD_REQUEST, m).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "patch failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
```

`request.pod` is the `Arc<Pod>` field chunk 1/2 gave `PodRequest`; use its
name if it kept `store`. The early `OutsideStorage` check and the `may_write`
call go: `patch_in` does both, inside the transaction.

- [ ] **Step 15: Run the Solid tests and watch them pass**

Run: `cargo test -p brolly-solid`
Expected: PASS, including the ten new tests in `ldp_conformance`, two in
`ldp_nonrdf` and two in `acl_control`.

Run: `grep -n "legacy_under_root\|storage::exists\|storage::members" adapters/solid/src/ldp.rs adapters/solid/src/patch.rs`
Expected: no output.

- [ ] **Step 16: Format**

```bash
cargo fmt --all
```

- [ ] **Step 17: Gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p brolly-store -p brolly-authz -p brolly-solid
```

Expected: clean, and PASS. `cargo test --workspace` now fails in the server
tests listed at the top of this chunk; that's expected until chunk 4.

- [ ] **Step 18: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs adapters/solid/src/patch.rs adapters/solid/src/storage.rs \
        adapters/solid/tests/ldp_conformance.rs adapters/solid/tests/ldp_nonrdf.rs \
        adapters/solid/tests/acl_control.rs adapters/solid/tests/publication_boundary.rs \
        adapters/solid/tests/patch_conformance.rs server/src/pod.rs
```

---

### Task 5: WAC picks the governing ACL by metadata

Spec *ACLs exist by metadata* (R16). `effective_acl` asks which candidates are
recorded as `brolly:Auxiliary`, instead of which have triples. An emptied ACL
then governs, and grants nothing.

**Files:**
- Modify: `authz/src/wac.rs` (imports; `effective_acl`, `:105-148`)
- Modify: `authz/tests/conformance_matrix.rs` (`fixture`, `matrix` paths, `direct_acl_wins_over_inherited`, `an_accessto_grant_does_not_leak_through_inheritance`; one new test)
- Modify: `adapters/solid/tests/acl_control.rs` (one new test)

- [ ] **Step 1: Write the failing tests**

Append to `adapters/solid/tests/acl_control.rs`:

```rust
/// Solid's rule: an existing ACL governs, and an empty one grants nothing. It
/// must not fall through to the container's broader `acl:default`.
#[test]
fn an_empty_acl_governs_and_grants_nothing() {
    let (_m, _d, store) = shared_pod();
    ldp::put(&store, None, BASE, "/~/shared/doc", &alice(), NOTE, "text/turtle", ROOT).unwrap();
    assert!(
        ldp::granted_modes(&store.read_store(), BASE, "/~/shared/doc", &bob())
            .contains(&AccessMode::Write),
        "precondition: the container's default reaches Bob"
    );

    ldp::put(&store, None, BASE, "/~/shared/doc.acl", &alice(), b"", "text/turtle", ROOT).unwrap();

    assert!(meta(&store, &format!("{ROOT}shared/doc.acl")).is_some());
    assert!(
        ldp::granted_modes(&store.read_store(), BASE, "/~/shared/doc", &bob()).is_empty(),
        "an empty ACL fell through to the container's default"
    );
    assert!(matches!(
        ldp::read(&store, None, BASE, "/~/shared/doc", &bob(), None),
        Err(LdpError::NotFound)
    ));
}
```

In `authz/tests/conformance_matrix.rs`, the fixture moves under a storage
root: only a resource under the root has metadata, so an ACL at
`https://alice.brolly.id/public.acl` could never be recorded. Add

```rust
const ROOT: &str = "https://alice.brolly.id/~/";
```

and add `Content` to its `brolly_store::resources` import. Replace chunk 2's
`fixture()` with:

```rust
fn fixture() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mgr = StoreManager::open(dir.path(), 4, 60).expect("manager");
    let store = mgr.pod(Uuid::new_v4()).expect("pod");

    let authorization = |g: &str, fragment: &str, pairs: &[(&str, String)]| -> Vec<Quad> {
        let a = format!("{g}#{fragment}");
        pairs
            .iter()
            .map(|(p, o)| t(g, &a, &format!("{ACL}{p}"), o))
            .collect()
    };
    let mut acls: Vec<(String, Vec<Quad>)> = Vec::new();

    // /~/public.acl — public read.
    let g = format!("{ROOT}public.acl");
    let quads = authorization(&g, "public", &[
        ("accessTo", format!("{ROOT}public")),
        ("mode", format!("{ACL}Read")),
        ("agentClass", format!("{FOAF}Agent")),
    ]);
    acls.push((g, quads));

    // /~/members.acl — any authenticated agent may read.
    let g = format!("{ROOT}members.acl");
    let quads = authorization(&g, "members", &[
        ("accessTo", format!("{ROOT}members")),
        ("mode", format!("{ACL}Read")),
        ("agentClass", format!("{ACL}AuthenticatedAgent")),
    ]);
    acls.push((g, quads));

    // /~/bob-only.acl — one specific WebID, read + write.
    let g = format!("{ROOT}bob-only.acl");
    let quads = authorization(&g, "bob", &[
        ("accessTo", format!("{ROOT}bob-only")),
        ("mode", format!("{ACL}Read")),
        ("mode", format!("{ACL}Write")),
        ("agent", "https://bob.example/profile#me".to_string()),
    ]);
    acls.push((g, quads));

    // /~/friends.acl — group access. The group document lives at a graph the
    // ACL does not name, which is what the predecessor's fragment-stripping
    // assumed.
    let g = format!("{ROOT}friends.acl");
    let quads = authorization(&g, "friends", &[
        ("accessTo", format!("{ROOT}friends")),
        ("mode", format!("{ACL}Read")),
        ("agentGroup", format!("{ROOT}groups/inner#g")),
    ]);
    acls.push((g, quads));

    let group_doc = format!("{ROOT}groups/somewhere-else");
    let group = [t(
        &group_doc,
        &format!("{ROOT}groups/inner#g"),
        &format!("{VCARD}hasMember"),
        "https://carol.example/profile#me",
    )];

    // /~/notes/.acl — inherited default: authenticated append on the container.
    let g = format!("{ROOT}notes/.acl");
    let quads = authorization(&g, "inherit", &[
        ("default", format!("{ROOT}notes/")),
        ("mode", format!("{ACL}Write")),
        ("agentClass", format!("{ACL}AuthenticatedAgent")),
    ]);
    acls.push((g, quads));

    store
        .write(|w| {
            w.create_root(ROOT)?;
            for (acl, quads) in &acls {
                w.put(acl, Content::Auxiliary(quads))?;
            }
            w.put(&group_doc, Content::Rdf(&group))?;
            Ok(())
        })
        .expect("seed acls");
    (mgr, dir, store)
}
```

In `matrix()`, each `path:` gains the `/~` prefix: `"/public"` →
`"/~/public"`, and likewise `/members`, `/bob-only`, `/friends`,
`/notes/first` and `/nothing-here`. The `/~/nothing-here` case still expects
no grant: this fixture records no root ACL. In `direct_acl_wins_over_inherited`,
the paths become `"/~/notes/first"` and `"/~/public"`, and the expected IRIs
`format!("{ROOT}notes/.acl")`, `format!("{ROOT}notes/")` and
`format!("{ROOT}public.acl")`. In
`an_accessto_grant_does_not_leak_through_inheritance`, `graph` and `scope`
become `format!("{ROOT}public.acl")` and `format!("{ROOT}public")`. Chunk 2's
`seed` goes if nothing uses it.

Append:

```rust
#[test]
fn an_empty_recorded_acl_governs_and_grants_nothing() {
    let (_mgr, _dir, store) = fixture();
    let locked = format!("{ROOT}notes/locked.acl");
    store
        .write(|w| w.put(&locked, Content::Auxiliary(&[])).map(|_| ()))
        .expect("record an empty ACL");

    let reader = store.read_store();
    let acl = effective_acl(&reader, BASE, "/~/notes/locked")
        .unwrap()
        .expect("the empty ACL governs");
    assert_eq!(acl.graph.as_str(), locked);
    assert!(acl.direct);
    let dave = Agent::Authenticated("https://dave.example/profile#me".to_string());
    assert!(
        !authorize(&reader, &acl, &dave, AccessMode::Append).unwrap(),
        "an empty ACL grants nothing, whatever the container's default says"
    );
    // Its sibling still inherits the container's.
    assert!(surface_allows(
        Surface::Solid,
        &reader,
        "/~/notes/first",
        &dave,
        AccessMode::Append
    ));
}
```

(`surface_allows` takes `&impl PodRead` since chunk 2.)

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-authz --test conformance_matrix`
Expected: `an_empty_recorded_acl_governs_and_grants_nothing` FAILS at
`expect("the empty ACL governs")` (found `/~/notes/.acl` instead: an empty
graph is invisible to `GRAPH ?acl { ?s ?p ?o }`). The rest pass.

Run: `cargo test -p brolly-solid --test acl_control an_empty_acl`
Expected: FAIL, "an empty ACL fell through to the container's default".

- [ ] **Step 3: Find ACLs by metadata**

In `authz/src/wac.rs`, add to the imports:

```rust
use brolly_store::resources::METADATA_GRAPH;
```

Replace `effective_acl`'s doc comment and its query (the `let query = …;`
statement):

```rust
/// Find the ACL that governs `path`.
///
/// **One query, not one probe per level.** Candidates are generated in Rust,
/// then a single `SELECT` asks which of them exist; the caller takes the most
/// specific. The predecessor issued a `resource_exists` round trip per
/// hierarchy level.
///
/// **An ACL exists when the pod's metadata records it** (spec 5a, R16), not
/// when its graph has triples. So an emptied ACL governs, and grants nothing,
/// instead of falling through to an ancestor's broader `acl:default`. Which
/// authorizations it holds is still read from its graph, by [`authorize`].
```

```rust
    // Candidates are server-generated from a validated path, never user text.
    let query = format!(
        r#"
        SELECT DISTINCT ?acl WHERE {{
          VALUES ?acl {{ {values} }}
          GRAPH <{METADATA_GRAPH}> {{ ?acl a <{auxiliary}> }}
        }}
        "#,
        auxiliary = vocab::BROLLY_AUXILIARY,
    );
```

The metadata graph is named through the constant, so the IRI is still spelled
only in `resources.rs` (chunk 4's architecture rule).

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-authz -p brolly-solid`
Expected: PASS.

- [ ] **Step 5: Format**

```bash
cargo fmt --all
```

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p brolly-store -p brolly-authz -p brolly-solid
```

- [ ] **Step 7: Stage, don't commit**

```bash
git add authz/src/wac.rs authz/tests/conformance_matrix.rs adapters/solid/tests/acl_control.rs
```

Chunk 4 continues commit 2 and commits it.


## Chunk 4: Posts, media and provisioning on metadata; the switch lands (commit 2, part B)

Spec sections: *Every writer uses `Pod::write`* (the `inbox`, `outbox`,
`mastodon_api` and `provision` rows), *Deciding from the IRI, not the caller*,
*Updating a stage 0 comment*, *Architecture tests*, *`acl-uncontain` is
removed*, *No rollback*, and **Testing** for `federation_flows.rs`,
`mastodon_*.rs`, `auth_flow.rs` and the *After an upgrade* case in
`pod_http.rs`.

This chunk and chunk 3 are **rollout commit 2, one commit**. Chunk 3's tasks
and Tasks 1–7 here stage; **only Task 8 commits.** Don't commit in between: the
trees in the middle either serve pods without metadata (provisioning still
writing the old layout) or still carry `legacy_under_root`, the bypass this
commit exists to remove.

**What changes, in one place:**

| File | Change |
|---|---|
| `server/src/provision.rs` | `pod` takes `&Pod`, runs `create_root` then the root ACL as `Content::Auxiliary`, in one `Pod::write` |
| `store/src/resources.rs` | `PodWrite::under_root` (public); `legacy_under_root` and `LegacyWriter` deleted |
| `adapters/activitypub/src/inbox.rs` | `deliver`/`remove` decide from each IRI: `put`/`remove` under the root, outside-root methods elsewhere |
| `adapters/activitypub/src/processor.rs` | the stage 0 "An LDP resource is never…" comment rewritten |
| `server/src/outbox.rs` | the author's copy (or Delete) and its outbox entry in one `Pod::write`, closed before the recipient `.await`s |
| `server/src/mastodon_api.rs` | upload: `put_in` + alt text in one closure; alt text updates via `append`; `get_media`/`update_media`/`create_status` read blob metadata |
| `server/src/maintenance.rs`, `server/tests/maintenance.rs`, `server/tests/admin_cli.rs` | deleted |
| `server/src/lib.rs`, `server/src/bin/admin.rs` | `maintenance` and `acl-uncontain` gone |
| `adapters/solid/src/storage.rs`, `adapters/solid/tests/acl_control.rs` | `uncontain_acls` and its test gone (if chunk 3 left them) |
| `test-support/src/lib.rs` | `TestDb.url` gone (only `admin_cli.rs` read it) |
| `docs/deploying.md` | the acl-uncontain section becomes the forward-only note |
| `docs/specs/2026-09-22-solid-resource-metadata.md` | `doc-paths: skip` marker (it cites `server/src/maintenance.rs`, deleted here) |
| `server/tests/architecture.rs` | two rules: only `resources.rs` names `urn:brolly:resources`; `raw_store` only in test code |
| tests | `store/tests/resources.rs`, `server/tests/{auth_flow,federation_flows,mastodon_compose,pod_http}.rs` |

**Line numbers** are as of HEAD `f564eb6`. Chunks 1–3 move most of these
files, so every step also names its anchor (a function, a comment's first
line). Go by the anchor.

### Interfaces this chunk consumes

From the fixed cross-chunk list, used as written: `Pod::{read, read_store,
write, raw_store}`, `PodWrite::{meta, put, append, remove, create_root, graph,
insert, remove_quads, replace_graph, clear_graph}`, `PodRead`, `Content`,
`ResourceMeta`, `Kind`, `BlobMeta`, `StoreError::{UnderRoot, NotUnderRoot,
BlobMissing}`, `store::resources::upgrade`, `METADATA_GRAPH`.

Assumed from chunks 1–3. They aren't in the fixed list. **If a chunk named one
differently, substitute its name and keep the structure shown here:**

| Assumed | Where it comes from |
|---|---|
| `ResourceRead::meta(&self, &str) -> Result<Option<ResourceMeta>, StoreError>` | chunk 1; `ldp::read` needs it for "existence from metadata in one snapshot" |
| `inbox::deliver(&mut PodWrite, inbox, activity, received_at)`, `inbox::remove(&mut PodWrite, inbox, activity)`, `InboxError: From<StorageError>` | chunk 2 |
| `processor::process_member(w: &mut PodWrite<'_>, inbox: &str, outbox: &str, activity: &Value, received_at: &str) -> Result<(), ProcessError>` | chunk 2 (spec: `process_member(&mut PodWrite, …)`) |
| `collection::literal(&impl PodRead, subject, predicate)`, `follows::followers(&impl PodRead, …)`, `inbox::read_activity(&impl PodRead, …)` | chunk 2 |
| Test harnesses: `stores.pod(id)` / `h.pod(name)` return `Arc<Pod>` | chunk 2 |
| `ldp::prepare(blobs: Option<&BlobStore>, body: &[u8], content_type: &str) -> Result<ldp::Body, LdpError>` writes a non-RDF body's bytes to the `BlobStore` and returns the prepared body; `ldp::put_in(w, base, path, subject, &Body, storage_root) -> Result<(), LdpError>`; `LdpError::BlobMissing` | chunk 3 (spec *Writing*: outer functions write the bytes, then run one `Pod::write` around `put_in`). `ldp::put`'s own body is the reference: `upload_media` does what it does, plus the alt-text `append` in the same closure |

---

### Task 1: Provisioning records the root

Every server test that provisions a pod (`federation_flows`, `mastodon_*`,
`auth_flow`, `dashboard`) needs a root in metadata before LDP on metadata can
answer anything, so this goes first. **If chunk 3 already converted
`provision::pod`, check it matches Step 3, run Steps 1–2 and 4 as a
regression test, and skip Step 3.**

**Files:**
- Modify: `server/src/provision.rs` (imports `:12-16`, `pod` `:35-70`)
- Test: `server/tests/auth_flow.rs` (imports `:7-12`; new helper after `register_alice` `:116-134`; new test after `registering_provisions_a_pod_the_member_can_write_to` `:401-450`)

- [ ] **Step 1: Write the failing test**

In `server/tests/auth_flow.rs`, add to the imports:

```rust
use std::sync::{Arc, Mutex};

use brolly_store::resources::Kind;
use tracing_subscriber::layer::SubscriberExt;
```

`tracing` and `tracing-subscriber` are `brolly-server` `[dependencies]`, so
its integration tests can use them without a manifest change.

After `register_alice`, add the log capture:

```rust
/// Every `error` event emitted on this thread while it's installed, as text.
///
/// `#[tokio::test]` runs the test and the handlers it drives on one thread, so
/// a thread-local subscriber sees everything registration logs.
struct ErrorLog {
    events: Arc<Mutex<Vec<String>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl ErrorLog {
    fn install() -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Collect(Arc::clone(&events)));
        Self {
            events,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

struct Collect(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collect {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() == tracing::Level::ERROR {
            let mut text = event.metadata().target().to_string();
            event.record(&mut Fields(&mut text));
            self.0.lock().unwrap().push(text);
        }
    }
}

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}
```

After `registering_provisions_a_pod_the_member_can_write_to`:

```rust
/// Stage 5a: registration opens a brand-new pod, which the upgrade marks
/// current on the spot, and provisioning records its root and root ACL in the
/// pod's metadata. None of that is an error.
///
/// Reopening the pod is what shows it's at layout 2. An unmarked pod would be
/// upgraded again, find no old-layout root (provisioning never writes one), and
/// log at `error`.
#[tokio::test]
async fn a_new_registrations_pod_starts_on_the_current_layout() {
    let errors = ErrorLog::install();
    let (db, dir, router) = harness().await;
    register_alice(&db, &router).await;
    let alice = db::find_by_username(&db.pool, "alice")
        .await
        .unwrap()
        .expect("registration created alice");

    // Close every store the server holds, so the pod is opened afresh.
    drop(router);
    let stores =
        brolly_store::StoreManager::open(dir.path(), 4, 60).expect("reopen the stores");
    let pod = stores.pod(alice.id).expect("reopen alice's pod");

    let root = pod
        .read(|r| r.meta("https://alice.brolly.test/~/"))
        .unwrap()
        .expect("provisioning recorded the storage root");
    assert!(matches!(root.kind, Kind::Container), "the root is a container");
    let acl = pod
        .read(|r| r.meta("https://alice.brolly.test/~/.acl"))
        .unwrap()
        .expect("the root ACL is a resource");
    assert!(matches!(acl.kind, Kind::Auxiliary), "the root ACL is auxiliary");

    assert_eq!(
        errors.take(),
        Vec::<String>::new(),
        "registering or reopening the pod logged an error"
    );
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-server --test auth_flow a_new_registrations_pod_starts_on_the_current_layout`
Expected: FAIL, panicking with `provisioning recorded the storage root`.
Chunk 2 left `provision::pod` writing the old layout through
`legacy_under_root`, which records no metadata.

- [ ] **Step 3: Implement**

In `server/src/provision.rs`, replace the imports `:12-16` with:

```rust
use brolly_identity::db::{self, DbError};
use brolly_identity::{routing, webid};
use brolly_store::StoreError;
use brolly_store::resources::{Content, Pod};
use oxigraph_model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use sqlx::PgPool;
use uuid::Uuid;
```

Replace `pod` (the doc comment at `:35` through `:70`, whatever chunk 2 left
in its body) with:

```rust
/// Create a member's storage root and the ACL that makes it theirs.
///
/// One write. `create_root` records the root in the pod's metadata, and only
/// provisioning calls it. The ACL is stored as an auxiliary resource, so it
/// exists and has a version but is never a member of the root. A root without
/// its ACL is a pod its owner can't write to, so the two commit together or
/// not at all.
///
/// The grant carries **both** `acl:accessTo` and `acl:default`: the first
/// governs the container itself, the second governs everything inside it. They
/// are distinct scopes, and conflating them is how an ACL silently grants more
/// or less than intended.
pub fn pod(pod: &Pod, username: &str, base_domain: &str) -> Result<(), StoreError> {
    let root = routing::storage_root(username, base_domain);
    let acl = format!("{root}.acl");
    let owner = format!("{acl}#owner");
    let member = webid::webid(username, base_domain);

    let grant = [
        triple(&acl, &owner, &format!("{ACL}accessTo"), &root),
        triple(&acl, &owner, &format!("{ACL}default"), &root),
        triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        triple(
            &acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ),
        triple(&acl, &owner, &format!("{ACL}agent"), &member),
    ];

    pod.write(|w| {
        w.create_root(&root)?;
        w.put(&acl, Content::Auxiliary(&grant))?;
        Ok(())
    })
}
```

The only caller, `server/src/auth.rs:332`, passes `&pod` (an `Arc<Pod>`, which
derefs) and logs the error with `%e`, so it compiles unchanged. Test callers
`.unwrap()` the result.

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-server --test auth_flow`
Expected: all pass, including the new test and
`registering_provisions_a_pod_the_member_can_write_to`.

- [ ] **Step 5: Format**

```bash
cargo fmt --all
```

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 7: Stage, don't commit**

```bash
git add server/src/provision.rs server/tests/auth_flow.rs
```

Commit 2 is one commit. Task 8 commits.

---

### Task 2: Posts are pod resources; a recipient's copy isn't

**Files:**
- Modify: `store/src/resources.rs` (`impl PodWrite`, next to chunk 1's under-root methods)
- Modify: `adapters/activitypub/src/inbox.rs` (imports `:14-17`, `InboxError` `From` impls `:61-71`, `deliver` `:76-126`, `write_record` `:128-136`, `clear_received_at` `:138-152`, `remove` `:154-177`)
- Modify: `adapters/activitypub/src/processor.rs` (the comment in the member `Delete` branch, `:117-124`, first line `// Remove only what delivery put there`)
- Modify: `server/src/outbox.rs` (`authored` doc `:155-159`; `deliver` from `let received = now();` `:268` through the end of the author's-copy `if`/`else` `:296`; a new `rollback` helper after `deliver`)
- Test: `store/tests/resources.rs` (chunk 1's file), `server/tests/federation_flows.rs` (a `get` helper in `impl Harness` `:91-197`; two tests after `publishing_stores_the_post_in_the_authors_own_pod` `:563-592`)

- [ ] **Step 1: Write the failing store test**

Append to `store/tests/resources.rs`. Self-contained, so it doesn't depend on
chunk 1's helpers:

```rust
/// `inbox` decides per IRI which family of methods to use, so it needs the
/// same test `put` and the outside-root methods apply, and they must agree.
#[test]
fn under_root_is_the_test_put_and_the_outside_root_methods_apply() {
    let dir = tempfile::tempdir().unwrap();
    let stores = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    let pod = stores.pod(uuid::Uuid::new_v4()).unwrap();
    let root = "https://alice.brolly.test/~/";
    let note = "https://alice.brolly.test/~/notes/1";
    let foreign = "https://bob.brolly.test/~/notes/1";

    pod.write(|w| {
        assert!(!w.under_root(note)?, "a pod with no root has nothing under it");
        w.create_root(root)?;
        assert!(w.under_root(note)?);
        assert!(w.under_root(root)?);
        assert!(!w.under_root("https://alice.brolly.test/inbox")?);
        assert!(!w.under_root(foreign)?);

        assert!(matches!(
            w.replace_graph(note, &[]),
            Err(brolly_store::StoreError::UnderRoot)
        ));
        assert!(matches!(
            w.put(foreign, brolly_store::resources::Content::Rdf(&[])),
            Err(brolly_store::StoreError::NotUnderRoot)
        ));
        Ok(())
    })
    .unwrap();
}
```

If `store/tests/resources.rs` doesn't already import `tempfile` and `uuid`
through its dev-dependencies, chunk 1 added them for its own tests. Check
`store/Cargo.toml` `[dev-dependencies]`.

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-store --test resources under_root`
Expected: compile error, `error[E0599]: no method named 'under_root' found for mutable reference '&mut PodWrite<'_>'`.

- [ ] **Step 3: Implement `PodWrite::under_root`**

In `store/src/resources.rs`, inside `impl PodWrite`, next to the under-root
methods. Chunk 1's `put` already finds the root for its `NotUnderRoot`
refusal, and the outside-root methods already test membership for their
`UnderRoot` refusal. **Expose that same test.** If chunk 1 has a private helper
doing exactly this, make it `pub` under this name with this doc comment.
Otherwise add:

```rust
    /// Whether `iri` names a resource under this pod's storage root, by the
    /// same test `put` and the outside-root methods apply. False while the pod
    /// has no root recorded.
    ///
    /// For a caller storing protocol records that must pick, per IRI, between
    /// `put`/`remove` and the outside-root methods, as `activitypub::inbox`
    /// does.
    pub fn under_root(&self, iri: &str) -> Result<bool, StoreError> {
        let storage = self
            .quads_for_pattern(
                None,
                Some(NamedNodeRef::new_unchecked(vocab::RDF_TYPE)),
                Some(NamedNodeRef::new_unchecked(vocab::PIM_STORAGE).into()),
                Some(NamedNodeRef::new_unchecked(METADATA_GRAPH).into()),
            )
            .next()
            .transpose()?;
        Ok(match storage.map(|quad| quad.subject) {
            Some(NamedOrBlankNode::NamedNode(root)) => iri.starts_with(root.as_str()),
            _ => false,
        })
    }
```

If chunk 1's membership test differs from `starts_with` (for example it
normalises the IRI first), use chunk 1's, so the three can't disagree. That's
what the last two assertions in Step 1 check. `vocab::PIM_STORAGE` is chunk
1's name for `http://www.w3.org/ns/pim/space#Storage`. Import `NamedNodeRef`
and `NamedOrBlankNode` from `oxigraph::model` if the file doesn't already.

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-store --test resources under_root`
Expected: 1 passed.

- [ ] **Step 5: Write the failing federation tests**

In `server/tests/federation_flows.rs`, add to the imports:

```rust
use brolly_store::resources::Kind;
```

Add to `impl Harness`, after `get_status`:

```rust
    /// GET a path in a member's pod as Turtle, for its status and body.
    async fn get(&self, username: &str, cookie: &str, path: &str) -> (StatusCode, String) {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, format!("{username}.{BASE}"))
                    .header(header::ACCEPT, "text/turtle")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                .to_string();
        (status, body)
    }
```

After `publishing_stores_the_post_in_the_authors_own_pod`:

```rust
// --- posts are pod resources (stage 5a) --------------------------------------

/// A post is an LDP resource in its author's pod: the note is listed in
/// `/~/notes/` and its `Create` in `/~/activities/`. The author's `Delete`
/// de-lists both, because it goes through the same `remove` an LDP DELETE
/// does.
#[tokio::test]
async fn a_published_note_is_listed_in_the_authors_notes_until_she_deletes_it() {
    let h = harness().await;
    let alice = h.login("alice").await;

    let (status, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "listed", "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "publish: {created}");
    let note = created["object"]["id"].as_str().unwrap().to_string();
    let activity = created["id"].as_str().unwrap().to_string();
    let note_path = note
        .strip_prefix(&format!("https://alice.{BASE}"))
        .unwrap()
        .to_string();

    let (status, notes) = h.get("alice", &alice, "/~/notes/").await;
    assert_eq!(status, StatusCode::OK, "{notes}");
    assert!(notes.contains(&note), "the note isn't listed: {notes}");
    let (status, activities) = h.get("alice", &alice, "/~/activities/").await;
    assert_eq!(status, StatusCode::OK, "{activities}");
    assert!(
        activities.contains(&activity),
        "the Create isn't listed: {activities}"
    );
    assert_eq!(h.get_status("alice", &alice, &note_path).await, StatusCode::OK);

    let (status, _) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Delete", "object": note, "to": [PUBLIC]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, notes) = h.get("alice", &alice, "/~/notes/").await;
    assert_eq!(status, StatusCode::OK, "the container outlives its last member");
    assert!(!notes.contains(&note), "the deleted note is still listed: {notes}");
    let (_, activities) = h.get("alice", &alice, "/~/activities/").await;
    assert!(
        !activities.contains(&activity),
        "the deleted post's Create is still listed: {activities}"
    );
    assert_eq!(
        h.get_status("alice", &alice, &note_path).await,
        StatusCode::NOT_FOUND
    );
}

/// A follower's copy lives under the author's origin, so it can never be under
/// the follower's storage root. It's protocol state in their pod, not a
/// resource, and their own storage doesn't list it.
#[tokio::test]
async fn a_followers_copy_of_a_post_is_not_a_resource_in_their_pod() {
    let h = harness().await;
    let alice = h.login("alice").await;
    let bob = h.login("bob").await;
    h.publish(
        "bob",
        &bob,
        &json!({"type": "Follow", "object": actor("alice")}),
    )
    .await;
    let (_, created) = h
        .publish(
            "alice",
            &alice,
            &json!({"type": "Note", "content": "for my followers", "to": [PUBLIC]}),
        )
        .await;
    let note = created["object"]["id"].as_str().unwrap().to_string();

    // Setup: bob has the copy, or the rest proves nothing.
    assert!(inbox::read_activity(&h.pod("bob").read_store(), &note).is_some());

    assert!(
        !matches!(h.pod("bob").read(|r| r.meta(&note)), Ok(Some(_))),
        "bob's copy of alice's note was recorded as a resource in his pod"
    );
    let (status, listing) = h.get("bob", &bob, "/~/").await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(
        !listing.contains(&format!("alice.{BASE}")),
        "bob's storage lists something of alice's: {listing}"
    );

    // The same note is a resource in its author's pod.
    assert!(matches!(
        h.pod("alice").read(|r| r.meta(&note)),
        Ok(Some(meta)) if matches!(meta.kind, Kind::RdfSource)
    ));
}
```

- [ ] **Step 6: Run them and watch them fail**

Run: `cargo test -p brolly-server --test federation_flows -- a_published_note_is_listed a_followers_copy`
Expected:
- `a_published_note_is_listed_in_the_authors_notes_until_she_deletes_it`
  FAILS at the first `assert_eq!(status, StatusCode::OK, …)` with `left: 404`.
  `inbox` still writes the note through `legacy_under_root`, so `/~/notes/` is
  recorded nowhere.
- `a_followers_copy_of_a_post_is_not_a_resource_in_their_pod` FAILS at its
  last assertion: alice's note has no metadata in her own pod either. Its
  first two assertions already pass. They're the guard against Step 7
  over-recording.

- [ ] **Step 7: `inbox` decides from the IRI**

In `adapters/activitypub/src/inbox.rs`, the imports become:

```rust
use brolly_domain::faithful;
use brolly_store::StoreError;
use brolly_store::resources::{Content, PodRead, PodWrite};
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode, Quad, Term,
};
use serde_json::Value;
```

Keep `use brolly_store::write::WriteError;` only if `impl From<WriteError> for
InboxError` is still there and chunk 2 kept it. It's harmless either way. Make
sure this impl exists. Add it next to the other `From` impls if chunk 2 didn't:

```rust
impl From<StoreError> for InboxError {
    fn from(e: StoreError) -> Self {
        InboxError::Store(e.to_string())
    }
}
```

Replace `deliver`, `write_record`, `clear_received_at` and `remove`, whatever
chunk 2 left in them, with:

```rust
/// Store an activity in an inbox or outbox collection.
///
/// Idempotent: a remote instance may deliver to both the shared inbox and the
/// personal one, and arriving twice must not show the post twice. The graph is
/// named by the activity IRI and containment is a single triple, so a repeat
/// delivery rewrites the same quads rather than adding more.
///
/// The activity and any embedded object each get their own graph, and
/// [`write_record`] decides from each IRI whether that graph is a resource in
/// this pod or a copy of someone else's. The collection entry is protocol
/// state outside the storage root either way.
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

/// Store one record as its own graph, replacing whatever was there.
///
/// Where it goes is decided from its IRI, never by the caller. Under this
/// pod's storage root it's the author's own note or activity, and `put`
/// records it as a resource: it exists, it's listed in its container, and it
/// has a version, like anything written over LDP. Anywhere else it's a copy of
/// someone else's post: protocol state, with no metadata. So an author's post
/// is always a pod resource, and a recipient's copy, under another origin,
/// never is.
fn write_record(w: &mut PodWrite<'_>, id: &str, record: &Value) -> Result<(), InboxError> {
    let node = iri(id);
    let quads = faithful::encode(record, &node, &node, AS2).map_err(InboxError::Encode)?;
    // Replace rather than merge: a redelivered activity that lost a field
    // should not keep the old value alongside the new one.
    if w.under_root(id)? {
        w.put(id, Content::Rdf(&quads))?;
    } else {
        w.replace_graph(id, &quads)?;
    }
    Ok(())
}

fn clear_received_at(w: &mut PodWrite<'_>, inbox: &str, activity: &str) -> Result<(), InboxError> {
    let existing = w
        .quads_for_pattern(
            Some(NamedNodeRef::new_unchecked(activity).into()),
            Some(NamedNodeRef::new_unchecked(RECEIVED_AT)),
            None,
            Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(inbox))),
        )
        .collect::<Result<Vec<Quad>, _>>()?;
    w.remove_quads(&existing)?;
    Ok(())
}

/// Drop an activity from an inbox, graph and all.
///
/// Both halves matter: a membership row left pointing at a cleared graph is a
/// hole in every timeline that tries to render it.
///
/// The graph goes the way [`write_record`] stored it. A resource under this
/// pod's root goes through `remove`, which also takes it out of its container
/// and drops its metadata. `remove` of one already gone is a no-op, so a
/// Delete that reaches the same graph twice doesn't fail. A copy under another
/// origin is cleared.
pub fn remove(w: &mut PodWrite<'_>, inbox: &str, activity: &str) -> Result<(), InboxError> {
    let inbox_node = iri(inbox);

    w.remove_quads(&[Quad::new(
        NamedOrBlankNode::NamedNode(inbox_node.clone()),
        iri(LDP_CONTAINS),
        Term::NamedNode(iri(activity)),
        GraphName::NamedNode(inbox_node),
    )])?;
    clear_received_at(w, inbox, activity)?;
    if w.under_root(activity)? {
        w.remove(activity)?;
    } else {
        w.clear_graph(activity)?;
    }
    Ok(())
}
```

`quads_for_pattern` is a `PodRead` method, hence that import. Its items are
`Result<Quad, oxigraph::store::StorageError>`. `InboxError` already converts
from that (`:67-71`). If chunk 1's `PodRead` yields `StoreError` instead, the
`From<StoreError>` above covers it.

- [ ] **Step 8: Rewrite the stage 0 comment in `processor.rs`**

In `adapters/activitypub/src/processor.rs`, in the member `Delete` branch
(`process_member` after chunk 2; `process_for_member` `:116-140` at HEAD),
replace the comment starting `// Remove only what delivery put there` (`:117-124`)
with:

```rust
        // Remove only what delivery put there: a graph on the actor's origin
        // that arrived as the embedded object of one of the actor's activities,
        // in this pod's inbox (a recipient's copy) or outbox (the author's own).
        //
        // Origin alone isn't enough. The owner's pod receives the owner's own
        // activities, so a Delete naming their `/~/.acl` would pass it and
        // remove the ACL without WAC ever seeing the request. Posts are LDP
        // resources in their author's pod, so what keeps a Delete to posts is
        // three facts together:
        // - It removes only what a same-origin activity listed in this pod's
        //   inbox or outbox carried in as its embedded object.
        // - The server mints every such id, under `/~/notes/`
        //   (`outbox::as_activity`, checked again by `outbox::authored`).
        // - LDP writes can't create inbox or outbox entries. Those collections
        //   live outside `/~/`, where `ldp::put` refuses to write.
```

The code under it is unchanged.

- [ ] **Step 9: The outbox writes the author's copy once**

In `server/src/outbox.rs`, the `authored` doc (`:155-159`) becomes:

```rust
/// Does this activity name only graphs the server minted for its author?
///
/// `base` is the author's origin, `https://<username>.<base_domain>`. The
/// author's own copy, which `deliver` writes without going through the
/// processor, lands only where this allows: an activity under `/~/activities/`
/// and a note under `/~/notes/`. Both are resources in the author's pod, and
/// none of the author's other resources can be reached this way.
```

In `deliver`, replace everything from `let received = now();` (`:268`) through
the closing brace of the author's-copy `if`/`else` (`:296`, just before
`// A Follow is also a relationship`) with:

```rust
    let received = now();
    let Ok(author_pod) = state.stores.pod(author.id) else {
        return Err(DeliverError::Failed);
    };
    let inbox = webid::inbox(&author.username, &state.base_domain);
    let outbox = webid::outbox(&author.username, &state.base_domain);

    // The author holds their own post — content lives in exactly one place (D2)
    // and this is it. The note and its activity are resources under the
    // author's `/~/`, listed in `/~/notes/` and `/~/activities/`, and the outbox
    // entry naming the activity lives outside it. One write covers all three,
    // so a failure can't leave a post the outbox doesn't list. A Delete removes
    // rather than stores, in the same single write.
    //
    // `Pod::write` is synchronous, so this write is closed before the recipient
    // loop's first `.await`, and no member's delivery waits on the author's
    // lock.
    let deleting = activity["type"] == "Delete";
    let stored = author_pod.write(|w| {
        if deleting {
            processor::process_member(w, &inbox, &outbox, activity, &received).map_err(rollback)
        } else {
            brolly_activitypub::inbox::deliver(w, &outbox, activity, &received)
                .map(|_| ())
                .map_err(rollback)
        }
    });
    if let Err(e) = stored {
        let what = if deleting { "removing" } else { "storing" };
        tracing::error!(error = %e, "{what} the author's copy failed");
        return Err(DeliverError::Failed);
    }
```

The rest of `deliver` (the Follow bookkeeping, the recipient loop, the
instance) is chunk 2's and stays. Check that it matches the spec's outbox row:
the Follow bookkeeping in its own `author_pod.write`, and each
`deliver_locally` running its recipient's writes in its own `Pod::write`.

After `deliver`, add:

```rust
/// The `StoreError` that makes `Pod::write` roll back, keeping the failure's
/// message for the log. A delivery failure isn't a storage error, but the
/// closure has to return one to abort.
fn rollback(e: impl std::fmt::Display) -> brolly_store::StoreError {
    brolly_store::StoreError::Backend(e.to_string())
}
```

If chunk 2 already wrote an equivalent helper in this file, use it instead.

- [ ] **Step 10: Run them and watch them pass**

Run: `cargo test -p brolly-server --test federation_flows && cargo test -p brolly-activitypub && cargo test -p brolly-store --test resources`
Expected: all pass. The processor's own tests (`adapters/activitypub/tests/processor.rs`)
use pods with no root, where `under_root` is false everywhere, so they take the
outside-root path they took before and need no change.
`a_delete_of_your_own_note_removes_every_copy` and
`an_owner_cannot_delete_their_own_acl_through_the_outbox` now run through
`PodWrite::remove` for the author's copies and must still pass unchanged.

- [ ] **Step 11: Format**

```bash
cargo fmt --all
```

- [ ] **Step 12: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 13: Stage, don't commit**

```bash
git add store/src/resources.rs store/tests/resources.rs \
        adapters/activitypub/src/inbox.rs adapters/activitypub/src/processor.rs \
        server/src/outbox.rs server/tests/federation_flows.rs
```

---

### Task 3: Mastodon media on metadata, with its alt text in the same write

**Files:**
- Modify: `server/src/mastodon_api.rs`: imports `:14-27`; `upload_media` `:481-560` (from `let id = status_id::mint_note_id();` `:521` through the alt-text block `:547`); `set_alt_text` `:562-574` and `alt_text` `:576-578` replaced; `update_media` from `let Ok(pod)` `:617` to its end `:640`; `get_media` from `let Ok(pod)` `:659` to its end `:678`; `create_status`'s attachment loop `:726-758`
- Test: `server/tests/mastodon_compose.rs` (imports `:15-20`; new test after `alt_text_can_be_set_after_upload_and_before_posting` `:262-295`)

- [ ] **Step 1: Write the failing test**

In `server/tests/mastodon_compose.rs`, add to the imports:

```rust
use brolly_store::resources::{Kind, PodRead};
use oxigraph::model::{GraphNameRef, NamedNodeRef};
```

After `alt_text_can_be_set_after_upload_and_before_posting`:

```rust
async fn get_media(h: &Harness, token: &str, media_id: &str) -> Reply {
    send(
        h,
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/media/{media_id}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// Stage 5a: an upload's media type and blob live in the pod's resource
/// metadata, not in triples a client could write. `GET` and `PUT` on the media
/// read them from there, and the alt text sent with an upload arrives in the
/// same write as the upload itself.
#[tokio::test]
async fn an_upload_reads_back_from_metadata_with_its_alt_text() {
    let h = harness().await;
    let (user, token) = a_member(&h, "alice").await;

    let media_id = upload(&h, &token, Some("a small dog")).await;
    let got = get_media(&h, &token, &media_id).await;
    assert_eq!(got.status, StatusCode::OK, "body: {}", got.body);
    assert_eq!(got.json()["type"], "image", "the media type wasn't read from metadata");
    assert_eq!(
        got.json()["description"], "a small dog",
        "the alt text sent with the upload was lost"
    );
    let iri = got.json()["url"].as_str().unwrap().to_string();

    // The server recorded the blob as the upload's metadata, and nothing in the
    // upload's own graph names it.
    let pod = h.stores.pod(user).unwrap();
    let meta = pod
        .read(|r| r.meta(&iri))
        .unwrap()
        .expect("the upload is a pod resource");
    assert!(matches!(meta.kind, Kind::NonRdfSource));
    assert_eq!(meta.blob.expect("with blob metadata").media_type, "image/png");
    let pointers = pod
        .read_store()
        .quads_for_pattern(
            None,
            Some(NamedNodeRef::new_unchecked("https://brolly.id/ns#blobDigest")),
            None,
            Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(&iri))),
        )
        .count();
    assert_eq!(pointers, 0, "a blob pointer is still in the content graph");

    // Alt text added later reads back through the same path.
    let later = upload(&h, &token, None).await;
    let updated = send(
        &h,
        Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/media/{later}"))
            .header(header::HOST, BASE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("description=added%20later"))
            .unwrap(),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "body: {}", updated.body);
    assert_eq!(updated.json()["type"], "image");
    let got = get_media(&h, &token, &later).await;
    assert_eq!(got.json()["type"], "image");
    assert_eq!(got.json()["description"], "added later");
}
```

`oxigraph` is already a `brolly-server` dev-dependency (`server/Cargo.toml`).

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p brolly-server --test mastodon_compose an_upload_reads_back_from_metadata`
Expected: FAIL at `the media type wasn't read from metadata`, `left: "unknown"`,
`right: "image"`. `get_media` still reads `BLOB_MEDIA_TYPE` from the content
graph, where chunk 3's `put` no longer writes it. Depending on what chunk 3
left in `get_media`, it may fail earlier instead, with `404` at the status
assertion if the existence check still reads the content graph.
`an_uploaded_image_reaches_the_post` fails the same way on its `type`
assertion.

- [ ] **Step 3: Implement**

In `server/src/mastodon_api.rs`, add to the imports:

```rust
use brolly_store::StoreError;
use brolly_store::resources::{Pod, PodRead};
```

In `upload_media`, replace from `let id = status_id::mint_note_id();` through
the alt-text block (`if let Some(text) = description…`, ending `:547`) with:

```rust
    let id = status_id::mint_note_id();
    let path = format!("/~/media/{id}");
    let base = format!("https://{}.{}", user.username, state.base_domain);
    let iri = media_iri(&user.username, &state.base_domain, &id);
    let root = brolly_identity::routing::storage_root(&user.username, &state.base_domain);
    let subject = subject_for(&state, &user, &grant);
    let alt = description.as_deref().filter(|d| !d.trim().is_empty());

    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };
    let blobs = state.stores.blobs(user.id).ok();

    // The bytes go into the blob store first, outside the pod's lock, so an
    // upload doesn't queue behind it on disk I/O. Then the resource and its alt
    // text commit in one write, so a client never reads back an upload without
    // the description it was sent with. The multipart awaits are all behind
    // us, so nothing here holds the lock across one.
    let store_upload = || -> Result<(), StoreError> {
        let body = brolly_solid::ldp::prepare(blobs.as_ref(), &bytes, &media_type)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        pod.write(|w| {
            brolly_solid::ldp::put_in(w, &base, &path, &subject, &body, &root).map_err(
                |e| match e {
                    brolly_solid::ldp::LdpError::BlobMissing => StoreError::BlobMissing,
                    e => StoreError::Backend(e.to_string()),
                },
            )?;
            if let Some(text) = alt {
                w.set_description(&iri, &[alt_text_quad(&iri, text)])?;
            }
            Ok(())
        })
    };
    // Identical bytes, released by a delete between the two steps above: write
    // them again and retry, once (spec 5a, R12).
    let stored = match store_upload() {
        Err(StoreError::BlobMissing) => store_upload(),
        other => other,
    };
    if let Err(e) = stored {
        tracing::error!(error = %e, "media upload failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Upload failed");
    }
```

The response after it (`let media_id = …`) is unchanged. It already uses `iri`,
now bound earlier. Delete the old `let iri = media_iri(…)` line that followed
the `put`.

Replace `set_alt_text` and `alt_text` (`:562-578`) with:

```rust
/// The triple recording an upload's alt text, in the upload's own graph.
fn alt_text_quad(iri: &str, text: &str) -> oxigraph_model::Quad {
    use oxigraph_model::{GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
    let node = NamedNode::new_unchecked(iri);
    Quad::new(
        NamedOrBlankNode::NamedNode(node.clone()),
        NamedNode::new_unchecked(ALT_TEXT),
        Term::Literal(Literal::new_simple_literal(text)),
        GraphName::NamedNode(node),
    )
}

fn alt_text(pod: &impl PodRead, iri: &str) -> Option<String> {
    brolly_store::collection::literal(pod, iri, ALT_TEXT)
}

/// What the Mastodon API shows of an upload.
struct Media {
    media_type: String,
    description: Option<String>,
}

/// The upload at `iri`, or `None` if there's no binary there.
///
/// One snapshot. The media type comes from the pod's resource metadata, which
/// the server records and no client write reaches. Only the alt text is read
/// from the upload's own graph, because a member writes it.
fn media(pod: &Pod, iri: &str) -> Result<Option<Media>, StoreError> {
    pod.read(|r| {
        let Some(blob) = r.meta(iri)?.and_then(|meta| meta.blob) else {
            return Ok(None);
        };
        Ok(Some(Media {
            media_type: blob.media_type,
            description: alt_text(r, iri),
        }))
    })
}
```

In `update_media`, replace from `let Ok(pod) = state.stores.pod(user.id)`
(`:617`) to the end of the function with:

```rust
    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };
    let iri = media_iri(&user.username, &state.base_domain, &local_id);

    // Checking it's an upload and adding the alt text are one write, so the
    // upload can't be deleted in between. Appending changes its version, like
    // any other edit.
    if let Some(text) = update.description.as_deref() {
        let appended = pod.write(|w| {
            if w.meta(&iri)?.and_then(|meta| meta.blob).is_none() {
                return Ok(false);
            }
            w.set_description(&iri, &[alt_text_quad(&iri, text)])?;
            Ok(true)
        });
        match appended {
            Ok(true) => {}
            Ok(false) => return not_found(),
            Err(e) => {
                tracing::error!(error = %e, "storing alt text failed");
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not save the description",
                );
            }
        }
    }

    match media(&pod, &iri) {
        Ok(Some(upload)) => Json(media_json(
            &id,
            &iri,
            &upload.media_type,
            upload.description.as_deref(),
        ))
        .into_response(),
        _ => not_found(),
    }
}
```

In `get_media`, replace from `let Ok(pod) = state.stores.pod(user.id)`
(`:659`) to the end of the function with:

```rust
    let Ok(pod) = state.stores.pod(user.id) else {
        return not_found();
    };
    let iri = media_iri(&user.username, &state.base_domain, &local_id);
    match media(&pod, &iri) {
        Ok(Some(upload)) => Json(media_json(
            &id,
            &iri,
            &upload.media_type,
            upload.description.as_deref(),
        ))
        .into_response(),
        _ => not_found(),
    }
}
```

In `create_status`'s attachment loop, replace from
`let iri = media_iri(&user.username, &state.base_domain, &local_id);` through
the end of `attachments.push(…);` (`:741-757`) with:

```rust
        let iri = media_iri(&user.username, &state.base_domain, &local_id);
        let Ok(Some(upload)) = media(&pod, &iri) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Validation failed: Media attachment not found",
            );
        };
        attachments.push(compose::Attachment {
            media_type: upload.media_type,
            description: upload.description,
            url: iri,
        });
```

After this, `mastodon_api.rs` names neither `ldp::blob_digest` nor
`ldp::BLOB_MEDIA_TYPE`. Confirm with
`grep -n "blob_digest\|BLOB_MEDIA_TYPE\|legacy_under_root\|insert_quads" server/src/mastodon_api.rs`,
which should find nothing.

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p brolly-server --test mastodon_compose && cargo test -p brolly-server --test mastodon_api`
Expected: all pass, including `an_uploaded_image_reaches_the_post`,
`alt_text_can_be_set_after_upload_and_before_posting` and
`another_members_attachment_cannot_be_posted`.

- [ ] **Step 5: Format**

```bash
cargo fmt --all
```

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 7: Stage, don't commit**

```bash
git add server/src/mastodon_api.rs server/tests/mastodon_compose.rs
```

---

### Task 4: An upgraded container stops listing a deleted member, over HTTP

The spec's *After an upgrade* case. Chunk 3 implements the upgrade and tests
it in `store`. This is the end-to-end guard, and it also carries the one
guarantee `acl-uncontain` gave (Task 6 removes it): a pod whose root still
lists its `.acl` stops listing it.

**Files:**
- Modify (maybe): `server/Cargo.toml` `[dev-dependencies]` (`brolly-store` needs `test-fixtures` for `raw_store`)
- Test: `server/tests/pod_http.rs` (new test after `delete_removes_the_resource` `:277-288`)

- [ ] **Step 1: Make `raw_store` reachable from server tests**

Run: `grep -n 'brolly-store' server/Cargo.toml`
If the `[dev-dependencies]` entry is still `brolly-store.workspace = true`,
make it:

```toml
brolly-store = { workspace = true, features = ["test-fixtures"] }
```

If chunk 1 or 3 already did this, skip. If this step changes the manifest,
Step 6 adds `cargo deny check`.

- [ ] **Step 2: Write the test**

In `server/tests/pod_http.rs`, after `delete_removes_the_resource`:

```rust
/// Spec 5a, *After an upgrade*. A pod as stage 0 wrote it keeps containment in
/// each container's own graph. After the upgrade, deleting a member de-lists
/// it. A copy-only upgrade would leave the old `ldp:contains` in the content
/// graph and list the member forever. The root's stale listing of its own
/// `.acl`, which `acl-uncontain` used to sweep, doesn't survive either.
#[tokio::test]
async fn an_upgraded_container_stops_listing_a_deleted_member() {
    const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    const LDP: &str = "http://www.w3.org/ns/ldp#";
    let h = harness().await;
    let folder = format!("{ROOT}folder/");
    let doc = format!("{folder}doc");
    let acl = format!("{ROOT}.acl");
    let owner = format!("{acl}#owner");

    // Everything goes, the metadata graph included, and the old layout goes in
    // its place: the root's types and listing in its own graph, the folder's
    // listing in the folder's graph, and the owner's grant.
    let pod = h.stores.pod(h.user).unwrap();
    let raw = pod.raw_store();
    raw.clear().unwrap();
    for quad in [
        t(ROOT, ROOT, RDF_TYPE, &format!("{LDP}BasicContainer")),
        t(ROOT, ROOT, RDF_TYPE, "http://www.w3.org/ns/pim/space#Storage"),
        t(ROOT, ROOT, &format!("{LDP}contains"), &folder),
        t(ROOT, ROOT, &format!("{LDP}contains"), &acl),
        t(&folder, &folder, RDF_TYPE, &format!("{LDP}BasicContainer")),
        t(&folder, &folder, &format!("{LDP}contains"), &doc),
        t(&doc, &doc, "https://example.org/title", "https://example.org/a"),
        t(&acl, &owner, &format!("{ACL}accessTo"), ROOT),
        t(&acl, &owner, &format!("{ACL}default"), ROOT),
        t(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(&acl, &owner, &format!("{ACL}agent"), &format!("{BASE}/profile#me")),
    ] {
        raw.insert(&quad).unwrap();
    }
    brolly_store::resources::upgrade(&pod).unwrap();
    drop(pod);

    let (status, root, _) = h.send("GET", "/~/", None, true).await;
    assert_eq!(status, StatusCode::OK, "{root}");
    assert!(root.contains(&folder), "the upgrade lost a listed container: {root}");
    assert!(!root.contains(&acl), "the root still lists its ACL: {root}");

    let (status, listing, _) = h.send("GET", "/~/folder/", None, true).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(listing.contains(&doc), "setup: the member is listed: {listing}");

    let (status, _, _) = h.send("DELETE", "/~/folder/doc", None, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, listing, _) = h.send("GET", "/~/folder/", None, true).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(
        !listing.contains(&doc),
        "the deleted member is still listed: {listing}"
    );
}
```

`t`, `ROOT`, `BASE`, `ACL` and `send` are the file's own
(`pod_http.rs:14-29`, `:122-152`). `ACL` here is the `acl:` namespace.
`raw.insert` is oxigraph's `Store::insert`.

- [ ] **Step 3: Run it**

Run: `cargo test -p brolly-server --test pod_http an_upgraded_container_stops_listing`
Expected: PASS, on chunk 3's upgrade and `remove`. There's no production code
in this task.

- [ ] **Step 4: Check it can fail**

In `store/src/resources.rs`, temporarily comment out the call that strips
server triples from content graphs (the upgrade's step 5). Rerun Step 3's
command. Expected: FAIL at `the deleted member is still listed`. Restore the
line and rerun: PASS.

- [ ] **Step 5: Format**

```bash
cargo fmt --all
```

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

If Step 1 changed `server/Cargo.toml`, also run `cargo deny check`.

- [ ] **Step 7: Stage, don't commit**

```bash
git add server/tests/pod_http.rs server/Cargo.toml
```

---

### Task 5: Remove `legacy_under_root`

Commit 1's temporary raw under-root writer goes. Once it's deleted, the
compiler lists every caller still using it.

**Files:**
- Modify: `store/src/resources.rs` (`legacy_under_root`, `LegacyWriter` and its `impl`, their docs)
- Modify: `store/tests/resources.rs` (any test of `LegacyWriter`)
- Modify: every remaining caller the compiler names (see Step 2)

- [ ] **Step 1: Delete it**

In `store/src/resources.rs`, delete the method `PodWrite::legacy_under_root`,
the `LegacyWriter` struct and its `impl` block, and any doc text marking them
temporary. In `store/tests/resources.rs`, delete any test that exercises
`legacy_under_root` or `LegacyWriter`.

- [ ] **Step 2: List what's left**

```bash
cargo build --workspace --all-targets 2>&1 | grep -A3 "legacy_under_root\|LegacyWriter"
grep -rn "legacy_under_root\|LegacyWriter" --include='*.rs' adapters authz domain identity server store test-support
```

After Tasks 1–3 and chunk 3, `server/src/provision.rs`,
`adapters/activitypub/src/inbox.rs`, `server/src/mastodon_api.rs` and the
Solid adapter's `ldp.rs`, `patch.rs` and `storage.rs` should be off it. Any
that isn't is a gap in an earlier task or in chunk 3. Go back and finish that
task rather than patching it here. What's likely left is test code seeding
pods that chunk 2 moved onto the legacy writer: the harnesses at HEAD
`server/tests/pod_http.rs:57-79` and `:747-776` (`share_with_bob`),
`server/tests/solid_token_access.rs:64-86`, `server/tests/dashboard.rs:48-49`,
`server/tests/activitypub_discovery.rs:43-44`, the Solid adapter's
`tests/*.rs`, and `authz/tests/conformance_matrix.rs`.

- [ ] **Step 3: Convert each caller**

Pick the recipe that matches what the call seeds. Each keeps the quads the
test already builds.

**A root, and an ACL on it** (`pod_http.rs` harness, `solid_token_access.rs`):

```rust
    let pod = stores.pod(user.id).unwrap();
    pod.write(|w| {
        w.create_root(ROOT)?;
        w.put(&format!("{ROOT}.acl"), Content::Auxiliary(&acl_quads))?;
        Ok(())
    })
    .unwrap();
```

where `acl_quads` is the harness's existing ACL array, bound to a local first.
If a harness grants the owner the same thing `provision::pod` does, call
`brolly_server::provision::pod(&pod, "alice", "brolly.test").unwrap()`
instead.

**A root alone** (`dashboard.rs`, `activitypub_discovery.rs`, where HEAD calls
`storage::init_storage_root`):

```rust
    pod.write(|w| w.create_root(ROOT)).unwrap();
```

**An ACL below the root** (`share_with_bob`):

```rust
    pod.write(|w| w.put(&g, Content::Auxiliary(&quads)).map(|_| ()))
        .unwrap();
```

**An RDF document under the root** (the `NOTE` quad in
`solid_token_access.rs:77-82`, split out of the ACL array into its own
write):

```rust
    pod.write(|w| w.put(NOTE, Content::Rdf(&[note_quad])).map(|_| ()))
        .unwrap();
```

**A deliberately old or broken layout:** `pod.raw_store()` and oxigraph's own
`insert`/`clear_graph`, as Task 4 does.

Import `brolly_store::resources::Content` where a recipe needs it.

- [ ] **Step 4: Confirm it's gone**

```bash
grep -rn "legacy_under_root\|LegacyWriter" --include='*.rs' adapters authz domain identity server store test-support
```

Expected: no output.

- [ ] **Step 5: Format**

```bash
cargo fmt --all
```

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 7: Stage, don't commit**

```bash
git add -u store adapters authz server
```

(`-u`: only files already tracked, which is everything this task touches.)

---

### Task 6: Remove `acl-uncontain` and `maintenance.rs`; the forward-only note

**Files:**
- Delete: `server/src/maintenance.rs`, `server/tests/maintenance.rs`, `server/tests/admin_cli.rs`
- Modify: `server/src/lib.rs` (`:24`, `pub mod maintenance;`)
- Modify: `server/src/bin/admin.rs` (USAGE `:24`, `:36-39`, `:44`; the match arm `:93`; `acl_uncontain` `:352-426`)
- Modify: `adapters/solid/src/storage.rs` (`uncontain_acls` and `is_acl_containment` `:130-167`, if chunk 3 left them)
- Modify: `adapters/solid/tests/acl_control.rs` (`stale_acl_containment_is_swept_and_a_rerun_removes_nothing` `:555-590`, if chunk 3 left it)
- Modify: `test-support/src/lib.rs` (`TestDb.url` `:27-29`, and its initialiser `:52-56`)
- Modify: `docs/deploying.md` (`### Past stage 0 (ACL resources)` `:158-204`)
- Modify: `docs/specs/2026-09-22-solid-resource-metadata.md` (a `doc-paths: skip` marker after the title)

- [ ] **Step 1: Check nothing else uses them**

```bash
grep -rn "maintenance::\|acl_uncontain\|uncontain_acls\|acl-uncontain" --include='*.rs' --include='*.md' --include='*.toml' . | grep -v "^./target\|^./spikes\|^./docs/plans/\|^./docs/specs/2026-09-17"
grep -rn "db\.url\|\.url\b" --include='*.rs' server test-support adapters store authz | grep -i "testdb\|db\.url"
```

Expected: the first finds only the files this task deletes or edits (and the
5a spec, which describes the removal). The second finds only
`server/tests/admin_cli.rs`. That makes `TestDb.url` unused once the file
goes. `stores.pod_exists` stays: `server/tests/dashboard.rs:702` and
`store/tests/storage_invariants.rs:112` use it. `db::list_users` stays:
`server/src/admin.rs:194` uses it.

- [ ] **Step 2: Delete the files and the module**

```bash
git rm server/src/maintenance.rs server/tests/maintenance.rs server/tests/admin_cli.rs
```

In `server/src/lib.rs`, delete line `:24`, `pub mod maintenance;`.

- [ ] **Step 3: Remove the command from `brolly-admin`**

In `server/src/bin/admin.rs`:
- In `USAGE`, delete the line `    brolly-admin acl-uncontain` (`:24`), the
  four-line `acl-uncontain` entry under `COMMANDS:` (`:36-39`), and the
  `BROLLY_DATA_DIR` line under `ENVIRONMENT:` (`:44`). No other command reads
  `BROLLY_DATA_DIR`.
- In `main`'s `match command`, delete `"acl-uncontain" => acl_uncontain(&pool).await,` (`:93`).
- Delete `acl_uncontain` and its doc comment (`:352-426`, to the end of the
  file). Keep the blank line and closing brace of the function before it.

- [ ] **Step 4: Remove the sweep from the Solid adapter**

If `adapters/solid/src/storage.rs` still has `uncontain_acls` and
`is_acl_containment`, delete both with their doc comments (`:130-167` at
HEAD). If `adapters/solid/tests/acl_control.rs` still has
`stale_acl_containment_is_swept_and_a_rerun_removes_nothing`, delete it. Its
guarantee (an ACL is never contained) now comes from the upgrade (spec step 3),
and Task 4 tests that over HTTP. Remove any import that deletion leaves unused.

- [ ] **Step 5: Drop `TestDb.url`**

In `test-support/src/lib.rs`, delete the field and its doc comment (`:27-29`):

```rust
    /// The connection string, for tests that spawn a subprocess rather than
    /// using the pool. `brolly-admin` connects with `DATABASE_URL`.
    pub url: String,
```

and make the initialiser (`:52-56`):

```rust
    TestDb {
        _container: container,
        pool,
    }
```

`url` is still used to connect, just above.

- [ ] **Step 6: Replace the deploy section**

In `docs/deploying.md`, replace the whole `### Past stage 0 (ACL resources)`
section (`:158-204`, through the paragraph ending `then start the server.`)
with the following. Move it to be the first subsection under `## Upgrading`
(before `### Activities stored before 865cc98`), because it's the one that
needs doing before the deploy:

````markdown
### Stage 5a (resource metadata): snapshot first, forward-only

From stage 5a on, each pod records what the server knows about its resources
(whether each one exists, its container, its version and its binary) in a
graph of its own, where no client write can reach it. A pod upgrades itself
the first time the server opens it after the deploy. There's no command to run,
and new pods start on the new layout.

**This is the first change that redeploying the old image can't undo.** The
upgrade moves containment out of each container's own graph, and the old code
reads it only from there. So:

1. **Snapshot the data volume before you deploy.** On Railway, back up the
   service's volume. With docker compose, stop the server and copy the data
   directory (`/var/lib/brolly` in the image, or wherever `BROLLY_DATA_DIR`
   points).
2. Deploy. Pods upgrade as members use them.
3. **To go back, restore the snapshot**, then deploy the old image. Anything
   written after the snapshot is lost.

If the upgrade can't find a pod's storage root, it writes nothing, leaves the
pod as it was and logs at `error`. That pod's LDP reads then answer 404. Only a
pod that was never provisioned can get there.

`brolly-admin acl-uncontain` is gone. The upgrade never lists an `.acl` as a
member, so a pod that was never swept needs nothing more.
````

- [ ] **Step 7: Keep the doc-path check green**

The 5a spec cites `server/src/maintenance.rs` in backticks (its *`acl-uncontain`
is removed* section), and `tools/check-doc-paths.sh` fails on a cited path that
doesn't resolve. That check is also lefthook's pre-commit hook. In
`docs/specs/2026-09-22-solid-resource-metadata.md`, insert after the first
line (`# Stage 5a: server-managed resource metadata`):

```markdown

<!-- doc-paths: skip -->
<!-- The spec cites a file this stage deletes, so not every path it names
     resolves once it's implemented. -->
```

Run: `./tools/check-doc-paths.sh`
Expected: `doc paths ok (N checked)`.

- [ ] **Step 8: Format**

```bash
cargo fmt --all
```

- [ ] **Step 9: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && ./tools/check-doc-paths.sh
```

No `Cargo.toml` changes. `brolly-admin` still builds (`cargo build -p brolly-server --bin brolly-admin`
is part of `--all-targets`), and `cargo run --bin brolly-admin -- --help` no
longer lists `acl-uncontain`.

- [ ] **Step 10: Stage, don't commit**

```bash
git add -u server adapters/solid test-support docs
```

(`git rm` in Step 2 already staged the deletions.)

---

### Task 7: The architecture rules

**Files:**
- Modify: `server/tests/architecture.rs` (a `rust_files` walker after `source_files` `:69-92`; two tests at the end; the Mastodon lint's list and doc `:227-259`)

- [ ] **Step 1: Write the rules**

After `source_files` (`:69-92`):

```rust
/// Every `.rs` file in the workspace, wherever it sits: `src/`, `tests/`,
/// `benches/`, `examples/`. `target/` is build output and the spike is
/// throwaway.
fn rust_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|n| n == "target" || n == "spikes" || n == ".git")
                {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&workspace_root(), &mut out);
    out
}
```

At the end of the file:

```rust
/// The metadata graph has one owner: `store/src/resources.rs`.
///
/// Stage 5a keeps existence, containment, versions and blob pointers in
/// `urn:brolly:resources`, where no client write can reach them. Code that
/// named the graph could read or write it around `PodWrite`, and the metadata
/// would stop being true. Everything else asks `resources`.
#[test]
fn only_resources_names_the_metadata_graph() {
    const GRAPH: &str = "urn:brolly:resources";
    let owner = workspace_root().join("store/src/resources.rs");
    assert!(
        std::fs::read_to_string(&owner).is_ok_and(|text| text.contains(GRAPH)),
        "{} no longer names {GRAPH}; this rule would pass vacuously",
        owner.display()
    );

    let offenders: Vec<_> = source_files()
        .into_iter()
        .filter(|p| *p != owner && !p.to_string_lossy().contains("/spikes/"))
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|text| text.contains(GRAPH)))
        .collect();

    assert!(
        offenders.is_empty(),
        "{GRAPH} is named outside store/src/resources.rs in {offenders:?}. \
         Read and write resource metadata through Pod, PodWrite and \
         ResourceRead instead."
    );
}

/// `Pod::raw_store` hands out the bare `Store`: no lock, no metadata. It exists
/// so tests can build old-layout pods. Anywhere else it's the bypass stage 5a
/// closed, so it may appear only in test and bench code, and in `store`'s own
/// source where it's defined.
#[test]
fn raw_store_is_reached_only_from_tests() {
    let store_src = workspace_root().join("store/src");
    let offenders: Vec<_> = rust_files()
        .into_iter()
        .filter(|p| !p.starts_with(&store_src))
        .filter(|p| {
            !p.components()
                .any(|c| c.as_os_str() == "tests" || c.as_os_str() == "benches")
        })
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|text| text.contains("raw_store")))
        .collect();

    assert!(
        offenders.is_empty(),
        "raw_store is used outside test code in {offenders:?}. Write through \
         Pod::write, which keeps the metadata true."
    );
}
```

In `the_mastodon_crate_never_writes_to_a_store` (`:227-298`), the doc's last
paragraph (`:236-238`) becomes:

```rust
/// A lint as well as the type system. Pod writes need a `PodWrite`, reached
/// only through `Pod::write`, so the lint looks for those names alongside the
/// store's own write functions and the raw oxigraph calls.
```

and `MUTATORS` gains the pod write path:

```rust
    const MUTATORS: [&str; 13] = [
        // brolly-store's write path.
        "insert_quads",
        "insert_record",
        "replace_graph",
        "record_note",
        "forget_note",
        "index::clear",
        // A pod write (stage 5a).
        "PodWrite",
        ".write(|",
        // Raw oxigraph, which would sidestep canonicalization entirely.
        ".insert(",
        ".remove(",
        "clear_graph",
        ".transaction(",
        "bulk_loader",
    ];
```

- [ ] **Step 2: Run them**

Run: `cargo test -p brolly-server --test architecture`
Expected: all pass. The rules are guards, so they pass on a tree that already
obeys them.

- [ ] **Step 3: Check each rule can fail**

- Add a line `// urn:brolly:resources` to `server/src/provision.rs`. Rerun:
  `only_resources_names_the_metadata_graph` FAILS naming that file. Remove the
  line.
- Add a line `// raw_store` to `server/src/outbox.rs`. Rerun:
  `raw_store_is_reached_only_from_tests` FAILS naming that file. Remove the
  line.
- Add a line `// PodWrite` to `adapters/mastodon/src/compose.rs`. Rerun:
  `the_mastodon_crate_never_writes_to_a_store` FAILS. Remove the line.

Then rerun: all pass. If `only_resources_names_the_metadata_graph` fails on a
real file (for example `server/src/account.rs` naming the graph for export),
change that file to use `brolly_store::resources::METADATA_GRAPH` rather than
widening the rule.

- [ ] **Step 4: Format**

```bash
cargo fmt --all
```

- [ ] **Step 5: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 6: Stage, don't commit**

```bash
git add server/tests/architecture.rs
```

---

### Task 8: Commit 2, the switch

- [ ] **Step 1: The whole of commit 2 builds from nothing**

```bash
cargo clean -p brolly-store -p brolly-solid -p brolly-activitypub -p brolly-server
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && ./tools/check-doc-paths.sh
```

If any `Cargo.toml` changed in chunk 3 or Task 4, also run:

```bash
cargo deny check
```

Expected: `advisories ok, bans ok, licenses ok, sources ok`.

- [ ] **Step 2: The removals are complete**

```bash
grep -rn "legacy_under_root\|LegacyWriter\|acl_uncontain\|uncontain_acls\|maintenance::\|storage::exists\|init_storage_root" --include='*.rs' adapters authz domain identity server store test-support
```

Expected: no output.

- [ ] **Step 3: Review what's staged**

```bash
git add -A adapters authz domain identity server store test-support docs Cargo.lock
git status --short
```

Expected: only chunk 3's files and this chunk's. Nothing under `target/` or
`spikes/`, and no files from the plan directory. Unstage anything else with
`git restore --staged <path>`.

- [ ] **Step 4: Commit**

```bash
git commit -m "feat(store): pods keep their own resource metadata

The switch, stage 5a commit 2. Each pod records what the server knows
about its resources in urn:brolly:resources: existence, kind,
containment, modified time, version and blob metadata. No client write
reaches that graph, and every writer keeps it true.

- Pods upgrade on first open. A fresh store is marked current. An
  old-layout pod is classified, recorded and stripped of server triples
  in one transaction. A pod with no root at /~/ is left unmarked and
  logged.
- LDP reads and writes go through the metadata. Empty documents and
  containers exist, a container PUT can't change its members, and blob
  pointers in a document are inert data.
- WAC picks the governing ACL by metadata, so an empty ACL governs and
  grants nothing.
- Posts are pod resources. The outbox writes the note, its activity and
  the outbox entry in one write, and the author's Delete de-lists them.
  A recipient's copy is protocol state, decided from its IRI.
- A Mastodon upload stores its blob and alt text in one write. Media
  reads come from metadata.
- Provisioning records the root with create_root and the root ACL as an
  auxiliary resource.
- acl-uncontain, maintenance.rs and commit 1's temporary raw under-root
  writer are gone. The upgrade never contains an ACL.

Forward-only. The upgrade strips the old containment triples, so the
previous image can't read an upgraded pod. Snapshot the data volume
before deploying, and restore it to go back (docs/deploying.md,
Upgrading).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

lefthook's pre-commit hook reruns fmt, clippy and the doc-path check. If it
fails, fix the cause, restage, and commit again. Don't use `--no-verify`.

- [ ] **Step 5: Verify the commit from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && ./tools/check-doc-paths.sh
cd - && git worktree remove /tmp/verify --force
```

It has to pass there too, or the commit isn't done. A fresh worktree builds
RocksDB from scratch, which takes a few minutes. Run it in the background
rather than skipping it.

- [ ] **Step 6: Before deploying**

Not a gate, but it's the operator step this commit introduces: snapshot the
data volume (Railway: a volume backup), then deploy. Pods upgrade themselves
on first open. `docs/deploying.md` has this under *Upgrading*.

---

### Notes for the reviewer

1. **Assumed interfaces from chunks 1–3.** The fixed list doesn't cover
   `ResourceRead::meta`, `processor::process_member`'s exact parameters,
   `inbox::{deliver, remove}` on `&mut PodWrite`, or chunk 3's `ldp::prepare`,
   `ldp::put_in`, `ldp::Body` and `LdpError::BlobMissing`. The table under
   *Interfaces this chunk consumes* shows the shapes this chunk calls. The
   Mastodon upload is the most exposed: it has to do what chunk 3's outer
   `ldp::put` does (bytes first, `put_in` inside one `Pod::write`, one retry on
   `BlobMissing`), plus the `append`. If chunk 3 put the byte-writing somewhere
   else, follow `ldp::put`.
2. **`PodWrite::under_root` is new public API.** It isn't in the fixed list.
   The spec requires `inbox` to decide "from the IRI, against the pod's
   metadata root". That needs either this, or trying `put` and falling back on
   `NotUnderRoot`, which is error-as-control-flow and misreads `NoRoot`. The
   method reuses chunk 1's own membership test, so the choice can't disagree
   with the refusals, and Task 2's store test checks that.
3. **Provisioning is Task 1, not later.** Until `provision::pod` records a root,
   no server test's pod has metadata, so chunk 3's server-level LDP tests
   can't pass on a provisioned pod. If chunk 3 had to convert `provision::pod`
   to get green, Task 1 reduces to its test.
4. **Follow bookkeeping stays in its own write.** The spec's outbox row puts
   only the author's copy, its outbox entry and the author's Delete in the
   single `Pod::write`. `follows::record_following` is still best effort
   (`let _ =`) in a write of its own, as chunk 2 left it. Folding it in would
   let its failure roll back the post.
5. **Alt text updates accumulate.** At HEAD, `set_alt_text` inserts without
   removing, so a second `PUT /api/v1/media/{id}` leaves two `altText`
   literals and reads return whichever comes first. The spec says "alt text
   updates via `append`", which keeps that. Replacing it needs a way to drop
   one triple under the root, which `PodWrite` deliberately doesn't offer.
   `put` of `Content::Binary` with the same blob, then `append`, would work,
   but it's a behaviour change the spec doesn't ask for. So Task 3's test
   updates only an upload that had no alt text. Worth a follow-up.
6. **`update_media` now fails loudly.** At HEAD a failed alt-text write was
   logged at `warn` and the handler still answered 200 with the text it didn't
   store. It now answers 500. The existence check and the append share one
   write, so a concurrent delete can't slip between them.
7. **"Logs no error" in `auth_flow`.** The test captures `error` events with a
   thread-local `tracing` subscriber, which works because `#[tokio::test]` is
   single-threaded. "Ends at layout 2" is checked by behaviour: the root and
   ACL are in metadata, and reopening the pod logs nothing (an unmarked pod
   would re-run the upgrade, find no old-layout root and log at `error`). The
   test doesn't read the layout triple itself, because only `resources.rs`
   should name that graph. It needs `drop(router)` to release RocksDB's lock
   before reopening. If some part of `AppState` outlives the router, the
   reopen fails loudly rather than passing wrongly.
8. **The architecture rules' scope.**
   - `urn:brolly:resources` is checked in `src/` files only. Chunk 1 and 3's
     store tests may spell it out, and tests can't bypass anything at runtime.
   - `raw_store` is allowed under `tests/` and `benches/` (the spec asks for
     `tests/` only) and anywhere in `store/src/`. The spec's `store/benches/`
     upgrade case likely needs an old-layout pod, and `store/src/lib.rs` may
     mention it in docs.
   - The Mastodon projection lint gains `PodWrite` and `.write(|`. That goes
     beyond the two rules the spec names, but the lint's old doc ("there is no
     `&mut` to withhold") stopped being true in commit 1.
9. **The spec gets a `doc-paths: skip` marker.** It cites
   `server/src/maintenance.rs` in backticks, which this chunk deletes.
   `tools/check-doc-paths.sh` exempts only `docs/plans/`, and it's lefthook's
   pre-commit hook, so without the marker the commit fails. That's a two-line
   edit to an approved spec. The alternative is removing the backticks from
   its text.
10. **`admin_cli.rs` goes whole.** All three of its tests are `acl-uncontain`
    tests, and `TestDb.url` was added for them in `f0b8b85` and read nowhere
    else. `brolly-admin` no longer reads `BROLLY_DATA_DIR` at all, so the
    USAGE line goes with the command.
11. **What `acl-uncontain` guaranteed survives as a test.** Task 4 seeds a root
    that lists its own `.acl` and checks the upgraded listing doesn't show it,
    over HTTP. The stage 0 adapter test of `uncontain_acls` is removed with the
    function.
12. **The 865cc98 deploy note still holds.** A pre-`865cc98` activity embedding
    a member's `/~/.acl` is still a carrier, and the author's own Delete now
    reaches the ACL through `PodWrite::remove` rather than `clear_graph`. It's
    the same exposure, bounded to the member's own origin, so the note stays
    as written.
13. **Expected failures depend on chunk 3's end state.** Each "watch it fail"
    names the failure if chunk 3 left `inbox`, `provision` and the Mastodon
    media reads as chunk 2 wrote them. If chunk 3 already moved one of them,
    that test passes at Step 2. Confirm it passes for the right reason and
    carry on.
14. **Rootless pods are unchanged.** `under_root` is false in a pod with no
    recorded root, so `adapters/activitypub/tests/processor.rs`, whose pods
    are never provisioned, keeps writing every graph through the outside-root
    methods and needs no edit.
15. **No guard against a container or `.acl` IRI in `write_record`.** Under the
    root, only server-minted ids reach it (`outbox::authored` for the author's
    copy, the processor's origin check for delivery), so `Content::Rdf` is
    always right there. A defensive refusal would be dead code today. Revisit
    when federation is enabled.


## Chunk 5: Conditional requests, ETag and Last-Modified (commit 3)

Spec section **Conditional requests**, and its tests under **Testing →
server/tests/pod_http.rs** (Headers, Preconditions, Disclosure, Concurrency).
This is rollout commit 3. It assumes chunks 1–4 (commits 1 and 2) are merged:
every resource under the root has a `ResourceMeta` with a `version` (a ULID) and
a `modified` (`xsd:dateTime`, UTC, millisecond precision), `ldp` has its two
layers, and `pod.rs` holds a `Pod`, not a `Store`.

Four tasks, **one commit** (Task 4 commits). Tasks 1 and 3 leave the workspace
green; Task 2 adds HTTP tests that fail until Task 4, so don't commit before
then.

**What changes:**

| File | Change |
|---|---|
| `adapters/solid/src/conditional.rs` (new) | `EntityTag`, `Condition` (the parsed `If-Match` / `If-None-Match` field), `Preconditions`, `Method`, `PreconditionFailed`, `etag`, `http_date`. Pure, transport-free, unit-tested. |
| `adapters/solid/src/lib.rs` | `pub mod conditional;` |
| `adapters/solid/src/ldp.rs` | `LdpError::PreconditionFailed`. `LdpOutcome` gains `version` and `modified`, from the same `Pod::read` snapshot as the body. `put_in`, `append_in`, `delete_in` take `preconditions: &Preconditions` and evaluate it after WAC, before writing, in the caller's transaction. Outer `put_if`, `append_if`, `delete_if`; `put`, `append`, `delete` become wrappers passing `Preconditions::NONE`. |
| `adapters/solid/src/patch.rs` | `PatchError::NotCurrent`, only if chunk 4's PATCH closure carries `PatchError` (see Task 3, Step 1). |
| `server/src/pod.rs` | Reads `If-Match` / `If-None-Match` into `Preconditions`. GET/HEAD: `ETag`, `Last-Modified`, and 304. PUT/POST/DELETE via the `_if` functions. PATCH evaluates in its closure. `ldp_error` maps `PreconditionFailed` to 412. |
| `server/src/mastodon_api.rs`, and any other `_in` caller | pass `&Preconditions::NONE` |
| `server/tests/pod_http.rs` | the spec's header, precondition, disclosure and concurrency tests |

**Why the precondition goes into the `_in` functions.** The spec requires a
failed write precondition to be "checked in the same `Pod::write` closure as the
write", and evaluated after authorisation (RFC 9110 §13.2.1) so that a caller
without the needed mode gets the ordinary refusal. `put_in`, `append_in` and
`delete_in` are where WAC runs inside the transaction (spec, *Writing*). So the
check goes in there, directly after WAC, and reads `w.meta(..)` through the same
transaction. Nothing can commit between the check and the write, because
`Pod::write` holds the pod's lock for the whole closure (R5).

**GET and HEAD need no parameter.** `ldp::read` already reads metadata and
content from one `Pod::read` snapshot. It returns that snapshot's `version` and
`modified` in `LdpOutcome`, and `pod.rs` compares `If-None-Match` against them.
That comparison runs only after `read` returns `Ok`, so only after the Read
check has passed.

**HEAD.** `axum`'s `get(..)` also answers HEAD by running the GET handler and
dropping the body (`axum-0.8.9/src/routing/method_routing.rs:1157-1158`). So
`ETag`, `Last-Modified` and the 304 come to HEAD for free. HEAD with a DPoP
token still fails, because `resolve` verifies the proof against `"GET"`. That's
5b. The HEAD tests here authenticate with the session cookie.

### Task 1: `conditional`, the parser and the rules

**Files:**
- Create: `adapters/solid/src/conditional.rs`
- Modify: `adapters/solid/src/lib.rs:12-16` (module list)

- [ ] **Step 1: Write the failing tests**

In `adapters/solid/src/lib.rs`, add the module to the list (alphabetical, so
before `ldp`):

```rust
pub mod conditional;
pub mod ldp;
pub mod oidc;
pub mod patch;
pub mod profile;
pub mod storage;
```

(If chunk 4 left `storage` out or renamed it, keep its list and insert only
`pub mod conditional;`.)

Create `adapters/solid/src/conditional.rs` with only the tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Method; 4] = [Method::Put, Method::Patch, Method::Delete, Method::Post];

    fn strong(s: &str) -> EntityTag {
        EntityTag {
            weak: false,
            opaque: s.to_string(),
        }
    }

    fn weak(s: &str) -> EntityTag {
        EntityTag {
            weak: true,
            opaque: s.to_string(),
        }
    }

    fn with(if_match: Option<&str>, if_none_match: Option<&str>) -> Preconditions {
        Preconditions::from_fields(if_match, if_none_match)
    }

    // --- parsing ---------------------------------------------------------------

    #[test]
    fn a_star_alone_is_any() {
        assert_eq!(Condition::parse("*"), Condition::Any);
        assert_eq!(Condition::parse("  *\t"), Condition::Any);
        assert_eq!(Condition::parse("*, *"), Condition::Any);
    }

    #[test]
    fn a_list_is_quoted_tags_separated_by_commas() {
        assert_eq!(
            Condition::parse(r#""a", W/"b" ,"c""#),
            Condition::Tags(vec![strong("a"), weak("b"), strong("c")])
        );
        // RFC 9110 §5.6.1: a recipient accepts empty list elements.
        assert_eq!(
            Condition::parse(r#", "a",, "b","#),
            Condition::Tags(vec![strong("a"), strong("b")])
        );
    }

    #[test]
    fn a_comma_inside_the_quotes_belongs_to_the_tag() {
        // etagc includes ",", so splitting on commas first would be wrong.
        assert_eq!(
            Condition::parse(r#""a,b", "c""#),
            Condition::Tags(vec![strong("a,b"), strong("c")])
        );
    }

    #[test]
    fn malformed_elements_are_dropped_and_the_rest_kept() {
        // Unquoted, a lower-case weak prefix, junk after the quote, and a star
        // inside a list are each malformed on their own.
        assert_eq!(
            Condition::parse(r#"abc, w/"x", "y"z, *, "ok""#),
            Condition::Tags(vec![strong("ok")])
        );
        assert_eq!(
            Condition::parse(r#""ok", "unterminated"#),
            Condition::Tags(vec![strong("ok")])
        );
        // A space isn't etagc.
        assert_eq!(Condition::parse(r#""a b""#), Condition::Tags(vec![]));
        assert_eq!(Condition::parse(""), Condition::Tags(vec![]));
    }

    #[test]
    fn an_absent_field_is_no_condition() {
        assert_eq!(with(None, None), Preconditions::NONE);
        assert_eq!(with(Some(""), None).if_match, Some(Condition::Tags(vec![])));
    }

    // --- writes ----------------------------------------------------------------

    #[test]
    fn no_conditions_always_hold() {
        for method in ALL {
            assert_eq!(Preconditions::NONE.check_write(method, None), Ok(()));
            assert_eq!(Preconditions::NONE.check_write(method, Some("v")), Ok(()));
        }
        assert!(!Preconditions::NONE.not_modified("v"));
    }

    #[test]
    fn if_match_star_needs_a_current_resource() {
        let p = with(Some("*"), None);
        for method in ALL {
            assert_eq!(p.check_write(method, None), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, Some("v")), Ok(()));
        }
    }

    #[test]
    fn if_match_compares_strongly() {
        let p = with(Some(r#""old", "v""#), None);
        for method in ALL {
            assert_eq!(p.check_write(method, Some("v")), Ok(()));
            assert_eq!(p.check_write(method, Some("new")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, None), Err(PreconditionFailed));
        }
        // A weak tag never matches, even with the right opaque value.
        assert_eq!(
            with(Some(r#"W/"v""#), None).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
        // A field with nothing usable in it holds for nothing: fail closed.
        assert_eq!(
            with(Some("v"), None).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
    }

    #[test]
    fn if_none_match_star_guards_creation_on_put_and_patch_only() {
        let p = with(None, Some("*"));
        for method in [Method::Put, Method::Patch] {
            assert_eq!(p.check_write(method, Some("v")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, None), Ok(()));
        }
        // Not in the spec's table for DELETE or POST.
        assert_eq!(p.check_write(Method::Delete, Some("v")), Ok(()));
        assert_eq!(p.check_write(Method::Post, Some("v")), Ok(()));
    }

    #[test]
    fn if_none_match_tags_refuse_the_current_version() {
        let p = with(None, Some(r#""old", "v""#));
        for method in [Method::Put, Method::Patch, Method::Delete] {
            assert_eq!(p.check_write(method, Some("v")), Err(PreconditionFailed));
            assert_eq!(p.check_write(method, Some("new")), Ok(()));
            assert_eq!(p.check_write(method, None), Ok(()));
        }
        // Not in the spec's table for POST.
        assert_eq!(p.check_write(Method::Post, Some("v")), Ok(()));
        // RFC 9110 §13.1.2: If-None-Match uses the weak comparison.
        assert_eq!(
            with(None, Some(r#"W/"v""#)).check_write(Method::Put, Some("v")),
            Err(PreconditionFailed)
        );
    }

    #[test]
    fn both_fields_must_hold() {
        let p = with(Some(r#""v""#), Some("*"));
        assert_eq!(p.check_write(Method::Put, Some("v")), Err(PreconditionFailed));
    }

    // --- reads -----------------------------------------------------------------

    #[test]
    fn a_read_is_not_modified_when_if_none_match_matches() {
        assert!(with(None, Some(r#""v""#)).not_modified("v"));
        assert!(with(None, Some(r#""old", W/"v""#)).not_modified("v"));
        assert!(with(None, Some("*")).not_modified("v"));
        assert!(!with(None, Some(r#""old""#)).not_modified("v"));
        // If-Match isn't evaluated on a read.
        assert!(!with(Some(r#""old""#), None).not_modified("v"));
    }

    // --- headers out -------------------------------------------------------------

    #[test]
    fn an_etag_is_the_version_in_quotes() {
        assert_eq!(etag("01J8Z3T5V7W9X1Y3Z5A7B9C1D3"), r#""01J8Z3T5V7W9X1Y3Z5A7B9C1D3""#);
    }

    #[test]
    fn last_modified_is_an_imf_fixdate() {
        // RFC 9110 §5.6.7's own example.
        assert_eq!(
            http_date("1994-11-06T08:49:37.000Z").as_deref(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
        // Milliseconds are dropped: an HTTP-date has one-second precision.
        assert_eq!(
            http_date("2026-09-22T09:05:03.999Z").as_deref(),
            Some("Tue, 22 Sep 2026 09:05:03 GMT")
        );
        assert_eq!(
            http_date("2024-02-29T23:59:59+00:00").as_deref(),
            Some("Thu, 29 Feb 2024 23:59:59 GMT")
        );
        assert_eq!(http_date("2026-09-22T09:05:03"), None, "no zone");
        assert_eq!(http_date("2026-09-22T09:05:03+02:00"), None, "not UTC");
        assert_eq!(http_date("2026-02-30T00:00:00Z"), None, "no such day");
        assert_eq!(http_date("not a date"), None);
    }
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p brolly-solid --lib conditional`
Expected: compile failure, `error[E0433]`/`E0412`: cannot find `Method`,
`EntityTag`, `Condition`, `Preconditions`, `PreconditionFailed`, `etag`,
`http_date` in this scope.

- [ ] **Step 3: Implement**

Put this above the `#[cfg(test)]` module in
`adapters/solid/src/conditional.rs`:

```rust
//! Conditional requests: `If-Match` and `If-None-Match` (RFC 9110 §13).
//!
//! Transport-free like the rest of this crate. It takes header *values* and a
//! resource's current version, and says whether a request may go ahead. The
//! version is `brolly:version` from `urn:brolly:resources`, a fresh ULID on
//! every change, and the `ETag` is that version in quotes (spec R4). There is
//! one version per resource whatever the representation, so every tag the
//! server issues is strong.
//!
//! **Where it runs.** A write's preconditions are evaluated in
//! `ldp::put_in`, `append_in` and `delete_in`, after WAC and before the write,
//! inside the `Pod::write` closure. A read's are evaluated by `pod.rs` against
//! the version `ldp::read` returns from its snapshot. Both come after
//! authorisation (RFC 9110 §13.2.1), so a caller without the needed mode gets
//! the ordinary refusal whether or not the resource exists.
//!
//! `If-Modified-Since` and `If-Unmodified-Since` are ignored. The ETag is
//! authoritative, and one-second dates can't tell apart two writes in the same
//! second.

/// One `entity-tag` (RFC 9110 §8.8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTag {
    /// Sent with the `W/` prefix.
    pub weak: bool,
    /// What was between the quotes.
    pub opaque: String,
}

impl EntityTag {
    /// Strong comparison: both strong, same opaque value. Ours are always
    /// strong, so a `W/` tag never matches.
    fn strong_eq(&self, version: &str) -> bool {
        !self.weak && self.opaque == version
    }

    /// Weak comparison: same opaque value, prefix ignored.
    fn weak_eq(&self, version: &str) -> bool {
        self.opaque == version
    }
}

/// A parsed `If-Match` or `If-None-Match` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `*`: any current representation.
    Any,
    /// A list of tags. Empty when the field had nothing usable, which then
    /// matches nothing.
    Tags(Vec<EntityTag>),
}

/// One element of the list, before it is known to be usable.
enum Element {
    Star,
    Tag(EntityTag),
    Malformed,
}

impl Condition {
    /// Parse a field value: `*`, or a comma-separated list of entity tags.
    ///
    /// Robust rather than strict. A malformed element is dropped and the rest
    /// still count, so a stray token can't turn `If-Match` into "anything". A
    /// field with no usable element matches nothing, so `If-Match` fails
    /// closed. A `*` counts only on its own; mixed into a list it's malformed.
    pub fn parse(field: &str) -> Condition {
        let mut tags = Vec::new();
        let mut stars = 0usize;
        let mut elements = 0usize;
        let mut rest = field;
        loop {
            rest = rest.trim_start_matches([' ', '\t', ',']);
            if rest.is_empty() {
                break;
            }
            let (element, after) = next_element(rest);
            rest = after;
            elements += 1;
            match element {
                Element::Star => stars += 1,
                Element::Tag(tag) => tags.push(tag),
                Element::Malformed => {}
            }
        }
        if stars > 0 && stars == elements {
            Condition::Any
        } else {
            Condition::Tags(tags)
        }
    }
}

/// Read one element from the front of `s`, which starts at a non-separator.
/// Returns it and whatever follows, starting at the next `,` or empty.
fn next_element(s: &str) -> (Element, &str) {
    if let Some(after) = s.strip_prefix('*') {
        return finish(Element::Star, after);
    }
    // `W/` is case-sensitive (RFC 9110 §8.8.3: `%s"W/"`).
    let (weak, quoted) = match s.strip_prefix("W/") {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let Some(inner) = quoted.strip_prefix('"') else {
        return skip(s);
    };
    // The closing quote. etagc excludes `"`, so the first one ends the tag.
    let Some(end) = inner.find('"') else {
        return (Element::Malformed, "");
    };
    let (opaque, closing) = inner.split_at(end);
    let after = closing.strip_prefix('"').unwrap_or(closing);
    if !opaque.chars().all(is_etagc) {
        return skip(after);
    }
    finish(
        Element::Tag(EntityTag {
            weak,
            opaque: opaque.to_string(),
        }),
        after,
    )
}

/// After an element only whitespace, then a comma or the end, may follow.
fn finish(element: Element, after: &str) -> (Element, &str) {
    let trimmed = after.trim_start_matches([' ', '\t']);
    if trimmed.is_empty() || trimmed.starts_with(',') {
        (element, trimmed)
    } else {
        skip(trimmed)
    }
}

/// Give up on this element and resume at the next comma.
fn skip(s: &str) -> (Element, &str) {
    match s.find(',') {
        Some(comma) => (Element::Malformed, s.split_at(comma).1),
        None => (Element::Malformed, ""),
    }
}

/// `etagc = %x21 / %x23-7E / obs-text`.
fn is_etagc(c: char) -> bool {
    c == '\x21' || ('\x23'..='\x7e').contains(&c) || !c.is_ascii()
}

/// Which write a precondition guards. The spec's table differs per method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Put,
    Patch,
    Delete,
    /// Evaluated against the container posted to (or the document appended
    /// to), which is the request's target.
    Post,
}

/// A write precondition didn't hold: 412, and nothing written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreconditionFailed;

impl std::fmt::Display for PreconditionFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "precondition failed")
    }
}

impl std::error::Error for PreconditionFailed {}

/// A request's `If-Match` and `If-None-Match`, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preconditions {
    pub if_match: Option<Condition>,
    pub if_none_match: Option<Condition>,
}

impl Preconditions {
    /// No conditions: every write and read goes ahead. For callers that aren't
    /// answering an HTTP request.
    pub const NONE: Preconditions = Preconditions {
        if_match: None,
        if_none_match: None,
    };

    /// From the two field values. `None` is an absent header. A header sent on
    /// several lines is passed as one value, the lines joined with `", "`
    /// (RFC 9110 §5.3).
    pub fn from_fields(if_match: Option<&str>, if_none_match: Option<&str>) -> Self {
        Preconditions {
            if_match: if_match.map(Condition::parse),
            if_none_match: if_none_match.map(Condition::parse),
        }
    }

    /// May this write go ahead? `current` is the resource's version, `None`
    /// if it doesn't exist.
    ///
    /// | Field | Methods | Fails when |
    /// |---|---|---|
    /// | `If-Match: *` | all four | the resource doesn't exist |
    /// | `If-Match: "a", …` | all four | no tag strongly matches |
    /// | `If-None-Match: *` | PUT, PATCH | the resource exists |
    /// | `If-None-Match: "a", …` | PUT, PATCH, DELETE | a tag weakly matches |
    pub fn check_write(&self, method: Method, current: Option<&str>) -> Result<(), PreconditionFailed> {
        if let Some(condition) = &self.if_match {
            let holds = match (condition, current) {
                (_, None) => false,
                (Condition::Any, Some(_)) => true,
                (Condition::Tags(tags), Some(version)) => {
                    tags.iter().any(|tag| tag.strong_eq(version))
                }
            };
            if !holds {
                return Err(PreconditionFailed);
            }
        }
        if let Some(condition) = &self.if_none_match {
            let fails = match (condition, current) {
                (_, None) => false,
                (Condition::Any, Some(_)) => matches!(method, Method::Put | Method::Patch),
                (Condition::Tags(tags), Some(version)) => {
                    method != Method::Post && tags.iter().any(|tag| tag.weak_eq(version))
                }
            };
            if fails {
                return Err(PreconditionFailed);
            }
        }
        Ok(())
    }

    /// Should a GET or HEAD of a resource at `current` answer 304?
    ///
    /// Only `If-None-Match` counts on a read. `If-Match` on a GET is ignored,
    /// as in the spec's table.
    pub fn not_modified(&self, current: &str) -> bool {
        match &self.if_none_match {
            None => false,
            Some(Condition::Any) => true,
            Some(Condition::Tags(tags)) => tags.iter().any(|tag| tag.weak_eq(current)),
        }
    }
}

/// The `ETag` for a version: the version in quotes, strong.
pub fn etag(version: &str) -> String {
    format!("\"{version}\"")
}

/// `dcterms:modified` as an HTTP-date (IMF-fixdate, RFC 9110 §5.6.7), for
/// `Last-Modified`.
///
/// `modified` is the `xsd:dateTime` lexical form `resources.rs` writes:
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC. `+00:00` is accepted too. Anything else
/// (no zone, another offset, a date that doesn't exist) is `None`, and the
/// response goes out without `Last-Modified` rather than with a wrong one.
/// Parsed by hand because this crate's `time` has `formatting` but not
/// `parsing`, and the format is fixed.
pub fn http_date(modified: &str) -> Option<String> {
    use time::{Date, Month, Time, Weekday};

    let (date, rest) = modified.split_once('T')?;
    let clock = rest
        .strip_suffix('Z')
        .or_else(|| rest.strip_suffix("+00:00"))?;
    // HTTP-dates have one-second precision.
    let clock = clock.split('.').next()?;

    let mut ymd = date.splitn(3, '-');
    let year: i32 = ymd.next()?.parse().ok()?;
    let month: u8 = ymd.next()?.parse().ok()?;
    let day: u8 = ymd.next()?.parse().ok()?;

    let mut hms = clock.splitn(3, ':');
    let hour: u8 = hms.next()?.parse().ok()?;
    let minute: u8 = hms.next()?.parse().ok()?;
    let second: u8 = hms.next()?.parse().ok()?;

    let month = Month::try_from(month).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Time::from_hms(hour, minute, second).ok()?;

    let weekday = match date.weekday() {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    };
    let month = match month {
        Month::January => "Jan",
        Month::February => "Feb",
        Month::March => "Mar",
        Month::April => "Apr",
        Month::May => "May",
        Month::June => "Jun",
        Month::July => "Jul",
        Month::August => "Aug",
        Month::September => "Sep",
        Month::October => "Oct",
        Month::November => "Nov",
        Month::December => "Dec",
    };
    Some(format!(
        "{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT"
    ))
}
```

`closing.strip_prefix('"').unwrap_or(closing)` is `Option::unwrap_or`, which
the `unwrap_used` lint doesn't cover. `find('"')` returns the byte index of an
ASCII character, so `split_at` lands on a character boundary and can't panic.
The same holds for `skip`'s `find(',')`.

- [ ] **Step 4: Run them and watch them pass**

Run: `cargo test -p brolly-solid --lib conditional`
Expected: 14 passed.

- [ ] **Step 5: Format**

Run: `cargo fmt --all`

- [ ] **Step 6: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && ./tools/check-doc-paths.sh
```

No `Cargo.toml` changes, so `cargo deny check` isn't needed.

- [ ] **Step 7: Stage, don't commit**

```bash
git add adapters/solid/src/conditional.rs adapters/solid/src/lib.rs
```

### Task 2: The HTTP tests, failing

**Files:**
- Modify: `server/tests/pod_http.rs`: helpers after the `impl Harness` block
  (`:122-152` at f564eb6); tests appended after the last test in the file
  (`wac_allow_on_an_acl_names_nothing_for_bob`, `:866-887` at f564eb6)

These use only the router, `h.session`, `HOST`, `NOTE`, `member_session` and
`harness()`. Chunk 4 rewrites how `harness()` seeds the pod (provisioning
instead of raw inserts) but not these, so they apply to whatever chunk 4 left.

- [ ] **Step 1: Add the helpers**

After the existing `impl Harness { … }` block, add:

```rust
/// A request with extra headers, as whoever holds `session`, or anonymously.
fn conditional_request(
    method: &str,
    path: &str,
    body: Option<(&str, &str)>,
    session: Option<&str>,
    extra: &[(&str, &str)],
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST);
    if let Some(session) = session {
        builder = builder.header(header::COOKIE, format!("brolly_session={session}"));
    }
    if let Some((content_type, _)) = body {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder
        .body(body.map_or(Body::empty(), |(_, b)| Body::from(b.to_string())))
        .unwrap()
}

/// Send a request. Takes the router by value so a test can `tokio::spawn` it.
async fn run(
    router: axum::Router,
    request: Request<Body>,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let text = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, text, headers)
}

impl Harness {
    /// [`Harness::send`] as the owner, with extra request headers.
    async fn send_if(
        &self,
        method: &str,
        path: &str,
        body: Option<(&str, &str)>,
        extra: &[(&str, &str)],
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        run(
            self.router.clone(),
            conditional_request(method, path, body, Some(self.session.as_str()), extra),
        )
        .await
    }

    /// The `ETag` the owner sees on `path`.
    async fn etag(&self, path: &str) -> String {
        let (status, body, headers) = self.send("GET", path, None, true).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        headers
            .get(header::ETAG)
            .unwrap_or_else(|| panic!("no ETag on {path}"))
            .to_str()
            .unwrap()
            .to_string()
    }
}
```

- [ ] **Step 2: Write the tests**

Append to the end of `server/tests/pod_http.rs`:

```rust
// --- conditional requests (stage 5a) -------------------------------------------

const EDITED: &str = r#"<> <https://example.org/title> "Edited" ."#;

#[tokio::test]
async fn get_and_head_carry_an_etag_and_last_modified() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    let (status, _, get) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let etag = get
        .get(header::ETAG)
        .expect("no ETag on GET")
        .to_str()
        .unwrap();
    assert!(
        etag.len() > 2 && etag.starts_with('"') && etag.ends_with('"'),
        "a strong tag: {etag}"
    );
    let modified = get
        .get(header::LAST_MODIFIED)
        .expect("no Last-Modified on GET")
        .to_str()
        .unwrap();
    assert!(modified.ends_with(" GMT"), "an HTTP-date: {modified}");

    // HEAD is GET without the body, so it carries the same validators.
    let (status, body, head) = h.send("HEAD", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "HEAD sent a body: {body}");
    assert_eq!(head.get(header::ETAG), get.get(header::ETAG));
    assert_eq!(head.get(header::LAST_MODIFIED), get.get(header::LAST_MODIFIED));
}

/// Every kind has a version: a container (here the root) and a binary too.
#[tokio::test]
async fn a_container_and_a_binary_have_an_etag_too() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for path in ["/~/", "/~/paper.pdf"] {
        let (status, _, headers) = h.send("GET", path, None, true).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(headers.get(header::ETAG).is_some(), "{path}: no ETag");
        assert!(
            headers.get(header::LAST_MODIFIED).is_some(),
            "{path}: no Last-Modified"
        );
    }
}

/// RFC 9110 §9.3.4: the server transforms what it stores, so a write response
/// carries no ETag. The version still moves.
#[tokio::test]
async fn a_write_response_carries_no_etag_and_the_etag_moves() {
    let h = harness().await;
    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    assert!(status.is_success(), "{status}");
    assert!(headers.get(header::ETAG).is_none(), "PUT (create) sent an ETag");
    let before = h.etag("/~/note").await;

    let (status, _, headers) = h
        .send("PUT", "/~/note", Some(("text/turtle", EDITED)), true)
        .await;
    assert!(status.is_success(), "{status}");
    assert!(headers.get(header::ETAG).is_none(), "PUT (replace) sent an ETag");
    let after = h.etag("/~/note").await;
    assert_ne!(after, before, "the ETag didn't change after a PUT");

    let sparql =
        r#"INSERT DATA { <https://alice.brolly.test/~/note> <https://example.org/tag> "x" }"#;
    let (status, _, headers) = h
        .send(
            "PATCH",
            "/~/note",
            Some(("application/sparql-update", sparql)),
            true,
        )
        .await;
    assert!(status.is_success(), "{status}");
    assert!(headers.get(header::ETAG).is_none(), "PATCH sent an ETag");
    assert_ne!(h.etag("/~/note").await, after, "the ETag didn't change after a PATCH");

    let (status, _, headers) = h
        .send("POST", "/~/", Some(("text/turtle", NOTE)), true)
        .await;
    assert!(status.is_success(), "{status}");
    assert!(headers.get(header::ETAG).is_none(), "POST sent an ETag");
}

/// What Solid clients use to create without overwriting.
#[tokio::test]
async fn if_none_match_star_creates_but_never_overwrites() {
    let h = harness().await;

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", NOTE)),
            &[("if-none-match", "*")],
        )
        .await;
    assert!(status.is_success(), "a new resource is created: {status}");

    let before = h.etag("/~/note").await;
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-none-match", "*")],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(
        body.contains("Written over HTTP") && !body.contains("Edited"),
        "the refused PUT landed: {body}"
    );
    assert_eq!(h.etag("/~/note").await, before, "a refused PUT moved the version");
}

/// What Solid clients use to detect a conflicting edit.
#[tokio::test]
async fn if_match_needs_the_current_strong_tag() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let stale = h.etag("/~/note").await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;
    assert_ne!(stale, current);

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", stale.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "a stale tag");
    assert_eq!(h.etag("/~/note").await, current, "the refused PUT landed");

    // A weak tag never matches, even with the right opaque value.
    let weak = format!("W/{current}");
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", weak.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "a weak tag");
    assert_eq!(h.etag("/~/note").await, current, "the refused PUT landed");

    // A list holds if any member matches.
    let list = format!("{stale}, {current}");
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", list.as_str())],
        )
        .await;
    assert!(status.is_success(), "the current tag: {status}");
    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(body.contains("Edited"), "got: {body}");
}

#[tokio::test]
async fn if_match_star_needs_the_resource_to_exist() {
    let h = harness().await;

    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/absent",
            Some(("text/turtle", NOTE)),
            &[("if-match", "*")],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    let (status, _, _) = h.send("GET", "/~/absent", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the refused PUT created it");

    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-match", "*")],
        )
        .await;
    assert!(status.is_success(), "{status}");
}

#[tokio::test]
async fn if_none_match_with_the_current_tag() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;

    // GET and HEAD: 304, with the ETag and no body.
    for method in ["GET", "HEAD"] {
        let (status, body, headers) = h
            .send_if(method, "/~/note", None, &[("if-none-match", current.as_str())])
            .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED, "{method}");
        assert_eq!(
            headers.get(header::ETAG).and_then(|v| v.to_str().ok()),
            Some(current.as_str()),
            "{method}: a 304 names the version it confirms"
        );
        assert!(body.is_empty(), "{method}: a 304 has no body: {body}");
    }

    // Another tag is a full response.
    let (status, body, _) = h
        .send_if("GET", "/~/note", None, &[("if-none-match", "\"other\"")])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Written over HTTP"), "got: {body}");

    // PUT and DELETE: 412, and nothing written.
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-none-match", current.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "PUT");
    let (status, _, _) = h
        .send_if("DELETE", "/~/note", None, &[("if-none-match", current.as_str())])
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "DELETE");
    assert_eq!(h.etag("/~/note").await, current, "a refused write landed");
}

#[tokio::test]
async fn patch_and_delete_honour_if_match() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let stale = h.etag("/~/note").await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    let current = h.etag("/~/note").await;

    let sparql =
        r#"INSERT DATA { <https://alice.brolly.test/~/note> <https://example.org/tag> "patched" }"#;
    let (status, _, _) = h
        .send_if(
            "PATCH",
            "/~/note",
            Some(("application/sparql-update", sparql)),
            &[("if-match", stale.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "PATCH, stale");
    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(!body.contains("patched"), "the refused PATCH landed: {body}");

    let (status, _, _) = h
        .send_if(
            "PATCH",
            "/~/note",
            Some(("application/sparql-update", sparql)),
            &[("if-match", current.as_str())],
        )
        .await;
    assert!(status.is_success(), "PATCH, current: {status}");
    let patched = h.etag("/~/note").await;

    // `current` is stale now.
    let (status, _, _) = h
        .send_if("DELETE", "/~/note", None, &[("if-match", current.as_str())])
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "DELETE, stale");
    let (status, _, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::OK, "the refused DELETE landed");

    let (status, _, _) = h
        .send_if("DELETE", "/~/note", None, &[("if-match", patched.as_str())])
        .await;
    assert!(status.is_success(), "DELETE, current: {status}");
    let (status, _, _) = h.send("GET", "/~/note", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A POST's `If-Match` names the container, the request's target, not the
/// member it would mint.
#[tokio::test]
async fn if_match_on_a_post_is_about_the_container() {
    let h = harness().await;
    let (status, _, _) = h
        .send("PUT", "/~/c/", Some(("text/turtle", "")), true)
        .await;
    assert!(status.is_success(), "an empty container: {status}");
    let stale = h.etag("/~/c/").await;

    // A member moves the container's version (R9).
    let (status, _, _) = h
        .send("POST", "/~/c/", Some(("text/turtle", NOTE)), true)
        .await;
    assert!(status.is_success(), "{status}");
    let current = h.etag("/~/c/").await;
    assert_ne!(stale, current);

    let (status, _, _) = h
        .send_if(
            "POST",
            "/~/c/",
            Some(("text/turtle", NOTE)),
            &[("if-match", stale.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        h.etag("/~/c/").await,
        current,
        "the refused POST added a member"
    );

    let (status, _, headers) = h
        .send_if(
            "POST",
            "/~/c/",
            Some(("text/turtle", NOTE)),
            &[("if-match", current.as_str())],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(headers.get(header::LOCATION).is_some());
}

/// The ETag is authoritative; dates are ignored.
#[tokio::test]
async fn date_preconditions_are_ignored() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    // Honoured, this would be a 304.
    let (status, _, _) = h
        .send_if(
            "GET",
            "/~/note",
            None,
            &[("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT")],
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Honoured, this would be a 412.
    let (status, _, _) = h
        .send_if(
            "PUT",
            "/~/note",
            Some(("text/turtle", EDITED)),
            &[("if-unmodified-since", "Mon, 01 Jan 1990 00:00:00 GMT")],
        )
        .await;
    assert!(status.is_success(), "{status}");
}

/// A caller without the mode a method needs gets the same answer whether or
/// not the resource exists. The precondition is evaluated after authorisation,
/// so it can't become an existence oracle.
#[tokio::test]
async fn a_caller_without_the_mode_learns_nothing_from_a_precondition() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;
    h.send("PUT", "/~/c/", Some(("text/turtle", "")), true)
        .await;
    // Bob holds no grant anywhere in Alice's pod.
    let bob = member_session(&h, "bob").await;

    let turtle = Some(("text/turtle", NOTE));
    let sparql = Some((
        "application/sparql-update",
        r#"INSERT DATA { <https://alice.brolly.test/~/note> <https://example.org/tag> "bob" }"#,
    ));
    let cases: [(&str, &str, &str, Option<(&str, &str)>, (&str, &str)); 8] = [
        ("PUT", "/~/note", "/~/absent", turtle, ("if-none-match", "*")),
        ("PUT", "/~/note", "/~/absent", turtle, ("if-match", "*")),
        ("PUT", "/~/note", "/~/absent", turtle, ("if-match", "\"stale\"")),
        ("PATCH", "/~/note", "/~/absent", sparql, ("if-match", "*")),
        ("PATCH", "/~/note", "/~/absent", sparql, ("if-none-match", "*")),
        ("DELETE", "/~/note", "/~/absent", None, ("if-match", "\"stale\"")),
        ("POST", "/~/c/", "/~/absent/", turtle, ("if-match", "*")),
        ("GET", "/~/note", "/~/absent", None, ("if-none-match", "*")),
    ];

    for (method, existing, missing, body, condition) in cases {
        let (on_existing, _, _) = run(
            h.router.clone(),
            conditional_request(method, existing, body, Some(bob.as_str()), &[condition]),
        )
        .await;
        let (on_missing, _, _) = run(
            h.router.clone(),
            conditional_request(method, missing, body, Some(bob.as_str()), &[condition]),
        )
        .await;
        assert_eq!(
            on_existing, on_missing,
            "{method} {condition:?}: the answer depends on existence"
        );
        assert!(
            !on_existing.is_success()
                && on_existing != StatusCode::PRECONDITION_FAILED
                && on_existing != StatusCode::NOT_MODIFIED,
            "{method} {condition:?}: got {on_existing}, not a refusal"
        );
    }

    let (_, body, _) = h.send("GET", "/~/note", None, true).await;
    assert!(!body.contains("bob"), "a refused write landed: {body}");
    let (status, _, _) = h.send("GET", "/~/absent", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a refused write created it");
}

/// The lost-update case `If-Match` exists for. The check and the write are one
/// `Pod::write`, under the pod's lock, so two writers holding the same tag
/// can't both pass. Spawned, so they run on different worker threads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn of_two_concurrent_puts_with_one_if_match_exactly_one_lands() {
    let h = harness().await;
    h.send("PUT", "/~/note", Some(("text/turtle", NOTE)), true)
        .await;

    for round in 0..8 {
        let tag = h.etag("/~/note").await;
        let spawn = |writer: &str| {
            let body = format!("<> <https://example.org/writer> \"{writer}-{round}\" .");
            let request = conditional_request(
                "PUT",
                "/~/note",
                Some(("text/turtle", body.as_str())),
                Some(h.session.as_str()),
                &[("if-match", tag.as_str())],
            );
            tokio::spawn(run(h.router.clone(), request))
        };
        let (a, b) = (spawn("a"), spawn("b"));
        let (a, b) = (a.await.unwrap().0, b.await.unwrap().0);

        let landed = [a, b].iter().filter(|s| s.is_success()).count();
        assert_eq!(landed, 1, "round {round}: {a} and {b}");
        assert!(
            [a, b].contains(&StatusCode::PRECONDITION_FAILED),
            "round {round}: {a} and {b}"
        );
    }
}
```

`PDF` is the constant already in this file (the LDP-NR section). `send_if` with
method `HEAD` works because `conditional_request` sends whatever method it's
given, and axum routes HEAD to the GET handler.

- [ ] **Step 3: Run them and watch them fail**

Run: `cargo test -p brolly-server --test pod_http -- --test-threads=4 etag if_ precondition concurrent date_`

Expected (the filters match every new test):
- **Fail:** `get_and_head_carry_an_etag_and_last_modified` panics with
  `no ETag on GET`. `a_container_and_a_binary_have_an_etag_too` panics with
  `/~/: no ETag`. `a_write_response_carries_no_etag_and_the_etag_moves`,
  `if_none_match_star_creates_but_never_overwrites`,
  `if_match_needs_the_current_strong_tag`,
  `if_none_match_with_the_current_tag`, `patch_and_delete_honour_if_match`,
  `if_match_on_a_post_is_about_the_container` and
  `of_two_concurrent_puts_with_one_if_match_exactly_one_lands` panic in
  `Harness::etag` with `no ETag on /~/note` (or `/~/c/`).
  `if_match_star_needs_the_resource_to_exist` fails `assert_eq!` with
  `left: 204` or `201`, `right: 412`, because the PUT ignored `If-Match`.
- **Pass already:** `date_preconditions_are_ignored` (nothing honours dates yet)
  and `a_caller_without_the_mode_learns_nothing_from_a_precondition` (nothing
  evaluates preconditions yet). Both are guards that must still pass after
  Task 4.

Don't run the gates or stage in this task. The tree has failing tests until
Task 4.

### Task 3: `ldp` evaluates preconditions inside the transaction

**Files:**
- Modify: `adapters/solid/src/ldp.rs`: `LdpError` (`:21-45` at f564eb6), `LdpOutcome` (`:114-124` at f564eb6), `read`, `put`/`put_in`, `append`/`append_in`, `delete`/`delete_in` as chunk 4 left them
- Modify: `adapters/solid/src/patch.rs`: `PatchError` (`:29-57` at f564eb6), only if Step 1 says so
- Modify: every caller of `put_in`, `append_in`, `delete_in` outside `ldp.rs` (at least `server/src/mastodon_api.rs`'s upload path, per the spec)

- [ ] **Step 1: Reconcile with chunk 4**

This chunk was written against f564eb6 and the spec. Before editing, open
`adapters/solid/src/ldp.rs`, `server/src/pod.rs` and the PATCH path as chunks
3–4 left them, and confirm the shapes this task assumes. Adapt *names* to what
you find, not behaviour:

1. The outer `put`, `append`, `delete` take `&Pod` and otherwise the
   parameters they had at f564eb6. Each runs one `pod.write(|w| …)` that calls
   the matching `put_in(w, …)`, `append_in(w, …)`, `delete_in(w, …)`.
2. Each `_in` function checks WAC against the transaction first (returning
   `LdpError::Forbidden` on refusal), and knows the full resource IRI
   (`resource`, or `container` in `append_in`).
3. `PodWrite::meta(&str) -> Result<Option<ResourceMeta>, StoreError>` (the
   fixed interface), and `LdpError` has a way in from `StoreError` (`From`, or
   `LdpError::Store(e.to_string())`).
4. `read` gets the resource's `ResourceMeta` from its `Pod::read` snapshot
   (existence is `meta(..).is_some()`, spec *Reading a resource*), and builds
   `LdpOutcome` from that snapshot.
5. However chunk 4's outer functions carry an `LdpError` out of the
   `Pod::write` closure (whose error type is `StoreError`), the same carrier
   carries `PreconditionFailed`. The check runs before any write in the
   closure, so the transaction it aborts or commits is empty either way.
6. PATCH: `server/src/pod.rs::patch` runs a `Pod::write` closure that checks
   Write and then calls a `patch::apply_*` function. Note which error type the
   closure carries out, `PatchError` or `LdpError`. Task 4, Step 4 uses it.

If `put_in` or `append_in` already has 8 parameters, the one added here takes
it over `clippy.toml`'s `too-many-arguments-threshold = 8`. Use the same
`#[allow]` and comment as the outer `_if` functions below.

- [ ] **Step 2: `LdpError::PreconditionFailed`**

In `adapters/solid/src/ldp.rs`, import the module:

```rust
use crate::conditional::{self, PreconditionFailed, Preconditions};
```

Add the variant to `LdpError`, after `OutsideStorage` (keep whatever chunk 4
added, such as `NotRdf` and `ContainmentChange`):

```rust
    /// An `If-Match` or `If-None-Match` didn't hold (412). Evaluated after WAC,
    /// so only a caller holding the needed mode can see it.
    PreconditionFailed,
```

its `Display` arm:

```rust
            LdpError::PreconditionFailed => write!(f, "precondition failed"),
```

and the conversion, next to the other `From` impls:

```rust
impl From<PreconditionFailed> for LdpError {
    fn from(_: PreconditionFailed) -> Self {
        LdpError::PreconditionFailed
    }
}
```

- [ ] **Step 3: `LdpOutcome` carries the snapshot's version**

Add two fields to `LdpOutcome`, after `is_container`:

```rust
    /// `brolly:version` from the same snapshot as `body`: the `ETag`.
    pub version: String,
    /// `dcterms:modified` from the same snapshot, as stored
    /// (`xsd:dateTime`): the `Last-Modified`.
    pub modified: String,
```

In `read`, every `LdpOutcome { … }` literal (the binary branch, and the RDF and
container branch or branches) gets:

```rust
        version: meta.version.clone(),
        modified: meta.modified.clone(),
```

where `meta` is the `ResourceMeta` the snapshot closure already read to decide
existence (Step 1, item 4). If chunk 4 matched it away (`let Some(_) = …`),
bind it instead (`let Some(meta) = …`). Take them from that value, not from a
second read, so the ETag always describes the body it goes out with.

- [ ] **Step 4: The `_in` functions evaluate preconditions**

Add a last parameter to each of `put_in`, `append_in`, `delete_in`:

```rust
    preconditions: &Preconditions,
```

Add to each doc comment:

```rust
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the resource, so no other write
/// can land between the check and this one. Pass `Preconditions::NONE` when not
/// answering an HTTP request.
```

Then insert the check.

**`put_in`**, immediately after the Write check's `return Err(LdpError::Forbidden)`
and before anything is parsed into `Content`, compared with the container's
members, or written:

```rust
    let current = w.meta(&resource)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Put, current.as_deref())?;
```

**`append_in`**, immediately after the Append check. The target is the
request's IRI, the container (or the document appended to), not the member it
mints:

```rust
    // A POST's precondition is about the container (or the document appended
    // to), which is what the client addressed and holds a tag for.
    let current = w.meta(&container)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Post, current.as_deref())?;
```

**`delete_in`**, after the Write check *and* after the not-found check, but
before the non-empty-container refusal and before `remove`. A DELETE of a
missing resource answers 404 whatever its preconditions (RFC 9110 §13.2.1: a
server ignores preconditions when the unconditional response wouldn't be 2xx or
412):

```rust
    preconditions.check_write(conditional::Method::Delete, Some(meta.version.as_str()))?;
```

where `meta` is the `ResourceMeta` the not-found check just read. If chunk 4
tests existence with `is_none()`/`is_some()` instead of binding it, bind it:
`let Some(meta) = w.meta(&resource)? else { return Err(LdpError::NotFound) };`.

In each, if `w.meta` returns `StoreError` and `LdpError` has no `From`, write
`w.meta(&resource).map_err(|e| LdpError::Store(e.to_string()))?`.

- [ ] **Step 5: The outer `_if` functions**

Rename chunk 4's outer `pub fn put(…)` to `put_if`, add
`preconditions: &Preconditions` as its last parameter, and pass it to its
`put_in(…)` call. Do the same for `append` → `append_if` and `delete` →
`delete_if`. Put this on `put_if` and `append_if` (nine parameters):

```rust
// One over `clippy.toml`'s threshold. `put` keeps the old eight for every caller
// that isn't HTTP; folding the request into a struct is 5b's HTTP-surface work.
#[allow(clippy::too_many_arguments)]
```

Then restore the old names as wrappers, directly after each `_if`. With the
f564eb6 parameter lists (keep chunk 4's if they changed):

```rust
/// [`put_if`] with no preconditions.
pub fn put(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
) -> Result<(), LdpError> {
    put_if(
        pod,
        blobs,
        base,
        path,
        subject,
        body,
        content_type,
        storage_root,
        &Preconditions::NONE,
    )
}

/// [`append_if`] with no preconditions.
pub fn append(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
) -> Result<String, LdpError> {
    append_if(
        pod,
        blobs,
        base,
        path,
        subject,
        body,
        content_type,
        storage_root,
        &Preconditions::NONE,
    )
}

/// [`delete_if`] with no preconditions.
pub fn delete(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    storage_root: &str,
) -> Result<(), LdpError> {
    delete_if(pod, blobs, base, path, subject, storage_root, &Preconditions::NONE)
}
```

The return types are chunk 4's. If `put` now returns, say, whether it created,
the wrapper returns the same.

So the ~80 calls to `ldp::put`, `append` and `delete` in
`adapters/solid/tests/*.rs`, `authz/tests/conformance_matrix.rs` and
`server/src/mastodon_api.rs` don't change.

- [ ] **Step 6: Release the bytes a refused binary write left behind**

In `put_if` and `append_if`, the binary branch writes the bytes to `BlobStore`
before `pod.write` (spec, *Blob bytes go in first*). If the write then fails its
precondition, nothing records the new digest, and the file would stay on disk
unreferenced. Right after the binary branch's `pod.write(…)` returns, with
`digest` the new bytes' digest and `result` the write's result (use chunk 4's
names):

```rust
        if matches!(result, Err(LdpError::PreconditionFailed)) {
            // Under the lock, `release_blob` deletes the file only if nothing
            // references it. So bytes identical to a live resource (this one's
            // own, sent with a stale tag, say) survive, and a concurrent upload
            // of the same bytes either committed first or gets `BlobMissing`
            // and writes them again (R12). A failure here leaves an orphan
            // file, not a wrong answer, so the 412 still stands.
            let _ = pod.write(|w| {
                w.release_blob(&digest);
                Ok(())
            });
        }
```

If chunk 4 already releases the new digest on *every* error from the write,
this is covered, so skip this step.

- [ ] **Step 7: `PatchError::NotCurrent`, if PATCH carries `PatchError`**

Only if Step 1, item 6 found that the PATCH closure carries `PatchError`. (If it
carries `LdpError`, Task 4 uses `LdpError::PreconditionFailed` and this step is
skipped.) In `adapters/solid/src/patch.rs`, add to `PatchError`, after
`EscapesGraph`:

```rust
    /// The request's `If-Match` or `If-None-Match` didn't hold (412). Not
    /// `Precondition`, which is a `solid:where` that didn't bind (409).
    NotCurrent,
```

the `Display` arm:

```rust
            PatchError::NotCurrent => write!(f, "the resource is not at the version the request named"),
```

and the conversion, after `impl std::error::Error for PatchError {}`:

```rust
impl From<crate::conditional::PreconditionFailed> for PatchError {
    fn from(_: crate::conditional::PreconditionFailed) -> Self {
        PatchError::NotCurrent
    }
}
```

- [ ] **Step 8: Fix the `_in` callers**

Run: `cargo build --workspace --all-targets`

Each error is a call to `put_in`, `append_in` or `delete_in` that's now one
argument short (`error[E0061]: this function takes N arguments but N-1 arguments
were supplied`). Outside `ldp.rs`, append `&brolly_solid::conditional::Preconditions::NONE`
(or import it). The spec names `mastodon_api.rs`'s upload with alt text, which
calls `put_in` then `append_in` in one closure. Neither is an HTTP
precondition, so both get `NONE`. Inside `ldp.rs`, the `_if` functions pass
their `preconditions` through (Step 5).

Repeat until it builds.

- [ ] **Step 9: Run the adapter's tests**

Run: `cargo test -p brolly-solid && cargo test -p brolly-authz`
Expected: all pass, the same count as before this task plus Task 1's 14. No
existing behaviour changed, because every existing caller passes
`Preconditions::NONE`, whose `check_write` is always `Ok`.

`pod_http`'s new tests still fail, because `pod.rs` doesn't pass preconditions
or send `ETag` yet.

- [ ] **Step 10: Format**

Run: `cargo fmt --all`

- [ ] **Step 11: Gates, except `pod_http`**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --exclude brolly-server && cargo test -p brolly-server --lib --bins && ./tools/check-doc-paths.sh
```

Also run `cargo test -p brolly-server` and confirm that the only failures are
the Task 2 tests listed as failing in Task 2, Step 3.

- [ ] **Step 12: Stage, don't commit**

```bash
git add adapters/solid/src/ldp.rs adapters/solid/src/patch.rs server/tests/pod_http.rs
git add -u   # the `_in` callers Step 8 touched
git status   # nothing unstaged, no stray files
```

### Task 4: `pod.rs` sends validators and answers 304 and 412, then commit

**Files:**
- Modify: `server/src/pod.rs`: imports (`:8-18` at f564eb6), a new helper after `wac_allow` (`:235-247`), `ldp_error` (`:216-233`), `get` (`:249-288`), `put` (`:290-320`), `post` (`:322-352`), `patch` (`:354-416`), `delete` (`:418-440`), all as chunk 4 left them

The handlers below are written against f564eb6 with `request.store` renamed
`request.pod` (chunk 4's `PodRequest` holds an `Arc<Pod>`). Where chunk 4 changed
anything else in a handler (a new status code, a new `LdpError` arm, how the
PATCH closure is spelled), keep chunk 4's version and change only the lines
this task names.

- [ ] **Step 1: Read the preconditions from the request**

Add to the imports:

```rust
use axum::http::HeaderValue;
use brolly_solid::conditional::{self, Preconditions};
```

and after `wac_allow`:

```rust
/// A request's `If-Match` and `If-None-Match`.
///
/// Each header may arrive on several lines, which mean the same as one line
/// joined with commas (RFC 9110 §5.3). Bytes that aren't UTF-8 go in lossily.
/// They can't match a version, which is ASCII, so an `If-Match` made only of
/// them fails, and an `If-None-Match` made only of them holds.
fn preconditions(headers: &HeaderMap) -> Preconditions {
    let field = |name: header::HeaderName| -> Option<String> {
        let lines: Vec<String> = headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        (!lines.is_empty()).then(|| lines.join(", "))
    };
    Preconditions::from_fields(
        field(header::IF_MATCH).as_deref(),
        field(header::IF_NONE_MATCH).as_deref(),
    )
}
```

- [ ] **Step 2: 412**

In `ldp_error`, add an arm before the `LdpError::Store` arm:

```rust
        LdpError::PreconditionFailed => {
            (StatusCode::PRECONDITION_FAILED, "precondition failed").into_response()
        }
```

- [ ] **Step 3: GET and HEAD**

Replace the body of `get` from `let accept = …` to the end with:

```rust
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    let outcome = match ldp::read(
        &request.pod,
        Some(&request.blobs),
        &request.base,
        &path,
        &request.subject,
        accept,
    ) {
        Ok(outcome) => outcome,
        Err(e) => return ldp_error(e),
    };

    // After `read` succeeded, so after the Read check, and against the version
    // from the same snapshot as the body. A caller without Read got 404 above
    // whatever they sent.
    let etag = conditional::etag(&outcome.version);
    if preconditions(&headers).not_modified(&outcome.version) {
        // RFC 9110 §15.4.5: a 304 carries the ETag and no body.
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }

    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, outcome.media_type.clone()),
            (
                header::HeaderName::from_static("wac-allow"),
                wac_allow(&outcome.granted),
            ),
            (
                header::LINK,
                format!("<{}{path}.acl>; rel=\"acl\"", request.base),
            ),
            (header::ETAG, etag),
        ],
        outcome.body,
    )
        .into_response();
    // Omitted rather than wrong if the stored time isn't one we can render.
    if let Some(date) = conditional::http_date(&outcome.modified)
        && let Ok(value) = HeaderValue::from_str(&date)
    {
        response.headers_mut().insert(header::LAST_MODIFIED, value);
    }
    response
}
```

If chunk 4 added headers to the 200 array, keep them and add only the
`(header::ETAG, etag)` entry.

Also extend `get`'s doc comment:

```rust
/// `GET /~/*path`, and `HEAD`, which axum routes here without the body.
///
/// Sends `ETag` (the resource's version) and `Last-Modified`, and answers 304
/// to an `If-None-Match` naming the current version. Only here: a write's
/// response carries no `ETag`, because the server transforms what it stores
/// (RFC 9110 §9.3.4).
```

- [ ] **Step 4: PUT, POST, DELETE, PATCH**

**`put`:** change the call from `ldp::put(` to `ldp::put_if(` and add
`&preconditions(&headers),` as the last argument, after `&request.storage_root,`.
Leave the `Ok` arm as chunk 4 left it. It must not add an `ETag`.

**`post`:** likewise `ldp::append(` → `ldp::append_if(`, with
`&preconditions(&headers),` last.

**`delete`:** likewise `ldp::delete(` → `ldp::delete_if(`, with
`&preconditions(&headers),` last.

**`patch`:** before the `Pod::write` call, add:

```rust
    let preconditions = preconditions(&headers);
```

Inside the closure, immediately after the Write check refuses (`Forbidden`) and
before the `apply_n3_patch` / `apply_sparql_update` call, add:

```rust
        // After the Write check and in the same transaction as the patch, so
        // nothing lands between the check and the write.
        let current = w.meta(&resource)?.map(|meta| meta.version);
        preconditions.check_write(conditional::Method::Patch, current.as_deref())?;
```

The `?` on `check_write` converts through `From<PreconditionFailed>` into the
closure's error type (Task 3, Step 1, item 6):
- If that's `PatchError`, Task 3, Step 7 added `NotCurrent`. Add an arm to the
  `match result` at the end of `patch`, before the catch-all `Err(e)` arm:

  ```rust
        Err(patch::PatchError::NotCurrent) => {
            (StatusCode::PRECONDITION_FAILED, "precondition failed").into_response()
        }
  ```

- If it's `LdpError`, `ldp_error` already maps it (Step 2), and there's no new
  arm.

If the `?` on `w.meta` doesn't convert (the closure's error type has no
`From<StoreError>`), use the conversion chunk 4 uses for the Write check's own
store errors in that closure.

The two content-type early returns (415 for an unknown PATCH format, 400 for a
non-UTF-8 SPARQL body) stay before the closure, and so before the precondition.
RFC 9110 §13.2.1 evaluates preconditions only when the request would otherwise
succeed, and these requests can't.

- [ ] **Step 5: Run the HTTP tests and watch them pass**

Run: `cargo test -p brolly-server --test pod_http`
Expected: all pass, including the 12 from Task 2.

Run the concurrency test alone a few times, since it's the one a regression
would make flaky rather than red:

```bash
for i in 1 2 3 4 5; do cargo test -p brolly-server --test pod_http of_two_concurrent_puts -- --exact --nocapture 2>&1 | tail -1; done
```

Expected: `test result: ok. 1 passed` five times. (`--exact` with the full
name `of_two_concurrent_puts_with_one_if_match_exactly_one_lands` if the filter
matches more than one.)

- [ ] **Step 6: Format**

Run: `cargo fmt --all`

- [ ] **Step 7: Gates**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && ./tools/check-doc-paths.sh
```

No `Cargo.toml` changes, so `cargo deny check` isn't needed.

- [ ] **Step 8: Commit**

```bash
git add server/src/pod.rs
git add -u
git status   # conditional.rs, lib.rs, ldp.rs, patch.rs (if changed), pod.rs, pod_http.rs, the _in callers; nothing else
git commit -F - <<'MSG'
feat(solid): ETags, and If-Match and If-None-Match on the pod

GET and HEAD send ETag, the resource's version from urn:brolly:resources,
and Last-Modified from its dcterms:modified, both from the same snapshot
as the body. If-None-Match naming the current version answers 304 with
the ETag. Write responses carry no ETag: the server transforms what it
stores (RFC 9110 9.3.4).

PUT, PATCH, DELETE and POST honour If-Match (strong comparison, so a W/
tag never matches; on a POST it names the container) and PUT and PATCH
honour If-None-Match: *, so a client can create without overwriting. A
failed precondition is 412 and writes nothing. It is checked inside the
write's Pod::write closure, after WAC and before the write, so two
writers holding the same tag can't both land, and a caller without the
mode the method needs gets the ordinary refusal whether or not the
resource exists. If-Modified-Since and If-Unmodified-Since are ignored.

The header parsing and the rules live in brolly_solid::conditional and
are unit-tested. ldp's _in functions take the preconditions; put_if,
append_if and delete_if are the HTTP entry points, and put, append and
delete keep their signatures and pass none.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

- [ ] **Step 9: Verify from a clean checkout**

```bash
rm -rf /tmp/verify && git worktree add --detach /tmp/verify HEAD
cd /tmp/verify && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && ./tools/check-doc-paths.sh
cd - && git worktree remove /tmp/verify --force
```

The commit isn't done until that passes.

### Notes for the reviewer

- **Written without chunks 1–4 in view.** They were being written in parallel,
  so Task 3, Step 1 lists every shape this chunk assumes of them (the `_in`
  layer and where its WAC check sits, `PodRequest.pod`, how an `LdpError` leaves
  a `Pod::write` closure, how PATCH's closure is spelled) and tells the
  implementer to adapt names, not behaviour. The line ranges cited are at
  f564eb6; chunks 1–4 move them.
- **If-None-Match uses the weak comparison.** The brief said "strong
  comparison, W/ never matches". The spec's table says that only for
  `If-Match`, and RFC 9110 §13.1.2 prescribes weak comparison for
  `If-None-Match`. So `If-None-Match: W/"v"` gives 304 on GET and 412 on
  PUT/PATCH/DELETE when `v` is current. It matters in practice: a proxy that
  compresses a response often weakens its ETag, and the browser then revalidates
  with `W/"…"`. Every tag we issue is strong, so `If-Match` is unaffected. To
  follow the brief literally instead, replace `weak_eq` with `strong_eq` in
  `check_write` and `not_modified`, and flip the two unit tests and none of the
  HTTP tests.
- **`If-None-Match: *` on GET answers 304.** The spec's table lists only a tag
  for GET/HEAD. RFC 9110 §13.1.2 says `*` matches any current representation,
  and a GET that got that far found one.
- **`If-Match` on GET/HEAD is ignored.** RFC 9110 would allow a 412. The spec's
  table lists `If-Match` only for writes, and no Solid client sends it on a
  read.
- **`If-None-Match: *` on DELETE and POST, and any `If-None-Match` on POST, are
  ignored.** That follows the spec's table exactly. RFC 9110 would evaluate
  them, but a POST's `If-None-Match` would be about the container, which always
  exists.
- **DELETE of a missing resource is 404 whatever its preconditions.** The check
  in `delete_in` comes after the not-found check, per RFC 9110 §13.2.1 (a server
  ignores preconditions when the unconditional answer wouldn't be 2xx or 412).
  PUT and POST to a missing target do evaluate, since their unconditional
  answer would be 2xx, which is what makes `If-Match: *` → 412 work.
- **Body parsing may come before the precondition.** Chunk 4's outer `put`
  likely parses the body (415 on bad syntax) and writes blob bytes before
  `Pod::write`. So a malformed body with a failing precondition gives 415, not
  412. RFC 9110 §13.2.1 would evaluate the precondition first. It's harmless
  (both refusals), and moving the parse inside the lock would hold it across
  parsing.
- **Orphaned bytes on a 412 binary write** are released (Task 3, Step 6) under
  the lock with `release_blob`, which keeps the bytes if any resource still
  references them. That's the R12 rule, applied to a new failure path.
- **Malformed fields.** A malformed element is dropped and the rest still
  count. A field with nothing usable holds for nothing, so `If-Match` fails
  closed and `If-None-Match` lets the request through. A `*` inside a list is
  malformed, not "any". The alternative was 400 for a malformed field. Neither
  RFC 9110 nor the spec requires it, and 5b owns the status codes.
- **`Preconditions` evaluation lives in `brolly-solid`**, not `server`, because
  it runs inside `ldp`'s `_in` functions, which `server` can't be depended on
  by. The module is transport-free (header *values* in), like the rest of the
  crate. `pod.rs` does the `HeaderMap` part.
- **`put_if` and `append_if` have nine parameters.** That's one over
  `clippy.toml`'s threshold, so each carries an `#[allow]` with a comment. The
  alternative, a request struct threaded through every `ldp` caller (~80 call
  sites in tests), is out of scope. The `_if` split keeps those call sites
  unchanged.
- **`Last-Modified` is formatted by hand** (`conditional::http_date`).
  `brolly-solid`'s `time` has `formatting` but not `parsing`, and `server`'s has
  neither. Adding `parsing` would change a `Cargo.toml` for one fixed format.
  It accepts `Z` or `+00:00`, and if chunk 1 stores `modified` in any other
  form the header is omitted and `get_and_head_carry_an_etag_and_last_modified`
  fails, which is the signal.
- **A 304 carries only `ETag`,** not `Last-Modified`, `WAC-Allow` or `Link`.
  RFC 9110 §15.4.5 says a 304 shouldn't carry other representation metadata. 5b
  adds `Vary: Accept` (R4), which a 304 should then also carry.
- **CORS already allows `If-Match`/`If-None-Match` and exposes `ETag`**
  (`server/src/lib.rs:176`, `:180`), and `Last-Modified` is safelisted, so
  `cors` doesn't change.
- **The disclosure test uses Bob with no grants,** not `share_with_bob`, so it
  doesn't depend on how chunk 4 reseeds ACLs in the harness. It passes before
  and after this chunk. It guards the ordering, so a later change that evaluates
  preconditions before WAC turns it red. The exact refusal codes (403/404 today,
  5b's 401/403 later) aren't asserted, only that existing and missing get the
  same one.
- **Authenticated HEAD with DPoP is 5b.** `resolve` verifies proofs against
  `"GET"`. The HEAD assertions here use the session cookie, per the brief.


## Done when

- Commits 1–3 are on `main`, each verified from a clean checkout.
- Every test named in the spec's Testing section passes.
- A pod written before commit 2 opens with every resource, listing and binary
  intact, and a second open changes nothing.
- `docs/deploying.md` says commit 2 is forward-only, and to snapshot the volume
  before deploying it.
- The roadmap marks stage 5a done.
