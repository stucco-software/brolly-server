# Stage 5a: server-managed resource metadata

<!-- doc-paths: skip -->
<!-- The spec cites a file this stage deletes, so not every path it names
     resolves once it's implemented. -->

**Status:** Approved for planning (2026-09-22), after three review passes
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 5, part a. Parts
b (HTTP surface), c (write semantics) and d (auxiliary resources and the
conformance suite) build on this one.
**Depends on:** ADR 0010 (storage root at `/~/`), ADR 0012 (the publication
surface), ADR 0013 (binaries as content-addressed blobs), and the stage 0 rules
(`docs/specs/2026-09-17-security-fixes.md`, A1 and A2).

## Problem

A pod stores each LDP resource as the named graph at its IRI. Everything the
server knows about the resource is read back out of that graph, the same graph
the member writes: whether it exists, what kind it is, what a container lists,
and where a binary's bytes are. Every writer also holds a bare `Store` and can
write anything anywhere in the pod. This causes six problems:

1. **An empty resource doesn't exist.** `storage::exists`
   (`adapters/solid/src/storage.rs`) is true only when the graph has at least
   one quad.
   - A `PUT` of an empty RDF body, or of a container with no body, leaves an
     empty graph.
   - The parent lists it, but `GET` and `DELETE` answer 404, so the listing can
     never be removed.
   - Inrupt's `solid-client`, soukai and LDO create containers exactly this way.
2. **A write can destroy a container's membership.**
   - `put` replaces the whole graph, so `PUT` to an existing container wipes its
     `ldp:contains` triples and its type.
   - The members survive, unlisted. The container then looks empty to `delete`,
     which removes it over a live subtree.
   - A PATCH can do the same, and a body saying `<> ldp:contains <x>` invents a
     member.
3. **Server-owned triples are writable.** The blob pointer triples (ADR 0013)
   sit in the resource's graph, and an RDF PUT or PATCH can write them. A member
   with Write on one resource can make it serve the bytes of any other blob in
   the same pod.
4. **Nothing records when a resource changed.** There's no modified time or
   version, so no `ETag`, `Last-Modified` or conditional requests. Solid clients
   use `If-None-Match: *` to create without overwriting, and `If-Match` to
   detect conflicting edits.
5. **Writes aren't atomic.** A PUT clears a graph, inserts, then updates the
   parent's containment as separate store calls. Concurrent writes can
   interleave, and a failure midway leaves a half-written resource.
6. **Posts aren't pod resources.** The outbox and the Mastodon composer write
   notes and activities under `/~/notes/` and `/~/activities/` through
   `activitypub::inbox`, bypassing LDP. Posts are readable by IRI but never
   listed, and a Solid app can't see one deleted.

## Goals

- **Server-managed state is out of client reach.** Existence, kind,
  containment, modified time, version and binary metadata live where no client
  write can reach them.
- **No writer bypasses the metadata.** Every write to a pod goes through one
  interface, which keeps the metadata true. The type system enforces this, not
  review.
- **Empty resources exist.** An empty RDF document and an empty container exist
  once created.
- **Containment can't be changed by a write.** This holds by construction.
- **Writes are atomic.** Each write is atomic, including its bookkeeping in
  other graphs.
- **Every resource has a version.** It's exposed as an `ETag` and honoured by
  `If-Match` and `If-None-Match`.
- **Everything under the storage root is a pod resource,** whichever protocol
  wrote it.
- **Existing pods upgrade themselves.** There's no operator step beyond the
  pre-deploy volume snapshot any schema change deserves.

## Non-goals

Parts 5b–5d cover:
- status codes (401/403, 409 for a non-empty container, 405 for the root ACL)
- response headers (`Allow`, `Accept-*`, `Link rel=type`, `WAC-Allow public=`)
- CORS and authenticated HEAD
- `Slug`, and creating containers by POST
- PATCH access modes and 409/422
- `/foo` vs `/foo/`
- `.meta`
- the conformance suite

Where a 5a behaviour needs a status code, it uses the mapping `pod.rs` already
has, and 5b corrects it.

Also not in scope:
- **Postgres.** The metadata is the member's own and goes with their pod.
- **Changes to how access control is evaluated,** apart from one: see *ACLs
  exist by metadata*.
- **Rolling back past this change.** See *Upgrading*.

## Design

### The metadata graph

Each pod gets one more named graph, `urn:brolly:resources`. It isn't an `https`
IRI, so no LDP path names it. It holds:

| Triple | Meaning |
|---|---|
| `<r> rdf:type ldp:Resource` | `r` exists. This triple *is* existence. |
| `<r> rdf:type ldp:Container`, `ldp:BasicContainer` | a container (the IRI ends in `/`) |
| `<root> rdf:type pim:Storage` | the storage root |
| `<r> rdf:type ldp:RDFSource` or `ldp:NonRDFSource` | which kind of document |
| `<r> rdf:type brolly:Auxiliary` | an auxiliary resource (today only `.acl`); never contained |
| `<c> ldp:contains <r>` | containment; written only by the server |
| `<r> dcterms:modified "…"^^xsd:dateTime` | last change: UTC, millisecond precision, monotonic |
| `<r> brolly:version "…"` | a new ULID on every change; the `ETag` |
| `<r> brolly:blobDigest`, `brolly:mediaType`, `brolly:byteSize` | binary metadata (ADR 0013) |
| `<urn:brolly:resources> brolly:layout 2` | the pod's layout version |

A resource's own graph holds what the member wrote:
- **An RDF document:** exactly what was stored.
- **A container:** only extra triples a client put there, never its containment
  or its server-managed types.
- **A binary:** only optional description triples (Mastodon alt text) until
  `.meta` (5d). GET of a binary serves the bytes.

**New vocabulary terms** go in `domain/src/vocab.rs`:
- `ldp:Container`, `ldp:RDFSource`, `ldp:NonRDFSource`, `ldp:contains`
- `pim:Storage`
- `dcterms:modified`
- `brolly:Auxiliary`, `brolly:version`, `brolly:layout`
- the three blob terms, moved from `adapters/solid/src/ldp.rs`

### The pod handle: reads, and one way to write

store/src/resources.rs (new) is the only code that writes
`urn:brolly:resources`. It lives in `store` because several protocols write to
pods. Its quads enter through `store/src/write.rs`, which gains transaction
variants, so the canonicalising write path is still the only way in.

**`StoreManager` caches a `Pod`**, not a bare `Arc<Store>`:

```rust
pub struct Pod {
    store: Store,                        // private
    write_lock: std::sync::Mutex<()>,
}

impl Pod {
    /// Everything a reader needs: pattern matching, containment checks,
    /// named-graph listing, SPARQL *queries*. No writes.
    pub fn read_store(&self) -> ReadStore<'_>;

    /// A consistent read: metadata and content from one snapshot, no lock.
    pub fn read<T>(&self, f: impl FnOnce(&ResourceRead<'_>) -> Result<T, StoreError>)
        -> Result<T, StoreError>;

    /// The only way to change a pod. Takes the write lock, then starts one
    /// transaction (so it sees every earlier commit), runs `f`, commits, then
    /// deletes released blobs that are no longer referenced, and only then
    /// releases the lock. A failed commit deletes nothing.
    pub fn write<T>(&self, f: impl FnOnce(&mut PodWrite<'_>) -> Result<T, StoreError>)
        -> Result<T, StoreError>;
}
```

**One read interface, three providers.** Every reader takes `&impl PodRead`, a
trait in `store` with two methods:
- `quads_for_pattern`
- `query`, which runs SPARQL SELECT and ASK only

Three types implement it:
- `ReadStore`, a plain read of the committed store
- `ResourceRead`, one snapshot
- `PodWrite`, which reads through the open transaction and so sees that
  transaction's own writes

Oxigraph makes this cheap: `Store::quads_for_pattern` and
`Transaction::quads_for_pattern` return the same `QuadIter`, and a prepared
query runs `on_store` or `on_transaction`. So a reader such as `wac`,
`collection`, `follows::followers`, `profile::read`, `ingest::read`,
`timeline::home` or `ldp::blob_digest` works both outside a write and inside
one. The ones inside a write include WAC inside `put_in`, a processor's carrier
check inside a Delete, `profile::write` reading before it replaces, and
`append_in` seeing the `put_in` just before it. `http-client` is off in
Oxigraph's features, so `SERVICE` can't reach the network through `query`.

**Access rules:**
- **No `Deref` to `Store`.** The `Store` is private, so a write that skips the
  lock or the metadata doesn't compile.
- **Reads take `&impl PodRead`.** That covers `authz`, `collection`,
  `profile::read`, timelines and the rest, so none of them can write.
- **Old-layout test fixtures** reach a raw store through
  `Pod::raw_store()`, behind a `test-fixtures` feature that each crate enables
  only in `[dev-dependencies]`. `cfg(test)` alone doesn't reach integration
  tests in other crates. An architecture rule checks that `raw_store` appears
  only under `tests/`.

**`PodWrite<'a>` borrows one transaction** and has two groups of methods.

**Resources under the storage root**, which keep the metadata:

```rust
fn meta(&self, resource: &str) -> Result<Option<ResourceMeta>, StoreError>;
fn members(&self, container: &str) -> Result<Vec<String>, StoreError>;
fn put(&mut self, resource: &str, content: Content) -> Result<ResourceMeta, StoreError>;
fn append(&mut self, resource: &str, quads: &[Quad]) -> Result<ResourceMeta, StoreError>;
/// Removes it if present. Returns whether it was there: a no-op on a missing
/// resource, so a Delete that reaches one graph twice doesn't fail.
fn remove(&mut self, resource: &str) -> Result<bool, StoreError>;
fn create_root(&mut self, root: &str) -> Result<(), StoreError>;   // provisioning only
fn release_blob(&mut self, digest: &str);
/// Replace a binary's description triples (today: Mastodon alt text) and bump
/// its version. Replaces rather than appends, so a second description doesn't
/// pile up beside the first.
fn set_description(&mut self, resource: &str, quads: &[Quad]) -> Result<ResourceMeta, StoreError>;

pub enum Content<'a> {
    Rdf(&'a [Quad]),            // may be empty
    Container(&'a [Quad]),      // extra triples; may be empty
    Binary(BlobMeta),           // bytes already in BlobStore
    Auxiliary(&'a [Quad]),      // an ACL
}
```

**The instance store is a different type.** `StoreManager::instance()` returns
an `InstanceStore`, not a `Pod`. It's never upgraded, and it exposes only the
`index` functions (`record_note`, `forget_note`, `is_indexed`, the timeline
reads), so nothing writes the instance except through `index`.
`processor::process` splits in two:
- `process_member(&mut PodWrite, …)` for member pods
- `process_instance(&InstanceStore, …)` for the index

`store::lib`'s free `insert_quads`/`insert_record` stop being public. `index` and
`resources` call the crate-internal write path.

**Protocol graphs outside the root**, with no metadata: the profile, `#social`,
the inbox and outbox collections, `at://` records, and a recipient's copies of
someone else's activities.

```rust
fn graph(&self, graph: &str) -> Result<Vec<Quad>, StoreError>;
fn insert(&mut self, quads: &[Quad]) -> Result<(), StoreError>;
fn remove_quads(&mut self, quads: &[Quad]) -> Result<(), StoreError>;
fn replace_graph(&mut self, graph: &str, quads: &[Quad]) -> Result<(), StoreError>;
fn clear_graph(&mut self, graph: &str) -> Result<(), StoreError>;
```

Each of these refuses, with `StoreError::UnderRoot`, any quad whose graph is
under the storage root. So the two families can't be confused: under the root
you go through `put`/`remove`, and everywhere else through these. One
transaction covers both, so a post and its outbox entry commit together.

**`put` finds the storage root from metadata** (`<root> a pim:Storage`) and
refuses an IRI outside it. `create_root` records the root, and only
provisioning calls it.

**Rules `Pod::write` enforces:**
- **Lock first.** The lock is taken *before* the transaction starts. Oxigraph
  transactions read a snapshot and commit a blind batch with no conflict
  detection.
- **No `.await` or nesting.** `f` is synchronous, so it can't hold the lock
  across an `.await`. Because the mutex isn't reentrant, it can't nest either: a
  caller that needs several operations (an upload and its alt text) does them in
  one closure.
- **Blob bytes go in first, and are released under the lock.**
  - A caller writes blob bytes with `BlobStore::put` *before* calling `write`.
    It's content-addressed and idempotent, so uploads don't queue behind the lock
    on disk I/O.
  - `Content::Binary` checks the blob file exists before recording it.
  - After a successful commit, and still holding the lock, `write` checks each
    released digest for remaining references and deletes the unreferenced ones.
    Only then is the lock released. So a failed commit deletes nothing, and a
    concurrent upload of identical bytes either committed first (the digest is
    still referenced and survives) or waits for the lock and finds the file
    gone. In that case `Content::Binary` refuses with `BlobMissing`, and the
    caller writes the bytes again and retries once.
- **Poisoned locks are recovered** with `PoisonError::into_inner`. The panicking
  closure never committed.

**What `put` does:**
- replaces the content graph
- records `ldp:Resource` and the kind
- sets `modified` to `max(now, previous + 1 ms)` and a new `version`
- unless the resource is auxiliary, adds it to its parent's containment and
  records missing intermediate containers, each with its own version

**What `remove` does:**
- deletes the content graph, the metadata, and its `.acl` graph and metadata
- removes it from its container
- releases its blob
- refuses a container that still has members

**Container versions follow the listing.** A container's `version` and
`modified` change when a direct member is added, removed or changed. That's the
direct parent only. 5b puts member metadata into listings, so the container's
ETag must move with them.

### Reading a resource

`ldp::read` uses `Pod::read`, so metadata and content come from one snapshot.

| Resource | Representation |
|---|---|
| RDF document | its content graph |
| Container | its content graph, plus from metadata: its types (`ldp:Container`, `ldp:BasicContainer`, `ldp:Resource`, and `pim:Storage` at the root) and one `ldp:contains` per member |
| Binary | the bytes named by its metadata blob digest |
| ACL | its content graph |

Existence comes from metadata for every kind: `meta(..).is_some()`.

**What moves to metadata:**
- `storage::exists` is removed.
- `ldp::blob_digest` reads the metadata, and so do Mastodon's blob reads
  (`get_media`, `update_media`, `create_status`).

### Writing

`ldp` gets two layers:
- **The outer functions (`read`, `put`, `append`, `delete`) take `&Pod`.** Each
  checks WAC, writes any blob bytes, and runs one `Pod::write`.
- **The inner `put_in`, `append_in` and `delete_in` take `&mut PodWrite`** and
  check WAC against the transaction's snapshot. A caller composing several
  operations in one transaction uses these. `upload_media`, for example, calls
  `put_in` and then the alt-text `set_description` in one closure, after its multipart
  awaits have finished.

**Callers updated:**
- `pod.rs`
- `mastodon_api.rs`
- the Solid adapter's tests
- `authz/tests/conformance_matrix.rs`

**PUT of an RDF document:** stored exactly as sent (`Content::Rdf`).
Containment and blob metadata are read only from `urn:brolly:resources`, so an
`ldp:contains` or `brolly:blobDigest` triple in an ordinary document is inert
data.

**PUT to a container** (the path ends in `/`), RDF body only:
- **A non-RDF body** is refused with `LdpError::NotRdf` (415 until 5b).
- **Containment triples** (`<container> ldp:contains ?x`) must name exactly the
  current members, so a GET-edit-PUT round trip works. Any other set is
  `LdpError::ContainmentChange` (409, Solid Protocol §5.3).
- **Echoed server types** are dropped: `<container> a ldp:Resource`,
  `ldp:Container`, `ldp:BasicContainer`, and `pim:Storage` at the root.
- **The rest** is stored as `Content::Container`. The members are untouched.

**PUT of a binary:** the bytes go to `BlobStore` first, then `Content::Binary`,
then the old digest to `release_blob`. The description triples are dropped, as
today.

**PUT of an ACL:** `Content::Auxiliary`. Stage 0's Control rule is unchanged.

**PATCH** runs in a scratch store as today, then writes the result with the
`Content` matching the target: `Rdf`, `Container` (under the containment rule),
or `Auxiliary`.
- **Creating:** a PATCH that creates a resource adds it to its container.
- **Known limitation:** a patch's `solid:where` can't match a container's
  `ldp:contains`, because containment isn't in the content graph. 5c revisits
  this if the conformance suite needs it.
- **Binaries:** PATCH is refused (`NotRdf`).

**POST to a container:** a `put` of the minted member.
- **POST to a document:** stage 0's append, unchanged until 5c.
- **Non-RDF POST body to a document:** refused (`NotRdf`).

**DELETE:** `remove`.

### ACLs exist by metadata

5a makes an empty `.acl` exist. `wac::effective_acl` finds ACLs with
`GRAPH ?acl { ?s ?p ?o }` (`authz/src/wac.rs`), which can't see an empty graph.
It would then fall through to an ancestor's `acl:default`. A member who empties
a resource's ACL to lock it down would find it existing but inheriting the
broader grant. Solid's rule is that an existing ACL governs, and an empty one
grants nothing.

So in commit 2, `effective_acl` picks the governing ACL by metadata existence:
the nearest candidate recorded as `brolly:Auxiliary` in `urn:brolly:resources`.
It still evaluates the authorizations in that ACL's graph as today. An empty
recorded ACL therefore governs, and grants nothing. The candidate list and the
single-query approach are unchanged. The query reads the metadata graph through
`PodRead` instead of probing content graphs.

### Conditional requests

`pod.rs` evaluates preconditions *after* authorisation (RFC 9110 §13.2.1).

| Header | On | Behaviour |
|---|---|---|
| `If-Match: *` | PUT, PATCH, DELETE, POST (to the container) | fails if the resource doesn't exist |
| `If-Match: "a", "b"` | same | strong comparison; a `W/` tag never matches |
| `If-None-Match: *` | PUT, PATCH | fails if the resource exists |
| `If-None-Match: "a"` | PUT, PATCH, DELETE | fails if the current version matches (weak comparison, RFC 9110 §13.1.2) |
| `If-None-Match: "a"` | GET, HEAD | 304 with `ETag` if the current version matches (weak comparison) |
| `If-Modified-Since`, `If-Unmodified-Since` | all | ignored; the ETag is authoritative |

**Write failures and snapshots:**
- **A failed write precondition** gives 412 and writes nothing. It's checked in
  the same `Pod::write` closure as the write.
- **GET and HEAD** use one `Pod::read` snapshot.

**`ETag` and `Last-Modified`:**
- **`ETag: "<version>"`** on GET and HEAD, with `Last-Modified` from
  `dcterms:modified`.
- **Not on PUT, PATCH or POST responses.** The server transforms what it stores,
  and RFC 9110 §9.3.4 rules out an `ETag` for a transformed PUT.
- **One version across content types (R4).** Community Solid Server does the
  same, and 5b adds `Vary: Accept`.

**What a precondition reveals.** A caller holding the mode a method needs can
learn whether the resource exists. A caller with Write but not Read sending
`If-None-Match: *` sees 412 or 201. Community Solid Server has the same
property. A caller *without* the required mode gets the refusal whether or not
the resource exists.

### Every writer uses `Pod::write`

With no bare `Store` reachable, every pod writer moves onto `Pod::write`:

| Writer | Change |
|---|---|
| `adapters/solid/src/ldp.rs`, `patch.rs`, `storage.rs` | `put`/`remove` under the root; `storage.rs`'s `exists`, `members`, `add_containment`, `remove_containment`, `uncontain_acls`, `init_storage_root` go (replaced by `resources`) |
| `adapters/solid/src/profile.rs` | profile writes use the outside-root methods |
| `adapters/activitypub/src/inbox.rs`, `follows.rs`, `processor.rs` | writers take `&mut PodWrite`, and readers take `&impl PodRead`. `inbox::deliver`/`remove` decide from the IRI, against the pod's metadata root, whether a graph is a resource under the root (`put`/`remove`) or protocol state (outside-root methods). `processor::process` splits into `process_member(&mut PodWrite)` and `process_instance(&InstanceStore)`. |
| `adapters/atproto/src/ingest.rs` | `at://` graphs and canonical profile triples use the outside-root methods |
| `server/src/outbox.rs` | the author's copy and its outbox entry, and the author's `Delete`, in one `Pod::write`, closed before the recipient loop's `.await`s; each recipient's delivery in its own `Pod::write` |
| `server/src/mastodon_api.rs` | uploads with alt text in one closure; alt text updates via `set_description`, replacing the old text; blob reads from metadata |
| `server/src/provision.rs` | `create_root`, then the root ACL as `Content::Auxiliary` |
| `server/src/account.rs` (export) | reads through `ReadStore`; includes `urn:brolly:resources` |

**Deciding from the IRI, not the caller.** `inbox` decides root membership from
the IRI, rather than trusting the caller to pass or omit a writer. So an
author's post is always recorded, and a recipient's copy under another origin
never is.

**Updating a stage 0 comment.** The comment in `processor.rs` ("An LDP resource
is never the embedded object of a delivered activity") is rewritten. Posts are
LDP resources now, and the stage 0 guarantee holds because of three facts:
- A `Delete` can only remove what a same-origin activity carried in as its
  embedded object.
- The server mints every such id under `/~/notes/`.
- LDP writes can't create inbox or outbox collection entries, which live outside
  `/~/`.

**Architecture tests.** `server/tests/architecture.rs` gains two rules. Nothing
outside store/src/resources.rs names `urn:brolly:resources`, and nothing outside
`store` names `oxigraph::store::Store` in a write position. The second rule is
belt and braces: the type system already enforces it.

**In-memory stores.** Oxigraph's in-memory backend serialises every transaction
behind one lock. A raw store write inside a `Pod::write` closure would deadlock
there. Pods are always RocksDB, so this only matters in tests, and
resources.rs documents it.

### Upgrading existing pods

**When it runs.** A pod is upgraded when `StoreManager` first opens it, inside
the `try_get_with` initialiser.
- **Concurrency.** The new `Pod` isn't yet reachable by any other thread, so
  taking its lock is uncontended. Concurrent requests for the same pod wait on
  moka.
- **Publication.** The `Pod` enters the live-handle map only after the upgrade
  succeeds.
- **No re-entry.** The initialiser never calls `pod()`.
- **Instance store.** It's opened separately and never upgraded.

**Which pods need it:**
- **A store with no named graphs** (a brand-new pod, opened by registration
  before provisioning) is marked `brolly:layout 2` straight away. Provisioning
  then records the root with `create_root`.
- **A pod already at layout 2** is left alone. Its root is read from metadata.
- **Otherwise** it's an old-layout pod, and it's upgraded.

**Finding the root of an old-layout pod.** The root is the one subject `r`
where:
- `<r> a pim:Storage` appears in `r`'s own graph (`init_storage_root` writes
  it), and
- `r`'s path is exactly `/~/`.

A member can write `<> a pim:Storage` into their own document, but that
document's path isn't `/~/`, so it can't be mistaken for the root. With no
candidate, or two on different hosts, the upgrade writes nothing, leaves the pod
unmarked and logs at `error`. The pod is then served without metadata: its LDP
reads answer 404, and the log line tells the operator. Only a pod that was never
provisioned can get there.

**What the upgrade does, in one transaction:**
1. **Classifies every named graph once**, in this order:
   - outside the root, or `urn:brolly:resources` itself: skipped
   - an `.acl` IRI with quads: auxiliary
   - a graph holding `<r> brolly:blobDigest "<64 hex>"`, with `r` equal to the
     graph and an existing blob file: binary
   - an IRI ending in `/`: container
   - anything else with quads: RDF document

   A digest triple that fails the binary test is logged and left as ordinary
   data.
2. **Records the root**, and every classified resource with its kind. Each gets
   `modified` set to the upgrade time and a fresh `version`, plus blob metadata
   for binaries.
3. **Records listed members.** For each `<c> ldp:contains <m>` in container
   `c`'s own graph, `m` is recorded and contained only if all of these hold:
   - `m` is under the root
   - `m`'s parent container is `c`
   - `m` isn't an ACL

   Anything else is logged and dropped. A listed member with an empty graph is
   recorded as an empty RDF document (or container, by IRI), which rescues
   today's empty resources.
4. **Records unlisted resources.** Every recorded non-auxiliary resource that
   isn't yet contained is added to its parent, and intermediate containers are
   created.
5. **Strips the server triples from content graphs.** From each container's own
   graph it removes `<c> ldp:contains ?x` and `<c> a ldp:BasicContainer`,
   `ldp:Container` and `pim:Storage`. From each binary's graph it removes the
   three blob triples. Subject-scoped, so a member's triples about other
   subjects stay.
6. **Marks the pod** with `brolly:layout 2`.

**If the upgrade fails,** `open` returns the error, that request fails, and the
next open retries.

**Cost.** The upgrade blocks the opening thread once per pod, for a scan of its
graphs. `store/benches/upgrade.rs` measures it (release build, 10 containers,
5 triples per document):

| documents | first open | reopen |
|---|---|---|
| 100 | 48 ms | 15 ms |
| 1,000 | 0.46 s | 0.11 s |
| 10,000 | 14.8 s | 1.3 s |

It's superlinear, and deliberately so: the whole upgrade is one transaction,
and Oxigraph keeps a transaction's pending writes in an in-memory batch whose
lookups slow as it grows. Splitting the upgrade across transactions would trade
that for a pod that can be left half-upgraded, which R7 rules out. It's a
one-time cost per pod, and today's pods hold tens of resources. A pod holding
100,000 would need this reconsidered.

**No rollback.** The upgrade strips, because a copy-only upgrade serves stale
listings (the metadata says a member is gone while the old triple still lists
it). And the rollback it would buy isn't real anyway: writes made after the
upgrade don't maintain the old triples. So deploying this change is
forward-only. `docs/deploying.md` gains an "Upgrading" note saying so: snapshot
the data volume before deploying (Railway: a volume backup), and if you must go
back, restore the snapshot. This is the first forward-only change, so the note
is written for it.

**`acl-uncontain` is removed.** After the upgrade, containment comes only from
metadata, and step 3 never contains an ACL. The command, its tests and its
`docs/deploying.md` section go. So does `server/src/maintenance.rs`, since
nothing else uses its pod iteration.

**Account export** includes `urn:brolly:resources`. It's the member's own
metadata, and export still names blobs by digest (ADR 0013).

### Where the code changes

| Crate | Change |
|---|---|
| `domain` | the new vocabulary terms |
| `store` | resources.rs (new): `Pod`, `PodRead`, `ReadStore`, `PodWrite`, `ResourceRead`, `upgrade`. `InstanceStore`. `manager.rs` caches `Pod`, holds `Weak<Pod>` in the live map, and upgrades on open. `instance()` returns `InstanceStore`. `write.rs` gets transaction variants. `lib.rs`'s free write helpers become crate-internal. |
| `adapters/solid` | `ldp.rs` in two layers (`&Pod` and `_in(&mut PodWrite)`), `blob_digest` from metadata. `storage.rs` shrinks to path helpers. `patch.rs` and `profile.rs` use `PodWrite`. |
| `adapters/activitypub` | `inbox`, `follows` and `processor` take `&mut PodWrite`, and the comment is rewritten |
| `adapters/atproto` | `ingest.rs` takes `&mut PodWrite` |
| `authz` | `wac.rs` reads through `&impl PodRead`, and picks the governing ACL by metadata existence (commit 2). `authz/tests/conformance_matrix.rs` uses `Pod`. |
| `server` | `pod.rs` handles preconditions, `ETag` and `Last-Modified`, and maps the new `LdpError` variants. `outbox.rs`, `mastodon_api.rs`, `provision.rs` and `account.rs` use `Pod::write` and `ReadStore`. `maintenance.rs` and `acl-uncontain` are removed. The test harnesses provision through `provision::pod`, or seed old layouts through `raw_store()`. |

## Testing

**store/tests/resources.rs (new):**
- **Existence and containment:**
  - An empty RDF document and an empty container exist after `put`.
  - Containment and intermediate containers are recorded, each intermediate
    with a version.
  - An ACL is recorded but never contained.
  - `remove` of a non-empty container is refused, and `remove` of a missing
    resource returns `false`.
- **Outside the root:** the outside-root methods refuse any graph under the
  root. A post and its outbox entry commit together, and roll back together
  when the closure errors.
- **Versions:**
  - A container's version changes when a direct member is added, removed or
    changed, and its grandparent's doesn't.
  - `modified` is strictly increasing within one millisecond.
- **Concurrency:**
  - Writers to one pod are serialised, and writers to different pods don't block
    each other.
  - A pod re-fetched after eviction while a writer holds it gives the same lock.
  - `read` sees one consistent version during a commit.
- **Commit failure:** a commit that fails deletes no blob.
- **Reads inside a write:** a read inside `Pod::write` sees that closure's own
  earlier writes. `PodRead` works the same over a store, a snapshot and a
  transaction.
- **Blobs:** an upload of identical bytes racing a release keeps the blob, or
  gets `BlobMissing` and succeeds on retry, and never commits a reference to a
  missing file.
- **Upgrade:**
  - an empty store is marked immediately
  - a pod at layout 2 isn't rescanned
  - on a hand-built old-layout pod, every step above runs
  - a forged `ldp:contains` naming a non-child or a foreign IRI is dropped
  - a forged `blobDigest` (subject ≠ graph, bad digest, missing file) isn't
    recorded as a binary
  - a planted `<> a pim:Storage` in `/~/app/doc` doesn't make a second root
  - a pod with no root is left unmarked
  - after the upgrade, container graphs hold no `ldp:contains`
  - a second run changes nothing

**Solid adapter tests:**
- **Empty resources:** PUT of an empty Turtle body gives GET 200 with an empty
  graph. PUT of `/~/c/` with no body gives the container types and no members.
- **Container PUT:**
  - with an extra triple, keeps the members
  - naming a non-member, gives `ContainmentChange`
  - echoing its listing exactly, succeeds
  - with a non-RDF body, gives `NotRdf`
- **An ordinary document** holding `ldp:contains` and `brolly:blobDigest`
  serves them as data.
- **A PATCH that creates a resource** lists it.
- **A container with members** can't be emptied by PUT and then deleted.
- **An `.acl`** exists, has a version, and is deleted with its resource.
- **An empty `.acl`** on a resource governs it and grants nothing, even when the
  parent's `acl:default` would grant more.
- **Rewrites:** tests using `storage::exists` are rewritten against `meta`.

**server/tests/pod_http.rs:**
- **Headers:** `ETag` and `Last-Modified` on GET and HEAD, none on PUT
  responses, and the ETag changes after a PUT.
- **Preconditions:**
  - `If-None-Match: *` on PUT gives 412 and no write for an existing resource,
    and creates a new one.
  - `If-Match` gives 412 for a stale tag and succeeds with the current tag. A
    `W/` tag never matches.
  - `If-None-Match` with the current tag gives 304 (with `ETag`) on GET, and 412
    on PUT.
- **Disclosure:** a caller *without the mode the method needs* gets the same
  answer whether or not the resource exists.
- **Concurrency:** of two concurrent PUTs with the same `If-Match`, exactly one
  succeeds.
- **After an upgrade:** a container GET, after its member is deleted, doesn't
  list that member.

**server/tests/auth_flow.rs:** a new registration's pod ends at layout 2, and
its first open logs no `error`.

**server/tests/mastodon_*.rs:** media get, update and attach work, a second description replaces the first, and alt text
survives in the same upload.

**server/tests/federation_flows.rs:**
- A published note is listed in the author's `/~/notes/`, and the author's
  `Delete` de-lists it.
- A recipient's copy under the author's origin isn't an LDP resource in the
  recipient's pod.

## Rollout

Commits on `main`, each deployable:

1. **`Pod`, `ReadStore`, `PodWrite`, `resources.rs`, and the vocabulary, with
   tests.** `StoreManager` caches `Pod`, the live map holds `Weak<Pod>`, and
   `Pod` has *no* `Deref`. Every existing reader moves to `ReadStore` and every
   writer to `Pod::write`, still writing the old layout. The outside-root methods
   and a temporary under-root raw-write method keep today's behaviour exactly.
   This is the mechanical, compile-driven commit.
2. **The switch:** the upgrade on open, LDP on metadata, Mastodon blob reads and
   alt text, provisioning via `create_root`, the outbox and `inbox` recording
   posts, and removing `acl-uncontain`, `maintenance.rs` and the temporary
   raw-write method. Forward-only, with the deploy note.
3. **Conditional requests,** `ETag` and `Last-Modified`.

Commits 1 and 2 are large. The plan splits each into tasks that stage and test
separately and commit together, as stage 0 did.

**Deploying commit 2:** snapshot the data volume, then deploy. Pods upgrade
themselves on first open.

## Decisions

| # | Decision | Why |
|---|---|---|
| R1 | Metadata lives in a per-pod graph, `urn:brolly:resources`, not Postgres. | It's the member's, so it leaves with their pod, and it's written in the content's transaction. |
| R2 | Existence is one metadata triple. | Empty documents and containers exist, as Solid requires. |
| R3 | Containment is read and written only through resources.rs. | Protection by construction. |
| R4 | The ETag is the version, the same across formats, and isn't sent on write responses. | It's a version for `If-Match`, and RFC 9110 §9.3.4 applies to transformed writes. |
| R5 | A per-pod lock is taken before the transaction, reached through a synchronous closure. | Oxigraph transactions don't detect conflicts, and the closure makes lock order, no nesting and no `.await` structural. |
| R6 | `Pod` owns the lock, and the live map holds `Weak<Pod>`. | Re-fetching an evicted-but-live pod yields the same lock. |
| R7 | There's no `Deref` to `Store`: reads use `ReadStore`, and all writes go through `Pod::write`, with separate methods for under-root resources and outside-root protocol graphs. | Every write keeps the metadata true. A missed call site is a compile error, not a silent bypass. |
| R8 | Only a container body's containment triples are policed, and documents are stored as sent. | Containment and blob pointers are read only from metadata, so in a document they're inert data. |
| R9 | A container's version changes when a direct member changes. | 5b's listings include member metadata. |
| R10 | Pods upgrade on first open. A fresh store is marked at once. An old-layout root is accepted only at path `/~/`. | No operator step, no error loop for new registrations, and no planted second root. |
| R11 | The upgrade strips server triples and is forward-only. | A copy-only upgrade serves stale listings and doesn't give a real rollback. A volume snapshot does. |
| R12 | Released blobs are checked and deleted under the lock, and `Content::Binary` verifies the file. | This closes the race with a concurrent upload of identical bytes. |
| R13 | `acl-uncontain` and `maintenance.rs` are removed. | The upgrade makes them unnecessary. |
| R14 | Readers take `&impl PodRead`, implemented by a store read, a snapshot, and the open transaction. | Readers run both outside and inside writes, and must see a write's own changes. |
| R15 | The instance store is its own type, `InstanceStore`, and the processor splits into member and instance halves. | The instance isn't a pod and must never be upgraded, and only `index` writes it. |
| R16 | WAC finds the governing ACL by metadata existence. | An empty ACL exists, so it must govern and grant nothing, not fall through to a broader parent. |
