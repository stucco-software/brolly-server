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

mod settings;
mod upgrade;

pub use settings::{provision_settings, resource_iris};
pub use upgrade::{UpgradeOutcome, UpgradeReport, upgrade};

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
    /// An auxiliary resource: an `.acl` or a `.meta`. Recorded, never
    /// contained.
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
    /// An auxiliary resource: an ACL or a `.meta` (spec 5d, H1).
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
            blobs: &self.blobs,
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
    blobs: &'a BlobStore,
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

    // --- internals ---

    /// Insert quads straight into [`METADATA_GRAPH`]. Crate-private: only this
    /// module's own bookkeeping (the upgrade's layout mark) writes there
    /// directly; everything else goes through `put`, `append` and `remove`.
    fn insert_metadata(&mut self, quads: &[Quad]) -> Result<(), StoreError> {
        let stray = quads.iter().any(|quad| quad.graph_name != metadata_graph());
        if stray {
            return Err(StoreError::Invalid(
                "a metadata quad names another graph".into(),
            ));
        }
        insert_quads_in(&mut self.transaction, quads);
        Ok(())
    }

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

/// The predicates of a resource's own record in [`METADATA_GRAPH`]: what
/// [`read_meta`] reads and `record` rewrites.
///
/// Read by predicate, never as "everything about the resource": a container's
/// subject also carries one `ldp:contains` per member, and scanning those on
/// every read and every rewrite made each member `put` cost the size of its
/// container.
const RECORD_PREDICATES: [&str; 6] = [
    vocab::RDF_TYPE,
    vocab::DCTERMS_MODIFIED,
    vocab::BROLLY_VERSION,
    vocab::BROLLY_BLOB_DIGEST,
    vocab::BROLLY_MEDIA_TYPE,
    vocab::BROLLY_BYTE_SIZE,
];

/// Every record quad about `resource`: one indexed lookup per record
/// predicate, so the cost doesn't grow with a container's members.
fn record_quads<R: PodRead + ?Sized>(read: &R, resource: &str) -> Result<Vec<Quad>, StoreError> {
    let subject = iri(resource);
    let graph = metadata_graph();
    let mut quads = Vec::new();
    for predicate in RECORD_PREDICATES {
        for quad in read.quads_for_pattern(
            Some(subject.as_ref().into()),
            Some(iri(predicate).as_ref()),
            None,
            Some(graph.as_ref()),
        ) {
            quads.push(quad?);
        }
    }
    Ok(quads)
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
    for quad in record_quads(read, resource)? {
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
            (vocab::DCTERMS_MODIFIED, Term::Literal(value)) => {
                modified = normalise_modified(value.value());
            }
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
        refuse_double_auxiliary(resource)?;
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
        refuse_double_auxiliary(resource)?;
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

    /// Replace a binary's description triples (today, Mastodon alt text) in
    /// its `.meta`'s graph, recording the `.meta` as an auxiliary resource
    /// (spec 5d, H6). Replaces rather than appends, so a second description
    /// doesn't sit beside the first. The binary keeps its bytes, its blob
    /// metadata and its version: the description is its own resource with its
    /// own version, which is also why replacing the binary's bytes keeps the
    /// description. Refuses anything that isn't an existing binary, and
    /// answers the new `.meta`'s record.
    pub fn set_description(
        &mut self,
        resource: &str,
        quads: &[Quad],
    ) -> Result<ResourceMeta, StoreError> {
        let previous = self.meta(resource)?;
        let Some(ResourceMeta {
            kind: Kind::NonRdfSource,
            blob: Some(_),
            ..
        }) = previous.as_ref()
        else {
            return Err(StoreError::Invalid(format!(
                "{resource} is not a binary, so it has no description"
            )));
        };
        // H6 (spec 5d): the description is the `.meta`'s content — its own
        // resource, never the binary's own graph — so replacing the bytes
        // keeps it and replacing it doesn't touch the binary. A binary can't
        // be recorded at an auxiliary IRI, so the `.meta` is never a double.
        let meta = format!("{resource}.meta");
        refuse_double_auxiliary(&meta)?;
        check_graph(&meta, quads)?;
        let previous_meta = self.meta(&meta)?;
        self.transaction
            .clear_graph(GraphNameRef::NamedNode(iri(&meta).as_ref()))?;
        insert_quads_in(&mut self.transaction, quads);
        self.record(&meta, Kind::Auxiliary, previous_meta.as_ref(), None)
    }

    /// Remove `resource` if present, returning whether it was there: a no-op
    /// on a missing resource, so a Delete that reaches one graph twice doesn't
    /// fail.
    ///
    /// Deletes the content graph, the metadata, and its auxiliary resources'
    /// graphs and metadata — the `.acl`, so a recreated resource can't quietly
    /// get its old grants back, and the `.meta`, which would describe
    /// something that is no longer there (Solid Protocol §5.4, spec 5d H5);
    /// takes it out of its container (whose version moves); releases its
    /// blob. Refuses a container that still has members, and the storage
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
            // Deleting a resource deletes its auxiliary resources (Solid
            // Protocol §5.4), or recreating it would quietly bring the old
            // grants and the stale description back.
            self.forget(&format!("{resource}.acl"))?;
            self.forget(&format!("{resource}.meta"))?;
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

    /// Whether `iri` names a resource under this pod's storage root, by the
    /// same test [`put`](Self::put) and the outside-root methods apply. False
    /// while the pod has no root recorded.
    ///
    /// For a caller storing protocol records that must pick, per IRI, between
    /// `put`/`remove` and the outside-root methods, as `activitypub::inbox`
    /// does.
    pub fn under_root(&self, iri: &str) -> Result<bool, StoreError> {
        Ok(self
            .storage_root()?
            .is_some_and(|root| iri.starts_with(&root)))
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
    /// what isn't the record's own: `ldp:contains`, which it never reads, and
    /// the root's `pim:Storage`.
    fn record(
        &mut self,
        resource: &str,
        kind: Kind,
        previous: Option<&ResourceMeta>,
        blob: Option<BlobMeta>,
    ) -> Result<ResourceMeta, StoreError> {
        let stale: Vec<Quad> = record_quads(&*self, resource)?
            .into_iter()
            .filter(is_record_quad)
            .collect();
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

/// Is this record-predicate quad part of a resource's own record, which
/// `record` rewrites? The root's `pim:Storage` type is not. (`ldp:contains`
/// isn't a record predicate, so it never gets this far.)
fn is_record_quad(quad: &Quad) -> bool {
    !(quad.predicate.as_str() == vocab::RDF_TYPE
        && matches!(&quad.object, Term::NamedNode(class) if class.as_str() == vocab::PIM_STORAGE))
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
    if is_auxiliary(resource) {
        Kind::Auxiliary
    } else if resource.ends_with('/') {
        Kind::Container
    } else {
        Kind::RdfSource
    }
}

/// Is this the IRI of an auxiliary resource: an `.acl` or a `.meta`
/// (spec 5d, H1)?
fn is_auxiliary(resource: &str) -> bool {
    resource.ends_with(".acl") || resource.ends_with(".meta")
}

/// Is this the IRI of an auxiliary of an auxiliary — a path ending in two
/// auxiliary suffixes (`.acl.acl`, `.acl.meta`, `.meta.acl`, `.meta.meta`)?
/// Such a resource can never exist (spec 5d, H1), so `put` and `append`
/// refuse it here. The HTTP surface answers such a path 404 before anything
/// is looked up; this is the defence in depth under it, and the refusal for
/// every caller that is not HTTP.
fn is_double_auxiliary(resource: &str) -> bool {
    let Some(stem) = resource
        .strip_suffix(".acl")
        .or_else(|| resource.strip_suffix(".meta"))
    else {
        return false;
    };
    stem.ends_with(".acl") || stem.ends_with(".meta")
}

/// Refuse an IRI naming an auxiliary of an auxiliary: no such resource can
/// exist, so no write may create one (spec 5d, H1).
fn refuse_double_auxiliary(resource: &str) -> Result<(), StoreError> {
    if is_double_auxiliary(resource) {
        return Err(StoreError::Invalid(format!(
            "{resource} is an auxiliary of an auxiliary, which can't exist"
        )));
    }
    Ok(())
}

/// A container's IRI ends in `/` and nothing else's does; an auxiliary's ends
/// in `.acl` or `.meta` and nothing else's does. The root is a container.
fn check_kind(resource: &str, root: &str, kind: Kind) -> Result<(), StoreError> {
    let fits = match kind {
        Kind::Container => resource.ends_with('/'),
        Kind::Auxiliary => is_auxiliary(resource),
        Kind::RdfSource | Kind::NonRdfSource => !resource.ends_with('/') && !is_auxiliary(resource),
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

/// Read a stored `modified` back as milliseconds.
///
/// Any RFC 3339 form, not only the fixed-width one written: Oxigraph normalises
/// an `xsd:dateTime` on the way in, so `.750Z` comes back as `.75Z` and `.000Z`
/// as `Z`. Reading only three fractional digits would lose the floor that keeps
/// `modified` increasing, about one write in ten.
fn parse_modified(text: &str) -> Option<i64> {
    let at =
        time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()?;
    i64::try_from(at.unix_timestamp_nanos() / 1_000_000).ok()
}

/// A stored `dcterms:modified` as milliseconds since the epoch, or `None` if
/// it isn't a time we wrote.
///
/// Public because `ldp` compares a client's echo of a member's modified time
/// against the one we serve, and must compare *values*: `.007Z` and
/// `.0070+00:00` are one instant. `brolly-solid`'s `time` has `formatting` but
/// not `parsing`, so this is the one parser, and it is the same one `meta()`
/// normalises through.
pub fn modified_ms(modified: &str) -> Option<i64> {
    parse_modified(modified)
}

/// A stored `modified`, in the fixed-width form every reader gets.
fn normalise_modified(stored: &str) -> String {
    parse_modified(stored)
        .and_then(|ms| format_modified(ms).ok())
        .unwrap_or_else(|| stored.to_owned())
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

// --- serving containers ----------------------------------------------------------

/// What a GET of `container` serves from metadata, in the container's own
/// graph: its types (`ldp:Resource`, `ldp:Container`, `ldp:BasicContainer`,
/// and `pim:Storage` at the root), one `ldp:contains` per member, and each
/// member's server-managed metadata (Solid Protocol §4.2.1).
///
/// Member metadata is `dcterms:modified`, `stat:mtime`, and `stat:size` for a
/// binary. All three come through the same path as [`PodRead::meta`], not
/// from the raw quads: a stored `xsd:dateTime` reads back shortened (`.750Z`
/// as `.75Z`), and a listing that disagreed with the member's own
/// `Last-Modified` would be worse than no listing. `stat:size` is omitted for
/// an RDF source, whose length depends on the syntax negotiated.
///
/// One metadata read per member. `ldp` reuses this one call for both the body
/// it serves and the §4.2.1 check on a write, so a container is read once
/// either way.
///
/// `ldp::read_in` adds these to the container's content graph, and a container
/// PUT is checked against them, so the echo of a GET round-trips.
pub fn container_triples(r: &impl PodRead, container: &str) -> Result<Vec<Quad>, StoreError> {
    const SERVED_TYPES: [&str; 4] = [
        vocab::LDP_RESOURCE,
        vocab::LDP_CONTAINER,
        vocab::LDP_BASIC_CONTAINER,
        vocab::PIM_STORAGE,
    ];

    let node = iri(container);
    let graph = GraphName::NamedNode(node.clone());
    let metadata = metadata_graph();
    let mut out = Vec::new();
    for predicate in [vocab::RDF_TYPE, vocab::LDP_CONTAINS] {
        for quad in r.quads_for_pattern(
            Some(node.as_ref().into()),
            Some(iri(predicate).as_ref()),
            None,
            Some(metadata.as_ref()),
        ) {
            let quad = quad?;
            let served = predicate == vocab::LDP_CONTAINS
                || matches!(&quad.object, Term::NamedNode(t) if SERVED_TYPES.contains(&t.as_str()));
            if served {
                out.push(Quad::new(
                    node.clone(),
                    quad.predicate,
                    quad.object,
                    graph.clone(),
                ));
            }
        }
    }

    // §4.2.1, for every member `out` now names.
    let members: Vec<NamedNode> = out
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::LDP_CONTAINS)
        .filter_map(|q| match &q.object {
            Term::NamedNode(member) => Some(member.clone()),
            _ => None,
        })
        .collect();
    for member in members {
        let Some(meta) = read_meta(r, member.as_str())? else {
            // Listed but with no record: a broken pod, not a reason to refuse
            // the whole listing. The `ldp:contains` still goes out.
            continue;
        };
        let subject = NamedOrBlankNode::NamedNode(member);
        let mut facts = vec![(
            vocab::DCTERMS_MODIFIED,
            Literal::new_typed_literal(meta.modified.clone(), iri(vocab::XSD_DATE_TIME)),
        )];
        if let Some(ms) = parse_modified(&meta.modified) {
            facts.push((
                vocab::STAT_MTIME,
                Literal::new_typed_literal((ms / 1000).to_string(), iri(vocab::XSD_INTEGER)),
            ));
        }
        if let Some(blob) = &meta.blob {
            facts.push((
                vocab::STAT_SIZE,
                Literal::new_typed_literal(blob.byte_size.to_string(), iri(vocab::XSD_INTEGER)),
            ));
        }
        out.extend(facts.into_iter().map(|(predicate, object)| {
            Quad::new(
                subject.clone(),
                iri(predicate),
                Term::Literal(object),
                graph.clone(),
            )
        }));
    }
    Ok(out)
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
        let meta = "https://alice.brolly.test/~/doc.meta";
        assert!(check_kind(doc, ROOT, Kind::RdfSource).is_ok());
        assert!(check_kind(doc, ROOT, Kind::NonRdfSource).is_ok());
        assert!(check_kind(dir, ROOT, Kind::Container).is_ok());
        assert!(check_kind(acl, ROOT, Kind::Auxiliary).is_ok());
        // Spec 5d, H1: a `.meta` is the second auxiliary suffix, and fits the
        // same kind an `.acl` does.
        assert!(check_kind(meta, ROOT, Kind::Auxiliary).is_ok());
        assert!(check_kind(doc, ROOT, Kind::Container).is_err());
        assert!(check_kind(dir, ROOT, Kind::RdfSource).is_err());
        assert!(check_kind(acl, ROOT, Kind::RdfSource).is_err());
        assert!(check_kind(meta, ROOT, Kind::RdfSource).is_err());
        assert!(check_kind(doc, ROOT, Kind::Auxiliary).is_err());
    }

    /// Spec 5d, H1: no auxiliary of an auxiliary. The four double-suffix
    /// shapes name resources that can never exist, and a name that is merely
    /// *like* a suffix is an ordinary document name.
    #[test]
    fn no_auxiliary_of_an_auxiliary() {
        for fiction in [
            "https://alice.brolly.test/~/doc.acl.acl",
            "https://alice.brolly.test/~/doc.acl.meta",
            "https://alice.brolly.test/~/doc.meta.acl",
            "https://alice.brolly.test/~/doc.meta.meta",
        ] {
            assert!(is_double_auxiliary(fiction), "{fiction}");
        }
        for real in [
            "https://alice.brolly.test/~/doc",
            "https://alice.brolly.test/~/doc.acl",
            "https://alice.brolly.test/~/doc.meta",
            "https://alice.brolly.test/~/doc.meta.ttl",
            "https://alice.brolly.test/~/doc.aclx",
            "https://alice.brolly.test/~/docx.meta",
        ] {
            assert!(!is_double_auxiliary(real), "{real}");
        }
    }
}
