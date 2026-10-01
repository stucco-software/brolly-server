//! Upgrading an old-layout pod to the current layout, once, when it's first
//! opened.
//!
//! Before layout 2 a pod kept what the server knew about a resource in the
//! resource's own graph: its types, its container's `ldp:contains`, and a
//! binary's blob pointer. Layout 2 recorded all of it in the metadata graph in
//! one transaction, and stripped it from the content graphs so the two can't
//! disagree. Layout 3 (spec 5d, H1 and H6) makes `.meta` the second auxiliary
//! suffix: a recorded `x.meta` — an ordinary contained document under layout 2
//! — is un-contained and retyped `Auxiliary`, and resources the new rules
//! refuse — an auxiliary of an auxiliary, a binary at a `.meta` IRI — are
//! removed. It's forward-only (spec 5a, *No rollback*).
//!
//! The layout-1 upgrade records through `PodWrite::put`, so each resource is
//! recorded exactly as a write would record it: its kind, a modified time and
//! a fresh version, containment in its parent, and missing intermediate
//! containers. And because `put` replaces the content graph, putting the
//! stripped content is what strips it.

use std::collections::{BTreeMap, BTreeSet};

use brolly_domain::vocab;
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, Term, TermRef,
};

use super::{
    BlobMeta, Content, Kind, METADATA_GRAPH, Pod, PodRead, PodWrite, ResourceMeta, containment,
    is_double_auxiliary, meta_quad, parent_container,
};
use crate::blobs::BlobStore;
use crate::manager::StoreError;
use crate::write::remove_quads_in;

/// The layout this code writes and reads.
const LAYOUT: &str = "3";
/// The layout before this one. A pod at the prior layout is upgraded by
/// [`migrate`] and marked current in the same transaction.
const PRIOR_LAYOUT: &str = "2";

/// What opening a pod found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeOutcome {
    /// The store held nothing: a new pod. Marked layout 2; provisioning
    /// records the root with `create_root`.
    Fresh,
    /// Already layout 2: the mark was read, or the metadata records a root and
    /// the mark has just been written.
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
    /// Layout 2 → 3: `x.meta` documents un-contained and retyped as
    /// auxiliaries (spec 5d, H6).
    pub metas_retyped: usize,
    /// Layout 2 → 3: resources removed as fictions — an auxiliary of an
    /// auxiliary, or a binary at a `.meta` IRI, neither of which can exist
    /// under the new rules (spec 5d, H1 and H4).
    pub fictions_removed: usize,
}

impl UpgradeReport {
    /// Did the layout-2 → 3 migration change anything?
    fn migrated(&self) -> bool {
        self.metas_retyped > 0 || self.fictions_removed > 0
    }
}

/// The layout mark a pod carries.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mark {
    /// The layout this code writes: nothing to do.
    Current,
    /// The prior layout: [`migrate`] upgrades it.
    Prior,
    /// Unmarked: a new pod, or a pod from before layout 2.
    None,
}

/// Bring `pod` to the current layout if it isn't already. `StoreManager` calls
/// this once per open, before the pod is reachable by anyone else.
///
/// - A pod already marked is left alone: its root is read from metadata.
/// - A pod at the prior layout (marked, or with a metadata root and the mark
///   missing) is upgraded by [`migrate`] and marked in the same transaction.
/// - A store with no quads at all is marked straight away.
/// - Otherwise it's an old-layout (layout 1) pod. Its root must be the one IRI
///   whose path is exactly `/~/` and whose own graph says it's a `pim:Storage`.
///   With no such IRI, or two (on different hosts), nothing is written and the
///   pod is left unmarked; the caller logs it.
///
/// One `Pod::write`, so a failure leaves the pod exactly as it was and the
/// next open retries.
pub fn upgrade(pod: &Pod) -> Result<UpgradeOutcome, StoreError> {
    pod.write(|w| {
        match mark_of(&*w)? {
            Mark::Current => Ok(UpgradeOutcome::Current),
            Mark::None if w.quads_for_pattern(None, None, None, None).next().is_none() => {
                mark(w)?;
                Ok(UpgradeOutcome::Fresh)
            }
            // A root in the metadata graph means this pod is at the prior
            // layout and only the mark is missing. That happens when a pod
            // took a protocol graph (a profile, say) before provisioning: the
            // first open found no old-layout root and left it unmarked, and
            // `create_root` then recorded the root in metadata alone. Without
            // this, every later open would rescan the pod, find no old-layout
            // root, and log it missing forever.
            Mark::None if w.storage_root()?.is_some() => migrate_marked(w),
            Mark::Prior => migrate_marked(w),
            Mark::None => {
                let root = match <[String; 1]>::try_from(root_candidates(&*w)?) {
                    Ok([root]) => root,
                    Err(candidates) => {
                        return Ok(UpgradeOutcome::NoRoot { candidates });
                    }
                };
                let report = record(w, &pod.blobs, &root)?;
                mark(w)?;
                Ok(UpgradeOutcome::Upgraded(report))
            }
        }
    })
}

/// Upgrade a prior-layout pod to the current layout (spec 5d, H6), then mark
/// it. Answers [`UpgradeOutcome::Current`] when the migration found nothing to
/// do, which is every pod that never held a stray `.meta`.
fn migrate_marked(w: &mut PodWrite<'_>) -> Result<UpgradeOutcome, StoreError> {
    let root = w
        .storage_root()?
        .ok_or_else(|| StoreError::Backend("a marked pod has no storage root".into()))?;
    let mut report = UpgradeReport {
        root,
        ..UpgradeReport::default()
    };
    migrate(w, &mut report)?;
    mark(w)?;
    Ok(if report.migrated() {
        UpgradeOutcome::Upgraded(report)
    } else {
        UpgradeOutcome::Current
    })
}

/// `<METADATA_GRAPH> brolly:layout 3`, in the metadata graph itself. A pod
/// moving up from the prior layout carries its old mark, which goes first —
/// or the graph would hold two layouts and [`mark_of`] could read either.
fn mark(w: &mut PodWrite<'_>) -> Result<(), StoreError> {
    let graph = NamedNode::new_unchecked(METADATA_GRAPH);
    let stale: Vec<Quad> = w
        .quads_for_pattern(
            Some(graph.as_ref().into()),
            Some(NamedNodeRef::new_unchecked(vocab::BROLLY_LAYOUT)),
            None,
            Some(GraphNameRef::NamedNode(graph.as_ref())),
        )
        .collect::<Result<_, _>>()?;
    remove_quads_in(&mut w.transaction, &stale);
    w.insert_metadata(&[Quad::new(
        graph.clone(),
        NamedNode::new_unchecked(vocab::BROLLY_LAYOUT),
        Literal::new_typed_literal(LAYOUT, NamedNode::new_unchecked(vocab::XSD_INTEGER)),
        GraphName::NamedNode(graph),
    )])
}

/// The layout mark the pod carries. A mark this server knows neither as
/// current nor as the prior layout is an error rather than a rescan: a newer
/// server wrote it.
fn mark_of(r: &impl PodRead) -> Result<Mark, StoreError> {
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
        return Ok(Mark::None);
    };
    match quad?.object {
        Term::Literal(layout) if layout.value() == LAYOUT => Ok(Mark::Current),
        Term::Literal(layout) if layout.value() == PRIOR_LAYOUT => Ok(Mark::Prior),
        other => Err(StoreError::Backend(format!(
            "this pod is at layout {other}, which this server doesn't know"
        ))),
    }
}

/// Every IRI `r` at path `/~/` with `<r> a pim:Storage` in `r`'s own graph,
/// sorted. A member can write `<> a pim:Storage` into their own document, but
/// its path isn't `/~/`.
fn root_candidates(r: &impl PodRead) -> Result<Vec<String>, StoreError> {
    let mut found = BTreeSet::new();
    for quad in r.quads_for_pattern(
        None,
        Some(NamedNodeRef::new_unchecked(vocab::RDF_TYPE)),
        Some(TermRef::NamedNode(NamedNodeRef::new_unchecked(
            vocab::PIM_STORAGE,
        ))),
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
    Binary {
        blob: BlobMeta,
        rest: Vec<Quad>,
    },
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
        // No auxiliary of an auxiliary (spec 5d, H1): layout 1 could record
        // one under the `.acl`-only rules. The graph and any record of it go.
        if is_double_auxiliary(&graph) {
            tracing::warn!(
                %graph,
                "upgrade: dropped an auxiliary-of-an-auxiliary graph, which can't exist"
            );
            w.forget(&graph)?;
            report.fictions_removed += 1;
            continue;
        }
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
                w.put(
                    &resource,
                    Content::Container(&strip_container(&resource, quads)),
                )?;
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
fn graphs_under(r: &impl PodRead, root: &str) -> Result<BTreeMap<String, Vec<Quad>>, StoreError> {
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

/// The spec's order: an `.acl` or `.meta` IRI is auxiliary (spec 5d, H1); a
/// graph passing the binary test is a binary; an IRI ending in `/` is a
/// container; anything else is an RDF document. Every graph here has quads.
/// The root is always a container, whatever its graph claims.
fn classify(
    graph: &str,
    root: &str,
    quads: Vec<Quad>,
    blobs: &BlobStore,
    report: &mut UpgradeReport,
) -> Found {
    if graph.ends_with(".acl") || graph.ends_with(".meta") {
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
/// never an auxiliary: an `.acl` or `.meta` is recorded but not contained
/// (Solid Protocol §4.3, spec 5d H1).
fn may_hold(container: &str, member: &str, root: &str) -> bool {
    member.starts_with(root)
        && member != root
        && !member.ends_with(".acl")
        && !member.ends_with(".meta")
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

/// Layout 2 → 3 (spec 5d, H1, H4 and H6), for a pod the metadata graph
/// already describes: every recorded resource, re-examined under the new
/// rules.
///
/// - A recorded `x.meta` — an ordinary contained document under layout 2 —
///   is un-contained and retyped `Auxiliary`. The retype is one triple, the
///   `brolly:Auxiliary` type, which subsumes a document record's types, so
///   the graph, the modified time and the version stay what the member last
///   saw. Only the parent's version moves, as a write that changed its
///   membership would move it (R9).
/// - An auxiliary of an auxiliary, and a `.meta` holding bytes — a binary
///   at a `.meta` IRI, which is RDF-only now (H4) — can't exist under the
///   new rules. Both are removed: graph, record, blob and containment.
fn migrate(w: &mut PodWrite<'_>, report: &mut UpgradeReport) -> Result<(), StoreError> {
    for (resource, meta) in recorded(&*w)? {
        // No auxiliary of an auxiliary (spec 5d, H1). Layout 2 recorded any
        // `.acl`-ending IRI as one — `x.meta.acl`, the ACL of a document
        // `x.meta` — and any other `.meta`-ending IRI, `x.acl.meta` included,
        // as an ordinary contained document. Neither can exist now.
        if is_double_auxiliary(&resource) {
            tracing::warn!(
                %resource,
                "upgrade: removed an auxiliary of an auxiliary, which can't exist"
            );
            remove_migrated(w, &resource, &meta, &report.root)?;
            report.fictions_removed += 1;
            continue;
        }
        if !resource.ends_with(".meta") {
            continue;
        }
        // A `.meta` holding bytes — recorded as a binary, or a document
        // record with blob metadata — can't exist: a `.meta` is RDF-only
        // (spec 5d, H4).
        if matches!(meta.kind, Kind::NonRdfSource) || meta.blob.is_some() {
            tracing::warn!(
                %resource,
                "upgrade: removed a .meta holding bytes, which is RDF-only"
            );
            remove_migrated(w, &resource, &meta, &report.root)?;
            report.fictions_removed += 1;
            continue;
        }
        // An ordinary contained document under layout 2 (spec 5d, H6):
        // un-contained and retyped. Layout 2 recorded no auxiliary at a
        // `.meta` IRI and no container there; one that reads back as either
        // is already right or beyond this migration, and not its to change.
        if meta.kind == Kind::RdfSource {
            w.insert_metadata(&[meta_quad(
                &resource,
                vocab::RDF_TYPE,
                Term::NamedNode(NamedNode::new_unchecked(vocab::BROLLY_AUXILIARY)),
            )])?;
            uncontain(w, &resource, &report.root)?;
            report.metas_retyped += 1;
        }
    }
    Ok(())
}

/// Every resource the metadata graph records — each subject of an
/// `rdf:type ldp:Resource` there (R2) — with the record as it reads back.
/// Sorted, so a container is visited before its members.
fn recorded(r: &impl PodRead) -> Result<BTreeMap<String, ResourceMeta>, StoreError> {
    let mut found = BTreeMap::new();
    for quad in r.quads_for_pattern(
        None,
        Some(NamedNodeRef::new_unchecked(vocab::RDF_TYPE)),
        Some(TermRef::NamedNode(NamedNodeRef::new_unchecked(
            vocab::LDP_RESOURCE,
        ))),
        Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(
            METADATA_GRAPH,
        ))),
    ) {
        let quad = quad?;
        if let NamedOrBlankNode::NamedNode(subject) = &quad.subject
            && let Some(meta) = r.meta(subject.as_str())?
        {
            found.insert(subject.as_str().to_string(), meta);
        }
    }
    Ok(found)
}

/// Remove a resource the new rules refuse: its graph, its record, its blob,
/// and its place in its parent. An auxiliary was never contained, so its
/// parent's version doesn't move.
fn remove_migrated(
    w: &mut PodWrite<'_>,
    resource: &str,
    meta: &ResourceMeta,
    root: &str,
) -> Result<(), StoreError> {
    w.forget(resource)?;
    if let Some(blob) = &meta.blob {
        w.release_blob(&blob.digest);
    }
    if meta.kind != Kind::Auxiliary {
        uncontain(w, resource, root)?;
    }
    Ok(())
}

/// Take `resource` out of its parent container, moving the parent's version
/// (R9). The containment triple goes even if the parent isn't recorded.
fn uncontain(w: &mut PodWrite<'_>, resource: &str, root: &str) -> Result<(), StoreError> {
    if let Some(parent) = parent_container(resource, root) {
        remove_quads_in(&mut w.transaction, &[containment(&parent, resource)]);
        w.touch(&parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::resources::types_for;

    const ROOT: &str = "https://alice.brolly.test/~/";
    const TITLE: &str = "https://example.org/title";
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
        Quad::new(
            n(s),
            n(p),
            Literal::new_simple_literal(o),
            GraphName::NamedNode(n(g)),
        )
    }

    /// A layout-2 record for `resource`, exactly as layout 2's `record`
    /// wrote it: the types, a modified time and a version.
    fn record_2(resource: &str, kind: Kind) -> Vec<Quad> {
        let mut quads: Vec<Quad> = types_for(kind)
            .iter()
            .map(|class| iri(METADATA_GRAPH, resource, vocab::RDF_TYPE, class))
            .collect();
        quads.extend([
            lit(
                METADATA_GRAPH,
                resource,
                vocab::DCTERMS_MODIFIED,
                "2026-09-29T12:00:00.000Z",
            ),
            lit(
                METADATA_GRAPH,
                resource,
                vocab::BROLLY_VERSION,
                "0LAYOUT2VERSION000000000",
            ),
        ]);
        quads
    }

    /// The storage root as layout 2 recorded it: a container's record, plus
    /// the `pim:Storage` type.
    fn root_2() -> Vec<Quad> {
        let mut quads = record_2(ROOT, Kind::Container);
        quads.push(iri(
            METADATA_GRAPH,
            ROOT,
            vocab::RDF_TYPE,
            vocab::PIM_STORAGE,
        ));
        quads
    }

    /// The layout-2 mark, as `mark` wrote it then.
    fn mark_2() -> Quad {
        mark_of_layout("2")
    }

    fn mark_of_layout(layout: &str) -> Quad {
        Quad::new(
            n(METADATA_GRAPH),
            n(vocab::BROLLY_LAYOUT),
            Literal::new_typed_literal(layout, n(vocab::XSD_INTEGER)),
            GraphName::NamedNode(n(METADATA_GRAPH)),
        )
    }

    /// A pod seeded as layout 2 left it, opened straight from its directory
    /// so no manager caches it. `extra` runs after the quads are in, for a
    /// blob the record needs the digest of.
    fn layout_2_pod(quads: &[Quad]) -> (tempfile::TempDir, Pod) {
        let dir = tempfile::tempdir().unwrap();
        let pod = Pod::open(dir.path()).unwrap();
        pod.raw_store().extend(quads.iter().cloned()).unwrap();
        (dir, pod)
    }

    /// The layout the pod is marked at, as text.
    fn layout(pod: &Pod) -> String {
        let quad = pod
            .read(|r| {
                Ok(r.quads_for_pattern(
                    Some(NamedOrBlankNodeRef::NamedNode(n(METADATA_GRAPH).as_ref())),
                    Some(n(vocab::BROLLY_LAYOUT).as_ref()),
                    None,
                    Some(GraphNameRef::NamedNode(n(METADATA_GRAPH).as_ref())),
                )
                .next()
                .transpose()?)
            })
            .unwrap()
            .expect("the pod is marked");
        match quad.object {
            Term::Literal(value) => value.value().to_string(),
            other => panic!("the layout mark is a literal, not {other:?}"),
        }
    }

    /// A recorded `.meta`, as layout 2 left it: an ordinary contained
    /// document with a title.
    fn stray_meta(resource: &str) -> Vec<Quad> {
        let mut quads = record_2(resource, Kind::RdfSource);
        quads.extend([
            iri(METADATA_GRAPH, ROOT, vocab::LDP_CONTAINS, resource),
            lit(resource, resource, TITLE, "a description"),
        ]);
        quads
    }

    #[test]
    fn a_prior_layout_pod_with_nothing_to_do_is_marked_current() {
        let doc = format!("{ROOT}doc");
        let acl = format!("{doc}.acl");
        let mut quads = vec![mark_2()];
        quads.extend(root_2());
        quads.extend(record_2(&doc, Kind::RdfSource));
        quads.push(iri(METADATA_GRAPH, ROOT, vocab::LDP_CONTAINS, &doc));
        quads.extend(record_2(&acl, Kind::Auxiliary));
        let (_dir, pod) = layout_2_pod(&quads);

        assert_eq!(upgrade(&pod).unwrap(), UpgradeOutcome::Current);
        assert_eq!(layout(&pod), LAYOUT);
        assert_eq!(pod.read(|r| r.members(ROOT)).unwrap(), vec![doc.clone()]);
        assert_eq!(
            pod.read(|r| r.meta(&doc)).unwrap().map(|m| m.kind),
            Some(Kind::RdfSource)
        );
        assert_eq!(
            pod.read(|r| r.meta(&acl)).unwrap().map(|m| m.kind),
            Some(Kind::Auxiliary)
        );
    }

    #[test]
    fn a_stray_meta_is_uncontained_and_retyped() {
        let doc = format!("{ROOT}doc");
        let meta = format!("{doc}.meta");
        let mut quads = vec![mark_2()];
        quads.extend(root_2());
        quads.extend(record_2(&doc, Kind::RdfSource));
        quads.push(iri(METADATA_GRAPH, ROOT, vocab::LDP_CONTAINS, &doc));
        quads.extend(stray_meta(&meta));
        let (_dir, pod) = layout_2_pod(&quads);

        assert_eq!(
            upgrade(&pod).unwrap(),
            UpgradeOutcome::Upgraded(UpgradeReport {
                root: ROOT.to_string(),
                metas_retyped: 1,
                ..UpgradeReport::default()
            })
        );
        assert_eq!(layout(&pod), LAYOUT);

        // The root lists the document, never the description.
        assert_eq!(pod.read(|r| r.members(ROOT)).unwrap(), vec![doc.clone()]);

        // Retyped, with the graph and the stamps preserved: the member
        // changed nothing.
        let retyped = pod.read(|r| r.meta(&meta)).unwrap().expect("retyped");
        assert_eq!(retyped.kind, Kind::Auxiliary);
        assert_eq!(retyped.modified, "2026-09-29T12:00:00.000Z");
        assert_eq!(retyped.version, "0LAYOUT2VERSION000000000");
        let graph: Vec<Quad> = pod
            .read_store()
            .quads_for_pattern(
                None,
                None,
                None,
                Some(GraphNameRef::NamedNode(n(&meta).as_ref())),
            )
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            graph,
            vec![lit(&meta, &meta, TITLE, "a description")],
            "the .meta's graph must survive untouched"
        );

        // And the root's version moved: its membership changed.
        let root = pod.read(|r| r.meta(ROOT)).unwrap().unwrap();
        assert_ne!(root.version, "0LAYOUT2VERSION000000000");

        // A second run finds the mark and changes nothing.
        assert_eq!(upgrade(&pod).unwrap(), UpgradeOutcome::Current);
    }

    #[test]
    fn a_meta_and_its_own_auxiliaries() {
        let doc = format!("{ROOT}doc");
        let doc_meta = format!("{doc}.meta");
        let meta_acl = format!("{doc_meta}.acl"); // layout 2's ACL of the .meta
        let acl_meta = format!("{doc}.acl.meta"); // layout 2's document beside the ACL
        let mut quads = vec![mark_2()];
        quads.extend(root_2());
        quads.extend(record_2(&doc, Kind::RdfSource));
        quads.push(iri(METADATA_GRAPH, ROOT, vocab::LDP_CONTAINS, &doc));
        quads.extend(record_2(&format!("{doc}.acl"), Kind::Auxiliary));
        quads.extend(stray_meta(&doc_meta));
        quads.extend(record_2(&meta_acl, Kind::Auxiliary));
        quads.push(lit(&meta_acl, &meta_acl, TITLE, "the grants"));
        quads.extend(stray_meta(&acl_meta));
        let (_dir, pod) = layout_2_pod(&quads);

        assert_eq!(
            upgrade(&pod).unwrap(),
            UpgradeOutcome::Upgraded(UpgradeReport {
                root: ROOT.to_string(),
                metas_retyped: 1,
                fictions_removed: 2,
                ..UpgradeReport::default()
            })
        );
        assert_eq!(
            pod.read(|r| r.meta(&doc_meta)).unwrap().map(|m| m.kind),
            Some(Kind::Auxiliary)
        );
        for fiction in [&meta_acl, &acl_meta] {
            assert!(
                pod.read(|r| r.meta(fiction)).unwrap().is_none(),
                "{fiction}"
            );
            let graph: Vec<Quad> = pod
                .read_store()
                .quads_for_pattern(
                    None,
                    None,
                    None,
                    Some(GraphNameRef::NamedNode(n(fiction).as_ref())),
                )
                .map(Result::unwrap)
                .collect();
            assert!(graph.is_empty(), "{fiction}'s graph survived: {graph:?}");
        }
        // The root lists the document only: never the .meta, never the
        // fictions.
        assert_eq!(pod.read(|r| r.members(ROOT)).unwrap(), vec![doc.clone()]);
    }

    #[test]
    fn a_meta_holding_bytes_is_removed_blob_and_all() {
        let dir = tempfile::tempdir().unwrap();
        let pod = Pod::open(dir.path()).unwrap();
        let digest = pod.blobs().put(PNG).unwrap();
        let photo_meta = format!("{ROOT}photo.meta");
        let mut quads = vec![mark_2()];
        quads.extend(root_2());
        quads.extend(record_2(&photo_meta, Kind::NonRdfSource));
        quads.push(iri(METADATA_GRAPH, ROOT, vocab::LDP_CONTAINS, &photo_meta));
        quads.extend([
            lit(
                METADATA_GRAPH,
                &photo_meta,
                vocab::BROLLY_BLOB_DIGEST,
                &digest,
            ),
            lit(
                METADATA_GRAPH,
                &photo_meta,
                vocab::BROLLY_MEDIA_TYPE,
                "image/png",
            ),
            Quad::new(
                n(&photo_meta),
                n(vocab::BROLLY_BYTE_SIZE),
                Literal::new_typed_literal(PNG.len().to_string(), n(vocab::XSD_INTEGER)),
                GraphName::NamedNode(n(METADATA_GRAPH)),
            ),
        ]);
        pod.raw_store().extend(quads.iter().cloned()).unwrap();

        assert_eq!(
            upgrade(&pod).unwrap(),
            UpgradeOutcome::Upgraded(UpgradeReport {
                root: ROOT.to_string(),
                fictions_removed: 1,
                ..UpgradeReport::default()
            })
        );
        assert!(pod.read(|r| r.meta(&photo_meta)).unwrap().is_none());
        assert_eq!(pod.read(|r| r.members(ROOT)).unwrap(), Vec::<String>::new());
        assert!(
            !pod.blobs().contains(&digest),
            "the blob of a removed fiction must be swept"
        );
    }

    #[test]
    fn an_unmarked_pod_with_a_recorded_root_migrates_too() {
        let meta = format!("{ROOT}doc.meta");
        let mut quads = root_2();
        quads.extend(stray_meta(&meta));
        let (_dir, pod) = layout_2_pod(&quads);

        assert_eq!(
            upgrade(&pod).unwrap(),
            UpgradeOutcome::Upgraded(UpgradeReport {
                root: ROOT.to_string(),
                metas_retyped: 1,
                ..UpgradeReport::default()
            })
        );
        assert_eq!(layout(&pod), LAYOUT);
    }

    #[test]
    fn a_newer_layout_is_an_error() {
        let mut quads = vec![mark_of_layout("4")];
        quads.extend(root_2());
        let (_dir, pod) = layout_2_pod(&quads);

        assert!(upgrade(&pod).is_err(), "a newer server wrote this pod");
    }
}
