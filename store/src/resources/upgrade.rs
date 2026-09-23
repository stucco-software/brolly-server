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
}

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
        // A root in the metadata graph means this pod is already layout 2 and
        // only the mark is missing. That happens when a pod took a protocol
        // graph (a profile, say) before provisioning: the first open found no
        // old-layout root and left it unmarked, and `create_root` then recorded
        // the root in metadata alone. Without this, every later open would scan
        // the pod, find no old-layout root, and log it missing forever.
        if w.storage_root()?.is_some() {
            mark(w)?;
            return Ok(UpgradeOutcome::Current);
        }
        let root = match <[String; 1]>::try_from(root_candidates(&*w)?) {
            Ok([root]) => root,
            Err(candidates) => return Ok(UpgradeOutcome::NoRoot { candidates }),
        };
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

/// `<METADATA_GRAPH> brolly:layout 2`, in the metadata graph itself.
fn mark(w: &mut PodWrite<'_>) -> Result<(), StoreError> {
    let graph = NamedNode::new_unchecked(METADATA_GRAPH);
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
