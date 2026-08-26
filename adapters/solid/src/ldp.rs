//! LDP operations, protocol-level and store-backed but transport-free.
//!
//! These take a `Subject` and return an [`LdpOutcome`]; the axum wiring lives in
//! `brolly-server`. Keeping HTTP out means the WAC conformance matrix can drive
//! them directly, which is what §2.8 requires — one authorization layer under
//! every protocol, exercised identically.
//!
//! **Every read and every write checks WAC** (plan §5). The predecessor's WAC
//! was reachable from one module while three other protocols bypassed it.

use brolly_authz::{AccessMode, authorize, effective_acl};
use brolly_domain::syntax::{self, ReadFormat, SyntaxError, WriteFormat};
use brolly_identity::Subject;
use brolly_store::BlobStore;
use brolly_store::write::{WriteError, insert_quads, replace_graph};
use oxigraph::model::{GraphNameRef, NamedNode, Quad};
use oxigraph::store::Store;

use crate::storage;

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
}

impl std::fmt::Display for LdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdpError::Forbidden => write!(f, "forbidden"),
            LdpError::NotFound => write!(f, "not found"),
            LdpError::Syntax(e) => write!(f, "{e}"),
            LdpError::Store(e) => write!(f, "storage: {e}"),
            LdpError::OutsideStorage => write!(f, "path is outside the storage root"),
        }
    }
}

impl std::error::Error for LdpError {}

impl From<SyntaxError> for LdpError {
    fn from(e: SyntaxError) -> Self {
        LdpError::Syntax(e)
    }
}

impl From<WriteError> for LdpError {
    fn from(e: WriteError) -> Self {
        LdpError::Store(e.to_string())
    }
}

impl From<oxigraph::store::StorageError> for LdpError {
    fn from(e: oxigraph::store::StorageError) -> Self {
        LdpError::Store(e.to_string())
    }
}

/// Predicates recording what a binary resource is and where its bytes are.
///
/// Ours, because no standard vocabulary names a content-addressed blob. The
/// media type and size are conventional; the digest is the join to the blob
/// store.
pub const BLOB_DIGEST: &str = "https://brolly.id/ns#blobDigest";
pub const BLOB_MEDIA_TYPE: &str = "https://brolly.id/ns#mediaType";
pub const BLOB_SIZE: &str = "https://brolly.id/ns#byteSize";

/// The digest recorded for `resource`, if it is a binary.
///
/// The presence of this triple is what makes a resource an LDP-NR: reads and
/// deletes branch on it rather than on the request, so a binary behaves the
/// same however it is reached.
pub fn blob_digest(store: &Store, resource: &str) -> Option<String> {
    literal_object(store, resource, BLOB_DIGEST)
}

fn literal_object(store: &Store, resource: &str, predicate: &str) -> Option<String> {
    let node = iri(resource);
    store
        .quads_for_pattern(
            Some((&oxigraph::model::NamedOrBlankNode::NamedNode(node.clone())).into()),
            Some(iri(predicate).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            oxigraph::model::Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
}

/// Is this digest still referenced by some other resource in the pod?
///
/// Content addressing means two resources can name one blob, so deleting either
/// must not blank the other.
fn digest_still_referenced(store: &Store, digest: &str, excluding: &str) -> bool {
    store
        .quads_for_pattern(None, Some(iri(BLOB_DIGEST).as_ref()), None, None)
        .filter_map(Result::ok)
        .any(|q| {
            let matches_digest =
                matches!(&q.object, oxigraph::model::Term::Literal(l) if l.value() == digest);
            matches_digest && q.subject.to_string() != format!("<{excluding}>")
        })
}

/// A successful read.
pub struct LdpOutcome {
    pub body: Vec<u8>,
    /// Owned: a binary's type comes from the pod, not from a fixed list.
    pub media_type: String,
    /// Modes the caller actually holds, for the `WAC-Allow` header. Clients use
    /// it to decide whether to show an edit affordance instead of discovering
    /// the answer by failing.
    pub granted: Vec<AccessMode>,
    pub is_container: bool,
}

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// Resolve and evaluate the ACL governing `resource`.
fn check(
    store: &Store,
    base: &str,
    path: &str,
    subject: &Subject,
    mode: AccessMode,
) -> Result<bool, LdpError> {
    let Some(acl) = effective_acl(store, base, path).map_err(|e| LdpError::Store(e.to_string()))?
    else {
        // No ACL anywhere in the hierarchy grants nothing. The storage root is
        // initialised with one, so this means a broken pod rather than a
        // default-open resource.
        return Ok(false);
    };
    authorize(store, &acl, &subject.agent(), mode).map_err(|e| LdpError::Store(e.to_string()))
}

fn granted_modes(store: &Store, base: &str, path: &str, subject: &Subject) -> Vec<AccessMode> {
    let Ok(Some(acl)) = effective_acl(store, base, path) else {
        return Vec::new();
    };
    [
        AccessMode::Read,
        AccessMode::Write,
        AccessMode::Append,
        AccessMode::Control,
    ]
    .into_iter()
    .filter(|mode| matches!(authorize(store, &acl, &subject.agent(), *mode), Ok(true)))
    .collect()
}

/// `GET` / `HEAD` an LDP resource.
///
/// A caller without Read gets `NotFound`, not `Forbidden`: telling an
/// unauthorized caller that a resource exists is itself a disclosure, and the
/// predecessor's WAC leaked existence this way.
pub fn read(
    store: &Store,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    accept: Option<&str>,
) -> Result<LdpOutcome, LdpError> {
    let resource = format!("{base}{path}");

    if !check(store, base, path, subject, AccessMode::Read)? {
        return Err(LdpError::NotFound);
    }
    if !storage::exists(store, &resource) {
        return Err(LdpError::NotFound);
    }

    // A binary answers with its bytes. The ACL check above already ran, so
    // there is no path to the blob store that skips authorization.
    if let Some(digest) = blob_digest(store, &resource) {
        let Some(blobs) = blobs else {
            return Err(LdpError::Store("no blob store for this pod".into()));
        };
        let bytes = blobs
            .get(&digest)
            .map_err(|e| LdpError::Store(e.to_string()))?
            // The graph says there are bytes and there are not. That is a
            // broken pod, not a missing resource.
            .ok_or_else(|| LdpError::Store(format!("blob {digest} is missing")))?;
        return Ok(LdpOutcome {
            body: bytes,
            // Owned, because a stored media type is not a &'static str.
            media_type: literal_object(store, &resource, BLOB_MEDIA_TYPE)
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            granted: granted_modes(store, base, path, subject),
            is_container: false,
        });
    }

    let node = iri(&resource);
    let quads: Vec<Quad> = store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .collect();

    let format = syntax::negotiate(accept);
    Ok(LdpOutcome {
        body: syntax::serialize(&quads, format)?,
        media_type: format.media_type().to_string(),
        granted: granted_modes(store, base, path, subject),
        is_container: storage::is_container(&resource),
    })
}

/// `PUT` — create or replace a resource.
///
/// Requires Write. Replacing is not Append: a client that may only add triples
/// must not be able to erase the ones already there.
pub fn put(
    store: &Store,
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
    if !check(store, base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Forbidden);
    }

    // ADR 0007: RDF/XML is refused rather than falling through to blob
    // storage. Every *other* unparseable type is a legitimate binary, so this
    // has to name RDF/XML specifically — `read_format` errors for all of them.
    refuse_rdf_xml(content_type)?;

    let quads = if syntax::is_parseable_rdf(content_type) {
        parse_into_graph(body, syntax::read_format(content_type)?, &resource)?
    } else {
        let blobs = blobs.ok_or_else(|| LdpError::Store("no blob store for this pod".into()))?;
        // The previous bytes are released only after the new ones land, so a
        // failed write leaves the old resource intact.
        let previous = blob_digest(store, &resource);
        let digest = blobs
            .put(body)
            .map_err(|e| LdpError::Store(e.to_string()))?;
        let quads = blob_quads(&resource, &digest, content_type, body.len());
        replace_graph(store, &iri(&resource), &quads)?;
        if let Some(previous) = previous
            && previous != digest
            && !digest_still_referenced(store, &previous, &resource)
        {
            blobs
                .remove(&previous)
                .map_err(|e| LdpError::Store(e.to_string()))?;
        }
        storage::add_containment(store, &resource, storage_root)?;
        return Ok(());
    };

    replace_graph(store, &iri(&resource), &quads)?;
    storage::add_containment(store, &resource, storage_root)?;
    Ok(())
}

/// ADR 0007: we serve RDF/XML but never parse it, and it must not become an
/// opaque blob either — storing it defers the parse rather than avoiding it,
/// and the two live `quick-xml` advisories are reachable either way.
fn refuse_rdf_xml(content_type: &str) -> Result<(), LdpError> {
    match syntax::read_format(content_type) {
        Err(e @ SyntaxError::RdfXmlNotAccepted) => Err(LdpError::Syntax(e)),
        _ => Ok(()),
    }
}

/// The graph an LDP-NR is described by.
fn blob_quads(resource: &str, digest: &str, media_type: &str, size: usize) -> Vec<Quad> {
    use oxigraph::model::{Literal, NamedOrBlankNode, Term};
    let node = iri(resource);
    let graph = GraphNameRef::NamedNode(node.as_ref()).into_owned();
    let subject = NamedOrBlankNode::NamedNode(node.clone());
    let media_type = syntax::media_type_of(media_type).to_string();

    vec![
        Quad::new(
            subject.clone(),
            iri(brolly_domain::vocab::RDF_TYPE),
            Term::NamedNode(iri(storage::LDP_NON_RDF_SOURCE)),
            graph.clone(),
        ),
        Quad::new(
            subject.clone(),
            iri(brolly_domain::vocab::RDF_TYPE),
            Term::NamedNode(iri(storage::LDP_RESOURCE)),
            graph.clone(),
        ),
        Quad::new(
            subject.clone(),
            iri(BLOB_DIGEST),
            Term::Literal(Literal::new_simple_literal(digest)),
            graph.clone(),
        ),
        Quad::new(
            subject.clone(),
            iri(BLOB_MEDIA_TYPE),
            Term::Literal(Literal::new_simple_literal(media_type)),
            graph.clone(),
        ),
        Quad::new(
            subject,
            iri(BLOB_SIZE),
            Term::Literal(Literal::new_typed_literal(
                size.to_string(),
                iri(brolly_domain::vocab::XSD_INTEGER),
            )),
            graph,
        ),
    ]
}

/// `POST` — append triples to a resource, or create a member of a container.
///
/// Requires Append, which Write satisfies (`acl:Write` implies `acl:Append`).
pub fn append(
    store: &Store,
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
    if !check(store, base, path, subject, AccessMode::Append)? {
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
    if !syntax::is_parseable_rdf(content_type) {
        let blobs = blobs.ok_or_else(|| LdpError::Store("no blob store for this pod".into()))?;
        let digest = blobs
            .put(body)
            .map_err(|e| LdpError::Store(e.to_string()))?;
        insert_quads(
            store,
            &blob_quads(&target, &digest, content_type, body.len()),
        )?;
        storage::add_containment(store, &target, storage_root)?;
        return Ok(target);
    }

    let quads = parse_into_graph(body, syntax::read_format(content_type)?, &target)?;
    insert_quads(store, &quads)?;
    storage::add_containment(store, &target, storage_root)?;
    Ok(target)
}

/// May this subject write to `path`?
///
/// Exposed for `PATCH`, which mutates through the SPARQL engine rather than
/// through [`put`] and so cannot borrow its check.
pub fn may_write(
    store: &Store,
    base: &str,
    path: &str,
    subject: &Subject,
) -> Result<bool, LdpError> {
    check(store, base, path, subject, AccessMode::Write)
}

/// `DELETE`.
pub fn delete(
    store: &Store,
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
    if !check(store, base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Forbidden);
    }
    if !storage::exists(store, &resource) {
        return Err(LdpError::NotFound);
    }

    // Refusing to delete a non-empty container is LDP's rule, and it is the
    // difference between removing a resource and silently orphaning a subtree.
    if storage::is_container(&resource) && !storage::members(store, &resource).is_empty() {
        return Err(LdpError::Forbidden);
    }

    // Read the digest before the graph goes, then release the bytes only if no
    // other resource still names them — content addressing means two resources
    // can share one blob.
    let digest = blob_digest(store, &resource);
    store.clear_graph(GraphNameRef::NamedNode(iri(&resource).as_ref()))?;
    storage::remove_containment(store, &resource, storage_root)?;

    if let Some(digest) = digest
        && !digest_still_referenced(store, &digest, &resource)
        && let Some(blobs) = blobs
    {
        blobs
            .remove(&digest)
            .map_err(|e| LdpError::Store(e.to_string()))?;
    }
    Ok(())
}

/// Parse a body and retarget every quad into the resource's own named graph.
///
/// A body may carry its own graph names; honouring them would let a `PUT` to
/// one resource write triples into another.
fn parse_into_graph(
    body: &[u8],
    format: ReadFormat,
    resource: &str,
) -> Result<Vec<Quad>, LdpError> {
    let graph = iri(resource);
    Ok(syntax::parse(body, format, resource)?
        .into_iter()
        .map(|q| Quad::new(q.subject, q.predicate, q.object, graph.clone()))
        .collect())
}

/// Response syntaxes we advertise in `Accept-Post` / `Accept-Patch`.
pub fn accepted_write_types() -> &'static str {
    "text/turtle, application/n-triples, application/n-quads, application/trig, application/ld+json"
}

/// Formats we can serve, for `OPTIONS`.
pub fn served_types() -> &'static [WriteFormat] {
    &[
        WriteFormat::Turtle,
        WriteFormat::NTriples,
        WriteFormat::NQuads,
        WriteFormat::TriG,
        WriteFormat::JsonLd,
        WriteFormat::RdfXml,
    ]
}
