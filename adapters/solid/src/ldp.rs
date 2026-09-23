//! LDP operations, protocol-level and store-backed but transport-free.
//!
//! These take a `Subject` and return an [`LdpOutcome`]; the axum wiring lives in
//! `brolly-server`. Keeping HTTP out means the WAC conformance matrix can drive
//! them directly, which is what §2.8 requires — one authorization layer under
//! every protocol, exercised identically.
//!
//! **Every read and every write checks WAC** (plan §5). The predecessor's WAC
//! was reachable from one module while three other protocols bypassed it.
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

impl std::error::Error for LdpError {}

impl From<SyntaxError> for LdpError {
    fn from(e: SyntaxError) -> Self {
        LdpError::Syntax(e)
    }
}

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

impl From<oxigraph::store::StorageError> for LdpError {
    fn from(e: oxigraph::store::StorageError) -> Self {
        LdpError::Store(e.to_string())
    }
}

/// The digest recorded for `resource`, if it is a binary. From metadata only.
pub fn blob_digest(pod: &Pod, resource: &str) -> Option<String> {
    pod.read(|r| r.meta(resource))
        .ok()
        .flatten()
        .and_then(|meta| meta.blob)
        .map(|blob| blob.digest)
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

/// The resource an ACL resource governs, or `None` if `path` is not one.
///
/// A path is an ACL resource when it ends in `.acl`. Every trailing `.acl`
/// comes off, so `/~/x.acl.acl` governs `/~/x`. Stopping after one would make
/// `/~/x.acl` the governed resource, and whoever holds Control over *that*
/// (which is anyone with Control over `/~/x`'s container, not over `/~/x`)
/// could reach it. Only the suffix is examined, so this works on a full IRI as
/// well as on a path.
pub fn governed(path: &str) -> Option<&str> {
    let mut resource = path.strip_suffix(".acl")?;
    while let Some(shorter) = resource.strip_suffix(".acl") {
        resource = shorter;
    }
    Some(resource)
}

/// Resolve and evaluate the ACL governing `resource`.
///
/// An ACL resource is the exception (stage 0, A2). Whatever mode is asked for,
/// it needs `acl:Control` on the resource it [`governed`]s, from that
/// resource's own ACL or an ancestor's `acl:default`. Without this, a caller
/// with inherited Write could rewrite the ACL above them and grant themselves
/// anything, and one with inherited Read could list who else has access.
fn check(
    store: &impl PodRead,
    base: &str,
    path: &str,
    subject: &Subject,
    mode: AccessMode,
) -> Result<bool, LdpError> {
    let (path, mode) = match governed(path) {
        Some(resource) => (resource, AccessMode::Control),
        None => (path, mode),
    };
    let Some(acl) = effective_acl(store, base, path).map_err(|e| LdpError::Store(e.to_string()))?
    else {
        // No ACL anywhere in the hierarchy grants nothing. The storage root is
        // initialised with one, so this means a broken pod rather than a
        // default-open resource.
        return Ok(false);
    };
    authorize(store, &acl, &subject.agent(), mode).map_err(|e| LdpError::Store(e.to_string()))
}

/// Modes `subject` holds on `path`, for the `WAC-Allow` header.
///
/// On an ACL resource this is all or nothing. Every mode needs Control on the
/// governed resource, so holding it grants all four and lacking it grants none.
/// Reporting the governed resource's own modes instead would advertise an edit
/// affordance the request would then refuse.
pub fn granted_modes(
    store: &impl PodRead,
    base: &str,
    path: &str,
    subject: &Subject,
) -> Vec<AccessMode> {
    const ALL: [AccessMode; 4] = [
        AccessMode::Read,
        AccessMode::Write,
        AccessMode::Append,
        AccessMode::Control,
    ];

    if governed(path).is_some() {
        return match check(store, base, path, subject, AccessMode::Control) {
            Ok(true) => ALL.to_vec(),
            _ => Vec::new(),
        };
    }

    let Ok(Some(acl)) = effective_acl(store, base, path) else {
        return Vec::new();
    };
    ALL.into_iter()
        .filter(|mode| matches!(authorize(store, &acl, &subject.agent(), *mode), Ok(true)))
        .collect()
}

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
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
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
            && !check(
                &self.pod.read_store(),
                self.base,
                self.path,
                self.subject,
                mode,
            )?
        {
            return Err(LdpError::Forbidden);
        }
        prepare(blobs, body, content_type)
    }
}

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
    let target = Target {
        pod,
        base,
        path,
        subject,
        storage_root,
    };
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

    let previous = w
        .meta(&resource)?
        .and_then(|meta| meta.blob)
        .map(|blob| blob.digest);
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

/// ADR 0007: we serve RDF/XML but never parse it, and it must not become an
/// opaque blob either — storing it defers the parse rather than avoiding it,
/// and the two live `quick-xml` advisories are reachable either way.
fn refuse_rdf_xml(content_type: &str) -> Result<(), LdpError> {
    match syntax::read_format(content_type) {
        Err(e @ SyntaxError::RdfXmlNotAccepted) => Err(LdpError::Syntax(e)),
        _ => Ok(()),
    }
}

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
    let target = Target {
        pod,
        base,
        path,
        subject,
        storage_root,
    };
    let attempt = || -> Result<String, LdpError> {
        let body = target.prepare(blobs, rdf_only, AccessMode::Append, body, content_type)?;
        in_write(pod, |w| {
            append_in(w, base, path, subject, &body, storage_root)
        })
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

/// May this subject write to `path`? For callers outside a write; `patch_in`
/// checks inside one.
pub fn may_write(
    store: &impl PodRead,
    base: &str,
    path: &str,
    subject: &Subject,
) -> Result<bool, LdpError> {
    check(store, base, path, subject, AccessMode::Write)
}

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
    in_write(pod, |w| {
        patch_in(w, base, path, subject, body, storage_root)
    })
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

#[cfg(test)]
mod tests {
    use super::governed;

    /// The table in spec A2, row for row.
    #[test]
    fn an_acl_governs_its_path_without_the_suffix() {
        assert_eq!(governed("/~/notes/.acl"), Some("/~/notes/"));
        assert_eq!(governed("/~/notes/first.acl"), Some("/~/notes/first"));
        // An ACL of an ACL is still guarded by Control on the thing at the
        // bottom, not by the ACL above it.
        assert_eq!(governed("/~/x.acl.acl"), Some("/~/x"));
    }

    #[test]
    fn other_paths_are_not_acl_resources() {
        assert_eq!(governed("/~/notes"), None);
        assert_eq!(governed("/~/x.aclx"), None);
    }

    #[test]
    fn a_full_iri_works_the_same_way() {
        assert_eq!(
            governed("https://alice.brolly.id/~/notes/.acl"),
            Some("https://alice.brolly.id/~/notes/")
        );
    }
}
