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
//! **Conditional requests.** Each write has an `_if` form ([`put_if`],
//! [`append_if`], [`delete_if`], [`patch_if`]) taking a
//! [`Preconditions`](crate::conditional::Preconditions); the plain names are
//! wrappers passing none. The `_in` functions evaluate it after WAC and before
//! any write, in the caller's transaction, so nothing can land in between.
//!
//! **Server-managed state comes from metadata** (`store::resources`):
//! existence, kind, containment and a binary's blob. None of it is read from
//! the graph a client writes, so an `ldp:contains` or `brolly:blobDigest`
//! triple in an ordinary document is inert data.

use std::collections::BTreeSet;

use brolly_authz::{AccessMode, authorize, effective_acl};
use brolly_domain::syntax::{self, ReadFormat, SyntaxError};
use brolly_domain::vocab;
use brolly_identity::Subject;
use brolly_store::resources::{
    self, BlobMeta, Content, Kind, Pod, PodRead, PodWrite, ResourceMeta, ResourceRead,
};
use brolly_store::{BlobStore, StoreError};
use oxigraph::model::{GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};

use crate::conditional::{self, PreconditionFailed, Preconditions};
use crate::patch::{self, PatchError};
use crate::storage;

#[derive(Debug)]
pub enum LdpError {
    /// The caller does not hold the mode this operation needs.
    ///
    /// Deliberately distinct from [`LdpError::NotFound`], which now means only
    /// *the caller holds the mode and there is nothing there*. `pod.rs` turns
    /// this into 401 or 403 from its own knowledge of the credential, which is
    /// the one thing this crate has no reason to know (spec 5b, H1).
    ///
    /// **It never depends on whether the resource exists.** Effective modes
    /// come from the nearest ACL up the path, which exists whether or not the
    /// resource does, so an unauthenticated caller sees the same refusal for
    /// `/~/secret` and `/~/does-not-exist` and cannot tell them apart.
    Denied,
    /// The caller holds the mode and there is nothing at this IRI.
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
    /// The storage root or the root's own ACL: the two resources Solid
    /// Protocol §5.4 says a server must refuse to delete. `pod.rs` answers it
    /// 405 with the caller's `Allow`.
    Undeletable,
    /// A container that still has members. Not "you may not" — "not while it
    /// has members". 5b's chunk 5 answers it 409 *with a body describing the
    /// error*, which §5.4 requires; until then it keeps stage 0's 403.
    NotEmpty,
    /// A binary's bytes vanished between `prepare` and the write: a
    /// concurrent delete released identical bytes. Prepare again and retry
    /// once (spec 5a, R12).
    BlobMissing,
    /// An `If-Match` or `If-None-Match` didn't hold (412). Evaluated after WAC,
    /// so only a caller holding the needed mode can see it.
    PreconditionFailed,
}

impl std::fmt::Display for LdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdpError::Denied => write!(f, "no grant for this operation"),
            LdpError::NotFound => write!(f, "not found"),
            LdpError::Syntax(e) => write!(f, "{e}"),
            LdpError::Store(e) => write!(f, "storage: {e}"),
            LdpError::OutsideStorage => write!(f, "path is outside the storage root"),
            LdpError::NotRdf => write!(f, "this resource takes an RDF body"),
            LdpError::ContainmentChange => write!(
                f,
                "a container's members change only by creating or deleting them"
            ),
            LdpError::Undeletable => write!(f, "this resource cannot be deleted"),
            LdpError::NotEmpty => write!(f, "this container still has members"),
            LdpError::BlobMissing => write!(f, "the blob was released before it was recorded"),
            LdpError::PreconditionFailed => write!(f, "precondition failed"),
        }
    }
}

impl std::error::Error for LdpError {}

impl From<PreconditionFailed> for LdpError {
    fn from(_: PreconditionFailed) -> Self {
        LdpError::PreconditionFailed
    }
}

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
            // Stage 0's answer to a populated container, until 5b's chunk 5
            // turns it into a 409 with a body.
            StoreError::ContainerNotEmpty => LdpError::NotEmpty,
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
    /// The syntax token of the representation in `body`: the second half of
    /// the `ETag` (H10). `conditional::BINARY` for a binary, whose bytes are
    /// the same for every `Accept`; otherwise the negotiated format's token.
    ///
    /// It comes from the same negotiation that produced `body`, so an `ETag`
    /// always names the bytes it goes out with.
    pub syntax: &'static str,
    /// The target as [`describe`] reports it, from the same snapshot as
    /// `body`: existence, kind, and both sets of modes. `Allow`, `Accept-*`
    /// and `WAC-Allow` are all built from this one value, on `GET`, `HEAD` and
    /// `OPTIONS` alike, so those three cannot disagree.
    pub description: Description,
    /// `brolly:version` from that snapshot: the `ETag`. Not an `Option` like
    /// the one inside `description`, because [`read`] returns only for a
    /// resource that is there — which makes the missing case unrepresentable
    /// rather than something `pod.rs` has to unwrap.
    pub version: String,
    /// `dcterms:modified` from that snapshot, as stored (`xsd:dateTime`): the
    /// `Last-Modified`.
    pub modified: String,
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

/// The IRI of the ACL that holds `target`'s access rules.
///
/// **Not the inverse of [`governed`].** `governed` strips *every* trailing
/// `.acl`, because `Control` at the bottom of the chain is what guards the
/// whole of it (stage 0's A2). This answers a different question — which IRI a
/// client fetches or writes to change `target`'s rules — and for an ACL
/// resource that is the ACL itself, because an `.acl` is governed by its own
/// `Control`.
///
/// Everything else gets `.acl` appended. That is one expression and two cases:
/// a container's ACL lives *inside* it (`/~/notes/` → `/~/notes/.acl`, since
/// the IRI already ends in `/`) and a document's beside it (`/~/note` →
/// `/~/note.acl`). Both agree with `authz::acl_candidates`' most specific
/// candidate, which is the graph WAC actually reads.
pub fn acl_iri(target: &str) -> String {
    match governed(target) {
        Some(_) => target.to_string(),
        None => format!("{target}.acl"),
    }
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

/// What a resource is, and what a caller may do with it — without its body.
///
/// The body-free half of [`read`], and the only thing the HTTP surface needs
/// to build `Allow`, `Accept-*`, `Link` and `WAC-Allow` (spec 5b, H4–H10).
/// `OPTIONS` needs it because it answers for resources the caller may not
/// read and for targets that do not exist yet; `GET` and `HEAD` take the same
/// value so the affordances a client reads cannot depend on which method it
/// read them from.
///
/// **Every field comes from one snapshot.** `Pod::read` drops its transaction
/// when the closure returns, so anything that asks these questions afterwards
/// is asking a different pod. That is why the anonymous probe for `public`
/// runs in here and rides out on the value, and it is what guarantees
/// `WAC-Allow`'s two components describe one ACL.
pub struct Description {
    /// The resource's metadata, or `None` when nothing is recorded at the IRI.
    /// Existence, kind, version and modified time all come from here, so they
    /// cannot disagree with each other.
    pub meta: Option<ResourceMeta>,
    /// Modes the caller holds. Empty means no access of any kind, which is
    /// what `pod.rs` turns into H1's 401 or 403.
    pub granted: Vec<AccessMode>,
    /// Modes an anonymous caller holds: `WAC-Allow`'s `public=`. A share UI
    /// has to be able to show whether a resource is world-readable, and
    /// failing at it is the only other way to find out.
    pub public: Vec<AccessMode>,
}

impl Description {
    /// Is there a resource at this IRI? Existence is one metadata triple
    /// (5a, R2), never a graph that happens to have triples in it.
    pub fn exists(&self) -> bool {
        self.meta.is_some()
    }

    /// What it is, or `None` when it isn't there.
    pub fn kind(&self) -> Option<Kind> {
        self.meta.as_ref().map(|meta| meta.kind)
    }

    /// A container by its *recorded* kind. Not the same question as
    /// [`storage::is_container`], which reads a trailing slash off an IRI and
    /// so answers for targets that don't exist.
    pub fn is_container(&self) -> bool {
        matches!(self.kind(), Some(Kind::Container))
    }

    /// Does the caller hold `mode`?
    pub fn holds(&self, mode: AccessMode) -> bool {
        self.granted.contains(&mode)
    }
}

/// Describe `path` without reading it: [`read`]'s metadata and modes, no body.
///
/// Takes no [`BlobStore`] on purpose. A binary is described from the
/// `BlobMeta` already in its metadata — kind, media type, size — and its bytes
/// are never fetched, so `OPTIONS` on a 40 MB video costs what `OPTIONS` on a
/// note costs.
///
/// Unlike [`read`] it does **not** check Read, and it does not refuse: it
/// reports, and the caller decides. `pod::options` refuses a caller holding no
/// mode at all (5b, H4), which is what keeps this from becoming an existence
/// oracle. Collapsing the two here would make "you may create here" and "this
/// already exists" the same answer, and `OPTIONS` needs to tell them apart.
pub fn describe(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
) -> Result<Description, LdpError> {
    pod.read(|r| Ok(describe_in(r, base, path, subject)))?
}

/// [`describe`] against a snapshot the caller already holds.
pub fn describe_in(
    r: &impl PodRead,
    base: &str,
    path: &str,
    subject: &Subject,
) -> Result<Description, LdpError> {
    let resource = format!("{base}{path}");
    Ok(Description {
        meta: r.meta(&resource)?,
        granted: granted_modes(r, base, path, subject),
        // Inside the snapshot, against the ACL `granted` just resolved, so the
        // two can never describe different states of the pod.
        public: granted_modes(r, base, path, &Subject::anonymous()),
    })
}

/// `GET` / `HEAD` an LDP resource, from one snapshot.
///
/// A caller without Read gets [`LdpError::Denied`], not `NotFound`: telling
/// them the resource exists would be a disclosure, and so would telling them
/// it doesn't. `pod.rs` answers both with the same status for the same caller,
/// so the two are indistinguishable from outside (spec 5b, H1).
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
        return Err(LdpError::Denied);
    }
    // One description, from this snapshot, carried out on the outcome. The
    // Read check stays separate: it propagates a broken ACL as a store error,
    // where `granted_modes` reports an empty set, and a pod that can't be
    // evaluated must not look like a pod that denies.
    let description = describe_in(r, base, path, subject)?;
    let Some(meta) = description.meta.clone() else {
        return Err(LdpError::NotFound);
    };
    // The validators come from this snapshot's metadata, the one the body is
    // read from, so an `ETag` always describes the bytes it goes out with.
    let version = meta.version.clone();
    let modified = meta.modified.clone();

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
            syntax: conditional::BINARY,
            description,
            version,
            modified,
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
        syntax: conditional::token(format),
        description,
        version,
        modified,
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
    ///   so a caller who may not write leaves nothing in the blob store and
    ///   gets `Denied` whatever the body's type. `put_in`/`append_in` check
    ///   again inside the transaction.
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
            return Err(LdpError::Denied);
        }
        prepare(blobs, body, content_type)
    }
}

/// `PUT` — create or replace a resource.
///
/// Requires Write. Replacing is not Append: a client that may only add triples
/// must not be able to erase the ones already there.
///
/// `preconditions` is evaluated in [`put_in`], after the WAC check and before
/// anything is written.
// One over `clippy.toml`'s threshold. `put` keeps the old eight for every
// caller that isn't HTTP; folding the request into a struct is 5b's
// HTTP-surface work.
#[allow(clippy::too_many_arguments)]
pub fn put_if(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
    preconditions: &Preconditions,
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
        let written = in_write(pod, |w| {
            put_in(w, base, path, subject, &body, storage_root, preconditions)
        });
        release_refused_bytes(pod, &body, &written);
        written
    };
    // Identical bytes released by a concurrent delete between `prepare` and
    // the write: write them again and retry, once (spec 5a, R12).
    match attempt() {
        Err(LdpError::BlobMissing) => attempt(),
        other => other,
    }
}

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

/// Give back the bytes a refused binary write left in the blob store.
///
/// [`prepare`] writes a binary body before the lock is taken, and a failed
/// precondition then records no digest, so the file would sit there
/// unreferenced. Under the lock, `release_blob` deletes it only if nothing
/// references it: bytes identical to a live resource (this one's own, sent
/// with a stale tag, say) survive, and a concurrent upload of the same bytes
/// either committed first or gets `BlobMissing` and writes them again (R12).
/// A failure here leaves an orphan file, not a wrong answer, so the 412 still
/// stands.
fn release_refused_bytes<T>(pod: &Pod, body: &Body, written: &Result<T, LdpError>) {
    let (Err(LdpError::PreconditionFailed), Body::Binary(blob)) = (written, body) else {
        return;
    };
    let _swept: Result<(), StoreError> = pod.write(|w| {
        w.release_blob(&blob.digest);
        Ok(())
    });
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
///
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the resource, so no other write
/// can land between the check and this one. Pass `Preconditions::NONE` when not
/// answering an HTTP request.
pub fn put_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &Body,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<(), LdpError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Denied);
    }
    let current = w.meta(&resource)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Put, current.as_deref())?;

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
///
/// `preconditions` is evaluated in [`append_in`], after the WAC check and
/// before anything is written. It is about the container posted to (or the
/// document appended to), not the member a POST mints.
// One over `clippy.toml`'s threshold. `append` keeps the old eight for every
// caller that isn't HTTP; folding the request into a struct is 5b's
// HTTP-surface work.
#[allow(clippy::too_many_arguments)]
pub fn append_if(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
    preconditions: &Preconditions,
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
        let written = in_write(pod, |w| {
            append_in(w, base, path, subject, &body, storage_root, preconditions)
        });
        release_refused_bytes(pod, &body, &written);
        written
    };
    match attempt() {
        Err(LdpError::BlobMissing) => attempt(),
        other => other,
    }
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

/// [`append`] inside the caller's write.
///
/// POST to a container is a `put` of the minted member. POST to a document is
/// stage 0's append, unchanged until 5c, and takes RDF only.
///
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the target, so no other write
/// can land between the check and this one. Pass `Preconditions::NONE` when not
/// answering an HTTP request.
pub fn append_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &Body,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<String, LdpError> {
    let target = format!("{base}{path}");
    if !target.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Append)? {
        return Err(LdpError::Denied);
    }
    // A POST's precondition is about the container (or the document appended
    // to), which is what the client addressed and holds a tag for.
    let current = w.meta(&target)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Post, current.as_deref())?;

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
///
/// `preconditions` is evaluated in [`delete_in`], after the WAC and not-found
/// checks and before anything is removed.
pub fn delete_if(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<(), LdpError> {
    in_write(pod, |w| {
        delete_in(w, base, path, subject, storage_root, preconditions)
    })
}

/// [`delete_if`] with no preconditions.
pub fn delete(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
    storage_root: &str,
) -> Result<(), LdpError> {
    delete_if(pod, base, path, subject, storage_root, &Preconditions::NONE)
}

/// [`delete`] inside the caller's write.
///
/// `remove` takes the resource's `.acl` with it (Solid Protocol §5.4), so a
/// recreated resource can't quietly get its old grants back, and releases its
/// blob. Content addressing means two resources can name one blob, which is
/// why the blob is released rather than deleted here.
///
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the resource, so no other write
/// can land between the check and this one. It comes after the not-found
/// check: a DELETE of a missing resource is 404 whatever its preconditions
/// (RFC 9110 §13.2.1). Pass `Preconditions::NONE` when not answering an HTTP
/// request.
pub fn delete_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<(), LdpError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Denied);
    }
    let Some(meta) = w.meta(&resource)? else {
        return Err(LdpError::NotFound);
    };
    preconditions.check_write(conditional::Method::Delete, Some(meta.version.as_str()))?;
    // Without its root a pod has nowhere to put anything, and only
    // provisioning records one. `pod.rs` answers 405 (§5.4).
    if resource == storage_root {
        return Err(LdpError::Undeletable);
    }
    // The root's ACL is undeletable too (§5.4). Deleting an ACL is how a
    // resource falls back to its container's rules (WAC §3.2), and the root
    // has no container: the pod would be left with no rule anywhere, and only
    // provisioning writes one. Only this ACL. Every other `.acl` may be
    // deleted by a caller with Control, because that is how a member un-shares.
    if resource == acl_iri(storage_root) {
        return Err(LdpError::Undeletable);
    }
    // Refusing to delete a non-empty container is LDP's rule, and it is the
    // difference between removing a resource and silently orphaning a subtree.
    // Chunk 5 answers 409 with the body §5.4 requires.
    if matches!(meta.kind, Kind::Container) && !w.members(&resource)?.is_empty() {
        return Err(LdpError::NotEmpty);
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

/// `PATCH`: WAC, the preconditions, the patch, and the write, in one
/// transaction.
pub fn patch_if(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
    body: PatchBody<'_>,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<(), PatchError> {
    in_write(pod, |w| {
        patch_in(w, base, path, subject, body, storage_root, preconditions)
    })
}

/// [`patch_if`] with no preconditions.
pub fn patch(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
    body: PatchBody<'_>,
    storage_root: &str,
) -> Result<(), PatchError> {
    patch_if(
        pod,
        base,
        path,
        subject,
        body,
        storage_root,
        &Preconditions::NONE,
    )
}

/// [`patch`] inside the caller's write. A patch mutates, so it needs Write
/// (Control, on an ACL). A binary has no triples to patch.
///
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the resource, so no other write
/// can land between the check and this one. Pass `Preconditions::NONE` when not
/// answering an HTTP request.
pub fn patch_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: PatchBody<'_>,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<(), PatchError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(PatchError::Ldp(LdpError::OutsideStorage));
    }
    if !check(&*w, base, path, subject, AccessMode::Write).map_err(PatchError::Ldp)? {
        return Err(PatchError::Ldp(LdpError::Denied));
    }
    let current = w.meta(&resource)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Patch, current.as_deref())?;
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

/// The media types a write body may carry: `Accept-Post`, `Accept-Put` and,
/// for a container or an ACL, the only types a `PUT` to it will be accepted
/// in. What the parser takes, which is deliberately narrower than what
/// `syntax::negotiate` serves — RDF/XML is served and never parsed (ADR 0007).
pub fn accepted_write_types() -> &'static str {
    "text/turtle, application/n-triples, application/n-quads, application/trig, application/ld+json"
}

#[cfg(test)]
mod tests {
    use super::{acl_iri, governed};

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

    /// H7's first case. The failure this guards is `pod.rs`'s concatenation:
    /// a GET of `/~/x.acl` advertised `</~/x.acl.acl>; rel="acl"`, an IRI no
    /// ACL governs and that a client following the link would create as an
    /// ordinary document.
    #[test]
    fn an_acl_is_its_own_acl() {
        assert_eq!(acl_iri("/~/x.acl"), "/~/x.acl");
        assert_eq!(acl_iri("/~/notes/.acl"), "/~/notes/.acl");
        // Including the fiction itself, if one ever gets written.
        assert_eq!(acl_iri("/~/x.acl.acl"), "/~/x.acl.acl");
    }

    /// A container's ACL lives *inside* it and a document's beside it. Both
    /// are `{target}.acl`, and they agree with `authz::acl_candidates`' first
    /// candidate — which is the resource WAC will actually read.
    #[test]
    fn a_containers_acl_is_inside_it_and_a_documents_is_beside_it() {
        assert_eq!(acl_iri("/~/notes/"), "/~/notes/.acl");
        assert_eq!(acl_iri("/~/notes/first"), "/~/notes/first.acl");
        assert_eq!(
            acl_iri("https://alice.brolly.id/~/"),
            "https://alice.brolly.id/~/.acl"
        );
    }

    /// `acl_iri` is not [`governed`] run backwards, and the two answer
    /// different questions: `governed` asks whose `Control` guards this,
    /// `acl_iri` asks which IRI holds the rules. Collapsing them is how the
    /// `.acl.acl` link got written in the first place.
    #[test]
    fn acl_iri_is_not_the_inverse_of_governed() {
        assert_eq!(governed("/~/x.acl.acl"), Some("/~/x"));
        assert_eq!(acl_iri("/~/x.acl.acl"), "/~/x.acl.acl");
        assert_eq!(acl_iri(governed("/~/x.acl").unwrap()), "/~/x.acl");
    }
}
