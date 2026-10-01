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

use std::collections::{BTreeMap, BTreeSet};

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
    /// A write named one of the server-managed statements a container's
    /// listing carries about a contained resource — `dcterms:modified`,
    /// `stat:mtime` or `stat:size` — with a value other than the one we serve
    /// (409, Solid Protocol §4.2.1). An exact echo is dropped instead, so a
    /// read-modify-write of a container still works.
    MemberMetadata,
    /// The storage root or the root's own ACL: the two resources Solid
    /// Protocol §5.4 says a server must refuse to delete. `pod.rs` answers it
    /// 405 with the caller's `Allow`.
    Undeletable,
    /// A `DELETE` of a container that still has members (409, Solid Protocol
    /// §5.4). Not "you may not" — "not while it has members": the caller may
    /// delete this container once it is empty, and the body says so.
    NotEmpty,
    /// A binary's bytes vanished between `prepare` and the write: a
    /// concurrent delete released identical bytes. Prepare again and retry
    /// once (spec 5a, R12).
    BlobMissing,
    /// An `If-Match` or `If-None-Match` didn't hold (412). Evaluated after WAC,
    /// so only a caller holding the needed mode can see it.
    PreconditionFailed,
    /// A POST to a target whose IRI does not end in `/` (405, spec 5c H3).
    /// POST is a container method; the non-standard append to a document is
    /// gone, and the insertion it performed is a `PATCH` with `INSERT`.
    /// Produced after the WAC check, so a caller with no mode at all still
    /// sees [`LdpError::Denied`], and before any `Slug` or `Link` validation —
    /// the method is wrong for the target whatever the headers say.
    NotAPostTarget,
    /// A `Slug` that cannot be made one safe path segment (400, spec 5c H1):
    /// it spans segments, names a query or fragment, carries control bytes,
    /// is `.` or `..`, is over the 128-byte cap, or ends in an auxiliary
    /// suffix, `.acl` or `.meta` (spec 5d, H4). The body names the offending
    /// slug and the rule it broke, because a silent UUID would leave the
    /// client building links to a name it was never given.
    InvalidSlug(String),
    /// A `PUT` whose body would change an existing resource's kind (422, spec
    /// 5c H8): RDF over a [`Kind::NonRdfSource`], or a binary over an RDF
    /// resource. Not [`LdpError::NotRdf`]: the media type is one this target's
    /// IRI accepts — a document-shaped IRI takes either — and what the request
    /// asks for is impossible only because of what is already there. Carries
    /// the recorded kind and the incoming media type, which the 422's body
    /// names. Produced after the WAC check, so only a caller holding Write
    /// learns the kind.
    KindChange {
        recorded: Kind,
        incoming: String,
    },
}

/// The LDP class a recorded kind is served as, for a refusal's body.
fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Container => "ldp:BasicContainer",
        Kind::RdfSource => "ldp:RDFSource",
        Kind::NonRdfSource => "ldp:NonRDFSource",
        Kind::Auxiliary => "auxiliary resource",
    }
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
            LdpError::MemberMetadata => write!(
                f,
                "a contained resource's modified time and size are the server's; \
                 re-read this container and send its current description"
            ),
            LdpError::Undeletable => write!(f, "this resource cannot be deleted"),
            LdpError::NotEmpty => write!(
                f,
                "this container still has members; delete them first, \
                 then re-read the container and retry"
            ),
            LdpError::BlobMissing => write!(f, "the blob was released before it was recorded"),
            LdpError::PreconditionFailed => write!(f, "precondition failed"),
            LdpError::NotAPostTarget => write!(
                f,
                "POST is a container method; this target does not end in `/`"
            ),
            LdpError::InvalidSlug(rule) => write!(f, "{rule}"),
            LdpError::KindChange { recorded, incoming } => write!(
                f,
                "a PUT cannot change a resource's kind: this one is recorded as \
                 {} and the body is {incoming}; delete it first to store the other kind",
                kind_name(*recorded)
            ),
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
            // Solid Protocol §5.4. `delete_in` refuses first, so this is the
            // same refusal reached by a caller composing its own transaction.
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

/// What a `PUT` did. LDP answers 201 for one and 204 for the other, and a
/// client that creates with `If-None-Match: *` branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    Created,
    Replaced,
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
///
/// `/~/x.acl.acl` is itself a fiction now, not a reachable resource: under
/// spec 5d, H1 a path ending in two auxiliary suffixes is answered 404 before
/// authorization, with the store's double-suffix refusal under it. The strip
/// stays as it is — a caller that skips the gate still gets a guard keyed to
/// Control on the thing at the bottom of the chain.
pub fn governed(path: &str) -> Option<&str> {
    let mut resource = path.strip_suffix(".acl")?;
    while let Some(shorter) = resource.strip_suffix(".acl") {
        resource = shorter;
    }
    Some(resource)
}

/// The resource a `.meta` resource describes, or `None` if `path` is not one.
///
/// Strips exactly one trailing `.meta` — a sibling of [`governed`]'s rule,
/// never composed with it (spec 5d, H2): a `.meta` is authorized by the same
/// mode on the resource it describes, not by `acl:Control`, so folding it
/// into `governed` would send `.meta` targets down the `Control` arm. A path
/// ending in both suffixes is a fiction answered 404 before authorization
/// (H1), so the two rules never meet on a target that can exist. Only the
/// suffix is examined, so this works on a full IRI as well as on a path.
pub fn describes(path: &str) -> Option<&str> {
    path.strip_suffix(".meta")
}

/// Is `resource` an auxiliary — an `.acl` or a `.meta` (spec 5d, H1)?
///
/// The boolean question behind [`governed`] and [`describes`], which answer
/// separately because the rule that authorizes the target differs —
/// `acl:Control` on the governed resource, the same mode on the described
/// one — while what follows from being an auxiliary at all does not: an
/// RDF-only body, `Content::Auxiliary`, and containment's refusal to list it.
pub fn is_auxiliary(resource: &str) -> bool {
    resource.ends_with(".acl") || resource.ends_with(".meta")
}

/// Is `resource` an auxiliary of an auxiliary (spec 5d, H1)?
///
/// Such an IRI — `.acl.acl`, `.acl.meta`, `.meta.acl`, `.meta.meta` — is a
/// fiction: the resource can never exist, so every method answers 404,
/// decided by the IRI's shape before any lookup and deliberately before WAC
/// — the shape is syntactic public knowledge, so there is no existence to
/// protect (5b H1's auth-before-target rule protects *lookups*, and no
/// lookup happens). `pod.rs`'s request gate answers it; the store's
/// double-suffix refusal is the defence in depth under it, for callers that
/// skip the gate. Only the suffix is examined, so this works on a full IRI
/// as well as on a path.
pub fn is_double_auxiliary(resource: &str) -> bool {
    let Some(stem) = resource
        .strip_suffix(".acl")
        .or_else(|| resource.strip_suffix(".meta"))
    else {
        return false;
    };
    stem.ends_with(".acl") || stem.ends_with(".meta")
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

/// The IRI of the `.meta` describing `target` (spec 5d, H1).
///
/// Always `format!("{target}.meta")`, which is [`acl_iri`]'s placement rule:
/// beside a document (`/~/note` → `/~/note.meta`), inside a container
/// (`/~/notes/` → `/~/notes/.meta`, since the IRI already ends in `/`).
///
/// No `acl_iri`-style special case for an auxiliary target: a `.meta`'s own
/// Link set announces its subject, not a description of itself (H3 omits
/// `describedby` on auxiliaries), so this is asked only about ordinary
/// resources — the client needs the IRI to create the description.
pub fn meta_iri(target: &str) -> String {
    format!("{target}.meta")
}

/// Resolve and evaluate the ACL governing `resource`.
///
/// An ACL resource is the exception (stage 0, A2). Whatever mode is asked for,
/// it needs `acl:Control` on the resource it [`governed`]s, from that
/// resource's own ACL or an ancestor's `acl:default`. Without this, a caller
/// with inherited Write could rewrite the ACL above them and grant themselves
/// anything, and one with inherited Read could list who else has access.
///
/// A `.meta` resource is the second exception (spec 5d, H2): whatever mode is
/// asked for, it is asked of the resource it [`describes`]s. Read on the
/// subject reads its `.meta`, Write on the subject writes and deletes it, and
/// Append alone does not — appending is not describing. A description is as
/// private as what it describes: no more (the `Control` wall is for policy,
/// not prose) and no less.
fn check(
    store: &impl PodRead,
    base: &str,
    path: &str,
    subject: &Subject,
    mode: AccessMode,
) -> Result<bool, LdpError> {
    // Two remaps, never composed (spec 5d, H2): a path ending in both
    // suffixes is answered 404 before authorization (H1), so the arms never
    // meet on a target that can exist.
    let (path, mode) = if let Some(resource) = governed(path) {
        (resource, AccessMode::Control)
    } else if let Some(resource) = describes(path) {
        (resource, mode)
    } else {
        (path, mode)
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
///
/// On a `.meta` it is the modes on the resource described (spec 5d, H2),
/// which is also the truthful answer for the `.meta` itself: it is
/// authorized by exactly those modes.
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

    // H2 (spec 5d): a `.meta`'s modes are its subject's.
    let path = describes(path).unwrap_or(path);

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

impl Body {
    /// The media type this body arrived as, parameters stripped.
    fn media_type(&self) -> &str {
        match self {
            Body::Rdf { format, .. } => format.media_type(),
            Body::Binary(blob) => &blob.media_type,
        }
    }
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
    /// - `rdf_only` targets (a container or an auxiliary for PUT, a document
    ///   for POST) refuse a binary body here, before its bytes reach the disk.
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
) -> Result<Written, LdpError> {
    let resource = format!("{base}{path}");
    // H4 (spec 5d): an auxiliary — an `.acl` or a `.meta` — joins containers
    // as an RDF-only target.
    let rdf_only = storage::is_container(&resource) || is_auxiliary(&resource);
    let target = Target {
        pod,
        base,
        path,
        subject,
        storage_root,
    };
    let attempt = || -> Result<Written, LdpError> {
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
) -> Result<Written, LdpError> {
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
/// precondition or a refused kind change (spec 5c, H8) then records no digest,
/// so the file would sit there unreferenced. Under the lock, `release_blob`
/// deletes it only if nothing
/// references it: bytes identical to a live resource (this one's own, sent
/// with a stale tag, say) survive, and a concurrent upload of the same bytes
/// either committed first or gets `BlobMissing` and writes them again (R12).
/// A failure here leaves an orphan file, not a wrong answer, so the 412 or
/// 422 still stands.
fn release_refused_bytes<T>(pod: &Pod, body: &Body, written: &Result<T, LdpError>) {
    let (Err(LdpError::PreconditionFailed | LdpError::KindChange { .. }), Body::Binary(blob)) =
        (written, body)
    else {
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
/// - an auxiliary — an ACL or a `.meta`: `Content::Auxiliary`, RDF only (the
///   authorization remaps are in `check`, stage 0's A2 and spec 5d's H2);
/// - a container (the path ends in `/`): RDF only, under [`container_body`]'s
///   rule, as `Content::Container`; its members are untouched;
/// - a document: `Content::Rdf`, stored exactly as sent;
/// - a binary: `Content::Binary`, then the previous blob, if any, is released.
///
/// The last two replace only their own kind (spec 5c, H8): RDF over an
/// existing binary, or a binary over an existing RDF resource, is
/// [`LdpError::KindChange`] and the old representation stays as it was. A
/// binary addressed to a container or an auxiliary is still [`LdpError::NotRdf`],
/// because those targets never take one whatever is there. Replacing a binary
/// with new bytes is the same kind and unaffected; the description triples
/// live in its `.meta` now (spec 5d, H6), so they survive the replacement.
///
/// Every refusal comes before the first write.
///
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the resource, so no other write
/// can land between the check and this one. Pass `Preconditions::NONE` when not
/// answering an HTTP request.
///
/// Answers [`Written::Created`] when the target had no metadata before this
/// write and [`Written::Replaced`] when it did, from the same read the
/// precondition uses. A container this write created on the way to the target
/// is not the target: only the resource addressed decides.
pub fn put_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &Body,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<Written, LdpError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Write)? {
        return Err(LdpError::Denied);
    }
    let current = w.meta(&resource)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Put, current.as_deref())?;
    // The same read the precondition used, so nothing can land between them.
    let written = match current {
        Some(_) => Written::Replaced,
        None => Written::Created,
    };

    if is_auxiliary(&resource) {
        let quads = rdf_quads(body, &resource)?;
        w.put(&resource, Content::Auxiliary(&quads))?;
        return Ok(written);
    }
    if storage::is_container(&resource) {
        let quads = rdf_quads(body, &resource)?;
        let kept = container_body(&*w, &resource, quads)?;
        w.put(&resource, Content::Container(&kept))?;
        return Ok(written);
    }

    let recorded = w.meta(&resource)?;
    // H8: a document-shaped IRI takes RDF or a binary, but not one over the
    // other. After WAC, so the kind is told only to a caller who may write
    // here, and after the precondition, like every refusal that depends on
    // what is stored.
    if let Some(meta) = &recorded
        && matches!(meta.kind, Kind::NonRdfSource) == matches!(body, Body::Rdf { .. })
    {
        return Err(LdpError::KindChange {
            recorded: meta.kind,
            incoming: body.media_type().to_string(),
        });
    }
    let previous = recorded.and_then(|meta| meta.blob).map(|blob| blob.digest);
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
    Ok(written)
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
/// - **A member's server-managed metadata** — `dcterms:modified`, `stat:mtime`
///   and `stat:size` on a contained resource (§4.2.1) — is dropped when its
///   value equals what we would serve and `MemberMetadata` when it differs or
///   won't parse. Per statement, and by value: `1790000000` and
///   `"1790000000"^^xsd:integer` are one number, and a timestamp a client
///   round-tripped through JSON-LD may be spelled a third way. Without the echo
///   tolerance every read-modify-write of a container would 409.
///   `rdf:type` is **not** on the list, because we don't serve it; nor is any
///   other predicate on a member, nor any of the three on a subject that isn't
///   a member. Both stay ordinary content.
/// - **The rest** is kept.
fn container_body(
    r: &impl PodRead,
    container: &str,
    quads: Vec<Quad>,
) -> Result<Vec<Quad>, LdpError> {
    let node = NamedOrBlankNode::NamedNode(iri(container));
    // What a GET serves from metadata: the types, the listing, and each
    // member's metadata. One read, shared by the rules below, so the check
    // cannot disagree with what a GET would say.
    let served = resources::container_triples(r, container)?;
    let members: BTreeSet<String> = served
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::LDP_CONTAINS)
        .map(|q| q.object.to_string())
        .collect();
    let member_iris: BTreeSet<&str> = served
        .iter()
        .filter(|q| q.predicate.as_str() == vocab::LDP_CONTAINS)
        .filter_map(|q| match &q.object {
            Term::NamedNode(member) => Some(member.as_str()),
            _ => None,
        })
        .collect();
    // (member, predicate) -> the value we serve, reduced the same way the
    // client's will be.
    let mut ours: BTreeMap<(&str, &str), i64> = BTreeMap::new();
    for quad in &served {
        let Some(subject) = subject_iri(&quad.subject) else {
            continue;
        };
        let predicate = quad.predicate.as_str();
        if member_iris.contains(subject)
            && let Some(value) = member_value(predicate, &quad.object)
        {
            ours.insert((subject, predicate), value);
        }
    }
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
        if echoed {
            continue;
        }
        // §4.2.1: a member's metadata is ours. An exact echo is not an update.
        let predicate = quad.predicate.as_str();
        if MANAGED_MEMBER_PREDICATES.contains(&predicate)
            && let Some(subject) = subject_iri(&quad.subject)
            && member_iris.contains(subject)
        {
            let sent = member_value(predicate, &quad.object);
            let mine = ours.get(&(subject, predicate)).copied();
            if sent.is_some() && sent == mine {
                continue;
            }
            return Err(LdpError::MemberMetadata);
        }
        kept.push(quad);
    }
    if !named.is_empty() && named != members {
        return Err(LdpError::ContainmentChange);
    }
    Ok(kept)
}

/// The statements a container's listing makes about each member, which §4.2.1
/// forbids a client to change. `rdf:type` is absent deliberately: we serve none
/// for a member, so a client naming one isn't echoing us.
const MANAGED_MEMBER_PREDICATES: [&str; 3] =
    [vocab::DCTERMS_MODIFIED, vocab::STAT_MTIME, vocab::STAT_SIZE];

fn subject_iri(subject: &NamedOrBlankNode) -> Option<&str> {
    match subject {
        NamedOrBlankNode::NamedNode(node) => Some(node.as_str()),
        NamedOrBlankNode::BlankNode(_) => None,
    }
}

/// One of [`MANAGED_MEMBER_PREDICATES`] reduced to a number, so two spellings
/// of one value compare equal.
///
/// `dcterms:modified` becomes milliseconds since the epoch through `store`'s
/// own parser — the same one `meta()` normalises through, and the only RFC 3339
/// parser this workspace has (`brolly-solid`'s `time` has `formatting` but not
/// `parsing`). The two `stat:` terms are integers. Every comparison is between
/// two values of the *same* predicate, so both sides are always reduced the
/// same way. `None` means "not a value we can compare", which the caller treats
/// as a change rather than an echo: failing closed refuses a body we couldn't
/// check, and the client re-reads.
fn member_value(predicate: &str, object: &Term) -> Option<i64> {
    let Term::Literal(literal) = object else {
        return None;
    };
    let text = literal.value().trim();
    match predicate {
        vocab::DCTERMS_MODIFIED => resources::modified_ms(text),
        vocab::STAT_MTIME | vocab::STAT_SIZE => text.parse().ok(),
        _ => None,
    }
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
pub(crate) fn in_write<T, E: From<StoreError>>(
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
pub(crate) fn refuse_rdf_xml(content_type: &str) -> Result<(), LdpError> {
    match syntax::read_format(content_type) {
        Err(e @ SyntaxError::RdfXmlNotAccepted) => Err(LdpError::Syntax(e)),
        _ => Ok(()),
    }
}

/// What a POST's `Link rel="type"` asked the minted member to be (spec 5c,
/// H2). The one creation fact a body cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedKind {
    /// `rel="type"` naming `ldp:BasicContainer` or `ldp:Container`: the
    /// member is a container whatever the body's content type says, its IRI
    /// ends in `/`, and its content goes through `Content::Container`, so the
    /// containment protections apply to it from birth.
    Container,
    /// Nothing asked: the body's content type decides document or binary,
    /// as it always has.
    Auto,
}

/// What a POST minted (spec 5c, H4): the member's IRI, and its kind, so the
/// 201 can carry the same `Link` set a creating `PUT` sends — a client that
/// just made a container learns its ACL IRI in the same response that minted
/// it, without a second request.
#[derive(Debug, Clone)]
pub struct Minted {
    /// The minted member's full IRI: the `Location` the 201 answers with.
    pub member: String,
    /// What was minted, for the 201's `Link rel="type"`.
    pub kind: Kind,
}

/// `POST` — create a member of a container (spec 5c, H1–H4).
///
/// Requires Append, which Write satisfies (`acl:Write` implies `acl:Append`).
/// The member's name is the sanitized `Slug` when there is one that can be
/// made a safe segment, disambiguated on collision, and a UUID otherwise.
/// `requested` says whether the `Link rel="type"` header asked for a
/// container. A document-shaped target is [`LdpError::NotAPostTarget`].
///
/// `preconditions` is evaluated in [`append_in`], after the WAC check and
/// before anything is written. It is about the container posted to, not the
/// member a POST mints.
// Two over `clippy.toml`'s threshold. `append` keeps the old eight for every
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
    slug: Option<&str>,
    requested: RequestedKind,
) -> Result<Minted, LdpError> {
    let target = Target {
        pod,
        base,
        path,
        subject,
        storage_root,
    };
    let attempt = || -> Result<Minted, LdpError> {
        // A container-typed POST takes RDF or empty (H2); a plain POST to a
        // container may mint a binary member, as it always has. A
        // document-shaped target is prepared not at all: `append_in` refuses
        // it (H3) before it reads `body`, so nothing about the body decides
        // anything and no blob bytes reach the disk for a request that cannot
        // land. The empty Turtle body stands in for the body that is never
        // looked at.
        let body = if storage::is_container(&format!("{base}{path}")) {
            target.prepare(
                blobs,
                requested == RequestedKind::Container,
                AccessMode::Append,
                body,
                content_type,
            )?
        } else {
            Body::Rdf {
                bytes: Vec::new(),
                format: ReadFormat::Turtle,
            }
        };
        let written = in_write(pod, |w| {
            append_in(
                w,
                base,
                path,
                subject,
                &body,
                storage_root,
                preconditions,
                slug,
                requested,
            )
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
#[allow(clippy::too_many_arguments)]
pub fn append(
    pod: &Pod,
    blobs: Option<&BlobStore>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &[u8],
    content_type: &str,
    storage_root: &str,
    slug: Option<&str>,
    requested: RequestedKind,
) -> Result<Minted, LdpError> {
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
        slug,
        requested,
    )
}

/// [`append`] inside the caller's write.
///
/// POST to a container is a `put` of the minted member: RDF or binary by the
/// body, a container when `requested` says the `Link rel="type"` header asked
/// for one (spec 5c, H2). POST to a document-shaped target is
/// [`LdpError::NotAPostTarget`] (H3): POST is a container method, and the
/// insertion it used to perform is a `PATCH` with `INSERT`.
///
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the target, so no other write
/// can land between the check and this one. Pass `Preconditions::NONE` when not
/// answering an HTTP request.
// One over `clippy.toml`'s threshold, like `append_if` above it.
#[allow(clippy::too_many_arguments)]
pub fn append_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: &Body,
    storage_root: &str,
    preconditions: &Preconditions,
    slug: Option<&str>,
    requested: RequestedKind,
) -> Result<Minted, LdpError> {
    let target = format!("{base}{path}");
    if !target.starts_with(storage_root) {
        return Err(LdpError::OutsideStorage);
    }
    if !check(&*w, base, path, subject, AccessMode::Append)? {
        return Err(LdpError::Denied);
    }
    // H3: the refusal comes after the WAC check — a caller with no mode at
    // all still sees `Denied` — and before any `Slug` or `Link` validation:
    // the method is wrong for the target whatever the headers say. It leaks
    // nothing an `OPTIONS` would not; the target's kind is decided by the
    // IRI's shape.
    if !storage::is_container(&target) {
        return Err(LdpError::NotAPostTarget);
    }
    // H1: the slug is sanitized (or refused) before the preconditions run,
    // and the preconditions before anything is written. A POST's precondition
    // is about the container, which is what the client addressed and holds a
    // tag for.
    let slug = sanitize_slug(slug)?;
    let current = w.meta(&target)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Post, current.as_deref())?;

    // The member's name: the sanitized slug, disambiguated against what
    // already exists (H1), or a UUID when the client asked for none.
    let member = match slug {
        Some(slug) => disambiguate(&*w, &target, &slug, requested)?,
        None => match requested {
            RequestedKind::Container => format!("{target}{}/", uuid::Uuid::new_v4()),
            RequestedKind::Auto => format!("{target}{}", uuid::Uuid::new_v4()),
        },
    };

    match requested {
        // H2: the content goes through `Content::Container`, so
        // `container_body`'s containment protections apply to it from birth.
        // A binary body never gets this far: `prepare` refused it with the
        // existing `NotRdf` 415.
        RequestedKind::Container => {
            let quads = rdf_quads(body, &member)?;
            let kept = container_body(&*w, &member, quads)?;
            w.put(&member, Content::Container(&kept))?;
            Ok(Minted {
                member,
                kind: Kind::Container,
            })
        }
        RequestedKind::Auto => match body {
            Body::Rdf { .. } => {
                let quads = rdf_quads(body, &member)?;
                w.put(&member, Content::Rdf(&quads))?;
                Ok(Minted {
                    member,
                    kind: Kind::RdfSource,
                })
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
                Ok(Minted {
                    member,
                    kind: Kind::NonRdfSource,
                })
            }
        },
    }
}

/// Sanitize a POST's `Slug` into one safe path segment (spec 5c, H1).
///
/// `None` in, `None` out: no slug, an empty one, or one that is only
/// whitespace mints a UUID, as it always has. A slug that cannot be made a
/// segment — it spans segments, names a query or fragment, carries control
/// is `.` or `..`, is over the 128-byte cap, or ends in an auxiliary suffix
/// — `.acl` or `.meta` (spec 5d, H4) — is a
/// 400 naming the slug and the rule, because a silent UUID would leave the
/// client building links to a name it was never given. What survives is the
/// slug's raw bytes percent-encoded into a segment: bytes outside RFC 3986
/// unreserved are encoded, `%` included (`%` → `%25`), so `Slug: a%20b` yields
/// `a%2520b` — lossless, and unambiguous where passing the `%` through would
/// not be. The slug is a *hint* (LDP §4.2.3 makes the server's naming final),
/// but a representable one.
fn sanitize_slug(slug: Option<&str>) -> Result<Option<String>, LdpError> {
    let Some(slug) = slug.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let refuse = |rule: &str| {
        LdpError::InvalidSlug(format!("the Slug header must be one path segment; {rule}"))
    };
    if slug == "." || slug == ".." {
        return Err(refuse(&format!(
            "`{slug}` is a dot segment, not a name; a client resolving it would walk out of the pod or normalize it away"
        )));
    }
    if slug.len() > 128 {
        return Err(refuse(&format!(
            "`{}` is {} bytes; the cap is 128",
            slug.chars().take(48).collect::<String>(),
            slug.len()
        )));
    }
    if slug.ends_with(".acl") || slug.ends_with(".meta") {
        return Err(refuse(&format!(
            "`{slug}` ends in an auxiliary suffix; an auxiliary is written by PUT under the check its own rule demands — `acl:Control` for an `.acl`, Write on what it describes for a `.meta` — and a POST's Append is neither"
        )));
    }
    if slug
        .as_bytes()
        .iter()
        .any(|&b| b == b'/' || b == b'?' || b == b'#' || b.is_ascii_control())
    {
        return Err(refuse(&format!(
            "`{}` carries a `/`, `?`, `#`, or control byte, and so names more than one segment or no segment at all",
            slug.chars().take(48).collect::<String>()
        )));
    }
    Ok(Some(encode_segment(slug)))
}

/// Encode raw slug bytes as one RFC 3986 path segment: unreserved bytes pass
/// through, everything else — `%` included — is percent-encoded.
fn encode_segment(slug: &str) -> String {
    let mut out = String::with_capacity(slug.len());
    for &b in slug.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// The member IRI for a sanitized `slug`: `{container}{slug}`, or — when that
/// IRI is taken — `{container}{stem}-N{ext}` with the `-N` before any
/// extension (spec 5c, H1), the disambiguation CSS implements and
/// `solid-client` depends on. A 409 would make the common
/// create-with-preferred-name flow a retry loop.
fn disambiguate(
    r: &impl PodRead,
    container: &str,
    slug: &str,
    requested: RequestedKind,
) -> Result<String, LdpError> {
    // `note.ttl` → stem `note`, extension `.ttl`; a slug that is all
    // extension (`.hidden`) or has none keeps its whole self as the stem.
    let (stem, ext) = match slug.rfind('.') {
        Some(0) | None => (slug, ""),
        Some(i) => slug.split_at(i),
    };
    for n in 0u32.. {
        let name = match n {
            0 => slug.to_string(),
            _ => format!("{stem}-{n}{ext}"),
        };
        let member = match requested {
            RequestedKind::Container => format!("{container}{name}/"),
            RequestedKind::Auto => format!("{container}{name}"),
        };
        if r.meta(&member)?.is_none() {
            return Ok(member);
        }
    }
    Err(LdpError::Store(
        "no free member IRI in this container".into(),
    ))
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
/// `remove` takes the resource's `.acl` and `.meta` with it (Solid Protocol
/// §5.4), so a recreated resource can't quietly get its old grants or its old
/// description back, and releases its blob. Content addressing means two
/// resources can name one blob, which is why the blob is released rather than
/// deleted here.
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
    // 409, not 403: the caller holds Write, and emptying it is the way through.
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
/// transaction. Answers [`Written`] so a patch that creates (spec 5c, H4) can
/// answer 201 where one that modifies stays 204.
pub fn patch_if(
    pod: &Pod,
    base: &str,
    path: &str,
    subject: &Subject,
    body: PatchBody<'_>,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<Written, PatchError> {
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
) -> Result<Written, PatchError> {
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

/// [`patch`] inside the caller's write. The patch is parsed and classified
/// **before** the mode is checked (spec 5c, H5): inserts only are authorized
/// by **Append** — WAC's Append is "add … without the right to modify or
/// remove" — and any delete needs **Write**; a patch on an ACL needs Control,
/// as ever. A binary has no triples to patch.
///
/// `preconditions` is evaluated after the WAC check and before anything is
/// written, against this transaction's view of the resource, so no other write
/// can land between the check and this one. Pass `Preconditions::NONE` when not
/// answering an HTTP request.
///
/// Answers [`Written::Created`] when the target had no metadata before this
/// patch and [`Written::Replaced`] when it did, from the same read the
/// precondition uses (spec 5c, H4).
pub fn patch_in(
    w: &mut PodWrite<'_>,
    base: &str,
    path: &str,
    subject: &Subject,
    body: PatchBody<'_>,
    storage_root: &str,
    preconditions: &Preconditions,
) -> Result<Written, PatchError> {
    let resource = format!("{base}{path}");
    if !resource.starts_with(storage_root) {
        return Err(PatchError::Ldp(LdpError::OutsideStorage));
    }
    // H5: the parse is classified, and the classified mode is what WAC
    // evaluates — so the check runs inside the transaction, on the classified
    // mode, and a `DELETE` inside a string literal classifies as an insert.
    let prepared = patch::prepare(body, &resource)?;
    if !check(&*w, base, path, subject, prepared.mode()).map_err(PatchError::Ldp)? {
        return Err(PatchError::Ldp(LdpError::Denied));
    }
    let current = w.meta(&resource)?.map(|meta| meta.version);
    preconditions.check_write(conditional::Method::Patch, current.as_deref())?;
    // The same read the precondition used, so nothing can land between them.
    let written = match current {
        Some(_) => Written::Replaced,
        None => Written::Created,
    };
    if w.meta(&resource)?
        .is_some_and(|meta| matches!(meta.kind, Kind::NonRdfSource))
    {
        return Err(PatchError::Ldp(LdpError::NotRdf));
    }
    prepared.apply(w, &resource)?;
    Ok(written)
}

/// Write a patched graph with the `Content` its target calls for: an
/// auxiliary (an `.acl` or a `.meta`) as `Auxiliary`, a container under
/// [`container_body`]'s rule, anything else as an RDF document. A patch that
/// creates a resource contains it, because `put` does.
///
/// A container's `solid:where` sees what a `GET` serves, `ldp:contains`
/// included, because [`patch::apply_scoped`] seeds the scratch graph with it
/// (spec 5c, H6) — and still cannot rewrite it, because the write lands here.
pub(crate) fn store_patched(
    w: &mut PodWrite<'_>,
    resource: &str,
    patched: Vec<Quad>,
) -> Result<(), LdpError> {
    if is_auxiliary(resource) {
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
pub(crate) fn parse_into_graph(
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
    use super::{acl_iri, check, describes, governed, meta_iri};
    use brolly_authz::AccessMode;
    use brolly_identity::{Scope, Subject, Via};
    use brolly_store::StoreManager;
    use brolly_store::resources::{Content, Pod};
    use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};

    const BASE: &str = "https://alice.brolly.id";
    const ROOT: &str = "https://alice.brolly.id/~/";
    const ACL: &str = "http://www.w3.org/ns/auth/acl#";

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

    /// H2 (spec 5d): `describes` strips exactly one `.meta` — a sibling of
    /// `governed`'s rule, never composed with it.
    #[test]
    fn a_meta_describes_its_path_without_the_suffix() {
        assert_eq!(describes("/~/notes/first.meta"), Some("/~/notes/first"));
        assert_eq!(describes("/~/notes/.meta"), Some("/~/notes/"));
        // Exactly one: `/~/x.meta.meta` describes `/~/x.meta` — itself a
        // fiction under H1 — not `/~/x`.
        assert_eq!(describes("/~/x.meta.meta"), Some("/~/x.meta"));
    }

    #[test]
    fn other_paths_are_not_descriptions() {
        assert_eq!(describes("/~/notes"), None);
        assert_eq!(describes("/~/x.metax"), None);
        // Not composed with `governed`: the strip stops at the `.meta`, even
        // where what is left ends in `.acl` — whose `Control` governs that is
        // the other arm's question, asked of a target that can exist. A path
        // ending in both suffixes is a fiction H1 answers 404 before
        // authorization.
        assert_eq!(describes("/~/x.acl"), None);
        assert_eq!(describes("/~/x.acl.meta"), Some("/~/x.acl"));
        assert_eq!(describes("/~/x.meta.acl"), None);
    }

    /// H1 (spec 5d): `meta_iri` is `acl_iri`'s placement rule — beside a
    /// document, inside a container — for the second auxiliary suffix.
    #[test]
    fn a_containers_meta_is_inside_it_and_a_documents_is_beside_it() {
        assert_eq!(meta_iri("/~/notes/first"), "/~/notes/first.meta");
        assert_eq!(meta_iri("/~/notes/"), "/~/notes/.meta");
        assert_eq!(
            meta_iri("https://alice.brolly.id/~/"),
            "https://alice.brolly.id/~/.meta"
        );
    }

    fn quad(graph: &str, s: &str, p: &str, o: &str) -> Quad {
        Quad::new(
            NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(s)),
            NamedNode::new_unchecked(p),
            Term::NamedNode(NamedNode::new_unchecked(o)),
            GraphName::NamedNode(NamedNode::new_unchecked(graph)),
        )
    }

    /// A pod whose root ACL grants Alice Read, Write and Control by default
    /// and Bob Append only — the two callers H2's `.meta` rule separates.
    /// Seeded through the pod, not through `ldp`, so the setup doesn't depend
    /// on the code under test.
    fn authz_pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
        let dir = tempfile::tempdir().unwrap();
        let mgr = StoreManager::open(dir.path(), 1, 60).unwrap();
        let pod = mgr.pod(uuid::Uuid::new_v4()).unwrap();
        pod.write(|w| w.create_root(ROOT)).unwrap();

        let g = format!("{ROOT}.acl");
        let owner = format!("{g}#owner");
        let bob = format!("{g}#bob");
        let quads = vec![
            quad(&g, &owner, &format!("{ACL}default"), ROOT),
            quad(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            quad(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            quad(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Control")),
            quad(
                &g,
                &owner,
                &format!("{ACL}agent"),
                "https://alice.brolly.id/profile#me",
            ),
            quad(&g, &bob, &format!("{ACL}default"), ROOT),
            quad(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Append")),
            quad(
                &g,
                &bob,
                &format!("{ACL}agent"),
                "https://bob.example/profile#me",
            ),
        ];
        pod.write(|w| w.put(&g, Content::Auxiliary(&quads)))
            .unwrap();
        (mgr, dir, pod)
    }

    fn alice() -> Subject {
        Subject::local(
            uuid::Uuid::new_v4(),
            "did:plc:alice".into(),
            "https://alice.brolly.id/profile#me".into(),
            Scope::parse("webid"),
            Via::SolidDpop,
        )
    }

    fn bob() -> Subject {
        Subject::local(
            uuid::Uuid::new_v4(),
            "did:plc:bob".into(),
            "https://bob.example/profile#me".into(),
            Scope::parse("webid"),
            Via::SolidDpop,
        )
    }

    /// H2 (spec 5d): a `.meta` needs the same mode on the resource it
    /// describes. Read on the subject reads its `.meta` — how Penny shows alt
    /// text for a shared image — Write on the subject writes and deletes it,
    /// and Append alone does not, because appending is not describing.
    #[test]
    fn a_meta_needs_the_same_mode_on_what_it_describes() {
        let (_m, _d, pod) = authz_pod();
        let r = pod.read_store();
        assert!(
            check(&r, BASE, "/~/image.meta", &alice(), AccessMode::Read).unwrap(),
            "Read on the subject reads its `.meta`"
        );
        assert!(
            check(&r, BASE, "/~/image.meta", &alice(), AccessMode::Write).unwrap(),
            "Write on the subject writes and deletes it"
        );
        assert!(
            !check(&r, BASE, "/~/image.meta", &bob(), AccessMode::Read).unwrap(),
            "Bob holds no Read on the subject"
        );
        assert!(
            !check(&r, BASE, "/~/image.meta", &bob(), AccessMode::Write).unwrap(),
            "Append alone does not describe"
        );
    }
}
