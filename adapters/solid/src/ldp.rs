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

/// A successful read.
pub struct LdpOutcome {
    pub body: Vec<u8>,
    pub media_type: &'static str,
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
        media_type: format.media_type(),
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

    // ADR 0007: RDF/XML errors here rather than falling through to blob storage.
    let format = syntax::read_format(content_type)?;
    let quads = parse_into_graph(body, format, &resource)?;

    replace_graph(store, &iri(&resource), &quads)?;
    storage::add_containment(store, &resource, storage_root)?;
    Ok(())
}

/// `POST` — append triples to a resource, or create a member of a container.
///
/// Requires Append, which Write satisfies (`acl:Write` implies `acl:Append`).
pub fn append(
    store: &Store,
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

    let format = syntax::read_format(content_type)?;

    // POST to a container mints a new member; POST to a resource appends.
    let target = if storage::is_container(&container) {
        format!("{container}{}", uuid::Uuid::new_v4())
    } else {
        container.clone()
    };

    let quads = parse_into_graph(body, format, &target)?;
    insert_quads(store, &quads)?;
    storage::add_containment(store, &target, storage_root)?;
    Ok(target)
}

/// `DELETE`.
pub fn delete(
    store: &Store,
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

    store.clear_graph(GraphNameRef::NamedNode(iri(&resource).as_ref()))?;
    storage::remove_containment(store, &resource, storage_root)?;
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
