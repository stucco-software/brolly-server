//! **The** write path. Every quad entering any store passes through here.
//!
//! A canonicalization table is worth nothing if a writer can bypass it. The
//! predecessor had no choke point, so whichever AS2 spelling a sender used got
//! stored, five reader modules had to match both, and a production bug shipped
//! when one of them matched only the `https` form.
//!
//! There is exactly one `insert` in this crate, it canonicalizes, and
//! `tests/canonical_on_write.rs` asserts that non-canonical input cannot
//! survive a round trip through storage.

use brolly_domain::faithful::{self, FaithfulError};
use brolly_domain::iri::canonicalize_quad;
use oxigraph::model::{NamedNode, Quad};
use oxigraph::store::Store;

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
/// The only insertion point in the workspace. Returns the number written.
pub fn insert_quads(store: &Store, quads: &[Quad]) -> Result<usize, WriteError> {
    for quad in quads {
        store
            .insert(&canonicalize_quad(quad))
            .map_err(|e| WriteError::Store(StoreError::from(e)))?;
    }
    Ok(quads.len())
}

/// Encode a protocol record into its graph, faithfully, then write it.
///
/// `lexicon` names the term space: an ATProtocol `$type`, or `"as2"` for
/// ActivityStreams. Unknown lexicons are fine — the faithful layer needs no
/// mapping table, which is what keeps export complete.
pub fn insert_record(
    store: &Store,
    record: &serde_json::Value,
    subject: &NamedNode,
    graph: &NamedNode,
    lexicon: &str,
) -> Result<usize, WriteError> {
    let quads = faithful::encode(record, subject, graph, lexicon)?;
    insert_quads(store, &quads)
}

/// Replace a graph's contents with `quads`, atomically from a reader's point of
/// view within this process. Used by PUT-shaped writes.
pub fn replace_graph(
    store: &Store,
    graph: &NamedNode,
    quads: &[Quad],
) -> Result<usize, WriteError> {
    store
        .clear_graph(graph.as_ref())
        .map_err(|e| WriteError::Store(StoreError::from(e)))?;
    insert_quads(store, quads)
}
