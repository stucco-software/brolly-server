//! **The** write path. Every quad entering any store passes through here.
//!
//! A canonicalization table is worth nothing if a writer can bypass it. The
//! predecessor had no choke point, so whichever AS2 spelling a sender used got
//! stored, five reader modules had to match both, and a production bug shipped
//! when one of them matched only the `https` form.
//!
//! There is exactly one insert per target in this crate, a store and a
//! transaction, both canonicalize, and `tests/storage_invariants.rs` asserts
//! that non-canonical input cannot survive a round trip through storage.
//!
//! The functions are crate-internal. Everything outside `store` writes a pod
//! through `Pod::write` and the instance through `index`, and both land here.
//! `WriteError` stays public for the adapters' error conversions.

use brolly_domain::faithful::FaithfulError;
use brolly_domain::iri::canonicalize_quad;
use oxigraph::model::Quad;
use oxigraph::store::{Store, Transaction};

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
/// The insertion point for a bare store: today only the instance index.
/// Returns the number written.
pub(crate) fn insert_quads(store: &Store, quads: &[Quad]) -> Result<usize, WriteError> {
    for quad in quads {
        store
            .insert(&canonicalize_quad(quad))
            .map_err(|e| WriteError::Store(StoreError::from(e)))?;
    }
    Ok(quads.len())
}

/// Insert quads inside an open transaction, normalizing every IRI on the way
/// in. The pod's insertion point: `PodWrite` and `resources` reach the
/// transaction only through here. Returns the number written.
pub(crate) fn insert_quads_in(transaction: &mut Transaction<'_>, quads: &[Quad]) -> usize {
    for quad in quads {
        transaction.insert(&canonicalize_quad(quad));
    }
    quads.len()
}

/// Remove quads inside an open transaction.
///
/// Canonicalized like an insert, so removing the `http` spelling of a quad
/// removes the `https` one that was actually stored.
pub(crate) fn remove_quads_in(transaction: &mut Transaction<'_>, quads: &[Quad]) {
    for quad in quads {
        transaction.remove(&canonicalize_quad(quad));
    }
}
