//! Per-user pod stores, the server-agent store, and the single write path.
//!
//! Two surfaces, and every query resolves to exactly one of them:
//!
//! | Store | Contains | Query scope |
//! |---|---|---|
//! | pod | one user's data, all protocols | cross-*protocol* joins |
//! | server agent | pointers + filter keys for all users | cross-*user* queries |
//!
//! The server-agent store holds **pointers and filter keys only, never
//! content** (decision D5), which is what makes account deletion `rm -rf` on
//! one directory and leaves the index to self-heal.
//!
//! See `docs/greenfield-implementation-plan.md` §3 Phase 2 and ADR 0005.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod blobs;
pub mod collection;
pub mod index;
pub mod manager;
pub mod resources;
pub mod write;

pub use blobs::BlobStore;
pub use index::InstanceStore;
pub use manager::{StoreError, StoreManager};
/// Re-exported so adapters and the server can name a store without taking a
/// direct oxigraph dependency — the engine stays an implementation detail of
/// this crate.
pub use oxigraph::store::Store;
pub use resources::{
    BlobMeta, Content, Kind, METADATA_GRAPH, Pod, PodRead, PodWrite, ReadStore, ResourceMeta,
    ResourceRead, container_triples, modified_ms,
};
