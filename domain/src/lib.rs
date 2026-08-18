//! Canonical vocabulary, quad model, projections, and IRI canonicalization.
//!
//! **Zero protocol dependencies and zero I/O.** Everything here is pure: terms,
//! the two-layer emission model (faithful always, canonical where entities are
//! genuinely the same thing), and the ports that adapters implement.
//!
//! See `docs/greenfield-implementation-plan.md` §3 Phase 1.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// Ports that adapters implement and `server` wires together.
///
/// Adapters must not depend on each other (enforced by
/// `server/tests/architecture.rs`). When one adapter needs another's behaviour —
/// Mastodon publishing an activity through ActivityPub delivery, for example —
/// the contract lives here and `server` injects the implementation.
pub mod ports {}
