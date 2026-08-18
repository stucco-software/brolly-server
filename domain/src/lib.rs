//! Canonical vocabulary, quad model, projections, and IRI canonicalization.
//!
//! **Zero protocol dependencies and zero I/O.** Everything here is pure, which
//! is what makes the round-trip property test in `tests/roundtrip.rs` possible.
//!
//! Two layers, per decision D7:
//!
//! * [`faithful`] — always emitted, lossless, no mapping table required. Works
//!   for lexicons nobody has seen yet. This is what makes "export" complete.
//! * [`canonical`] — *additional* standard-vocabulary assertions, for the
//!   entities that genuinely are the same thing across protocols. Profile only
//!   today; a second entity earns its way in.
//!
//! Harmonization is agreement on the **subject IRI**, not just the predicate.
//!
//! See `docs/greenfield-implementation-plan.md` §3 Phase 1.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod canonical;
pub mod faithful;
pub mod iri;
pub mod nsid;
pub mod ports;
pub mod vocab;
