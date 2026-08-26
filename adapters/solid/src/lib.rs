//! Solid: LDP under `/~/`, WAC on every read, N3 Patch and SPARQL Update.
//!
//! User content lives under the storage root (ADR 0010), advertised as
//! `space:storage` in the WebID profile so clients discover it. Everything
//! outside `/~/` on a subdomain is an explicit protocol resource or a 404, so
//! the catch-all here cannot shadow a protocol endpoint.
//!
//! See `docs/greenfield-implementation-plan.md` §3 Phase 4.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod ldp;
pub mod oidc;
pub mod patch;
pub mod profile;
pub mod storage;

pub use ldp::{LdpError, LdpOutcome};
