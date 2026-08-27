//! ATProtocol: XRPC, MST/repo/CAR (via `atrium-*`), PLC, OAuth, firehose.
//!
//! Records ingest through the faithful layer with an NSID-derived namespace, so
//! **any** lexicon round-trips without a mapping. Mapped lexicons additionally
//! assert canonical triples onto the shared subject.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod blocks;
pub mod keys;
pub mod repo;
pub mod state;
