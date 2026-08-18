//! Solid: LDP-RS/-NR/-BC, N3 Patch, SPARQL Update PATCH, Solid-OIDC.
//!
//! Solid LDP is **generic CRUD** (decision D9). A write is a publication only
//! when it has the right shape (`rdf:type as:Note`) in the right place (a typed
//! publication container). Everywhere else is private storage.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
