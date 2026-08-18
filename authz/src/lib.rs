//! Web Access Control, evaluated on every read path, for every protocol.
//!
//! WAC is expressed as SPARQL: `acl:agentGroup` → `vcard:hasMember` is a property
//! path, and effective-ACL discovery is a query rather than a container walk.
//! See `docs/greenfield-implementation-plan.md` §3 Phase 2.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
