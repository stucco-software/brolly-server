//! Web Access Control, evaluated as SPARQL on every read path.
//!
//! One authorization layer under every protocol (plan §2.8). The predecessor's
//! WAC was 1,767 well-written lines reachable from exactly one place —
//! `solid/ldp.rs` — while ActivityPub, Mastodon, and XRPC reads bypassed it
//! entirely. Each surface reimplemented visibility in its own idiom, so the same
//! triple was reachable through four doors and only one checked the lock.
//!
//! It was also the densest concentration of query-shaped code in the workspace:
//! `agent_matches` hand-checked four agent cases in sequence, including an
//! `acl:agentGroup` → `vcard:hasMember` traversal that is a graph join, and
//! effective-ACL discovery walked the container hierarchy with string
//! manipulation plus one existence probe per level.
//!
//! Here both are queries.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod wac;

pub use wac::{AccessMode, Agent, AuthzError, EffectiveAcl, authorize, effective_acl};
