//! Users, WebID, DIDs, and the one normalized [`Subject`] every handler takes.
//!
//! Two rules from the plan hold here:
//!
//! * **`did:plc` in every wire format** (D11). `did:web` is derived from the
//!   subdomain for routing only. The predecessor emitted `did:web` AT-URIs and
//!   became invisible to the AppView, then needed a backfill it never wrote.
//! * **One auth dispatcher.** Handlers receive a `Subject`; none parses an
//!   `Authorization` header itself. The predecessor had four independent
//!   header-parsing paths and four token tables.
//!
//! See `docs/greenfield-implementation-plan.md` §3 Phase 3 and ADR 0008.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod db;
pub mod did;
pub mod oauth;
pub mod routing;
pub mod subject;
pub mod webid;

pub use subject::{Credential, Scope, Subject, Via};
