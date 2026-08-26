//! ActivityPub: AS2 delivery, inbox, HTTP signatures (cavage-09).
//!
//! Inbox arrival writes containment plus a sort key, so a home timeline is a
//! single-store read. The server agent is a delivery recipient like any other —
//! the instance index is populated by push, never by crawling.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod actor;
pub mod federation;
pub mod inbox;
pub mod keys;

pub use federation::{FEDERATION_ENABLED, is_local, should_deliver};
