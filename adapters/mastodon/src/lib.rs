//! Mastodon Client API — a projection, not a storage layer.
//!
//! Home timeline queries the viewer's own inbox graphs; public/local queries the
//! server-agent index. This crate has **no write path to any store** and **no
//! dependency on a sibling adapter** — both enforced by
//! `server/tests/architecture.rs`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod status_id;
pub mod translate;
