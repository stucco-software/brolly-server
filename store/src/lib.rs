//! Per-user pod stores, the server-agent store, and query helpers.
//!
//! Two surfaces, and every query resolves to exactly one of them:
//!
//! | Store | Contains | Query scope |
//! |---|---|---|
//! | pod | one user's data, all protocols | cross-*protocol* joins |
//! | server agent | pointers + filter keys for all users | cross-*user* queries |
//!
//! The server-agent store holds **pointers and filter keys only, never content**.
//! See `docs/greenfield-implementation-plan.md` §2.2 and §3 Phase 2.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
