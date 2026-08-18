//! Users, WebID, DIDs, keys, sessions, and the normalized `Subject`.
//!
//! `did:web` is used for routing only; **`did:plc` appears in every wire format
//! from the first commit** (decision D11) so no AT-URI migration is needed later.
//! One auth dispatcher produces one `Subject`; handlers never parse an
//! `Authorization` header themselves.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
