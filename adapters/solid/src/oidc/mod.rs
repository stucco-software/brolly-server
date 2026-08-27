//! Solid-OIDC provider.

/// Re-exported: the verifier moved to `brolly-identity` when ATProtocol
/// needed it too (RFC 9449 is not Solid's). Phase 4's call sites are unchanged.
pub use brolly_identity::dpop;
pub mod keys;
pub mod store;
pub mod tokens;
