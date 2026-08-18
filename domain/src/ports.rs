//! Ports that adapters implement and `brolly-server` wires together.
//!
//! Adapters must not depend on each other — enforced by
//! `server/tests/architecture.rs`. When one adapter needs another's behaviour
//! (Mastodon publishing through ActivityPub delivery, say) the contract lives
//! here and the server injects the implementation.
//!
//! [`Adapter`] itself is deliberately **pure**: no store, no database, no
//! network in any implementation. That is what makes the round-trip property
//! test possible, and it is why the adapter crates carry no I/O dependencies.

use oxrdf::{NamedNode, Quad};
use serde_json::Value;

use crate::faithful::FaithfulError;

/// Translate one protocol's wire format to and from quads.
///
/// Implementations are pure functions over their arguments. An implementation
/// that reaches for a store or a socket is a bug the architecture test cannot
/// catch, so it is stated here instead.
pub trait Adapter {
    /// The record type this adapter names its term space with — an ATProtocol
    /// NSID, or the AS2 namespace marker.
    fn lexicon(&self, record: &Value) -> Option<String>;

    /// Wire → quads. Always lossless; see [`crate::faithful`].
    fn encode(
        &self,
        record: &Value,
        subject: &NamedNode,
        graph: &NamedNode,
    ) -> Result<Vec<Quad>, FaithfulError>;

    /// Quads → wire. Must reproduce the input of [`Adapter::encode`] exactly —
    /// the property test in `domain/tests/roundtrip.rs` is the contract.
    fn decode(&self, quads: &[Quad], subject: &NamedNode) -> Result<Value, FaithfulError>;
}

/// Somewhere an activity can be published. Implemented by the ActivityPub
/// adapter, consumed by Mastodon, injected by the server — so neither adapter
/// depends on the other.
pub trait Publisher: Send + Sync {
    /// Deliver `activity` on behalf of `actor`.
    fn publish(
        &self,
        actor: &NamedNode,
        activity: &Value,
    ) -> impl Future<Output = Result<(), PublishError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    Rejected(String),
    Transient(String),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishError::Rejected(m) => write!(f, "rejected: {m}"),
            PublishError::Transient(m) => write!(f, "transient: {m}"),
        }
    }
}

impl std::error::Error for PublishError {}
