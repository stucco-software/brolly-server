//! DIDs: `did:web` for routing, **`did:plc` for every wire format** (D11).
//!
//! Each local user has two identifiers. `did:web:<user>.<base>` is derivable
//! from the subdomain in O(1), which makes it convenient for internal
//! resolution. `did:plc:<id>` is the canonical federation identity: the relay
//! and AppView resolve users by PLC DID, and AT-URIs are keyed on it.
//!
//! The predecessor emitted `did:web` in API responses and repo commits. Its
//! content was invisible to bsky.app even with a correct PLC service endpoint
//! and a working firehose, and the corrective ADR noted that records already
//! written would need a backfill nobody had scoped. Hence D11: `did:plc`
//! appears in wire formats from the first commit, and this module makes the
//! distinction hard to get wrong.

/// Derive the routing DID from a subdomain. Cheap, local, never serialized.
pub fn did_web(username: &str, base_domain: &str) -> String {
    format!("did:web:{username}.{base_domain}")
}

/// Is this a `did:plc`?
pub fn is_plc(did: &str) -> bool {
    did.starts_with("did:plc:")
}

/// Is this a `did:web`?
pub fn is_web(did: &str) -> bool {
    did.starts_with("did:web:")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidError {
    /// A `did:web` reached a wire format. This is the predecessor's bug, and it
    /// is a hard error rather than a silent substitution: the caller holds the
    /// wrong identifier and needs to look up the user's `did_plc`.
    WebDidInWireFormat(String),
    NotADid(String),
}

impl std::fmt::Display for DidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DidError::WebDidInWireFormat(did) => write!(
                f,
                "{did} is a did:web and must not appear in a wire format — \
                 look up the user's did:plc (D11)"
            ),
            DidError::NotADid(s) => write!(f, "{s} is not a DID"),
        }
    }
}

impl std::error::Error for DidError {}

/// Gate for anything that serializes a DID to the network.
///
/// Every AT-URI, repo commit, and API response DID passes through here, so
/// "`did:plc` in every wire format" is enforced at a choke point rather than
/// remembered at ~40 call sites.
pub fn for_wire(did: &str) -> Result<&str, DidError> {
    if is_plc(did) {
        Ok(did)
    } else if is_web(did) {
        Err(DidError::WebDidInWireFormat(did.to_string()))
    } else if did.starts_with("did:") {
        // did:key and others are legitimate in their own contexts.
        Ok(did)
    } else {
        Err(DidError::NotADid(did.to_string()))
    }
}

/// Build an AT-URI. Rejects a `did:web` rather than emitting an invisible record.
pub fn at_uri(did: &str, collection: &str, rkey: &str) -> Result<String, DidError> {
    let did = for_wire(did)?;
    Ok(format!("at://{did}/{collection}/{rkey}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_uris_require_a_plc_did() {
        assert_eq!(
            at_uri("did:plc:abc123", "app.bsky.feed.post", "3k1").unwrap(),
            "at://did:plc:abc123/app.bsky.feed.post/3k1"
        );
    }

    #[test]
    fn a_web_did_in_an_at_uri_is_an_error_not_a_silent_pass() {
        // The predecessor shipped this and its content vanished from the AppView.
        let err = at_uri("did:web:alice.brolly.id", "app.bsky.feed.post", "3k1").unwrap_err();
        assert_eq!(
            err,
            DidError::WebDidInWireFormat("did:web:alice.brolly.id".into())
        );
    }

    #[test]
    fn did_web_is_derivable_for_routing() {
        assert_eq!(did_web("alice", "brolly.id"), "did:web:alice.brolly.id");
        assert!(is_web(&did_web("alice", "brolly.id")));
    }

    #[test]
    fn did_key_passes_the_wire_gate() {
        // Signing keys are did:key and belong on the wire in DID documents.
        assert!(for_wire("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").is_ok());
    }

    #[test]
    fn a_handle_is_not_a_did() {
        assert!(matches!(
            for_wire("alice.brolly.id"),
            Err(DidError::NotADid(_))
        ));
    }
}
