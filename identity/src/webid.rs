//! WebIDs — the subject IRI that authorization matches and that every protocol
//! asserts profile triples onto.
//!
//! The WebID is the harmonization point (D8). The Solid profile writer, the
//! ActivityPub actor builder, and the ATProtocol profile adapter all assert
//! `foaf:name` onto *this* node, so there is nothing to join.

/// The user's WebID: `https://<user>.<base>/profile#me`.
///
/// Per-user subdomains make the subdomain the identity prefix, so this reads as
/// a natural WebID rather than a path under a shared host.
pub fn webid(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/profile#me")
}

/// The document containing the WebID — also the named graph holding its triples.
pub fn profile_document(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/profile")
}

/// The ActivityPub actor IRI.
pub fn actor(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/actor")
}

/// Recover the username from a WebID belonging to this instance.
///
/// `None` for a remote WebID, which is how a federating peer is distinguished
/// from a local user without a database round trip.
pub fn local_username(webid: &str, base_domain: &str) -> Option<String> {
    let rest = webid.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/')?;
    if path != "profile#me" {
        return None;
    }
    let username = host.strip_suffix(&format!(".{base_domain}"))?;
    (!username.is_empty() && !username.contains('.')).then(|| username.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webid_round_trips_to_a_username() {
        let id = webid("alice", "brolly.id");
        assert_eq!(id, "https://alice.brolly.id/profile#me");
        assert_eq!(local_username(&id, "brolly.id"), Some("alice".to_string()));
    }

    #[test]
    fn a_remote_webid_is_not_local() {
        assert_eq!(
            local_username("https://bob.example.com/profile#me", "brolly.id"),
            None
        );
    }

    #[test]
    fn a_nested_subdomain_is_not_a_local_user() {
        // https://evil.alice.brolly.id/profile#me must not resolve to "alice".
        assert_eq!(
            local_username("https://evil.alice.brolly.id/profile#me", "brolly.id"),
            None
        );
    }

    #[test]
    fn the_profile_document_is_the_webid_without_the_fragment() {
        let doc = profile_document("alice", "brolly.id");
        assert_eq!(webid("alice", "brolly.id"), format!("{doc}#me"));
    }
}
