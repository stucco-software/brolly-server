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
    webid_at(&format!("https://{username}.{base_domain}"))
}

/// The WebID of the pod at `origin` — `https://<user>.<base>`, no trailing
/// slash, the `base` every LDP operation is handed.
///
/// [`webid`] is this with the origin spelled out, so the two cannot drift:
/// the owner bypass (ADR 0019) compares a subject's WebID against this, and
/// a subject's WebID was minted by [`webid`].
pub fn webid_at(origin: &str) -> String {
    format!("{origin}/profile#me")
}

/// The document containing the WebID — also the named graph holding its triples.
pub fn profile_document(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/profile")
}

/// The ActivityPub actor IRI.
pub fn actor(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/actor")
}

/// A member's personal inbox.
pub fn inbox(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/inbox")
}

/// A member's outbox — also the publication surface (ADR 0012). A write here
/// is a post; the same write anywhere in the pod is private CRUD.
pub fn outbox(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/outbox")
}

pub fn followers(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/followers")
}

pub fn following(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}/following")
}

// --- the instance's own identity (D4) --------------------------------------

/// The instance actor. Lives on the apex, because it is not any member's.
pub fn instance_actor(base_domain: &str) -> String {
    format!("https://{base_domain}/actor")
}

/// The instance's WebID, same shape as a member's so authorization needs no
/// special case for "the server is asking".
pub fn instance_webid(base_domain: &str) -> String {
    format!("https://{base_domain}/profile#me")
}

/// The shared inbox. Remote instances deliver here once rather than once per
/// local recipient, and it is also where the instance actor receives the
/// deliveries that populate the server index.
pub fn shared_inbox(base_domain: &str) -> String {
    format!("https://{base_domain}/inbox")
}

/// A handle in `@user@host` form, for WebFinger (ADR 0005 R9).
pub fn handle(username: &str, base_domain: &str) -> String {
    format!("{username}@{base_domain}")
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
    fn a_members_collections_all_live_on_their_own_subdomain() {
        // Every one of these is published in the actor document, so a remote
        // instance delivering to `inbox` has to reach the member's host and not
        // the apex — getting this wrong routes private delivery to the shared
        // inbox.
        for iri in [
            actor("alice", "brolly.id"),
            inbox("alice", "brolly.id"),
            outbox("alice", "brolly.id"),
            followers("alice", "brolly.id"),
            following("alice", "brolly.id"),
        ] {
            assert!(
                iri.starts_with("https://alice.brolly.id/"),
                "{iri} is not on alice's host"
            );
        }
    }

    #[test]
    fn the_instance_actor_is_on_the_apex_and_is_not_a_member() {
        // It must not collide with a member's, or a member registering that
        // name would take over instance delivery.
        assert_eq!(instance_actor("brolly.id"), "https://brolly.id/actor");
        assert_eq!(shared_inbox("brolly.id"), "https://brolly.id/inbox");
        assert_eq!(
            local_username(&instance_webid("brolly.id"), "brolly.id"),
            None,
            "the instance WebID must not resolve to a member"
        );
    }

    #[test]
    fn a_handle_is_user_at_host() {
        assert_eq!(handle("alice", "brolly.id"), "alice@brolly.id");
    }

    #[test]
    fn the_profile_document_is_the_webid_without_the_fragment() {
        let doc = profile_document("alice", "brolly.id");
        assert_eq!(webid("alice", "brolly.id"), format!("{doc}#me"));
    }
}
