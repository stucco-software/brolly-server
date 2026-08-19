//! Which host owns which path (ADR 0009).
//!
//! Server-wide protocol endpoints live on the apex; user resources live on the
//! subdomain, where Solid LDP is generic CRUD. Those two facts collide unless
//! the protocol prefixes are reserved: an unclaimed path on a subdomain is not
//! unrouted, it is **user-writable**, so `alice.brolly.id/oauth/token` would
//! otherwise be a resource inside Alice's pod that a misconfigured client could
//! post an authorization code to.

/// Path prefixes that belong to the apex and must never reach a user's LDP
/// handler.
///
/// `/inbox` is deliberately absent: the apex serves the ActivityPub *shared*
/// inbox while a subdomain serves that user's own, and both are real.
pub const RESERVED_ON_SUBDOMAIN: &[&str] = &[
    "/oauth/",
    "/.well-known/",
    "/api/",
    "/admin",
    "/dashboard",
    "/login",
    "/logout",
    "/register",
    "/index/",
];

/// Paths served only by the apex, used to check the reservation list is complete.
pub const APEX_ONLY_PREFIXES: &[&str] = &[
    "/oauth/",
    "/.well-known/",
    "/api/",
    "/admin",
    "/dashboard",
    "/login",
    "/logout",
    "/register",
    "/index/",
];

/// Is `path` reserved on a user subdomain?
///
/// Returns the matched prefix, which the handler puts in the `Link` header so a
/// client author can see where the request should have gone.
pub fn reserved_on_subdomain(path: &str) -> Option<&'static str> {
    RESERVED_ON_SUBDOMAIN
        .iter()
        .find(|prefix| path == prefix.trim_end_matches('/') || path.starts_with(*prefix))
        .copied()
}

/// The apex URL a reserved subdomain request should have used.
pub fn apex_equivalent(base_domain: &str, path: &str) -> String {
    format!("https://{base_domain}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{ENDPOINTS, Protocol};

    #[test]
    fn oauth_is_reserved_on_subdomains() {
        // The credential-exfiltration case: a client misconfigured with a user's
        // subdomain must not be able to post an authorization code into that
        // user's pod.
        for (path, _) in ENDPOINTS {
            assert!(
                reserved_on_subdomain(path).is_some(),
                "{path} would be a writable LDP resource on a user subdomain"
            );
        }
    }

    #[test]
    fn every_apex_prefix_is_reserved() {
        // Adding an apex endpoint without reserving it creates a writable
        // shadow of that endpoint in every user's pod.
        for prefix in APEX_ONLY_PREFIXES {
            assert!(
                reserved_on_subdomain(prefix).is_some(),
                "apex prefix {prefix} is not reserved on subdomains"
            );
        }
    }

    #[test]
    fn user_resources_are_not_reserved() {
        for path in [
            "/profile",
            "/actor",
            "/outbox",
            "/followers",
            "/following",
            "/notes/2026/first",
            "/oauthtokens", // no trailing slash: not the /oauth/ prefix
            "/apiary",      // not /api/
        ] {
            assert_eq!(
                reserved_on_subdomain(path),
                None,
                "{path} is a user resource and must remain writable"
            );
        }
    }

    #[test]
    fn inbox_exists_on_both_hosts() {
        assert_eq!(
            reserved_on_subdomain("/inbox"),
            None,
            "the apex serves the shared inbox; a subdomain serves the user's own"
        );
    }

    #[test]
    fn xrpc_is_not_reserved_because_users_own_their_repo() {
        assert_eq!(
            reserved_on_subdomain("/xrpc/com.atproto.repo.getRecord"),
            None
        );
    }

    #[test]
    fn the_apex_equivalent_names_the_right_host() {
        assert_eq!(
            apex_equivalent("brolly.id", "/oauth/token"),
            "https://brolly.id/oauth/token"
        );
    }

    #[test]
    fn mastodon_bare_paths_are_reserved_too() {
        // These are the ones clients hardcode, so they are the most likely to
        // arrive at the wrong host.
        for (path, proto) in ENDPOINTS {
            if *proto == Protocol::Mastodon {
                assert!(reserved_on_subdomain(path).is_some(), "{path}");
            }
        }
    }
}
