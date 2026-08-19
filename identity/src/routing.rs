//! Which host and which namespace owns which path (ADR 0010).
//!
//! The subdomain root belongs to the server; the user owns `/~/`. That is an
//! allowlist, and it is the whole point: the LDP catch-all is mounted *inside*
//! `/~/`, so it cannot shadow a protocol endpoint and no reserved list has to be
//! kept in sync. ADR 0009 tried the blocklist form and superseded itself.

/// Where user and app LDP content lives.
///
/// Advertised as `space:storage` in the WebID profile, so a Solid client
/// discovers it rather than assuming it. `~` is unreserved in RFC 3986, so it
/// needs no encoding.
pub const USER_STORAGE_ROOT: &str = "/~/";

/// Protocol resources served at a subdomain root.
///
/// These are server-generated projections, not arbitrary user content, which is
/// why they stay at the root — it keeps `https://alice.brolly.id/profile#me` as
/// the WebID, the subject IRI every protocol asserts onto (D8).
pub const USER_PROTOCOL_RESOURCES: &[&str] = &[
    "/profile",
    "/actor",
    "/inbox",
    "/outbox",
    "/followers",
    "/following",
];

/// Prefixes of protocol resources at a subdomain root.
pub const USER_PROTOCOL_PREFIXES: &[&str] = &["/xrpc/"];

/// What a path on a user subdomain resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubdomainRoute {
    /// Inside `/~/` — the LDP handler, user- and app-writable.
    UserStorage,
    /// A server-managed protocol resource at the root.
    ProtocolResource,
    /// The subdomain root itself: a server-rendered profile page.
    Root,
    /// Nothing. `404`, and deliberately no fallback — this is where the
    /// predecessor leaked RDF to Mastodon clients and where a misrouted OAuth
    /// request would otherwise have become a pod write.
    NotFound,
}

/// Resolve a path on a user subdomain.
pub fn subdomain_route(path: &str) -> SubdomainRoute {
    if path == "/" {
        return SubdomainRoute::Root;
    }
    if path == USER_STORAGE_ROOT.trim_end_matches('/') || path.starts_with(USER_STORAGE_ROOT) {
        return SubdomainRoute::UserStorage;
    }
    if USER_PROTOCOL_RESOURCES.contains(&path)
        || USER_PROTOCOL_PREFIXES.iter().any(|p| path.starts_with(p))
    {
        return SubdomainRoute::ProtocolResource;
    }
    SubdomainRoute::NotFound
}

/// The storage root IRI for a user — the value `space:storage` must advertise.
pub fn storage_root(username: &str, base_domain: &str) -> String {
    format!("https://{username}.{base_domain}{USER_STORAGE_ROOT}")
}

/// Map an LDP path inside the storage root to its full resource IRI.
pub fn storage_resource(username: &str, base_domain: &str, path: &str) -> String {
    let path = path.trim_start_matches('/');
    format!("{}{path}", storage_root(username, base_domain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::ENDPOINTS;
    use crate::webid;

    #[test]
    fn oauth_paths_cannot_be_written_on_a_subdomain() {
        // The credential-exfiltration case from ADR 0009, now structurally
        // impossible rather than excluded by a list.
        for (path, _) in ENDPOINTS {
            assert_eq!(
                subdomain_route(path),
                SubdomainRoute::NotFound,
                "{path} must not resolve to anything on a user subdomain"
            );
        }
    }

    #[test]
    fn no_apex_path_can_ever_reach_the_ldp_handler() {
        // Includes endpoints that do not exist yet — the property holds for any
        // path outside /~/, which is what deleting the reserved list bought.
        for path in [
            "/oauth/token",
            "/api/v1/statuses",
            "/.well-known/openid-configuration",
            "/admin/users",
            "/dashboard",
            "/login",
            "/index/public",
            "/some-protocol-invented-in-2030/endpoint",
        ] {
            assert_ne!(
                subdomain_route(path),
                SubdomainRoute::UserStorage,
                "{path} reached user storage"
            );
        }
    }

    #[test]
    fn user_content_lives_under_the_storage_root() {
        for path in ["/~/", "/~/notes/first", "/~/projects/2026/plan.ttl", "/~"] {
            assert_eq!(
                subdomain_route(path),
                SubdomainRoute::UserStorage,
                "{path} should be user storage"
            );
        }
    }

    #[test]
    fn protocol_resources_stay_at_the_root() {
        for path in [
            "/profile",
            "/actor",
            "/inbox",
            "/outbox",
            "/followers",
            "/following",
        ] {
            assert_eq!(
                subdomain_route(path),
                SubdomainRoute::ProtocolResource,
                "{path}"
            );
        }
        assert_eq!(
            subdomain_route("/xrpc/com.atproto.repo.getRecord"),
            SubdomainRoute::ProtocolResource
        );
    }

    #[test]
    fn the_webid_is_unaffected_by_the_storage_split() {
        // The reason protocol resources stay at the root: this stays pretty, and
        // it is the subject IRI every protocol asserts onto (D8).
        assert_eq!(
            webid::webid("alice", "brolly.id"),
            "https://alice.brolly.id/profile#me"
        );
        assert_eq!(
            subdomain_route("/profile"),
            SubdomainRoute::ProtocolResource
        );
    }

    #[test]
    fn advertised_storage_root_matches_what_the_router_mounts() {
        // The predecessor advertised space:storage <origin/> and never checked
        // that the value agreed with the router. If these drift, every Solid app
        // writes to a 404.
        let advertised = storage_root("alice", "brolly.id");
        let path = advertised
            .strip_prefix("https://alice.brolly.id")
            .expect("same origin");
        assert_eq!(path, USER_STORAGE_ROOT);
        assert_eq!(subdomain_route(path), SubdomainRoute::UserStorage);
    }

    #[test]
    fn a_resource_iri_is_built_from_the_advertised_root() {
        assert_eq!(
            storage_resource("alice", "brolly.id", "/notes/first"),
            "https://alice.brolly.id/~/notes/first"
        );
    }

    #[test]
    fn the_subdomain_root_is_the_servers_not_the_users() {
        // One real restriction from ADR 0010: alice cannot own "/".
        assert_eq!(subdomain_route("/"), SubdomainRoute::Root);
    }

    #[test]
    fn unmatched_paths_are_not_found_rather_than_falling_through() {
        assert_eq!(subdomain_route("/random"), SubdomainRoute::NotFound);
        assert_eq!(subdomain_route("/notes/first"), SubdomainRoute::NotFound);
    }
}
