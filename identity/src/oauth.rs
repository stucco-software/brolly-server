//! OAuth endpoint layout (ADR 0008).
//!
//! Routing is by path, not by request shape. Only Mastodon hardcodes its
//! endpoints, so Mastodon gets the bare paths; ATProtocol and Solid-OIDC are
//! told where to go by the discovery documents they already fetch.
//!
//! The shape inspection below exists purely to give a misconfigured client a
//! useful error instead of a deserialization failure naming an internal field —
//! it never routes.

/// Which protocol owns an OAuth endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Mastodon,
    Atproto,
    SolidOidc,
}

/// The authoritative endpoint map. Discovery documents are generated from this,
/// and a test asserts the mounted routes match — an advertised path that is not
/// mounted breaks every client that discovers it.
pub const ENDPOINTS: &[(&str, Protocol)] = &[
    // Mastodon: hardcoded by clients, so it owns the bare paths.
    ("/oauth/authorize", Protocol::Mastodon),
    ("/oauth/token", Protocol::Mastodon),
    // ATProtocol: advertised in /.well-known/oauth-authorization-server.
    ("/oauth/atproto/par", Protocol::Atproto),
    ("/oauth/atproto/authorize", Protocol::Atproto),
    ("/oauth/atproto/token", Protocol::Atproto),
    // Solid-OIDC: advertised in /.well-known/openid-configuration.
    ("/oauth/solid/authorize", Protocol::SolidOidc),
    ("/oauth/solid/token", Protocol::SolidOidc),
    ("/oauth/solid/register", Protocol::SolidOidc),
    ("/oauth/solid/jwks", Protocol::SolidOidc),
];

pub fn owner_of(path: &str) -> Option<Protocol> {
    ENDPOINTS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, proto)| *proto)
}

/// Paths a given protocol should advertise.
pub fn endpoints_for(protocol: Protocol) -> Vec<&'static str> {
    ENDPOINTS
        .iter()
        .filter(|(_, p)| *p == protocol)
        .map(|(path, _)| *path)
        .collect()
}

/// The parts of a request that identify which protocol a client *thinks* it is
/// speaking. Deliberately not tied to a web framework, so the precedence table
/// is testable without constructing HTTP.
#[derive(Debug, Clone, Default)]
pub struct RequestShape<'a> {
    pub path: &'a str,
    /// A `DPoP` request header is present.
    pub dpop_header: bool,
    /// `request_uri` query or form parameter — a PAR reference.
    pub request_uri: bool,
    /// `code_challenge` — PKCE.
    pub code_challenge: bool,
    /// `client_id` is an absolute URL rather than an opaque local id.
    pub client_id_is_url: bool,
}

/// A client that arrived at the wrong endpoint, and where it should have gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Misrouted {
    pub looks_like: Protocol,
    pub correct_path: &'static str,
}

/// Detect a client at a Mastodon path that is not speaking Mastodon.
///
/// Precedence, first match wins:
///
/// | # | Signal | Verdict |
/// |---|---|---|
/// | 1 | `request_uri` present | ATProtocol — only it mandates PAR |
/// | 2 | `DPoP` header + `client_id` is a URL | ATProtocol — PAR-less attempt |
/// | 3 | `DPoP` header | Solid-OIDC — DPoP without ATProtocol's URL client id |
/// | 4 | `client_id` is a URL, no DPoP | Solid-OIDC — client ID document |
/// | 5 | otherwise | Mastodon, correctly routed |
///
/// Rules 2 and 3 are the genuinely ambiguous pair: both protocols bind tokens to
/// a DPoP key. `client_id_is_url` breaks the tie because ATProtocol requires
/// client metadata at an HTTPS URL, while Mastodon issues opaque ids — and a
/// Solid client ID document is also a URL, which is why rule 1 (PAR) comes
/// first and rule 3 catches the remainder. Getting this wrong costs a confusing
/// error message, not a security decision, because it never routes.
pub fn detect_misrouted(shape: &RequestShape<'_>) -> Option<Misrouted> {
    if owner_of(shape.path) != Some(Protocol::Mastodon) {
        return None;
    }

    let authorize = shape.path.ends_with("authorize");

    if shape.request_uri {
        return Some(Misrouted {
            looks_like: Protocol::Atproto,
            correct_path: if authorize {
                "/oauth/atproto/authorize"
            } else {
                "/oauth/atproto/token"
            },
        });
    }

    if shape.dpop_header {
        let protocol = if shape.client_id_is_url {
            Protocol::Atproto
        } else {
            Protocol::SolidOidc
        };
        return Some(Misrouted {
            looks_like: protocol,
            correct_path: match (protocol, authorize) {
                (Protocol::Atproto, true) => "/oauth/atproto/authorize",
                (Protocol::Atproto, false) => "/oauth/atproto/token",
                (_, true) => "/oauth/solid/authorize",
                (_, false) => "/oauth/solid/token",
            },
        });
    }

    if shape.client_id_is_url {
        return Some(Misrouted {
            looks_like: Protocol::SolidOidc,
            correct_path: if authorize {
                "/oauth/solid/authorize"
            } else {
                "/oauth/solid/token"
            },
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(path: &str) -> RequestShape<'_> {
        RequestShape {
            path,
            ..Default::default()
        }
    }

    // --- one test per precedence branch (Phase 3 exit criterion) -----------

    #[test]
    fn branch_1_par_reference_means_atproto() {
        let shape = RequestShape {
            request_uri: true,
            ..at("/oauth/authorize")
        };
        let m = detect_misrouted(&shape).expect("detected");
        assert_eq!(m.looks_like, Protocol::Atproto);
        assert_eq!(m.correct_path, "/oauth/atproto/authorize");
    }

    #[test]
    fn branch_2_dpop_with_url_client_id_means_atproto() {
        let shape = RequestShape {
            dpop_header: true,
            client_id_is_url: true,
            ..at("/oauth/token")
        };
        let m = detect_misrouted(&shape).expect("detected");
        assert_eq!(m.looks_like, Protocol::Atproto);
        assert_eq!(m.correct_path, "/oauth/atproto/token");
    }

    #[test]
    fn branch_3_dpop_without_url_client_id_means_solid() {
        let shape = RequestShape {
            dpop_header: true,
            ..at("/oauth/token")
        };
        let m = detect_misrouted(&shape).expect("detected");
        assert_eq!(m.looks_like, Protocol::SolidOidc);
        assert_eq!(m.correct_path, "/oauth/solid/token");
    }

    #[test]
    fn branch_4_url_client_id_alone_means_solid() {
        let shape = RequestShape {
            client_id_is_url: true,
            ..at("/oauth/authorize")
        };
        let m = detect_misrouted(&shape).expect("detected");
        assert_eq!(m.looks_like, Protocol::SolidOidc);
        assert_eq!(m.correct_path, "/oauth/solid/authorize");
    }

    #[test]
    fn branch_5_a_real_mastodon_client_is_not_misrouted() {
        // Phanpy: PKCE, opaque client id, no DPoP. The case the predecessor
        // broke by putting ATProtocol at the bare path.
        let shape = RequestShape {
            code_challenge: true,
            ..at("/oauth/authorize")
        };
        assert_eq!(detect_misrouted(&shape), None);
    }

    // --- the table itself -------------------------------------------------

    #[test]
    fn detection_never_fires_on_a_protocols_own_path() {
        for (path, _) in ENDPOINTS {
            if owner_of(path) == Some(Protocol::Mastodon) {
                continue;
            }
            let shape = RequestShape {
                dpop_header: true,
                request_uri: true,
                client_id_is_url: true,
                ..at(path)
            };
            assert_eq!(
                detect_misrouted(&shape),
                None,
                "{path} is correctly routed; detection must stay silent"
            );
        }
    }

    #[test]
    fn every_suggested_path_is_a_real_endpoint() {
        let shapes = [
            RequestShape {
                request_uri: true,
                ..at("/oauth/authorize")
            },
            RequestShape {
                request_uri: true,
                ..at("/oauth/token")
            },
            RequestShape {
                dpop_header: true,
                client_id_is_url: true,
                ..at("/oauth/authorize")
            },
            RequestShape {
                dpop_header: true,
                client_id_is_url: true,
                ..at("/oauth/token")
            },
            RequestShape {
                dpop_header: true,
                ..at("/oauth/authorize")
            },
            RequestShape {
                dpop_header: true,
                ..at("/oauth/token")
            },
            RequestShape {
                client_id_is_url: true,
                ..at("/oauth/authorize")
            },
            RequestShape {
                client_id_is_url: true,
                ..at("/oauth/token")
            },
        ];
        for shape in shapes {
            let m = detect_misrouted(&shape).expect("should detect");
            assert!(
                owner_of(m.correct_path).is_some(),
                "suggested {} is not a mounted endpoint",
                m.correct_path
            );
            assert_eq!(
                owner_of(m.correct_path),
                Some(m.looks_like),
                "suggested path must belong to the detected protocol"
            );
        }
    }

    #[test]
    fn mastodon_owns_the_bare_paths() {
        assert_eq!(owner_of("/oauth/authorize"), Some(Protocol::Mastodon));
        assert_eq!(owner_of("/oauth/token"), Some(Protocol::Mastodon));
    }

    #[test]
    fn par_is_not_on_a_bare_path() {
        assert_eq!(
            owner_of("/oauth/par"),
            None,
            "PAR is reached through discovery"
        );
        assert_eq!(owner_of("/oauth/atproto/par"), Some(Protocol::Atproto));
    }
}
