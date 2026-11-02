//! Lifting a credential off a request.
//!
//! **This is the only place in the workspace that reads an `Authorization`
//! header or a session cookie**, enforced by `server/tests/architecture.rs`.
//! The predecessor had four independent parsing paths — one each for
//! Solid-OIDC, ATProtocol, Mastodon and sessions — and every handler that
//! wanted to know who was calling reimplemented the question.
//!
//! Deliberately takes `&str`, not an HTTP type, so it is pure and the
//! precedence is testable without constructing a request.

use crate::subject::Credential;

/// Session cookie name. Shared so the server does not restate it.
///
/// `__Host-` (ADR 0018, control 6): the browser enforces that such a cookie
/// is `Secure`, has `Path=/` and no `Domain`, and refuses to let a
/// subdomain set one for the apex or for any other host. Without the prefix,
/// a page on `alice.<apex>` — same-site with the apex — could toss a
/// `Domain=<apex>` cookie of this name onto a visitor and hand them the
/// attacker's session. The rename also leaves every cookie minted under the
/// old name, including any minted on a member host before `0a465e0`, inert:
/// nothing reads `brolly_session` any more.
pub const SESSION_COOKIE: &str = "__Host-brolly_session";

/// Choose a credential from what the request carried.
///
/// Precedence: a proof-bound `DPoP` credential wins over a bearer token, which
/// wins over a cookie. A caller presenting both an `Authorization` header and a
/// session cookie is an API client in a browser, and the explicit header is the
/// one it meant.
pub fn credential(authorization: Option<&str>, cookie_header: Option<&str>) -> Option<Credential> {
    if let Some(header) = authorization {
        let (scheme, value) = header.split_once(' ')?;
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        // Scheme names are case-insensitive per RFC 7235.
        return match scheme.to_ascii_lowercase().as_str() {
            "dpop" => Some(Credential::Dpop {
                token: value.to_string(),
                // The proof travels in its own header; the caller supplies it.
                proof: String::new(),
            }),
            "bearer" => Some(Credential::Bearer(value.to_string())),
            _ => None,
        };
    }

    let cookie_header = cookie_header?;
    cookie_header
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| Credential::Session(value.to_string()))
}

/// Attach the DPoP proof from its own header.
pub fn with_proof(credential: Credential, proof: Option<&str>) -> Credential {
    match (credential, proof) {
        (Credential::Dpop { token, .. }, Some(proof)) => Credential::Dpop {
            token,
            proof: proof.to_string(),
        },
        (other, _) => other,
    }
}

/// Extract the username from a `Host` header, given the instance's base domain.
///
/// Returns `None` for the apex, for a foreign host, and for a nested subdomain —
/// `evil.alice.brolly.id` must not resolve to `alice`.
pub fn subdomain_user(host: &str, base_domain: &str) -> Option<String> {
    // Strip the port; hosts arrive as `alice.brolly.id:3000` in development.
    let host = host.split(':').next()?.trim().to_ascii_lowercase();
    let base = base_domain.to_ascii_lowercase();

    let username = host.strip_suffix(&format!(".{base}"))?;
    let valid = !username.is_empty()
        && !username.contains('.')
        && username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    valid.then_some(username.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpop_outranks_bearer_and_cookie() {
        let c = credential(Some("DPoP abc"), Some("__Host-brolly_session=xyz")).unwrap();
        assert_eq!(
            c,
            Credential::Dpop {
                token: "abc".into(),
                proof: String::new()
            }
        );
    }

    #[test]
    fn an_explicit_header_outranks_a_cookie() {
        let c = credential(Some("Bearer abc"), Some("__Host-brolly_session=xyz")).unwrap();
        assert_eq!(c, Credential::Bearer("abc".into()));
    }

    #[test]
    fn scheme_names_are_case_insensitive() {
        assert!(matches!(
            credential(Some("bearer abc"), None),
            Some(Credential::Bearer(_))
        ));
        assert!(matches!(
            credential(Some("dpop abc"), None),
            Some(Credential::Dpop { .. })
        ));
    }

    #[test]
    fn the_cookie_is_found_among_others() {
        let c = credential(None, Some("theme=dark; __Host-brolly_session=xyz; other=1")).unwrap();
        assert_eq!(c, Credential::Session("xyz".into()));
    }

    #[test]
    fn nothing_useful_yields_nothing() {
        assert_eq!(credential(None, None), None);
        assert_eq!(credential(Some("Basic abc"), None), None);
        assert_eq!(credential(Some("Bearer "), None), None);
        assert_eq!(credential(None, Some("theme=dark")), None);
    }

    #[test]
    fn a_subdomain_resolves_to_its_user() {
        assert_eq!(
            subdomain_user("alice.brolly.id", "brolly.id").as_deref(),
            Some("alice")
        );
        assert_eq!(
            subdomain_user("alice.brolly.id:3000", "brolly.id").as_deref(),
            Some("alice")
        );
        assert_eq!(
            subdomain_user("ALICE.BROLLY.ID", "brolly.id").as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn the_apex_is_not_a_user() {
        assert_eq!(subdomain_user("brolly.id", "brolly.id"), None);
    }

    #[test]
    fn a_nested_subdomain_is_not_a_user() {
        // Must not resolve to "alice", or a hostname anyone can point at us
        // would impersonate a member.
        assert_eq!(subdomain_user("evil.alice.brolly.id", "brolly.id"), None);
    }

    #[test]
    fn a_foreign_host_is_not_a_user() {
        assert_eq!(subdomain_user("alice.example.com", "brolly.id"), None);
        assert_eq!(subdomain_user("notbrolly.id", "brolly.id"), None);
    }

    #[test]
    fn the_old_cookie_name_is_not_a_credential() {
        // ADR 0018: nothing reads `brolly_session` any more — a cookie minted
        // on a member host before `0a465e0`, or tossed by a member page, is
        // inert on the pod and the outbox as much as on the apex.
        assert!(credential(None, Some("brolly_session=xyz")).is_none());
        assert!(credential(None, Some("__Host-brolly_session=xyz")).is_some());
    }
}
