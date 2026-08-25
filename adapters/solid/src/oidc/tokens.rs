//! Access and ID tokens.
//!
//! An access token is **bound to the client's DPoP key** through the `cnf.jkt`
//! claim: presenting the token requires also presenting a proof signed by the
//! key whose thumbprint is recorded there. A token lifted off the wire, out of
//! a log, or out of a compromised store is inert without that key.
//!
//! Verification therefore takes both, and there is no path that checks one
//! without the other — see [`verify_access`].

use serde_json::json;

use super::dpop::{self, DpopError};
use super::keys::{JwtError, ProviderKey};

/// How long an access token lives. Short, because the client can refresh
/// silently with a stored key (no redirect), so there is no UX cost to it.
pub const ACCESS_TOKEN_TTL: i64 = 900;
/// ID tokens are read once at login.
pub const ID_TOKEN_TTL: i64 = 300;

#[derive(Debug)]
pub enum TokenError {
    Jwt(JwtError),
    Dpop(DpopError),
    /// The token is valid but was issued to a different DPoP key.
    WrongHolder,
    /// A DPoP-bound token presented without a proof.
    ProofRequired,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Jwt(e) => write!(f, "{e}"),
            TokenError::Dpop(e) => write!(f, "{e}"),
            TokenError::WrongHolder => {
                write!(f, "access token is bound to a different key")
            }
            TokenError::ProofRequired => {
                write!(f, "this access token requires a DPoP proof")
            }
        }
    }
}

impl std::error::Error for TokenError {}

impl From<JwtError> for TokenError {
    fn from(e: JwtError) -> Self {
        TokenError::Jwt(e)
    }
}

impl From<DpopError> for TokenError {
    fn from(e: DpopError) -> Self {
        TokenError::Dpop(e)
    }
}

/// What a verified access token tells us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessClaims {
    pub webid: String,
    pub client_id: String,
    pub scope: String,
}

/// Mint a DPoP-bound access token.
pub fn issue_access(
    key: &ProviderKey,
    issuer: &str,
    webid: &str,
    client_id: &str,
    scope: &str,
    jkt: &str,
    now: i64,
) -> Result<String, TokenError> {
    Ok(key.sign(&json!({
        "iss": issuer,
        // Solid-OIDC identifies the user by WebID in both sub and webid.
        "sub": webid,
        "webid": webid,
        "aud": "solid",
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        // RFC 9449 confirmation claim: the key this token is bound to.
        "cnf": {"jkt": jkt},
    }))?)
}

/// Mint an ID token.
pub fn issue_id_token(
    key: &ProviderKey,
    issuer: &str,
    webid: &str,
    client_id: &str,
    nonce: Option<&str>,
    now: i64,
) -> Result<String, TokenError> {
    let mut claims = json!({
        "iss": issuer,
        "sub": webid,
        "webid": webid,
        "aud": client_id,
        "iat": now,
        "exp": now + ID_TOKEN_TTL,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    Ok(key.sign(&claims)?)
}

/// Verify an access token **and** the proof that it belongs to this caller.
///
/// Both or neither: a token whose `cnf.jkt` does not match the proof's key was
/// not presented by its holder, and a bound token with no proof at all is
/// refused rather than downgraded to bearer semantics. Downgrading is the
/// mistake that makes DPoP decorative.
pub fn verify_access(
    key: &ProviderKey,
    token: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
) -> Result<AccessClaims, TokenError> {
    let claims = key.verify(token, now)?;

    let bound_to = claims["cnf"]["jkt"].as_str();
    if let Some(jkt) = bound_to {
        let Some(proof) = proof else {
            return Err(TokenError::ProofRequired);
        };
        let verified = dpop::verify(proof, method, url, Some(token), now)?;
        if verified.thumbprint != jkt {
            return Err(TokenError::WrongHolder);
        }
    }

    Ok(AccessClaims {
        webid: claims["webid"].as_str().unwrap_or_default().to_string(),
        client_id: claims["client_id"].as_str().unwrap_or_default().to_string(),
        scope: claims["scope"].as_str().unwrap_or_default().to_string(),
    })
}

/// The `/.well-known/openid-configuration` document.
///
/// The advertised paths come from [`brolly_identity::oauth`], which is the
/// authoritative endpoint map (ADR 0008) — clients discover endpoints from
/// here, so a value that disagrees with the router breaks every client that
/// trusts it.
pub fn discovery_document(issuer: &str) -> serde_json::Value {
    use brolly_identity::oauth::{Protocol, endpoints_for};

    let endpoint = |suffix: &str| {
        endpoints_for(Protocol::SolidOidc)
            .into_iter()
            .find(|p| p.ends_with(suffix))
            .map(|p| format!("{issuer}{p}"))
    };

    json!({
        "issuer": issuer,
        "authorization_endpoint": endpoint("authorize"),
        "token_endpoint": endpoint("token"),
        "registration_endpoint": endpoint("register"),
        "jwks_uri": format!("{issuer}/oauth/solid/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": ["none"],
        // PKCE is required by Solid-OIDC, and S256 is the only method we accept.
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "webid", "offline_access"],
        "claims_supported": ["sub", "webid", "iss", "aud", "exp", "iat"],
        "solid_oidc_supported": "https://solidproject.org/TR/solid-oidc",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    const ISSUER: &str = "https://brolly.id";
    const WEBID: &str = "https://alice.brolly.id/profile#me";
    const URL: &str = "https://alice.brolly.id/~/note";

    fn provider() -> ProviderKey {
        ProviderKey::from_bytes(&[3u8; 32]).unwrap()
    }

    fn client_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    fn proof_for(
        key: &SigningKey,
        method: &str,
        url: &str,
        token: Option<&str>,
        iat: i64,
    ) -> String {
        let sec1 = key.verifying_key().to_sec1_bytes();
        let jwk = json!({
            "kty": "EC", "crv": "P-256",
            "x": B64.encode(&sec1[1..33]),
            "y": B64.encode(&sec1[33..65]),
        });
        let header = json!({"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk});
        let mut claims = json!({"htm": method, "htu": url, "jti": "u", "iat": iat});
        if let Some(token) = token {
            claims["ath"] = json!(dpop::access_token_hash(token));
        }
        let signed = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(signed.as_bytes());
        format!("{signed}.{}", B64.encode(signature.to_bytes()))
    }

    fn jkt_of(key: &SigningKey) -> String {
        let sec1 = key.verifying_key().to_sec1_bytes();
        dpop::thumbprint(&dpop::PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: B64.encode(&sec1[1..33]),
            y: B64.encode(&sec1[33..65]),
        })
    }

    #[test]
    fn a_bound_token_verifies_with_its_own_proof() {
        let p = provider();
        let client = client_key(7);
        let token = issue_access(
            &p,
            ISSUER,
            WEBID,
            "urn:uuid:c",
            "webid",
            &jkt_of(&client),
            1000,
        )
        .unwrap();
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        let claims = verify_access(&p, &token, Some(&proof), "GET", URL, 1000).unwrap();
        assert_eq!(claims.webid, WEBID);
        assert_eq!(claims.scope, "webid");
    }

    #[test]
    fn a_stolen_token_is_useless_without_the_key() {
        // The property DPoP exists for.
        let p = provider();
        let owner = client_key(7);
        let thief = client_key(9);
        let token = issue_access(
            &p,
            ISSUER,
            WEBID,
            "urn:uuid:c",
            "webid",
            &jkt_of(&owner),
            1000,
        )
        .unwrap();

        let forged = proof_for(&thief, "GET", URL, Some(&token), 1000);
        assert!(matches!(
            verify_access(&p, &token, Some(&forged), "GET", URL, 1000),
            Err(TokenError::WrongHolder)
        ));
    }

    #[test]
    fn a_bound_token_without_a_proof_is_refused_not_downgraded() {
        // Falling back to bearer semantics here is what makes DPoP decorative.
        let p = provider();
        let client = client_key(7);
        let token = issue_access(
            &p,
            ISSUER,
            WEBID,
            "urn:uuid:c",
            "webid",
            &jkt_of(&client),
            1000,
        )
        .unwrap();
        assert!(matches!(
            verify_access(&p, &token, None, "GET", URL, 1000),
            Err(TokenError::ProofRequired)
        ));
    }

    #[test]
    fn a_proof_for_a_different_request_does_not_help() {
        let p = provider();
        let client = client_key(7);
        let token = issue_access(
            &p,
            ISSUER,
            WEBID,
            "urn:uuid:c",
            "webid",
            &jkt_of(&client),
            1000,
        )
        .unwrap();
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        assert!(matches!(
            verify_access(&p, &token, Some(&proof), "DELETE", URL, 1000),
            Err(TokenError::Dpop(_))
        ));
    }

    #[test]
    fn an_expired_access_token_is_refused() {
        let p = provider();
        let client = client_key(7);
        let token = issue_access(
            &p,
            ISSUER,
            WEBID,
            "urn:uuid:c",
            "webid",
            &jkt_of(&client),
            1000,
        )
        .unwrap();
        let later = 1000 + ACCESS_TOKEN_TTL + 1;
        let proof = proof_for(&client, "GET", URL, Some(&token), later);
        assert!(matches!(
            verify_access(&p, &token, Some(&proof), "GET", URL, later),
            Err(TokenError::Jwt(JwtError::Expired))
        ));
    }

    #[test]
    fn an_id_token_carries_the_webid() {
        let p = provider();
        let token = issue_id_token(&p, ISSUER, WEBID, "urn:uuid:c", Some("n-once"), 1000).unwrap();
        let claims = p.verify(&token, 1000).unwrap();

        // Solid-OIDC clients read either; both must be the WebID.
        assert_eq!(claims["sub"], WEBID);
        assert_eq!(claims["webid"], WEBID);
        assert_eq!(claims["aud"], "urn:uuid:c");
        assert_eq!(claims["nonce"], "n-once");
    }

    #[test]
    fn discovery_advertises_the_endpoints_the_router_mounts() {
        // If these drift, every client that discovers them breaks. The values
        // come from the authoritative map in brolly-identity (ADR 0008).
        use brolly_identity::oauth::owner_of;

        let doc = discovery_document(ISSUER);
        for field in [
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
        ] {
            let url = doc[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} missing"));
            let path = url.strip_prefix(ISSUER).expect("same origin");
            assert!(
                owner_of(path).is_some(),
                "{field} advertises {path}, which is not a mounted endpoint"
            );
        }
    }

    #[test]
    fn discovery_requires_pkce_and_dpop() {
        let doc = discovery_document(ISSUER);
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(doc["dpop_signing_alg_values_supported"], json!(["ES256"]));
        // Public clients only: a browser app cannot keep a secret.
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            json!(["none"])
        );
    }
}
