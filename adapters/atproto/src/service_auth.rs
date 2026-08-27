//! Inter-service auth: short-lived JWTs scoped to a single method.
//!
//! When a PDS calls another service on a member's behalf — an AppView, a
//! labeler, a relay — it signs a token with the member's repo key. The receiver
//! resolves the DID, finds the same `did:key` published in the PLC document,
//! and verifies. No shared secret, no registration, no key exchange: the
//! identity that signs commits is the identity that makes the call.
//!
//! **`lxm` is the reason this is safe to hand out.** It names the one method
//! the token authorizes. Without it a token minted so an AppView could read a
//! profile would equally authorize deleting a repo, and the holder would be
//! whichever service you last talked to. Scope is not advisory here; a token
//! presented at the wrong method is refused.
//!
//! Signed with `ES256K` (secp256k1) — the repo key's curve — not the `ES256`
//! the Solid provider uses. Two curves in one codebase is a real hazard, so the
//! header names which one and the verifier checks it rather than assuming.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::json;

use crate::keys::SigningKey;

/// How long a service token lives.
///
/// One minute. These are minted per call and travel to a service that is about
/// to use them immediately; a longer window is replay surface with no benefit.
pub const TTL_SECONDS: i64 = 60;

#[derive(Debug, PartialEq, Eq)]
pub enum ServiceAuthError {
    Malformed(String),
    /// The algorithm was not the repo key's curve.
    WrongAlgorithm(String),
    BadSignature,
    Expired,
    /// Issued for a different service.
    WrongAudience {
        expected: String,
        found: String,
    },
    /// Issued for a different method — the `lxm` mismatch.
    WrongMethod {
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for ServiceAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceAuthError::Malformed(m) => write!(f, "malformed service token: {m}"),
            ServiceAuthError::WrongAlgorithm(a) => write!(f, "unexpected algorithm {a}"),
            ServiceAuthError::BadSignature => write!(f, "signature does not verify"),
            ServiceAuthError::Expired => write!(f, "service token has expired"),
            ServiceAuthError::WrongAudience { expected, found } => {
                write!(f, "token is for {found}, not {expected}")
            }
            ServiceAuthError::WrongMethod { expected, found } => {
                write!(f, "token authorizes {found}, not {expected}")
            }
        }
    }
}

impl std::error::Error for ServiceAuthError {}

/// What a verified service token establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceClaims {
    /// The member the call is on behalf of.
    pub issuer: String,
    /// The service being called.
    pub audience: String,
    /// The single method authorized.
    pub method: String,
}

/// Mint a token for one call to one method.
///
/// `now` is passed rather than read so expiry is testable without sleeping.
pub fn issue(
    key: &SigningKey,
    issuer_did: &str,
    audience_did: &str,
    method: &str,
    now: i64,
) -> Result<String, ServiceAuthError> {
    // `typ: JWT` and the curve named explicitly. A verifier that assumes the
    // algorithm is how curve confusion gets in.
    let header = json!({"alg": "ES256K", "typ": "JWT"});
    let claims = json!({
        "iss": issuer_did,
        "aud": audience_did,
        "lxm": method,
        "iat": now,
        "exp": now + TTL_SECONDS,
        // A nonce, so two tokens for the same call in the same second differ
        // and a receiver can deduplicate.
        "jti": B64.encode(rand::random::<[u8; 16]>()),
    });

    let signed = format!(
        "{}.{}",
        B64.encode(
            serde_json::to_vec(&header).map_err(|e| ServiceAuthError::Malformed(e.to_string()))?
        ),
        B64.encode(
            serde_json::to_vec(&claims).map_err(|e| ServiceAuthError::Malformed(e.to_string()))?
        )
    );
    let signature = key
        .sign(signed.as_bytes())
        .map_err(|e| ServiceAuthError::Malformed(e.to_string()))?;

    Ok(format!("{signed}.{}", B64.encode(signature)))
}

/// Verify a token, against the issuer's published `did:key`.
///
/// `expected_audience` and `expected_method` are both required. A verifier that
/// checks the signature and not the scope has verified that *someone* signed
/// something, which is not the question being asked.
pub fn verify(
    token: &str,
    issuer_did_key: &str,
    expected_audience: &str,
    expected_method: &str,
    now: i64,
) -> Result<ServiceClaims, ServiceAuthError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ServiceAuthError::Malformed(
            "expected three JWT segments".into(),
        ));
    };

    let header: serde_json::Value = serde_json::from_slice(
        &B64.decode(header_b64)
            .map_err(|e| ServiceAuthError::Malformed(e.to_string()))?,
    )
    .map_err(|e| ServiceAuthError::Malformed(e.to_string()))?;

    // Checked, not assumed: this codebase already signs with two curves.
    if header["alg"] != "ES256K" {
        return Err(ServiceAuthError::WrongAlgorithm(
            header["alg"].as_str().unwrap_or_default().to_string(),
        ));
    }

    let signature = B64
        .decode(signature_b64)
        .map_err(|e| ServiceAuthError::Malformed(e.to_string()))?;
    atrium_crypto::verify::verify_signature(
        issuer_did_key,
        format!("{header_b64}.{claims_b64}").as_bytes(),
        &signature,
    )
    .map_err(|_| ServiceAuthError::BadSignature)?;

    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(claims_b64)
            .map_err(|e| ServiceAuthError::Malformed(e.to_string()))?,
    )
    .map_err(|e| ServiceAuthError::Malformed(e.to_string()))?;

    match claims["exp"].as_i64() {
        Some(exp) if exp <= now => return Err(ServiceAuthError::Expired),
        Some(_) => {}
        None => return Err(ServiceAuthError::Malformed("exp is required".into())),
    }

    let audience = claims["aud"].as_str().unwrap_or_default().to_string();
    if audience != expected_audience {
        return Err(ServiceAuthError::WrongAudience {
            expected: expected_audience.to_string(),
            found: audience,
        });
    }

    let method = claims["lxm"].as_str().unwrap_or_default().to_string();
    if method != expected_method {
        return Err(ServiceAuthError::WrongMethod {
            expected: expected_method.to_string(),
            found: method,
        });
    }

    Ok(ServiceClaims {
        issuer: claims["iss"].as_str().unwrap_or_default().to_string(),
        audience,
        method,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const AUDIENCE: &str = "did:web:api.bsky.app";
    const METHOD: &str = "app.bsky.actor.getProfile";
    const NOW: i64 = 1_724_000_000;

    #[test]
    fn a_token_verifies_against_the_issuers_published_key() {
        // The whole model: no shared secret, no registration. The key that
        // signs commits is the key that makes the call.
        let key = SigningKey::generate();
        let token = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).expect("issue");

        let claims = verify(&token, &key.did_key(), AUDIENCE, METHOD, NOW).expect("verify");
        assert_eq!(claims.issuer, ISSUER);
        assert_eq!(claims.audience, AUDIENCE);
        assert_eq!(claims.method, METHOD);
    }

    #[test]
    fn a_token_for_one_method_does_not_authorize_another() {
        // The reason `lxm` exists. Without it, a token minted so an AppView
        // could read a profile would equally authorize deleting the repo.
        let key = SigningKey::generate();
        let token = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).unwrap();

        assert_eq!(
            verify(
                &token,
                &key.did_key(),
                AUDIENCE,
                "com.atproto.repo.deleteRecord",
                NOW
            ),
            Err(ServiceAuthError::WrongMethod {
                expected: "com.atproto.repo.deleteRecord".into(),
                found: METHOD.into(),
            })
        );
    }

    #[test]
    fn a_token_for_one_service_does_not_authorize_another() {
        // Otherwise the holder is whichever service you last talked to.
        let key = SigningKey::generate();
        let token = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).unwrap();

        assert!(matches!(
            verify(&token, &key.did_key(), "did:web:evil.example", METHOD, NOW),
            Err(ServiceAuthError::WrongAudience { .. })
        ));
    }

    #[test]
    fn a_token_expires() {
        let key = SigningKey::generate();
        let token = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).unwrap();

        assert_eq!(
            verify(
                &token,
                &key.did_key(),
                AUDIENCE,
                METHOD,
                NOW + TTL_SECONDS + 1
            ),
            Err(ServiceAuthError::Expired)
        );
        // And is still good just inside the window.
        assert!(
            verify(
                &token,
                &key.did_key(),
                AUDIENCE,
                METHOD,
                NOW + TTL_SECONDS - 1
            )
            .is_ok()
        );
    }

    #[test]
    fn the_window_is_short_because_these_are_minted_per_call() {
        // `black_box` so the comparison is not folded away — the same trap
        // the federation tripwire hit. A budget assertion that optimizes to
        // nothing is worse than no assertion, because it reads as covered.
        assert!(
            std::hint::black_box(TTL_SECONDS) <= 60,
            "a long-lived service token is replay surface with no benefit"
        );
    }

    #[test]
    fn another_key_cannot_forge_a_token() {
        let key = SigningKey::generate();
        let impostor = SigningKey::generate();
        let token = issue(&impostor, ISSUER, AUDIENCE, METHOD, NOW).unwrap();

        assert_eq!(
            verify(&token, &key.did_key(), AUDIENCE, METHOD, NOW),
            Err(ServiceAuthError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_claim_invalidates_the_signature() {
        // Specifically: editing `lxm` to widen the scope must not survive.
        let key = SigningKey::generate();
        let token = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let widened = B64.encode(
            serde_json::to_vec(&json!({
                "iss": ISSUER, "aud": AUDIENCE,
                "lxm": "com.atproto.repo.deleteRecord",
                "iat": NOW, "exp": NOW + TTL_SECONDS,
            }))
            .unwrap(),
        );
        parts[1] = &widened;
        let forged = parts.join(".");

        assert_eq!(
            verify(
                &forged,
                &key.did_key(),
                AUDIENCE,
                "com.atproto.repo.deleteRecord",
                NOW
            ),
            Err(ServiceAuthError::BadSignature)
        );
    }

    #[test]
    fn the_curve_is_checked_rather_than_assumed() {
        // This codebase signs with two curves — ES256 for the Solid provider,
        // ES256K here. A verifier that assumes is how curve confusion gets in.
        let key = SigningKey::generate();
        let token = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let wrong = B64.encode(serde_json::to_vec(&json!({"alg": "ES256", "typ": "JWT"})).unwrap());
        parts[0] = &wrong;
        let swapped = parts.join(".");

        assert!(matches!(
            verify(&swapped, &key.did_key(), AUDIENCE, METHOD, NOW),
            Err(ServiceAuthError::WrongAlgorithm(_))
        ));
    }

    #[test]
    fn two_tokens_for_the_same_call_differ() {
        // The `jti` nonce, so a receiver can deduplicate.
        let key = SigningKey::generate();
        let first = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).unwrap();
        let second = issue(&key, ISSUER, AUDIENCE, METHOD, NOW).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn a_malformed_token_is_refused_rather_than_guessed() {
        let key = SigningKey::generate();
        for bad in ["", "not-a-token", "a.b", "a.b.c.d"] {
            assert!(verify(bad, &key.did_key(), AUDIENCE, METHOD, NOW).is_err());
        }
    }
}
