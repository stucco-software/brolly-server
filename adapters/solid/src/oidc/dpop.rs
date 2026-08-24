//! DPoP proof verification (RFC 9449).
//!
//! A DPoP proof binds a request to a key the client holds, so a stolen access
//! token is useless on its own. The proof is a JWT signed by the client's
//! private key, carrying its public key in the header.
//!
//! Two details are easy to get wrong and are the reason this is hand-verified
//! rather than passed to a general JWT library:
//!
//! * **Signatures are IEEE P1363** (`r || s`, 64 bytes) — what WebCrypto
//!   produces — not the DER encoding some JWT libraries expect. A verifier that
//!   assumes DER rejects every real browser client.
//! * **`ath` is conditional.** It binds the proof to a specific access token and
//!   appears on *resource* requests only; a proof sent to the token endpoint has
//!   no access token to bind to yet. Requiring it everywhere breaks login;
//!   never requiring it lets a proof for one token be replayed with another.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// How far a proof's `iat` may drift from our clock, in seconds.
///
/// RFC 9449 leaves this to the server. Sixty seconds tolerates ordinary clock
/// skew without leaving a replay window wide enough to matter.
pub const MAX_AGE_SECONDS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopError {
    Malformed(String),
    /// `typ` was not `dpop+jwt`. A plain JWT must not be accepted as a proof.
    WrongType,
    UnsupportedAlgorithm(String),
    BadSignature,
    /// `htm`/`htu` did not match the request the proof arrived on.
    WrongTarget {
        expected: String,
        found: String,
    },
    Expired,
    /// `ath` missing, or not the hash of the presented access token.
    TokenBindingFailed,
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DpopError::Malformed(m) => write!(f, "malformed DPoP proof: {m}"),
            DpopError::WrongType => write!(f, "proof is not typ=dpop+jwt"),
            DpopError::UnsupportedAlgorithm(a) => write!(f, "unsupported DPoP algorithm {a}"),
            DpopError::BadSignature => write!(f, "DPoP signature does not verify"),
            DpopError::WrongTarget { expected, found } => {
                write!(f, "DPoP proof is for {found}, not {expected}")
            }
            DpopError::Expired => write!(f, "DPoP proof is outside the freshness window"),
            DpopError::TokenBindingFailed => write!(f, "DPoP proof is not bound to this token"),
        }
    }
}

impl std::error::Error for DpopError {}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    jwk: PublicJwk,
}

/// The client's public key, as carried in the proof header.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    htm: String,
    htu: String,
    #[allow(dead_code)]
    jti: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
}

/// A verified proof.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedProof {
    /// JWK thumbprint (RFC 7638) of the proving key.
    ///
    /// This is the `jkt` an access token is bound to: the token and the proof
    /// must name the same key or the token was not presented by its holder.
    pub thumbprint: String,
    pub jwk: PublicJwk,
}

fn decode_part<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, DpopError> {
    let bytes = B64
        .decode(part)
        .map_err(|e| DpopError::Malformed(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| DpopError::Malformed(e.to_string()))
}

/// RFC 7638 JWK thumbprint: SHA-256 over the canonical member subset, in
/// lexicographic order, with no whitespace.
pub fn thumbprint(jwk: &PublicJwk) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

/// The `ath` value for an access token: base64url(SHA-256(token)).
pub fn access_token_hash(access_token: &str) -> String {
    B64.encode(Sha256::digest(access_token.as_bytes()))
}

fn verifying_key(jwk: &PublicJwk) -> Result<VerifyingKey, DpopError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(DpopError::UnsupportedAlgorithm(format!(
            "{} {}",
            jwk.kty, jwk.crv
        )));
    }
    let x = B64
        .decode(&jwk.x)
        .map_err(|e| DpopError::Malformed(e.to_string()))?;
    let y = B64
        .decode(&jwk.y)
        .map_err(|e| DpopError::Malformed(e.to_string()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(DpopError::Malformed(
            "EC coordinates are not 32 bytes".into(),
        ));
    }

    // SEC1 uncompressed point: 0x04 || x || y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| DpopError::Malformed(e.to_string()))
}

/// Verify a DPoP proof against the request it arrived on.
///
/// `access_token` is `Some` for resource requests, where the proof must carry a
/// matching `ath`, and `None` at the token endpoint, where there is no token to
/// bind to yet.
pub fn verify(
    proof: &str,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    now: i64,
) -> Result<VerifiedProof, DpopError> {
    let mut parts = proof.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopError::Malformed("expected three JWT segments".into()));
    };

    let header: Header = decode_part(header_b64)?;
    if header.typ != "dpop+jwt" {
        // Refusing anything else stops a general-purpose JWT the client holds
        // for another purpose from being replayed as a proof.
        return Err(DpopError::WrongType);
    }
    if header.alg != "ES256" {
        return Err(DpopError::UnsupportedAlgorithm(header.alg));
    }

    let key = verifying_key(&header.jwk)?;
    let signature_bytes = B64
        .decode(signature_b64)
        .map_err(|e| DpopError::Malformed(e.to_string()))?;
    // IEEE P1363, not DER — see the module docs.
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| DpopError::BadSignature)?;

    let signed = format!("{header_b64}.{claims_b64}");
    key.verify(signed.as_bytes(), &signature)
        .map_err(|_| DpopError::BadSignature)?;

    let claims: Claims = decode_part(claims_b64)?;

    if !claims.htm.eq_ignore_ascii_case(method) {
        return Err(DpopError::WrongTarget {
            expected: method.to_string(),
            found: claims.htm,
        });
    }
    if !htu_matches(&claims.htu, url) {
        return Err(DpopError::WrongTarget {
            expected: url.to_string(),
            found: claims.htu,
        });
    }
    if (now - claims.iat).abs() > MAX_AGE_SECONDS {
        return Err(DpopError::Expired);
    }

    match (access_token, claims.ath.as_deref()) {
        (Some(token), Some(ath)) if ath == access_token_hash(token) => {}
        (Some(_), _) => return Err(DpopError::TokenBindingFailed),
        // A proof at the token endpoint carries no ath, which is correct.
        (None, _) => {}
    }

    Ok(VerifiedProof {
        thumbprint: thumbprint(&header.jwk),
        jwk: header.jwk,
    })
}

/// Compare `htu` to the request URL, ignoring query and fragment per RFC 9449.
fn htu_matches(htu: &str, url: &str) -> bool {
    fn normalize(u: &str) -> &str {
        u.split(['?', '#']).next().unwrap_or(u)
    }
    normalize(htu) == normalize(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    fn make_proof(
        key: &SigningKey,
        method: &str,
        url: &str,
        iat: i64,
        ath: Option<&str>,
        typ: &str,
    ) -> String {
        // SEC1 uncompressed: 0x04 || x || y.
        let sec1 = key.verifying_key().to_sec1_bytes();
        assert_eq!(sec1[0], 0x04, "expected an uncompressed point");
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(&sec1[1..33]),
            "y": B64.encode(&sec1[33..65]),
        });
        let header = serde_json::json!({"alg": "ES256", "typ": typ, "jwk": jwk});
        let mut claims = serde_json::json!({
            "htm": method, "htu": url, "jti": "unique", "iat": iat
        });
        if let Some(ath) = ath {
            claims["ath"] = serde_json::Value::String(ath.to_string());
        }

        let signed = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(signed.as_bytes());
        // to_bytes() is P1363 — the format WebCrypto emits.
        format!("{signed}.{}", B64.encode(signature.to_bytes()))
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
    }

    const URL: &str = "https://alice.brolly.id/~/note";

    #[test]
    fn a_valid_resource_proof_verifies() {
        let token = "access-token";
        let proof = make_proof(
            &key(),
            "GET",
            URL,
            1000,
            Some(&access_token_hash(token)),
            "dpop+jwt",
        );
        let verified = verify(&proof, "GET", URL, Some(token), 1000).unwrap();
        assert!(!verified.thumbprint.is_empty());
    }

    #[test]
    fn a_token_endpoint_proof_needs_no_ath() {
        // The commonest login failure if a server requires ath everywhere.
        let proof = make_proof(
            &key(),
            "POST",
            "https://brolly.id/oauth/solid/token",
            1000,
            None,
            "dpop+jwt",
        );
        assert!(
            verify(
                &proof,
                "POST",
                "https://brolly.id/oauth/solid/token",
                None,
                1000
            )
            .is_ok()
        );
    }

    #[test]
    fn a_resource_proof_without_ath_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert_eq!(
            verify(&proof, "GET", URL, Some("access-token"), 1000),
            Err(DpopError::TokenBindingFailed)
        );
    }

    #[test]
    fn a_proof_for_a_different_token_is_refused() {
        // Otherwise a proof captured with one token could be replayed with
        // another the attacker also holds.
        let proof = make_proof(
            &key(),
            "GET",
            URL,
            1000,
            Some(&access_token_hash("some-other-token")),
            "dpop+jwt",
        );
        assert_eq!(
            verify(&proof, "GET", URL, Some("access-token"), 1000),
            Err(DpopError::TokenBindingFailed)
        );
    }

    #[test]
    fn a_proof_for_another_method_or_url_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(matches!(
            verify(&proof, "DELETE", URL, None, 1000),
            Err(DpopError::WrongTarget { .. })
        ));
        assert!(matches!(
            verify(&proof, "GET", "https://alice.brolly.id/~/other", None, 1000),
            Err(DpopError::WrongTarget { .. })
        ));
    }

    #[test]
    fn query_and_fragment_are_ignored_when_matching_htu() {
        // RFC 9449 compares the URL without query or fragment.
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(verify(&proof, "GET", &format!("{URL}?page=2"), None, 1000).is_ok());
    }

    #[test]
    fn a_stale_or_future_proof_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert_eq!(
            verify(&proof, "GET", URL, None, 5000),
            Err(DpopError::Expired)
        );
        assert_eq!(verify(&proof, "GET", URL, None, 0), Err(DpopError::Expired));
    }

    #[test]
    fn a_plain_jwt_is_not_a_proof() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "JWT");
        assert_eq!(
            verify(&proof, "GET", URL, None, 1000),
            Err(DpopError::WrongType)
        );
    }

    #[test]
    fn a_tampered_proof_fails_verification() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        let mut parts: Vec<&str> = proof.split('.').collect();
        let forged = B64.encode(
            serde_json::to_vec(&serde_json::json!({
                "htm": "DELETE", "htu": URL, "jti": "x", "iat": 1000
            }))
            .unwrap(),
        );
        parts[1] = &forged;
        assert_eq!(
            verify(&parts.join("."), "DELETE", URL, None, 1000),
            Err(DpopError::BadSignature)
        );
    }

    #[test]
    fn thumbprints_are_stable_and_key_specific() {
        let a = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        let first = verify(&a, "GET", URL, None, 1000).unwrap().thumbprint;
        let second = verify(&a, "GET", URL, None, 1000).unwrap().thumbprint;
        assert_eq!(first, second);

        let other = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let b = make_proof(&other, "GET", URL, 1000, None, "dpop+jwt");
        let different = verify(&b, "GET", URL, None, 1000).unwrap().thumbprint;
        assert_ne!(first, different, "the jkt must identify the key");
    }

    #[test]
    fn a_der_encoded_signature_is_rejected_not_accidentally_accepted() {
        // Guards the P1363 decision: if this ever starts passing, someone has
        // loosened signature parsing and browser clients may silently break.
        let key = key();
        let proof = make_proof(&key, "GET", URL, 1000, None, "dpop+jwt");
        let parts: Vec<&str> = proof.split('.').collect();
        let signature: Signature = key.sign(format!("{}.{}", parts[0], parts[1]).as_bytes());
        let der = B64.encode(signature.to_der().as_bytes());
        let rebuilt = format!("{}.{}.{}", parts[0], parts[1], der);
        assert_eq!(
            verify(&rebuilt, "GET", URL, None, 1000),
            Err(DpopError::BadSignature)
        );
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        for bad in ["", "a.b", "a.b.c.d", "not-base64.!!!.???"] {
            assert!(verify(bad, "GET", URL, None, 1000).is_err());
        }
    }
}
