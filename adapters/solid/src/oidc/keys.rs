//! The provider's ES256 signing key and its JWKS document.
//!
//! Signing is hand-rolled on `p256` rather than a JWT library, deliberately: the
//! DPoP verifier next door already does ECDSA on `p256` with IEEE P1363
//! signatures, and running two crates with different signature conventions in
//! one auth path is how the DER/P1363 confusion gets in. One curve, one crate,
//! one encoding.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    Malformed(String),
    BadSignature,
    /// Signed by a key we do not recognise.
    UnknownKey(String),
    Expired,
    /// A claim the caller required was absent or wrong.
    Claim(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Malformed(m) => write!(f, "malformed token: {m}"),
            JwtError::BadSignature => write!(f, "signature does not verify"),
            JwtError::UnknownKey(k) => write!(f, "unknown signing key {k}"),
            JwtError::Expired => write!(f, "token has expired"),
            JwtError::Claim(c) => write!(f, "claim check failed: {c}"),
        }
    }
}

impl std::error::Error for JwtError {}

/// The provider's signing key.
pub struct ProviderKey {
    signing: SigningKey,
    /// Key id, published in the JWKS so a verifier can pick the right key
    /// across a rotation.
    pub kid: String,
}

/// One public key, as published in `/oauth/solid/jwks`.
#[derive(Debug, Clone, Serialize)]
pub struct PublicJwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub alg: &'static str,
    #[serde(rename = "use")]
    pub key_use: &'static str,
    pub kid: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<PublicJwk>,
}

impl ProviderKey {
    /// Generate a fresh key.
    pub fn generate() -> Self {
        // Draw the scalar from the OS RNG and retry on the astronomically
        // unlikely out-of-range draw, rather than pinning an RNG type that
        // p256 and rand disagree about across versions.
        loop {
            let bytes: [u8; 32] = rand::random();
            if let Ok(signing) = SigningKey::from_slice(&bytes) {
                return Self::from_signing_key(signing);
            }
        }
    }

    /// Load from stored PKCS#8 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JwtError> {
        let signing =
            SigningKey::from_slice(bytes).map_err(|e| JwtError::Malformed(e.to_string()))?;
        Ok(Self::from_signing_key(signing))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing.to_bytes().to_vec()
    }

    fn from_signing_key(signing: SigningKey) -> Self {
        let (x, y) = coordinates(signing.verifying_key());
        // The kid is derived from the key rather than random, so the same key
        // always publishes the same id — a restart must not orphan live tokens.
        let kid = B64.encode(Sha256::digest(format!("{x}{y}").as_bytes()));
        Self { signing, kid }
    }

    pub fn public_jwk(&self) -> PublicJwk {
        let (x, y) = coordinates(self.signing.verifying_key());
        PublicJwk {
            kty: "EC",
            crv: "P-256",
            alg: "ES256",
            key_use: "sig",
            kid: self.kid.clone(),
            x,
            y,
        }
    }

    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![self.public_jwk()],
        }
    }

    /// Sign a claims object as a compact JWS.
    pub fn sign(&self, claims: &serde_json::Value) -> Result<String, JwtError> {
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": self.kid,
        });
        let signed = format!(
            "{}.{}",
            B64.encode(
                serde_json::to_vec(&header).map_err(|e| JwtError::Malformed(e.to_string()))?
            ),
            B64.encode(serde_json::to_vec(claims).map_err(|e| JwtError::Malformed(e.to_string()))?)
        );
        let signature: Signature = self.signing.sign(signed.as_bytes());
        // P1363, matching the DPoP verifier.
        Ok(format!("{signed}.{}", B64.encode(signature.to_bytes())))
    }

    /// Verify a token this provider issued and return its claims.
    ///
    /// `now` is passed rather than read so expiry is testable without sleeping.
    pub fn verify(&self, token: &str, now: i64) -> Result<serde_json::Value, JwtError> {
        verify_with(self.signing.verifying_key(), &self.kid, token, now)
    }
}

fn coordinates(key: &VerifyingKey) -> (String, String) {
    let sec1 = key.to_sec1_bytes();
    // SEC1 uncompressed: 0x04 || x || y.
    (B64.encode(&sec1[1..33]), B64.encode(&sec1[33..65]))
}

fn verify_with(
    key: &VerifyingKey,
    expected_kid: &str,
    token: &str,
    now: i64,
) -> Result<serde_json::Value, JwtError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed("expected three JWS segments".into()));
    };

    let header: serde_json::Value = serde_json::from_slice(
        &B64.decode(header_b64)
            .map_err(|e| JwtError::Malformed(e.to_string()))?,
    )
    .map_err(|e| JwtError::Malformed(e.to_string()))?;

    if header["alg"] != "ES256" {
        return Err(JwtError::Malformed(format!("alg {}", header["alg"])));
    }
    // Refuse a token signed by some other key even if the signature is valid
    // for it — this is what makes rotation safe.
    if header["kid"].as_str() != Some(expected_kid) {
        return Err(JwtError::UnknownKey(
            header["kid"].as_str().unwrap_or_default().to_string(),
        ));
    }

    let signature = Signature::from_slice(
        &B64.decode(signature_b64)
            .map_err(|e| JwtError::Malformed(e.to_string()))?,
    )
    .map_err(|_| JwtError::BadSignature)?;

    key.verify(format!("{header_b64}.{claims_b64}").as_bytes(), &signature)
        .map_err(|_| JwtError::BadSignature)?;

    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(claims_b64)
            .map_err(|e| JwtError::Malformed(e.to_string()))?,
    )
    .map_err(|e| JwtError::Malformed(e.to_string()))?;

    match claims["exp"].as_i64() {
        Some(exp) if exp <= now => return Err(JwtError::Expired),
        Some(_) => {}
        None => return Err(JwtError::Claim("exp is required".into())),
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> ProviderKey {
        ProviderKey::from_bytes(&[3u8; 32]).unwrap()
    }

    #[test]
    fn a_signed_token_verifies() {
        let k = key();
        let token = k.sign(&json!({"sub": "alice", "exp": 2000})).unwrap();
        let claims = k.verify(&token, 1000).unwrap();
        assert_eq!(claims["sub"], "alice");
    }

    #[test]
    fn an_expired_token_is_refused() {
        let k = key();
        let token = k.sign(&json!({"sub": "alice", "exp": 500})).unwrap();
        assert_eq!(k.verify(&token, 1000), Err(JwtError::Expired));
    }

    #[test]
    fn a_token_without_exp_is_refused() {
        // An access token that never expires is a credential nobody can revoke.
        let k = key();
        let token = k.sign(&json!({"sub": "alice"})).unwrap();
        assert!(matches!(k.verify(&token, 1000), Err(JwtError::Claim(_))));
    }

    #[test]
    fn a_token_from_another_provider_is_refused() {
        let mine = key();
        let theirs = ProviderKey::from_bytes(&[9u8; 32]).unwrap();
        let token = theirs.sign(&json!({"sub": "alice", "exp": 2000})).unwrap();
        assert!(matches!(
            mine.verify(&token, 1000),
            Err(JwtError::UnknownKey(_))
        ));
    }

    #[test]
    fn a_tampered_payload_fails_verification() {
        let k = key();
        let token = k.sign(&json!({"sub": "alice", "exp": 2000})).unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        parts[1] = B64.encode(serde_json::to_vec(&json!({"sub": "mallory", "exp": 2000})).unwrap());
        assert_eq!(
            k.verify(&parts.join("."), 1000),
            Err(JwtError::BadSignature)
        );
    }

    #[test]
    fn the_kid_is_derived_from_the_key_not_random() {
        // A restart must not orphan tokens issued before it.
        let a = ProviderKey::from_bytes(&[3u8; 32]).unwrap();
        let b = ProviderKey::from_bytes(&[3u8; 32]).unwrap();
        assert_eq!(a.kid, b.kid);

        let other = ProviderKey::from_bytes(&[4u8; 32]).unwrap();
        assert_ne!(a.kid, other.kid);
    }

    #[test]
    fn a_generated_key_round_trips_through_storage() {
        let original = ProviderKey::generate();
        let restored = ProviderKey::from_bytes(&original.to_bytes()).unwrap();
        assert_eq!(original.kid, restored.kid);

        let token = original
            .sign(&json!({"sub": "alice", "exp": 2000}))
            .unwrap();
        assert!(restored.verify(&token, 1000).is_ok());
    }

    #[test]
    fn the_jwks_publishes_a_usable_public_key() {
        let k = key();
        let jwks = k.jwks();
        assert_eq!(jwks.keys.len(), 1);
        let published = &jwks.keys[0];
        assert_eq!(published.kty, "EC");
        assert_eq!(published.crv, "P-256");
        assert_eq!(published.alg, "ES256");
        assert_eq!(published.kid, k.kid);
        // 32 bytes base64url with no padding.
        assert_eq!(B64.decode(&published.x).unwrap().len(), 32);
        assert_eq!(B64.decode(&published.y).unwrap().len(), 32);
    }

    #[test]
    fn malformed_tokens_error_rather_than_panic() {
        let k = key();
        for bad in ["", "a.b", "a.b.c.d", "!!.??.$$"] {
            assert!(k.verify(bad, 1000).is_err());
        }
    }
}
