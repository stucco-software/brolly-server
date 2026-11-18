//! Client assertions (stage 2, F): how a confidential client authenticates.
//!
//! A confidential client carries `client_assertion_type=
//! urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a
//! `client_assertion` JWT at PAR and at the token endpoint — `alg: ES256`,
//! `aud` = brolly's issuer, `iat`, a single-use `jti`, signed by a key in the
//! client's JWKS. Stage 0 refused confidential clients rather than accept an
//! unverified assertion (S6); this module is the verification that inverts
//! that argument (the spec's decision F): verified, an assertion is the
//! profile's own client authentication, and the only kind it trusts with long
//! sessions.
//!
//! The `jti` is spent the moment the assertion verifies — the DPoP discipline
//! (`Unspent` in `brolly_identity::dpop`), for the DPoP reason: a captured
//! assertion must not be retryable until one attempt works.

use brolly_identity::dpop::MAX_JTI_BYTES;
use brolly_identity::dpop::{PublicJwk, thumbprint};
use serde::Deserialize;
use sqlx::PgPool;

use crate::client_metadata::{ClientJwks, verifying_key};

/// The `client_assertion_type` this profile accepts (RFC 7523): the only one
/// the ATProto OAuth profile names.
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How far an assertion's `iat` may drift from our clock, in seconds.
///
/// The same ±60 s the DPoP proofs on these same endpoints already carry
/// (`dpop::MAX_AGE_SECONDS`): one clock discipline per client, not one per
/// credential.
pub const MAX_AGE_SECONDS: i64 = 60;

/// Why a client assertion was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionError {
    /// Not a jwt-bearer assertion, or not one that verified. Every reason
    /// names the rule, never anything fetched — it is safe to show the
    /// caller as `invalid_client`.
    Refused(&'static str),
    /// The `(jkt, jti)` pair was already spent: a replayed assertion.
    Replayed,
    /// The store failed. A server fault, not the client's — callers must not
    /// answer it as `invalid_client`. The detail is a string, the
    /// `DpopError::Storage` rule: the operator reads it, the caller never
    /// compares against it.
    Storage(String),
}

impl std::fmt::Display for AssertionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssertionError::Refused(rule) => f.write_str(rule),
            AssertionError::Replayed => {
                f.write_str("this assertion, or one with the same jti, was already used")
            }
            AssertionError::Storage(e) => write!(f, "recording the assertion failed: {e}"),
        }
    }
}

impl std::error::Error for AssertionError {}

/// A verified client assertion: the JWK thumbprint of the key that signed it.
///
/// This is the `client_jkt` a session is bound to (stage 2, F) — the same key
/// must re-appear at the token endpoint, and its leaving the client's JWKS
/// revokes the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAssertion {
    pub jkt: String,
}

/// A verified assertion whose `jti` has not been recorded yet.
///
/// The `Unspent` pattern from `brolly_identity::dpop`: the thumbprint is not
/// handed out until the `jti` is spent, so no caller can bind a session to a
/// key whose assertion might still be replayed.
pub struct UnspentAssertion {
    jkt: String,
    jti: String,
    iat: i64,
}

/// Record an assertion's `jti` and prune expired ones, in one statement.
///
/// `$3` is the row's expiry and `$4` the prune cutoff. Both come from the
/// application's clock, the `dpop_jti` rule (S7): that is the clock that
/// decides the assertion's freshness, and a prune by a database clock running
/// ahead would forget a row the application still counts.
const SPEND_ASSERTION_JTI: &str = "\
    WITH pruned AS (DELETE FROM atproto_used_assertion_jtis WHERE expires_at < to_timestamp($4)) \
    INSERT INTO atproto_used_assertion_jtis (jkt, jti, expires_at) \
    VALUES ($1, $2, to_timestamp($3)) \
    ON CONFLICT DO NOTHING \
    RETURNING jti";

impl UnspentAssertion {
    /// Record this assertion's `jti` and hand over the thumbprint.
    ///
    /// **An assertion is spent as soon as it verifies, even if the request
    /// then fails**, the DPoP discipline: RFC 7523 counts a `jti` as used
    /// once presented. Returns [`AssertionError::Replayed`] if this key has
    /// already used this `jti`, and [`AssertionError::Storage`] if the
    /// assertion couldn't be recorded; callers must treat both as a refusal.
    pub async fn spend(self, pool: &PgPool, now: i64) -> Result<ClientAssertion, AssertionError> {
        let recorded: Option<String> = sqlx::query_scalar(SPEND_ASSERTION_JTI)
            .bind(self.jkt.as_str())
            .bind(self.jti.as_str())
            .bind(self.iat.saturating_add(MAX_AGE_SECONDS))
            .bind(now.saturating_sub(MAX_AGE_SECONDS))
            .fetch_optional(pool)
            .await
            .map_err(|e| AssertionError::Storage(e.to_string()))?;
        match recorded {
            Some(_) => Ok(ClientAssertion { jkt: self.jkt }),
            None => Err(AssertionError::Replayed),
        }
    }
}

/// The assertion's header. `typ` is not checked: a client assertion is a
/// general-purpose JWT (RFC 7523), and the `aud` binding is what makes it
/// ours, the way `dpop+jwt` makes a proof one.
#[derive(Deserialize)]
struct Header {
    alg: String,
}

/// The `aud` claim: RFC 7523 allows a string or an array of strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum Aud {
    One(String),
    Many(Vec<String>),
}

impl Aud {
    fn names(&self, issuer: &str) -> bool {
        match self {
            Aud::One(aud) => aud == issuer,
            Aud::Many(auds) => auds.iter().any(|aud| aud == issuer),
        }
    }
}

#[derive(Deserialize)]
struct Claims {
    aud: Aud,
    iat: i64,
    jti: String,
}

/// Verify a client assertion against the client's key set.
///
/// Checks exactly what the profile requires (stage 2, F): `alg: ES256`, `aud`
/// naming this server's issuer, a fresh `iat`, a `jti`, and a signature by a
/// key in the JWKS — any key, since the thumbprint, not a `kid`, is what the
/// session binds to. Passing every check does not make the assertion usable
/// yet: it has not been checked for replay, so it comes back
/// [`UnspentAssertion`].
pub fn verify(
    jwks: &ClientJwks,
    assertion: &str,
    issuer: &str,
    now: i64,
) -> Result<UnspentAssertion, AssertionError> {
    use base64::Engine;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut parts = assertion.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AssertionError::Refused(
            "a client_assertion must be a JWT with three segments",
        ));
    };

    let header: Header = decode_part(header_b64)?;
    if header.alg != "ES256" {
        return Err(AssertionError::Refused(
            "a client_assertion must be signed with ES256",
        ));
    }

    let claims: Claims = decode_part(claims_b64)?;
    if !claims.aud.names(issuer) {
        return Err(AssertionError::Refused(
            "a client_assertion's aud must name this server's issuer",
        ));
    }
    // Saturating, the `dpop::verify` rule: `iat` is the client's claim and
    // i64::MIN is a legal JSON integer, so this is the one arithmetic in the
    // verifier an attacker chooses an operand of.
    if now.saturating_sub(claims.iat).saturating_abs() > MAX_AGE_SECONDS {
        return Err(AssertionError::Refused(
            "a client_assertion's iat is not fresh",
        ));
    }
    if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_BYTES {
        return Err(AssertionError::Refused(
            "a client_assertion's jti is missing or too long",
        ));
    }

    // Signed by a key in the client's JWKS. Any key: the thumbprint, not a
    // `kid`, is what identifies the signer to the session, so a `kid` that
    // disagrees with the verifying key cannot mislead.
    use p256::ecdsa::signature::Verifier;
    let signed = format!("{header_b64}.{claims_b64}");
    let signature_bytes = B64
        .decode(signature_b64)
        .map_err(|_| AssertionError::Refused("a client_assertion's signature is malformed"))?;
    // IEEE P1363, not DER — the DPoP convention this profile's keys follow.
    let signature = p256::ecdsa::Signature::from_slice(&signature_bytes)
        .map_err(|_| AssertionError::Refused("a client_assertion's signature is malformed"))?;
    let verified = jwks.keys().iter().find_map(|jwk: &PublicJwk| {
        let key = verifying_key(jwk)?;
        key.verify(signed.as_bytes(), &signature)
            .is_ok()
            .then_some(jwk)
    });
    let Some(signing_key) = verified else {
        return Err(AssertionError::Refused(
            "a client_assertion must be signed by a key in the client's JWKS",
        ));
    };

    Ok(UnspentAssertion {
        jkt: thumbprint(signing_key),
        jti: claims.jti,
        iat: claims.iat,
    })
}

fn decode_part<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, AssertionError> {
    use base64::Engine;
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = B64
        .decode(part)
        .map_err(|_| AssertionError::Refused("a client_assertion is malformed"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AssertionError::Refused("a client_assertion is malformed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_metadata::ClientJwks;
    use base64::Engine;
    use p256::ecdsa::signature::Signer;

    const ISSUER: &str = "https://brolly.test";

    fn key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap()
    }

    fn other_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[10u8; 32]).unwrap()
    }

    fn jwks_of(keys: &[p256::ecdsa::SigningKey]) -> ClientJwks {
        let value = serde_json::json!({
            "keys": keys.iter().map(|key| {
                let sec1 = key.verifying_key().to_sec1_bytes();
                serde_json::json!({
                    "kty": "EC", "crv": "P-256",
                    "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sec1[1..33]),
                    "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sec1[33..65]),
                })
            }).collect::<Vec<_>>()
        });
        ClientJwks::from_value(&value).unwrap()
    }

    /// An assertion as a confidential client produces one: ES256, aud, iat,
    /// jti — the four claims the profile requires, signed by `key`.
    fn assertion(key: &p256::ecdsa::SigningKey, aud: &str, jti: &str, iat: i64) -> String {
        let header = serde_json::json!({"alg": "ES256"});
        let claims = serde_json::json!({"aud": aud, "iat": iat, "jti": jti});
        let signed = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
        format!(
            "{signed}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn now() -> i64 {
        1_800_000_000
    }

    /// Refused for the rule named by `rule`. The assertion itself carries no
    /// `Debug` (the `Unspent` discipline), so a success is reported as one.
    fn refused(result: Result<UnspentAssertion, AssertionError>, rule: &str) {
        match result {
            Err(AssertionError::Refused(message)) => assert_eq!(
                message, rule,
                "refused for {message:?}, expected the {rule:?} rule"
            ),
            Err(other) => panic!("expected Refused for {rule:?}, got {other:?}"),
            Ok(_) => panic!("expected Refused for {rule:?}, got a verified assertion"),
        }
    }

    #[test]
    fn a_valid_assertion_verifies_and_names_its_key() {
        let key = key();
        let jwks = jwks_of(&[key.clone(), other_key()]);
        let unspent = verify(
            &jwks,
            &assertion(&key, ISSUER, "an-id", now()),
            ISSUER,
            now(),
        )
        .unwrap();
        assert_eq!(unspent.jkt, thumbprint_of(&key));
    }

    fn thumbprint_of(key: &p256::ecdsa::SigningKey) -> String {
        let sec1 = key.verifying_key().to_sec1_bytes();
        thumbprint(&PublicJwk {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sec1[1..33]),
            y: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sec1[33..65]),
        })
    }

    #[test]
    fn an_assertion_for_another_audience_is_refused() {
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        refused(
            verify(
                &jwks,
                &assertion(&key, "https://elsewhere.example", "an-id", now()),
                ISSUER,
                now(),
            ),
            "a client_assertion's aud must name this server's issuer",
        );
    }

    #[test]
    fn an_aud_array_naming_the_issuer_is_accepted() {
        // RFC 7523 allows aud as an array; a client that sends one naming us
        // among others has still addressed us.
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        let header = serde_json::json!({"alg": "ES256"});
        let claims = serde_json::json!({
            "aud": ["https://elsewhere.example", ISSUER],
            "iat": now(), "jti": "an-id"
        });
        let signed = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
        let token = format!(
            "{signed}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        assert!(verify(&jwks, &token, ISSUER, now()).is_ok());
    }

    #[test]
    fn a_stale_or_future_iat_is_refused() {
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        for iat in [now() - MAX_AGE_SECONDS - 1, now() + MAX_AGE_SECONDS + 1] {
            refused(
                verify(&jwks, &assertion(&key, ISSUER, "an-id", iat), ISSUER, now()),
                "a client_assertion's iat is not fresh",
            );
        }
    }

    #[test]
    fn an_absurd_iat_is_refused_not_panicked() {
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        refused(
            verify(
                &jwks,
                &assertion(&key, ISSUER, "an-id", i64::MIN),
                ISSUER,
                now(),
            ),
            "a client_assertion's iat is not fresh",
        );
    }

    #[test]
    fn a_key_outside_the_jwks_cannot_sign_an_assertion() {
        let jwks = jwks_of(&[key()]);
        refused(
            verify(
                &jwks,
                &assertion(&other_key(), ISSUER, "an-id", now()),
                ISSUER,
                now(),
            ),
            "a client_assertion must be signed by a key in the client's JWKS",
        );
    }

    #[test]
    fn a_tampered_assertion_does_not_verify() {
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        let token = assertion(&key, ISSUER, "an-id", now());
        // Re-sign the same payload with another key, keeping the header: the
        // signature is the only thing that changed.
        let mut parts = token.split('.');
        let header = parts.next().unwrap().to_owned();
        let claims = parts.next().unwrap().to_owned();
        let signed = format!("{header}.{claims}");
        let signature: p256::ecdsa::Signature = other_key().sign(signed.as_bytes());
        let forged = format!(
            "{signed}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        refused(
            verify(&jwks, &forged, ISSUER, now()),
            "a client_assertion must be signed by a key in the client's JWKS",
        );
    }

    #[test]
    fn a_non_es256_assertion_is_refused() {
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        let header = serde_json::json!({"alg": "RS256"});
        let claims = serde_json::json!({"aud": ISSUER, "iat": now(), "jti": "an-id"});
        let signed = format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).unwrap()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
        let token = format!(
            "{signed}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        refused(
            verify(&jwks, &token, ISSUER, now()),
            "a client_assertion must be signed with ES256",
        );
    }

    #[test]
    fn a_jti_of_exactly_the_limit_is_accepted() {
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        let jti = "a".repeat(MAX_JTI_BYTES);
        assert!(verify(&jwks, &assertion(&key, ISSUER, &jti, now()), ISSUER, now()).is_ok());
    }

    #[test]
    fn an_empty_jti_is_refused() {
        let key = key();
        let jwks = jwks_of(std::slice::from_ref(&key));
        refused(
            verify(&jwks, &assertion(&key, ISSUER, "", now()), ISSUER, now()),
            "a client_assertion's jti is missing or too long",
        );
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        let jwks = jwks_of(&[key()]);
        for input in ["", "not-a-jwt", "a.b", "a.b.c.d"] {
            assert!(verify(&jwks, input, ISSUER, now()).is_err(), "{input:?}");
        }
    }
}
