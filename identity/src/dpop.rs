//! DPoP proof verification (RFC 9449).
//!
//! Lives in `identity` rather than beside one protocol because **two** of them
//! bind tokens this way: Solid-OIDC and ATProtocol. Adapters may not depend on
//! each other (`server/tests/architecture.rs`), so the alternative was a second
//! copy — and a second copy of a verifier is how one of them quietly stops
//! matching the other, which is the exact failure the AS2 namespace split
//! produced in the predecessor.
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
//!
//! A proof is also **single-use**. `verify` can't know whether it has seen a
//! proof before, because that needs the database. So it returns [`Unspent`],
//! and the only way to reach the value inside is [`Unspent::spend`], which
//! records the proof's `jti`. A call site can't read the key thumbprint, or a
//! bound Solid token's claims, without spending the proof first.
//!
//! A proof may also carry a **nonce** (RFC 9449 §8.1) — a value the server
//! hands out and later demands, which is what stops a client from minting a
//! pile of proofs in advance. Nonces are per-protocol: ATProtocol's profile
//! requires them, Solid-OIDC does not, so [`verify`] takes the accepted
//! values as an optional argument and the check is simply off when it is
//! `None`. The values themselves are time buckets keyed by an instance
//! secret ([`current_nonce`], [`accepted_nonces`]) — HMACs rather than stored
//! rows, so any process of the instance verifies the same nonces with no
//! hot-path storage and no rotation job.
//!
//! That guarantee covers only what arrives inside the `Unspent`. A caller that
//! learns something from elsewhere before checking the proof is not held to it
//! by the compiler: XRPC's `token_caller` gets the grant, and so the `user_id`,
//! from `brolly_atproto::oauth::verify_token` before any proof is looked at,
//! and spends only by convention. Closing that is a stage 2 follow-up.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{KeyInit, Mac, SimpleHmac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// How far a proof's `iat` may drift from our clock, in seconds.
///
/// RFC 9449 leaves this to the server. Sixty seconds tolerates ordinary clock
/// skew without leaving a replay window wide enough to matter.
pub const MAX_AGE_SECONDS: i64 = 60;

/// The longest `jti` a proof may carry, in bytes.
///
/// RFC 9449 sets no limit. This one keeps the `(jkt, jti)` primary key of
/// `dpop_jti` well inside a btree index row, so an oversized `jti` is refused
/// here as `Malformed` instead of failing the insert and being logged as a
/// storage fault.
pub const MAX_JTI_BYTES: usize = 256;

/// How long one nonce value is handed out for, in seconds (stage 2, C).
///
/// RFC 9449 leaves nonce rotation to the server; the ATProtocol profile caps
/// it at five minutes. Time buckets of this width give exactly that: no value
/// is served for longer than one bucket, and rotation needs no job.
pub const NONCE_BUCKET_SECONDS: i64 = 300;

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
    /// This key has already presented a proof with this `jti`.
    Replayed,
    /// The proof carries no `nonce` claim, or one this server did not issue.
    ///
    /// Both cases get the same answer — the retry is the client's, with a
    /// fresh nonce the refusal hands it — so they share a variant.
    NonceRequired,
    /// The proof could not be recorded, so it is not accepted.
    ///
    /// Holds the message rather than the `sqlx::Error`, so this enum can stay
    /// `Clone` and `Eq`. Call sites log it and must not send it to the client.
    Storage(String),
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
            DpopError::Replayed => write!(f, "DPoP proof has already been used"),
            DpopError::NonceRequired => write!(f, "DPoP proof carries no valid nonce"),
            DpopError::Storage(e) => write!(f, "could not record the DPoP proof: {e}"),
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
    jti: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
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

/// A verified value that can't be used until its proof has been recorded.
///
/// The fields are private, and [`Unspent::spend`] is the only way to get the
/// value out. There is no `map`, because a closure could copy the value out.
/// Nor is there `Clone`, `Debug` or `PartialEq`, because each of those would
/// reach the value some other way.
///
/// Spending hands the value over:
///
/// ```
/// use brolly_identity::dpop::{DpopError, Unspent, VerifiedProof};
///
/// async fn thumbprint_of(
///     proof: Unspent<VerifiedProof>,
///     pool: &sqlx::PgPool,
///     now: i64,
/// ) -> Result<String, DpopError> {
///     let verified = proof.spend(pool, now).await?;
///     Ok(verified.thumbprint)
/// }
/// ```
///
/// Reaching past `spend` doesn't compile. This is the example above with that
/// one line changed, so it fails because the field is private, not because of a
/// typo:
///
/// ```compile_fail,E0616
/// use brolly_identity::dpop::{DpopError, Unspent, VerifiedProof};
///
/// async fn thumbprint_of(
///     proof: Unspent<VerifiedProof>,
///     pool: &sqlx::PgPool,
///     now: i64,
/// ) -> Result<String, DpopError> {
///     let verified = proof.value;
///     Ok(verified.thumbprint)
/// }
/// ```
#[must_use = "a verified proof proves nothing until it is spent"]
pub struct Unspent<T> {
    value: T,
    /// Thumbprint of the key that signed the proof.
    jkt: String,
    jti: String,
    iat: i64,
}

/// Record a proof and prune expired ones, in one statement.
///
/// `$3` is the row's expiry and `$4` the prune cutoff. Both come from the
/// application's clock. No row back means the `(jkt, jti)` pair already existed.
const SPEND_JTI: &str = "\
    WITH pruned AS (DELETE FROM dpop_jti WHERE expires_at < to_timestamp($4)) \
    INSERT INTO dpop_jti (jkt, jti, expires_at) \
    VALUES ($1, $2, to_timestamp($3)) \
    ON CONFLICT DO NOTHING \
    RETURNING jti";

impl<T> Unspent<T> {
    /// Record this proof's `jti` and hand over the value.
    ///
    /// **A proof is spent as soon as it is verified, even if the request then
    /// fails**, for example a PAR refused for its client metadata, or a token
    /// request with a bad code. RFC 9449 counts a `jti` as used once it has been
    /// presented. Don't move spending to after the request succeeds: a captured
    /// proof could then be retried until one attempt worked.
    ///
    /// `now` is the application's clock. It sets the row's expiry and decides
    /// which rows are pruned. The database's clock is never used: `verify`
    /// judges freshness by the application's clock, and pruning by a database
    /// clock running ahead would forget a proof that is still fresh.
    ///
    /// Returns [`DpopError::Replayed`] if this key has already used this `jti`,
    /// and [`DpopError::Storage`] if the proof couldn't be recorded. Callers
    /// must treat both as a refusal.
    ///
    /// Concurrent spends are safe for replay: the primary key lets exactly one
    /// insert of a `(jkt, jti)` pair win. Their prune `DELETE`s can overlap,
    /// though, and two of them locking expired rows in different orders can
    /// rarely deadlock. Postgres aborts one; that spend comes back as
    /// `Storage` and its request is refused, so a deadlock fails closed.
    pub async fn spend(self, pool: &PgPool, now: i64) -> Result<T, DpopError> {
        let recorded: Option<String> = sqlx::query_scalar(SPEND_JTI)
            .bind(self.jkt.as_str())
            .bind(self.jti.as_str())
            .bind(self.iat.saturating_add(MAX_AGE_SECONDS))
            .bind(now.saturating_sub(MAX_AGE_SECONDS))
            .fetch_optional(pool)
            .await
            .map_err(|e| DpopError::Storage(e.to_string()))?;
        match recorded {
            Some(_) => Ok(self.value),
            None => Err(DpopError::Replayed),
        }
    }

    /// Swap the wrapped value for another, keeping the proof that must be
    /// spent. The old value is dropped unread.
    ///
    /// `verify_access` uses this to turn `Unspent<VerifiedProof>` into
    /// `Unspent<AccessClaims>`, because the claims come from the token, not
    /// the proof.
    pub fn replace<U>(self, value: U) -> Unspent<U> {
        Unspent {
            value,
            jkt: self.jkt,
            jti: self.jti,
            iat: self.iat,
        }
    }

    /// Whether the proof was signed by the key with this thumbprint, without
    /// giving the thumbprint out.
    pub fn bound_to(&self, jkt: &str) -> bool {
        self.jkt == jkt
    }
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

/// The nonce for one time bucket: `base64url(HMAC-SHA256(secret, bucket))`.
///
/// The bucket is the decimal seconds-elapsed string. The encoding is internal
/// to the instance — a client treats the nonce as opaque — but it is stable
/// across processes, which is the one property it must have.
///
/// The secret is exactly SHA-256's block size, so `KeyInit::new` takes it
/// with no slicing and no error path.
fn nonce_for_bucket(secret: &[u8; 64], bucket: i64) -> String {
    let mut mac = SimpleHmac::<Sha256>::new(secret.into());
    mac.update(bucket.to_string().as_bytes());
    B64.encode(mac.finalize().into_bytes())
}

/// The nonce to hand out right now: the current bucket's value (stage 2, C).
///
/// This is the value a `DPoP-Nonce` response header carries, and the value a
/// client puts in the next proof's `nonce` claim.
pub fn current_nonce(secret: &[u8; 64], now: i64) -> String {
    nonce_for_bucket(secret, now.div_euclid(NONCE_BUCKET_SECONDS))
}

/// The nonce values a proof may carry right now (stage 2, C).
///
/// The current bucket's and the previous one's. Accepting the previous is the
/// ATProtocol profile's "recently-stale" allowance: a proof minted in the
/// last second of a bucket stays verifiable through the next one, so every
/// request in flight survives the boundary. Two buckets is a refusal — the
/// `iat` window is what bounds freshness, and it never launders a nonce.
pub fn accepted_nonces(secret: &[u8; 64], now: i64) -> [String; 2] {
    let bucket = now.div_euclid(NONCE_BUCKET_SECONDS);
    [
        nonce_for_bucket(secret, bucket),
        nonce_for_bucket(secret, bucket - 1),
    ]
}

/// Load the instance's DPoP nonce secret, creating it on first start.
///
/// One row, one secret, `ON CONFLICT DO NOTHING` then read back — the
/// `load_or_create` pattern `instance.rs` established, so two processes
/// starting together converge on one secret rather than one of them handing
/// out nonces from a key that was never stored.
pub async fn load_or_create_nonce_secret(pool: &PgPool) -> Result<[u8; 64], DpopError> {
    if let Some(secret) = read_nonce_secret(pool).await? {
        return Ok(secret);
    }
    let secret: [u8; 64] = rand::random();
    sqlx::query(
        "INSERT INTO dpop_nonce_secrets (id, secret) VALUES (1, $1) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(secret.as_slice())
    .execute(pool)
    .await
    .map_err(|e| DpopError::Storage(e.to_string()))?;
    read_nonce_secret(pool).await?.ok_or(DpopError::Storage(
        "the nonce secret did not appear after inserting it".into(),
    ))
}

async fn read_nonce_secret(pool: &PgPool) -> Result<Option<[u8; 64]>, DpopError> {
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT secret FROM dpop_nonce_secrets WHERE id = 1")
            .fetch_optional(pool)
            .await
            .map_err(|e| DpopError::Storage(e.to_string()))?;
    // A row of any other length is a corrupted one, and a startup failure is
    // the honest answer: every nonce it minted would be a guess.
    stored
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| DpopError::Storage("the stored nonce secret is not 64 bytes".into()))
        })
        .transpose()
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
/// `access_token` is `Some` for resource requests, where an `ath` the proof
/// carries must match it (a proof without one is accepted), and `None` at the
/// token endpoint, where there is no token to bind to yet.
///
/// `accepted_nonces` is `Some` where the protocol requires nonces —
/// ATProtocol does (stage 2, C); Solid-OIDC does not, and passes `None` to
/// leave that check off entirely. When it is `Some`, the proof's `nonce`
/// claim must be present and one of the accepted values, or the proof is
/// refused as [`DpopError::NonceRequired`].
///
/// Passing every check here doesn't make the proof usable yet. It has not been
/// checked for replay, so it comes back [`Unspent`].
pub fn verify(
    proof: &str,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    now: i64,
    accepted_nonces: Option<&[String]>,
) -> Result<Unspent<VerifiedProof>, DpopError> {
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

    // An empty jti can't be told apart from the next one, and an oversized one
    // would fail the dpop_jti insert as a storage error rather than a client's.
    if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_BYTES {
        return Err(DpopError::Malformed(format!(
            "jti must be 1 to {MAX_JTI_BYTES} bytes"
        )));
    }

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
    // Saturating: `iat` is the client's claim and i64::MIN is a legal JSON
    // integer, so this is the one arithmetic in the verifier an attacker
    // chooses an operand of. Plain subtraction panics in a debug build and
    // wraps in release — to a value inside the window.
    if now.saturating_sub(claims.iat).saturating_abs() > MAX_AGE_SECONDS {
        return Err(DpopError::Expired);
    }

    // An `ath` that is there must match the token. One that is absent is
    // accepted, as the reference Solid server does: Inrupt's client library,
    // which most Solid apps use, never sends it. What `ath` would add is
    // already held by the rest: the proof names one method and one URL, is
    // spent on first use (`jti`), and must be signed by the token's key.
    match (access_token, claims.ath.as_deref()) {
        (Some(token), Some(ath)) if ath != access_token_hash(token) => {
            return Err(DpopError::TokenBindingFailed);
        }
        // A proof at the token endpoint carries no ath, which is correct.
        _ => {}
    }

    // The nonce is a separate check with a separate window: the `iat` bound
    // above judges the *proof*, this judges the *nonce* — a fresh `iat`
    // wrapping a stale nonce is exactly the pair that must not slip through.
    // The accepted values are handed out by this server (`current_nonce`),
    // which is why a plain comparison suffices: the values are public, and
    // only this server's secret can produce the ones that pass.
    if let Some(accepted) = accepted_nonces
        && !claims
            .nonce
            .as_deref()
            .is_some_and(|nonce| accepted.iter().any(|a| a == nonce))
    {
        return Err(DpopError::NonceRequired);
    }

    let jkt = thumbprint(&header.jwk);
    Ok(Unspent {
        value: VerifiedProof {
            thumbprint: jkt.clone(),
            jwk: header.jwk,
        },
        jkt,
        jti: claims.jti,
        iat: claims.iat,
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
        make_proof_with_jti(key, method, url, iat, ath, typ, "unique")
    }

    /// A proof carrying a `nonce` claim, as an ATProtocol client produces one
    /// (stage 2, C).
    fn make_nonce_proof(
        key: &SigningKey,
        method: &str,
        url: &str,
        iat: i64,
        ath: Option<&str>,
        nonce: Option<&str>,
    ) -> String {
        let proof = make_proof(key, method, url, iat, ath, "dpop+jwt");
        let Some(nonce) = nonce else {
            return proof;
        };
        // Rebuild the claims with the nonce and re-sign: the proof is a
        // signature over the claims, so the claim cannot be added after.
        let parts: Vec<&str> = proof.split('.').collect();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        claims["nonce"] = serde_json::Value::String(nonce.to_string());
        let signed = format!(
            "{}.{}",
            parts[0],
            B64.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(signed.as_bytes());
        format!("{signed}.{}", B64.encode(signature.to_bytes()))
    }

    /// `verify` in the Solid-OIDC shape: no nonces, the check off entirely.
    ///
    /// The pre-nonce tests keep calling this so that the one behaviour this
    /// change must not alter — Solid — stays pinned by exactly these tests,
    /// untouched.
    fn verify_solid(
        proof: &str,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        now: i64,
    ) -> Result<Unspent<VerifiedProof>, DpopError> {
        verify(proof, method, url, access_token, now, None)
    }

    fn make_proof_with_jti(
        key: &SigningKey,
        method: &str,
        url: &str,
        iat: i64,
        ath: Option<&str>,
        typ: &str,
        jti: &str,
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
            "htm": method, "htu": url, "jti": jti, "iat": iat
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

    /// RFC 7638 for a P-256 key, written out here instead of calling
    /// `thumbprint`, so the assertions below test the thumbprint too.
    fn jkt_of(key: &SigningKey) -> String {
        let sec1 = key.verifying_key().to_sec1_bytes();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            B64.encode(&sec1[1..33]),
            B64.encode(&sec1[33..65])
        );
        B64.encode(Sha256::digest(canonical.as_bytes()))
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
        let verified = verify_solid(&proof, "GET", URL, Some(token), 1000).unwrap();
        assert!(verified.bound_to(&jkt_of(&key())));
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
            verify_solid(
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
    fn a_resource_proof_without_ath_is_accepted() {
        // Inrupt's client library, which most Solid apps use, sends no ath
        // (3.x through 5.x), and the reference server checks it only when it
        // is present. Requiring it locked every one of those apps out.
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(verify_solid(&proof, "GET", URL, Some("access-token"), 1000).is_ok());
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
            verify_solid(&proof, "GET", URL, Some("access-token"), 1000).err(),
            Some(DpopError::TokenBindingFailed)
        );
    }

    #[test]
    fn a_proof_for_another_method_or_url_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(matches!(
            verify_solid(&proof, "DELETE", URL, None, 1000),
            Err(DpopError::WrongTarget { .. })
        ));
        assert!(matches!(
            verify_solid(&proof, "GET", "https://alice.brolly.id/~/other", None, 1000),
            Err(DpopError::WrongTarget { .. })
        ));
    }

    #[test]
    fn query_and_fragment_are_ignored_when_matching_htu() {
        // RFC 9449 compares the URL without query or fragment.
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(verify_solid(&proof, "GET", &format!("{URL}?page=2"), None, 1000).is_ok());
    }

    #[test]
    fn a_stale_or_future_proof_is_refused() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert_eq!(
            verify_solid(&proof, "GET", URL, None, 5000).err(),
            Some(DpopError::Expired)
        );
        assert_eq!(
            verify_solid(&proof, "GET", URL, None, 0).err(),
            Some(DpopError::Expired)
        );
    }

    #[test]
    fn an_absurd_iat_is_stale_not_a_panic() {
        // `iat` is the client's claim, and i64::MIN is a legal JSON integer.
        // `now - iat` overflows on it: a panic in a debug build, a wrap in
        // release that lands inside the freshness window. Either way it is
        // the one arithmetic in the verifier an attacker chooses the operand
        // of, and the answer is simply "stale".
        for iat in [i64::MIN, i64::MAX, i64::MIN + 1] {
            let proof = make_proof(&key(), "GET", URL, iat, None, "dpop+jwt");
            assert_eq!(
                verify_solid(&proof, "GET", URL, None, 1_000).err(),
                Some(DpopError::Expired),
                "iat = {iat}"
            );
        }
    }

    #[test]
    fn a_plain_jwt_is_not_a_proof() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "JWT");
        assert_eq!(
            verify_solid(&proof, "GET", URL, None, 1000).err(),
            Some(DpopError::WrongType)
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
            verify_solid(&parts.join("."), "DELETE", URL, None, 1000).err(),
            Some(DpopError::BadSignature)
        );
    }

    #[test]
    fn thumbprints_are_stable_and_key_specific() {
        let mine = jkt_of(&key());
        let other = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let theirs = jkt_of(&other);
        assert_ne!(mine, theirs, "the jkt must identify the key");

        let a = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        assert!(
            verify_solid(&a, "GET", URL, None, 1000)
                .unwrap()
                .bound_to(&mine)
        );
        assert!(
            verify_solid(&a, "GET", URL, None, 1000)
                .unwrap()
                .bound_to(&mine)
        );

        let b = make_proof(&other, "GET", URL, 1000, None, "dpop+jwt");
        let different = verify_solid(&b, "GET", URL, None, 1000).unwrap();
        assert!(different.bound_to(&theirs));
        assert!(!different.bound_to(&mine));
    }

    #[test]
    fn a_verified_proof_carries_what_spending_it_needs() {
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        let unspent = verify_solid(&proof, "GET", URL, None, 1000).unwrap();
        assert_eq!(unspent.jti, "unique");
        assert_eq!(unspent.iat, 1000);
        assert_eq!(unspent.jkt, jkt_of(&key()));
    }

    #[test]
    fn replace_swaps_the_value_and_keeps_the_proof() {
        // What verify_access relies on: the claims come from the token, but
        // the proof that has to be spent is still this one.
        let proof = make_proof(&key(), "GET", URL, 1000, None, "dpop+jwt");
        let replaced = verify_solid(&proof, "GET", URL, None, 1000)
            .unwrap()
            .replace("claims");
        assert_eq!(replaced.value, "claims");
        assert_eq!(replaced.jti, "unique");
        assert_eq!(replaced.iat, 1000);
        assert!(replaced.bound_to(&jkt_of(&key())));
    }

    #[test]
    fn an_empty_jti_is_malformed() {
        // Nothing to record, so nothing to stop a replay.
        let proof = make_proof_with_jti(&key(), "GET", URL, 1000, None, "dpop+jwt", "");
        assert!(matches!(
            verify_solid(&proof, "GET", URL, None, 1000),
            Err(DpopError::Malformed(_))
        ));
    }

    #[test]
    fn a_jti_of_exactly_the_limit_is_accepted() {
        let jti = "j".repeat(MAX_JTI_BYTES);
        let proof = make_proof_with_jti(&key(), "GET", URL, 1000, None, "dpop+jwt", &jti);
        let unspent = verify_solid(&proof, "GET", URL, None, 1000).unwrap();
        assert_eq!(unspent.jti, jti);
    }

    #[test]
    fn a_jti_over_the_limit_is_malformed() {
        // Otherwise it reaches the (jkt, jti) primary key, overflows the btree
        // row, and comes back as Storage: a client's mistake logged as a
        // server fault.
        let jti = "j".repeat(MAX_JTI_BYTES + 1);
        let proof = make_proof_with_jti(&key(), "GET", URL, 1000, None, "dpop+jwt", &jti);
        assert!(matches!(
            verify_solid(&proof, "GET", URL, None, 1000),
            Err(DpopError::Malformed(_))
        ));
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
            verify_solid(&rebuilt, "GET", URL, None, 1000).err(),
            Some(DpopError::BadSignature)
        );
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        for bad in ["", "a.b", "a.b.c.d", "not-base64.!!!.???"] {
            assert!(verify_solid(bad, "GET", URL, None, 1000).is_err());
        }
    }

    // --- nonces (stage 2, C) ---------------------------------------------------------

    /// A secret that is not the test default, for the secret-specificity test.
    const OTHER_SECRET: &[u8; 64] = &[42u8; 64];

    #[test]
    fn a_proof_with_the_current_nonce_verifies() {
        let now = 1_000_000;
        let secret = [7u8; 64];
        let nonce = current_nonce(&secret, now);
        let proof = make_nonce_proof(&key(), "GET", URL, now, None, Some(&nonce));
        let accepted = accepted_nonces(&secret, now);
        assert!(verify(&proof, "GET", URL, None, now, Some(&accepted)).is_ok());
    }

    #[test]
    fn a_proof_with_the_previous_buckets_nonce_still_verifies() {
        // The profile's "recently-stale" allowance: a proof minted in the last
        // second of a bucket stays verifiable through the next one, so every
        // request in flight survives the boundary. The worst case is a client
        // that received a nonce in bucket N's first second and returns at
        // bucket N+1's last — one generation stale, still accepted.
        let secret = [7u8; 64];
        let bucket = 3_333; // arbitrary
        let boundary = bucket * NONCE_BUCKET_SECONDS;
        let minted_at = boundary - 1; // the last second of the previous bucket
        let stale_nonce = current_nonce(&secret, minted_at);

        // Verified anywhere inside the next bucket...
        for now in [boundary, boundary + 1, boundary + NONCE_BUCKET_SECONDS - 1] {
            let proof = make_nonce_proof(&key(), "GET", URL, now, None, Some(&stale_nonce));
            let accepted = accepted_nonces(&secret, now);
            assert!(
                verify(&proof, "GET", URL, None, now, Some(&accepted)).is_ok(),
                "now = {now}"
            );
        }
        // ...and not one bucket further (two generations stale).
        let after = boundary + NONCE_BUCKET_SECONDS;
        let proof = make_nonce_proof(&key(), "GET", URL, after, None, Some(&stale_nonce));
        let accepted = accepted_nonces(&secret, after);
        assert_eq!(
            verify(&proof, "GET", URL, None, after, Some(&accepted)).err(),
            Some(DpopError::NonceRequired)
        );
    }

    #[test]
    fn a_missing_nonce_is_refused_where_nonces_are_required() {
        let now = 1_000_000;
        let secret = [7u8; 64];
        let proof = make_nonce_proof(&key(), "GET", URL, now, None, None);
        let accepted = accepted_nonces(&secret, now);
        assert_eq!(
            verify(&proof, "GET", URL, None, now, Some(&accepted)).err(),
            Some(DpopError::NonceRequired)
        );
    }

    #[test]
    fn a_nonce_from_a_different_secret_is_refused() {
        // The values are public, but only this server's secret produces the
        // ones that pass — which is what makes a nonce a thing the server
        // issued rather than a claim the client chose.
        let now = 1_000_000;
        let secret = [7u8; 64];
        let foreign = current_nonce(OTHER_SECRET, now);
        let proof = make_nonce_proof(&key(), "GET", URL, now, None, Some(&foreign));
        let accepted = accepted_nonces(&secret, now);
        assert_eq!(
            verify(&proof, "GET", URL, None, now, Some(&accepted)).err(),
            Some(DpopError::NonceRequired)
        );
    }

    #[test]
    fn a_fresh_iat_does_not_launder_a_stale_nonce() {
        // The two windows are independent: `iat` bounds the proof, the bucket
        // bounds the nonce, and both must pass. A proof minted *now* carrying a
        // nonce from two buckets ago is fresh by `iat` and still refused.
        let secret = [7u8; 64];
        let now = 1_000_000;
        let stale = current_nonce(&secret, now - 2 * NONCE_BUCKET_SECONDS);
        let proof = make_nonce_proof(&key(), "GET", URL, now, None, Some(&stale));
        let accepted = accepted_nonces(&secret, now);
        assert_eq!(
            verify(&proof, "GET", URL, None, now, Some(&accepted)).err(),
            Some(DpopError::NonceRequired)
        );
    }

    #[test]
    fn a_nonce_claim_is_ignored_where_nonces_are_not_required() {
        // Solid passes `None`, so a Solid client that sends a nonce anyway —
        // one library shared with an ATProtocol client, say — is not refused
        // for it. The proof's own bindings do the work there.
        let now = 1_000_000;
        let proof = make_nonce_proof(
            &key(),
            "GET",
            URL,
            now,
            None,
            Some("a nonce no server issued"),
        );
        assert!(verify_solid(&proof, "GET", URL, None, now).is_ok());
    }

    #[test]
    fn nonces_rotate_at_bucket_boundaries_and_identify_the_secret() {
        let secret = [7u8; 64];
        let t = 90 * NONCE_BUCKET_SECONDS;

        // Stable within a bucket, across every second of it.
        assert_eq!(current_nonce(&secret, t), current_nonce(&secret, t + 299));
        // Different in the next.
        assert_ne!(current_nonce(&secret, t), current_nonce(&secret, t + 300));
        // Different for a different secret, at the same time.
        assert_ne!(current_nonce(&secret, t), current_nonce(OTHER_SECRET, t));

        // `accepted_nonces` is exactly the current and previous values.
        let accepted = accepted_nonces(&secret, t + 1);
        assert_eq!(accepted[0], current_nonce(&secret, t + 1));
        assert_eq!(
            accepted[1],
            current_nonce(&secret, t + 1 - NONCE_BUCKET_SECONDS)
        );
    }
}
