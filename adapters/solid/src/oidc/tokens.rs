//! Access and ID tokens.
//!
//! An access token is **bound to the client's DPoP key** through the `cnf.jkt`
//! claim: presenting the token requires also presenting a proof signed by the
//! key whose thumbprint is recorded there. A token lifted off the wire, out of
//! a log, or out of a compromised store is inert without that key.
//!
//! Verification therefore takes both, and there is no path that checks one
//! without the other — see [`verify_access`]. A token from another Solid-OIDC
//! issuer takes [`verify_remote_access`] (spec 6, H5), which checks both
//! against the issuer's own key set instead of ours, and requires the
//! binding outright: there is no bearer arm on the remote path.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::json;

use super::dpop::{self, DpopError};
use super::keys::{JwtError, ProviderKey, verify_with};

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

/// What [`verify_access`] found.
pub enum Access {
    /// A token without `cnf.jkt`. Nothing to prove, so nothing to spend.
    Bearer(AccessClaims),
    /// A DPoP-bound token whose proof checked out and was signed by the
    /// token's key. The claims stay wrapped until the proof is spent. Spending
    /// needs the database, and keeping it out of this function keeps this
    /// function synchronous.
    Bound(dpop::Unspent<AccessClaims>),
}

/// Verify an access token **and** the proof that it belongs to this caller.
///
/// Both or neither: a token whose `cnf.jkt` does not match the proof's key was
/// not presented by its holder, and a bound token with no proof at all is
/// refused rather than downgraded to bearer semantics. Downgrading is the
/// mistake that makes DPoP decorative.
///
/// A bound token comes back as [`Access::Bound`]. Its claims are reachable only
/// by spending the proof, so the caller can't skip the replay check.
pub fn verify_access(
    key: &ProviderKey,
    token: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
) -> Result<Access, TokenError> {
    let claims = key.verify(token, now)?;
    let access = AccessClaims {
        webid: claims["webid"].as_str().unwrap_or_default().to_string(),
        client_id: claims["client_id"].as_str().unwrap_or_default().to_string(),
        scope: claims["scope"].as_str().unwrap_or_default().to_string(),
    };

    let Some(jkt) = claims["cnf"]["jkt"].as_str() else {
        return Ok(Access::Bearer(access));
    };
    bind_proof(token, jkt, proof, method, url, now, access).map(Access::Bound)
}

/// The proof half both verification paths share (spec 6, H5): a token bound
/// through `cnf.jkt` requires its proof, the proof must be signed by the bound
/// key, and the claims arrive [`Unspent`](dpop::Unspent) — reachable only by
/// spending the proof, so no caller can skip the replay check.
fn bind_proof(
    token: &str,
    jkt: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
    access: AccessClaims,
) -> Result<dpop::Unspent<AccessClaims>, TokenError> {
    let Some(proof) = proof else {
        return Err(TokenError::ProofRequired);
    };
    let verified = dpop::verify(proof, method, url, Some(token), now)?;
    if !verified.bound_to(jkt) {
        return Err(TokenError::WrongHolder);
    }
    // The proof's own value is dropped unread; the claims are the token's.
    Ok(verified.replace(access))
}

// --- foreign issuers (spec 6, H5) ----------------------------------------------
//
// The remote half of verification: a token another Solid-OIDC issuer signed
// is verified against that issuer's own key set, fetched from its discovery
// document, and the WebID it names is bound to the issuer by the WebID's own
// `solid:oidcIssuer`. The fetching and the binding live in the server — the
// hardened transport, the caches, the pod surface — because they are network
// round trips; what lives here is everything downstream of the bytes: the
// split, the key set, and the checks.

/// A foreign issuer's OIDC discovery document (spec 6, H5), as the remote
/// path reads it: the two fields it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDiscovery {
    /// The issuer the document names. Must equal the token's `iss` claim —
    /// discovery cannot be used to launder one issuer for another — which
    /// the remote path checks, because it is the one holding the claim.
    pub issuer: String,
    /// Where the issuer's key set lives.
    pub jwks_uri: String,
}

/// Why fetched bytes are not a usable discovery document (spec 6, H5).
///
/// Every message names the rule, never anything fetched: the operator's log
/// gets the detail, and the caller gets one answer for every cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidDiscovery {
    /// Served as something JSON is not served as.
    NotJson(String),
    /// The body did not parse as JSON.
    Unparseable(String),
    /// Parsed, but no `issuer`/`jwks_uri` to read.
    Incomplete,
}

impl std::fmt::Display for InvalidDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidDiscovery::NotJson(content_type) => write!(
                f,
                "a discovery document must be served as application/json, not {content_type}"
            ),
            InvalidDiscovery::Unparseable(e) => {
                write!(f, "the discovery document did not parse: {e}")
            }
            InvalidDiscovery::Incomplete => {
                f.write_str("the discovery document names no issuer or jwks_uri")
            }
        }
    }
}

impl std::error::Error for InvalidDiscovery {}

impl RemoteDiscovery {
    /// Parse `{iss}/.well-known/openid-configuration` (spec 6, H5). The
    /// `issuer` equality check is not here: the claim it must equal arrives
    /// with the token, and the remote path holds both.
    pub fn parse(content_type: &str, body: &[u8]) -> Result<Self, InvalidDiscovery> {
        json_document(content_type, body).map_err(|e| match e {
            JsonError::NotJson(t) => InvalidDiscovery::NotJson(t),
            JsonError::Unparseable(e) => InvalidDiscovery::Unparseable(e),
        })?;
        let json: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| InvalidDiscovery::Unparseable(e.to_string()))?;
        let (Some(issuer), Some(jwks_uri)) = (json["issuer"].as_str(), json["jwks_uri"].as_str())
        else {
            return Err(InvalidDiscovery::Incomplete);
        };
        Ok(Self {
            issuer: issuer.to_owned(),
            jwks_uri: jwks_uri.to_owned(),
        })
    }
}

/// Why fetched bytes are not JSON (spec 6, H5). The one check both JSON
/// documents share, so it is one function.
fn json_document(content_type: &str, body: &[u8]) -> Result<(), JsonError> {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(JsonError::NotJson(content_type.to_string()));
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|e| JsonError::Unparseable(e.to_string()))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonError {
    NotJson(String),
    Unparseable(String),
}

/// One key in a foreign issuer's set (spec 6, H5): an ES256 P-256 key,
/// addressed by `kid`.
#[derive(Debug, Clone)]
pub struct RemoteKey {
    pub kid: String,
    key: p256::ecdsa::VerifyingKey,
}

impl RemoteKey {
    /// Verify a token against this key, which its header's `kid` must name.
    fn verify(&self, token: &str, now: i64) -> Result<serde_json::Value, JwtError> {
        verify_with(&self.key, &self.kid, token, now)
    }
}

/// A foreign issuer's key set (spec 6, H5), as the remote path verifies
/// against it.
#[derive(Debug, Clone)]
pub struct RemoteJwks {
    keys: Vec<RemoteKey>,
}

/// Why fetched bytes are not a usable key set (spec 6, H5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidJwks {
    /// Served as something JSON is not served as.
    NotJson(String),
    /// The body did not parse as JSON.
    Unparseable(String),
}

impl std::fmt::Display for InvalidJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidJwks::NotJson(content_type) => write!(
                f,
                "a key set must be served as application/json, not {content_type}"
            ),
            InvalidJwks::Unparseable(e) => write!(f, "the key set did not parse: {e}"),
        }
    }
}

impl std::error::Error for InvalidJwks {}

impl RemoteJwks {
    /// Parse the document a `jwks_uri` serves (spec 6, H5).
    ///
    /// A key is kept when it is an ES256 P-256 key with a `kid` — the one
    /// algorithm the remote path accepts (H5), the one we advertise and the
    /// one Solid-OIDC's ecosystem converged on. Anything else in the set is
    /// skipped, not refused: a set may carry keys for algorithms we do not
    /// verify, and a skipped key is one the `kid` lookup will not find.
    pub fn parse(content_type: &str, body: &[u8]) -> Result<Self, InvalidJwks> {
        json_document(content_type, body).map_err(|e| match e {
            JsonError::NotJson(t) => InvalidJwks::NotJson(t),
            JsonError::Unparseable(e) => InvalidJwks::Unparseable(e),
        })?;
        let json: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| InvalidJwks::Unparseable(e.to_string()))?;
        let mut keys = Vec::new();
        for key in json["keys"].as_array().into_iter().flatten() {
            if key["kty"] != "EC" || key["crv"] != "P-256" {
                continue;
            }
            // A key that names another algorithm must not be used for ours.
            if key["alg"].is_string() && key["alg"] != "ES256" {
                continue;
            }
            let (Some(kid), Some(x), Some(y)) =
                (key["kid"].as_str(), key["x"].as_str(), key["y"].as_str())
            else {
                continue;
            };
            if let Some(key) = remote_key(x, y) {
                keys.push(RemoteKey {
                    kid: kid.to_owned(),
                    key,
                });
            }
        }
        Ok(Self { keys })
    }

    /// The key a token's `kid` names (spec 6, H5). `None` is what a rotation
    /// looks like from the outside: the caller re-fetches the set once, then
    /// refuses.
    pub fn key_for(&self, kid: &str) -> Option<&RemoteKey> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}

/// An EC public key from its base64url coordinates, or `None` if they do not
/// name a point on the curve — a key nothing can verify with, which the set
/// is better off without.
fn remote_key(x: &str, y: &str) -> Option<p256::ecdsa::VerifyingKey> {
    let x = B64.decode(x).ok()?;
    let y = B64.decode(y).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    // SEC1 uncompressed: 0x04 || x || y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// Which issuer a token names, read without verifying it (spec 6, H5).
///
/// The split has to happen before any signature check — the key comes from
/// the issuer — so this is a peek, never a trust decision: whichever way it
/// answers, the token is verified (or refused) immediately after. `None` is
/// the fast path: a malformed token, one with no `iss`, or one naming our
/// own issuer, whose `kid` check already ties it to this deployment's key —
/// a stronger binding than the WebID dereference, which is why ours is the
/// one `iss` exempt from it.
pub fn foreign_issuer(token: &str, ours: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (_, Some(claims_b64), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let claims: serde_json::Value = serde_json::from_slice(&B64.decode(claims_b64).ok()?).ok()?;
    let iss = claims["iss"].as_str()?;
    (iss != ours).then(|| iss.to_string())
}

/// Verify a foreign issuer's access token against that issuer's key set, and
/// the proof that it belongs to this caller (spec 6, H5).
///
/// The remote twin of [`verify_access`], differing exactly where a foreign
/// issuer makes a difference:
///
/// * The signature is checked against `jwks` — the issuer's own set, the key
///   chosen by the token's `kid`. ES256 only, no other algorithm accepted.
/// * `aud` must be `solid`: a token minted for some other resource server is
///   not ours to accept.
/// * `cnf.jkt` is **required**. [`verify_access`] answers a token without it
///   as [`Access::Bearer`] — no proof at all — unreachable for our tokens,
///   which always carry the binding, but reachable for a foreign issuer that
///   mints none. The remote path has no bearer arm: a foreign token without
///   a binding is refused rather than downgraded to a proof-free read.
///
/// An unknown `kid` comes back as [`JwtError::UnknownKey`], which is what a
/// rotation looks like from the outside; the caller re-fetches the set once
/// and tries again. The proof half is shared with [`verify_access`], and the
/// claims arrive unspent exactly as there.
pub fn verify_remote_access(
    jwks: &RemoteJwks,
    token: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
) -> Result<dpop::Unspent<AccessClaims>, TokenError> {
    let kid = kid_of(token)?;
    let Some(key) = jwks.key_for(&kid) else {
        return Err(JwtError::UnknownKey(kid).into());
    };
    let claims = key.verify(token, now)?;

    // `aud` may be a string or a list of strings (RFC 7519 §4.1.3); either
    // way, `solid` must be among them.
    let audience = match &claims["aud"] {
        serde_json::Value::String(aud) => aud == "solid",
        serde_json::Value::Array(auds) => auds.iter().any(|aud| aud.as_str() == Some("solid")),
        _ => false,
    };
    if !audience {
        return Err(JwtError::Claim("aud must be solid".into()).into());
    }

    let access = AccessClaims {
        webid: claims["webid"].as_str().unwrap_or_default().to_string(),
        client_id: claims["client_id"].as_str().unwrap_or_default().to_string(),
        scope: claims["scope"].as_str().unwrap_or_default().to_string(),
    };

    // The no-bearer-arm rule (H5): there is no `Access::Bearer` to answer
    // with on this path, so a token without a binding is refused — the
    // tightest closure the rule can take.
    let Some(jkt) = claims["cnf"]["jkt"].as_str() else {
        return Err(JwtError::Claim("cnf.jkt is required".into()).into());
    };
    bind_proof(token, jkt, proof, method, url, now, access)
}

/// The token's `kid` header, decoded but not trusted (spec 6, H5): the
/// address of the key in the issuer's set. A header that does not name ES256
/// is refused here, before the set is consulted — no other algorithm is
/// accepted on the remote path.
fn kid_of(token: &str) -> Result<String, JwtError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(_), Some(_), None) =
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
    Ok(header["kid"].as_str().unwrap_or_default().to_string())
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
        "jwks_uri": endpoint("jwks"),
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

        let Access::Bound(unspent) =
            verify_access(&p, &token, Some(&proof), "GET", URL, 1000).unwrap()
        else {
            panic!("a token with cnf.jkt must come back bound to its proof");
        };
        // The claims stay wrapped until the pod spends the proof.
        assert!(unspent.bound_to(&jkt_of(&client)));
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
    fn a_token_without_a_binding_is_bearer_and_its_claims_are_readable() {
        // Unchanged behaviour: only cnf.jkt makes a proof necessary, so there
        // is nothing to spend.
        let p = provider();
        let token = p
            .sign(&json!({
                "webid": WEBID,
                "client_id": "urn:uuid:c",
                "scope": "webid",
                "exp": 1000 + ACCESS_TOKEN_TTL,
            }))
            .unwrap();

        let Access::Bearer(claims) = verify_access(&p, &token, None, "GET", URL, 1000).unwrap()
        else {
            panic!("a token without cnf.jkt has no proof to spend");
        };
        assert_eq!(claims.webid, WEBID);
        assert_eq!(claims.client_id, "urn:uuid:c");
        assert_eq!(claims.scope, "webid");
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

    // --- foreign issuers (spec 6, H5) ----------------------------------------

    const FOREIGN: &str = "https://idp.example";
    const REMOTE_WEBID: &str = "https://bob.example.org/profile#me";
    const KID: &str = "idp-2026-1";

    fn issuer() -> SigningKey {
        SigningKey::from_slice(&[13u8; 32]).unwrap()
    }

    /// The key set a foreign issuer serves at its `jwks_uri`, built from the
    /// key itself so the signature below is really its.
    fn key_set(key: &SigningKey, kid: &str) -> RemoteJwks {
        let sec1 = key.verifying_key().to_sec1_bytes();
        let body = json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid,
                "x": B64.encode(&sec1[1..33]),
                "y": B64.encode(&sec1[33..65]),
            }]
        });
        RemoteJwks::parse("application/json", body.to_string().as_bytes()).unwrap()
    }

    /// Sign `claims` as a foreign issuer would: ES256, P1363, `kid` in the
    /// header naming the key the set carries.
    fn signed_by(key: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": kid});
        let signed = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(signed.as_bytes());
        format!("{signed}.{}", B64.encode(signature.to_bytes()))
    }

    fn remote_claims(jkt: &str) -> serde_json::Value {
        json!({
            "iss": FOREIGN,
            "sub": REMOTE_WEBID,
            "webid": REMOTE_WEBID,
            "aud": "solid",
            "client_id": "https://penny.example/id",
            "scope": "webid",
            "iat": 1000,
            "exp": 1000 + ACCESS_TOKEN_TTL,
            "cnf": {"jkt": jkt},
        })
    }

    #[test]
    fn the_iss_split_names_the_issuer_to_fetch_from() {
        // The split is a peek, never a trust decision, so every way a token
        // can fail to name a foreign issuer answers the fast path's `None`.
        let ours = "https://brolly.id";
        let issuer = issuer();
        let says = |iss: Option<&str>, claims: &serde_json::Value| {
            let mut claims = claims.clone();
            match iss {
                Some(iss) => claims["iss"] = json!(iss),
                None => {
                    claims.as_object_mut().unwrap().remove("iss");
                }
            }
            signed_by(&issuer, KID, claims)
        };

        assert_eq!(foreign_issuer("not a token", ours), None);
        assert_eq!(foreign_issuer("a.b", ours), None);
        assert_eq!(foreign_issuer(&says(None, &remote_claims("")), ours), None);
        // Ours is the one iss exempt from the dereference: the fast path's
        // kid check binds harder (H5).
        assert_eq!(
            foreign_issuer(&says(Some(ours), &remote_claims("")), ours),
            None
        );
        assert_eq!(
            foreign_issuer(&says(Some(FOREIGN), &remote_claims("")), ours),
            Some(FOREIGN.to_string())
        );
    }

    #[test]
    fn a_foreign_token_verifies_against_its_issuers_key_set() {
        let issuer = issuer();
        let client = client_key(7);
        let token = signed_by(&issuer, KID, remote_claims(&jkt_of(&client)));
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        let unspent = verify_remote_access(
            &key_set(&issuer, KID),
            &token,
            Some(&proof),
            "GET",
            URL,
            1000,
        )
        .unwrap();
        // The claims stay wrapped until the pod spends the proof, exactly as
        // the fast path's do.
        assert!(unspent.bound_to(&jkt_of(&client)));
    }

    #[test]
    fn a_foreign_token_signed_by_another_key_is_refused() {
        // The set names the kid, but the signature is not the key's.
        let issuer = issuer();
        let client = client_key(7);
        let token = signed_by(&client_key(9), KID, remote_claims(&jkt_of(&client)));
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        assert!(matches!(
            verify_remote_access(
                &key_set(&issuer, KID),
                &token,
                Some(&proof),
                "GET",
                URL,
                1000
            ),
            Err(TokenError::Jwt(JwtError::BadSignature))
        ));
    }

    #[test]
    fn an_unknown_kid_is_what_a_rotation_looks_like() {
        let client = client_key(7);
        let token = signed_by(
            &issuer(),
            "a-kid-nobody-has",
            remote_claims(&jkt_of(&client)),
        );
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        assert!(matches!(
            verify_remote_access(&key_set(&issuer(), KID), &token, Some(&proof), "GET", URL, 1000),
            Err(TokenError::Jwt(JwtError::UnknownKey(kid))) if kid == "a-kid-nobody-has"
        ));
    }

    #[test]
    fn no_other_algorithm_is_accepted_on_the_remote_path() {
        // ES256 only (H5): the one we advertise and the one the ecosystem
        // converged on. The header is checked before the set is consulted.
        let issuer = issuer();
        let client = client_key(7);
        let claims = B64.encode(serde_json::to_vec(&remote_claims(&jkt_of(&client))).unwrap());
        for alg in ["ES384", "RS256", "none"] {
            let header = json!({"alg": alg, "typ": "JWT", "kid": KID});
            let token = format!(
                "{}.{}",
                B64.encode(serde_json::to_vec(&header).unwrap()),
                claims
            );
            assert!(
                matches!(
                    verify_remote_access(&key_set(&issuer, KID), &token, None, "GET", URL, 1000),
                    Err(TokenError::Jwt(JwtError::Malformed(_)))
                ),
                "{alg} was accepted"
            );
        }
    }

    #[test]
    fn a_foreign_token_for_another_audience_is_refused() {
        let issuer = issuer();
        let client = client_key(7);
        let mut claims = remote_claims(&jkt_of(&client));
        claims["aud"] = json!("some-other-resource-server");
        let token = signed_by(&issuer, KID, claims);
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        assert!(matches!(
            verify_remote_access(
                &key_set(&issuer, KID),
                &token,
                Some(&proof),
                "GET",
                URL,
                1000
            ),
            Err(TokenError::Jwt(JwtError::Claim(_)))
        ));
    }

    #[test]
    fn an_expired_foreign_token_is_refused() {
        let issuer = issuer();
        let client = client_key(7);
        let mut claims = remote_claims(&jkt_of(&client));
        claims["exp"] = json!(500);
        let token = signed_by(&issuer, KID, claims);
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        assert!(matches!(
            verify_remote_access(
                &key_set(&issuer, KID),
                &token,
                Some(&proof),
                "GET",
                URL,
                1000
            ),
            Err(TokenError::Jwt(JwtError::Expired))
        ));
    }

    #[test]
    fn a_foreign_token_without_a_binding_is_refused_not_downgraded() {
        // The no-bearer-arm rule (H5): verify_access answers a token without
        // cnf.jkt as Bearer — unreachable for our tokens, reachable for a
        // foreign issuer that mints none. The remote path refuses instead.
        let issuer = issuer();
        let client = client_key(7);
        let mut claims = remote_claims(&jkt_of(&client));
        claims.as_object_mut().unwrap().remove("cnf");
        let token = signed_by(&issuer, KID, claims);
        let proof = proof_for(&client, "GET", URL, Some(&token), 1000);

        assert!(matches!(
            verify_remote_access(
                &key_set(&issuer, KID),
                &token,
                Some(&proof),
                "GET",
                URL,
                1000
            ),
            Err(TokenError::Jwt(JwtError::Claim(_)))
        ));
    }

    #[test]
    fn a_bound_foreign_token_still_requires_its_proof() {
        // DPoP runs exactly as today on the remote path (H5).
        let issuer = issuer();
        let client = client_key(7);
        let token = signed_by(&issuer, KID, remote_claims(&jkt_of(&client)));

        assert!(matches!(
            verify_remote_access(&key_set(&issuer, KID), &token, None, "GET", URL, 1000),
            Err(TokenError::ProofRequired)
        ));
    }

    #[test]
    fn a_foreign_token_bound_to_another_key_is_refused() {
        // The cnf.jkt/proof binding (H5): a proof from the thief's key does
        // not satisfy a token bound to the holder's.
        let issuer = issuer();
        let holder = client_key(7);
        let thief = client_key(9);
        let token = signed_by(&issuer, KID, remote_claims(&jkt_of(&holder)));
        let forged = proof_for(&thief, "GET", URL, Some(&token), 1000);

        assert!(matches!(
            verify_remote_access(
                &key_set(&issuer, KID),
                &token,
                Some(&forged),
                "GET",
                URL,
                1000
            ),
            Err(TokenError::WrongHolder)
        ));
    }

    #[test]
    fn a_key_set_skips_keys_it_cannot_verify_with() {
        // A set may carry keys for other algorithms and curves; the kid
        // lookup just never finds them. Nothing here is a refusal.
        let issuer = issuer();
        let sec1 = issuer.verifying_key().to_sec1_bytes();
        let body = json!({
            "keys": [
                {"kty": "RSA", "kid": "an-rsa-key", "n": "...", "e": "AQAB"},
                {"kty": "EC", "crv": "P-384", "kid": "the-wrong-curve"},
                {"kty": "EC", "crv": "P-256", "alg": "RS256", "kid": "the-wrong-alg",
                 "x": B64.encode(&sec1[1..33]), "y": B64.encode(&sec1[33..65])},
                {"kty": "EC", "crv": "P-256", "kid": "no-coordinates"},
                {"kty": "EC", "crv": "P-256", "kid": KID,
                 "x": B64.encode(&sec1[1..33]), "y": B64.encode(&sec1[33..65])},
            ]
        });
        let set = RemoteJwks::parse("application/json", body.to_string().as_bytes()).unwrap();

        for kid in [
            "an-rsa-key",
            "the-wrong-curve",
            "the-wrong-alg",
            "no-coordinates",
        ] {
            assert!(set.key_for(kid).is_none(), "{kid} was kept");
        }
        assert!(
            set.key_for(KID).is_some(),
            "the one ES256 P-256 key was kept"
        );
    }

    #[test]
    fn a_discovery_document_is_read_strictly() {
        assert_eq!(
            RemoteDiscovery::parse(
                "application/json",
                br#"{"issuer": "https://idp.example", "jwks_uri": "https://idp.example/jwks"}"#
            )
            .unwrap(),
            RemoteDiscovery {
                issuer: FOREIGN.to_string(),
                jwks_uri: format!("{FOREIGN}/jwks"),
            }
        );
        // Parameters on the content type are fine.
        assert!(
            RemoteDiscovery::parse(
                "application/json; charset=utf-8",
                br#"{"issuer": "https://idp.example", "jwks_uri": "https://x"}"#
            )
            .is_ok()
        );
        assert!(matches!(
            RemoteDiscovery::parse("text/html", br#"{"issuer": "x"}"#),
            Err(InvalidDiscovery::NotJson(_))
        ));
        assert!(matches!(
            RemoteDiscovery::parse("application/json", b"not json"),
            Err(InvalidDiscovery::Unparseable(_))
        ));
        // No issuer to check against the claim, no jwks_uri to fetch.
        assert_eq!(
            RemoteDiscovery::parse("application/json", br#"{"issuer": "https://idp.example"}"#),
            Err(InvalidDiscovery::Incomplete)
        );
    }
}
