//! ATProtocol's OAuth surface: PAR, authorize, token.
//!
//! The paths ADR 0008 reserved (`/oauth/atproto/*`), advertised in
//! `/.well-known/oauth-authorization-server` so clients are told where to go
//! rather than guessing — which is what let Mastodon keep the bare paths its
//! clients hardcode without a request-shape dispatcher in the middle.
//!
//! Three requirements run through every handler, and all three are the
//! protocol's rather than ours:
//!
//! * **PAR first.** The authorization request is pushed here and referenced by
//!   an opaque `request_uri`. Nothing meaningful travels through the browser,
//!   so nothing in the address bar can be edited.
//! * **DPoP everywhere**, with the key pledged at push time — so the token is
//!   bound to a key the client committed to before the member saw a screen.
//! * **`client_id` is a URL** serving client metadata. No registration, no
//!   secret: the client's identity is a document anyone can fetch.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use brolly_atproto::oauth;
use brolly_identity::db::{self, User};
use brolly_identity::dpop::{self, DpopError};
use brolly_identity::extract;
use brolly_identity::oauth::Protocol;
use serde::Deserialize;
use serde_json::json;

use brolly_atproto::client_assertion;
use brolly_atproto::client_metadata::{
    ClientAuth, ClientError, ClientId, ClientJwks, ClientMetadata, check_request, parse_client_id,
};

use crate::auth::session_user;
use crate::client_metadata::{LookupError, lookup_client, refetch_client};
use crate::{AppState, consent};
use url::Url;

const CONSENT_TTL: i64 = 600;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn oauth_error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error": code, "error_description": description})),
    )
        .into_response()
}

fn wrong_host(state: &AppState, headers: &HeaderMap) -> bool {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    extract::subdomain_user(host, &state.base_domain).is_some()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// A DPoP proof checked for one of these endpoints.
///
/// The nonce failure gets its own arm (stage 2, C): it is the one refusal
/// whose answer is a *retry*, with the fresh nonce the retry needs, so both
/// endpoints must be able to tell it from any other bad proof.
enum ProofCheck {
    /// Verified and spent; carries the key thumbprint the token binds to.
    Spent(String),
    /// The proof carries no valid nonce: answer `use_dpop_nonce` with a fresh
    /// one, and the client retries.
    NeedNonce,
    /// No usable proof: the refusal both endpoints already made.
    Missing,
}

/// Verify and spend the DPoP proof on a request to one of these endpoints.
///
/// The proof is spent before anything else about the request is checked, so a
/// request refused later has still used it (see `Unspent::spend`). A failure to
/// record the proof refuses the request too. It is logged at `error` so it
/// isn't mistaken for a client's mistake.
async fn proof_thumbprint(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> ProofCheck {
    let Some(proof) = headers.get("dpop").and_then(|h| h.to_str().ok()) else {
        return ProofCheck::Missing;
    };
    let url = format!("https://{}{path}", state.base_domain);
    let at = now();
    // The ATProtocol profile requires nonces (stage 2, C): the current and
    // previous bucket's values are the ones a proof may carry.
    let accepted = dpop::accepted_nonces(&state.dpop_nonce_secret, at);
    let unspent = match dpop::verify(proof, method, &url, None, at, Some(&accepted)) {
        Ok(unspent) => unspent,
        Err(DpopError::NonceRequired) => return ProofCheck::NeedNonce,
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof rejected");
            return ProofCheck::Missing;
        }
    };
    match unspent.spend(&state.pool, at).await {
        Ok(verified) => ProofCheck::Spent(verified.thumbprint),
        Err(DpopError::Storage(e)) => {
            tracing::error!(error = %e, "recording a DPoP proof failed");
            ProofCheck::Missing
        }
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof refused");
            ProofCheck::Missing
        }
    }
}

fn missing_proof() -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_dpop_proof",
        "ATProtocol requires a valid DPoP proof on this endpoint",
    )
}

/// The `DPoP-Nonce` header a response hands out: the current bucket's value
/// (stage 2, C). `Ok`/`Err` rather than `expect` because that is the pattern
/// `pod.rs`'s `challenge_response` set — and the fallback is a degraded but
/// honest answer, not a panic. Unreachable in practice: base64url is always a
/// legal header value.
fn nonce_header(state: &AppState) -> Option<(header::HeaderName, header::HeaderValue)> {
    let nonce = dpop::current_nonce(&state.dpop_nonce_secret, now());
    let value = header::HeaderValue::from_str(&nonce).ok()?;
    Some((header::HeaderName::from_static("dpop-nonce"), value))
}

/// The AS-side nonce dance (stage 2, C): a 400 naming the retry, plus the
/// fresh nonce to retry with — the shape the reference's `UseDpopNonceError`
/// builds. RFC 9449's flow, which clients are required to be resilient to.
fn use_dpop_nonce(state: &AppState) -> Response {
    match nonce_header(state) {
        Some((name, value)) => (
            StatusCode::BAD_REQUEST,
            [(name, value)],
            Json(json!({
                "error": "use_dpop_nonce",
                "error_description": "retry with this nonce in the proof's nonce claim",
            })),
        )
            .into_response(),
        None => oauth_error(
            StatusCode::BAD_REQUEST,
            "use_dpop_nonce",
            "retry with a fresh DPoP nonce",
        ),
    }
}

/// A client, or what it asked for, was refused.
///
/// Always JSON, never a redirect: the redirect URI is exactly the thing that
/// hasn't been shown to belong to the client.
fn client_refusal(e: &ClientError) -> Response {
    let code = match e {
        ClientError::RedirectUriNotAllowed => "invalid_request",
        ClientError::ScopeNotAllowed(_) => "invalid_scope",
        ClientError::InvalidClientId(_) | ClientError::InvalidMetadata(_) => "invalid_client",
    };
    oauth_error(StatusCode::BAD_REQUEST, code, &e.to_string())
}

/// The client's metadata couldn't be used.
///
/// `LookupError`'s `Display` gives every `Unreachable` the same description,
/// so this can't be used to map internal hosts (S4).
fn lookup_refusal(e: &LookupError<ClientError>) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_client", &e.to_string())
}

/// What the consent screen calls a client: its host, or
/// `localhost (development)`.
///
/// Never its self-asserted `client_name` or `logo_uri`. The spec says not to
/// show those for clients the operator hasn't vetted, and brolly has no vetted
/// list (S5). `None` if the stored `client_id` no longer parses.
fn app_name(client_id: &str) -> Option<String> {
    match parse_client_id(client_id).ok()? {
        ClientId::Discoverable(url) => url.host_str().map(str::to_owned),
        ClientId::Loopback(_) => Some("localhost (development)".to_owned()),
    }
}

// --- confidential clients (stage 2, F) --------------------------------------------

/// Whether a request carries any client-assertion field. A public client's
/// request carries none — one that does is refused, because an assertion is a
/// credential only a confidential client can have verified.
fn carries_assertion(assertion_type: Option<&str>, assertion: Option<&str>) -> bool {
    assertion_type.is_some() || assertion.is_some()
}

/// A confidential session's client authentication at the token endpoint
/// (stage 2, F): the same kind of assertion, and the same key — a different
/// key is a different client instance, answered `invalid_grant`.
async fn token_authentication(
    state: &AppState,
    client_id: &str,
    bound_jkt: &str,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
    bypass_cache: bool,
) -> Result<(), Response> {
    let jwks = confidential_keys(state, client_id, bypass_cache).await?;
    bound_assertion(state, &jwks, bound_jkt, assertion_type, assertion).await
}

/// The assertion a confidential client must carry: the jwt-bearer type and
/// the JWT itself. `None` is a refusal — a confidential client that does not
/// authenticate is not one.
fn required_assertion<'a>(
    assertion_type: Option<&str>,
    assertion: Option<&'a str>,
) -> Option<&'a str> {
    match (assertion_type, assertion) {
        (Some(t), Some(a)) if t == client_assertion::ASSERTION_TYPE => Some(a),
        _ => None,
    }
}

/// The wire answer to a missing or malformed client assertion (stage 2, F).
fn missing_assertion() -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_client",
        "a confidential client must carry client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer and a client_assertion",
    )
}

/// A confidential client's key set: the inline `jwks` its metadata carries,
/// or the document its `jwks_uri` serves — through the same hardened fetch
/// (https only, public addresses only). `bypass_cache` is the refresh case
/// (stage 2, F): a key removed from a `jwks_uri` document must be noticed on
/// the very next refresh, not when the cache happens to expire.
async fn client_keys(
    state: &AppState,
    metadata: &ClientMetadata,
    bypass_cache: bool,
) -> Result<ClientJwks, Response> {
    let refusal =
        |description: &str| oauth_error(StatusCode::BAD_REQUEST, "invalid_client", description);
    let ClientAuth::Confidential { jwks, jwks_uri } = metadata.client_auth() else {
        return Err(refusal(
            "this session's client is no longer a confidential client",
        ));
    };
    if let Some(jwks) = jwks {
        return Ok(jwks.clone());
    }
    let Some(uri) = jwks_uri else {
        return Err(refusal("this client's metadata names no key set"));
    };
    let Ok(url) = Url::parse(uri) else {
        return Err(refusal("this client's jwks_uri is not a URL"));
    };
    let fetched = if bypass_cache {
        state.client_jwks.refetch(&url).await
    } else {
        state.client_jwks.fetch(&url).await
    };
    fetched.map_err(|e| lookup_refusal(&e))
}

/// Verify and spend a client assertion, mapping every refusal to the wire
/// (stage 2, F): a refused assertion is `invalid_client`, and a storage fault
/// is the server's, not the client's.
async fn spend_assertion(
    state: &AppState,
    jwks: &ClientJwks,
    assertion: &str,
) -> Result<String, Response> {
    let issuer = format!("https://{}", state.base_domain);
    let unspent = match client_assertion::verify(jwks, assertion, &issuer, now()) {
        Ok(unspent) => unspent,
        Err(e) => {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                &e.to_string(),
            ));
        }
    };
    match unspent.spend(&state.pool, now()).await {
        Ok(verified) => Ok(verified.jkt),
        Err(client_assertion::AssertionError::Storage(e)) => {
            tracing::error!(error = %e, "recording a client assertion failed");
            Err(oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not verify the client",
            ))
        }
        Err(e) => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            &e.to_string(),
        )),
    }
}

/// The client authentication a push must carry (stage 2, F): a confidential
/// client's jwt-bearer assertion, verified against its own key set and spent
/// (the `jti` is single-use); a public client carries nothing. Returns the
/// signing key's thumbprint — the `client_jkt` the session binds to — or
/// `None` for a public client.
async fn push_authentication(
    state: &AppState,
    metadata: &ClientMetadata,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<Option<String>, Response> {
    if !metadata.client_auth().is_confidential() {
        if carries_assertion(assertion_type, assertion) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "a public client does not authenticate with a client assertion",
            ));
        }
        return Ok(None);
    }
    let assertion = required_assertion(assertion_type, assertion);
    let Some(assertion) = assertion else {
        return Err(missing_assertion());
    };
    let jwks = client_keys(state, metadata, false).await?;
    Ok(Some(spend_assertion(state, &jwks, assertion).await?))
}

/// A confidential client's key set, looked up by the `client_id` its
/// session names (stage 2, F). `bypass_cache` is the refresh case: the
/// metadata — and the key set behind a `jwks_uri` — is fetched
/// cache-bypassingly, the fetch `issuer_jwks` does for a Solid key rotation,
/// so a key removed from the JWKS is noticed on the very next refresh.
async fn confidential_keys(
    state: &AppState,
    client_id: &str,
    bypass_cache: bool,
) -> Result<ClientJwks, Response> {
    let id = match parse_client_id(client_id) {
        Ok(id) => id,
        Err(e) => return Err(client_refusal(&e)),
    };
    let metadata = if bypass_cache {
        refetch_client(state.clients.as_ref(), &id).await
    } else {
        lookup_client(state.clients.as_ref(), &id).await
    };
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(e) => return Err(lookup_refusal(&e)),
    };
    client_keys(state, &metadata, bypass_cache).await
}

/// A confidential session's client authentication at the token endpoint
/// (stage 2, F): the same kind of assertion, and the same key — a different
/// key is a different client instance, answered `invalid_grant`.
async fn bound_assertion(
    state: &AppState,
    jwks: &ClientJwks,
    bound_jkt: &str,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<(), Response> {
    let assertion = required_assertion(assertion_type, assertion);
    let Some(assertion) = assertion else {
        return Err(missing_assertion());
    };
    let jkt = spend_assertion(state, jwks, assertion).await?;
    if jkt != bound_jkt {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this session is bound to a different client key",
        ));
    }
    Ok(())
}

// --- discovery -------------------------------------------------------------------

/// The scopes this server grants (stage 2, E): everything the AS metadata
/// advertises as `scopes_supported`, in one constant so the advertisement and
/// the PAR check cannot drift. A requested scope outside it is refused at
/// push, not echoed into a token response — a granted scope the metadata
/// never declared is the metadata lying.
const SCOPES_SUPPORTED: &[&str] = &["atproto", "transition:generic"];

/// `GET /.well-known/oauth-authorization-server`
///
/// Generated from the endpoint map, so an advertised path that is not mounted
/// is impossible rather than merely unlikely (ADR 0008).
pub async fn metadata(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let issuer = format!("https://{}", state.base_domain);
    let endpoint = |suffix: &str| {
        brolly_identity::oauth::endpoints_for(Protocol::Atproto)
            .into_iter()
            .find(|p| p.ends_with(suffix))
            .map(|p| format!("{issuer}{p}"))
    };

    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": endpoint("authorize"),
        "token_endpoint": endpoint("token"),
        "pushed_authorization_request_endpoint": endpoint("par"),
        // Not optional, and said so: a client that skips PAR is refused.
        "require_pushed_authorization_requests": true,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "scopes_supported": SCOPES_SUPPORTED,
        "client_id_metadata_document_supported": true,
        // Declaring the `iss` the redirect already emits (stage 2, E), so a
        // client that checked the profile's matrix knows to expect it.
        "authorization_response_iss_parameter_supported": true,
        // The one client-authentication algorithm the profile requires (stage
        // 2, E) — the algorithm every confidential client's assertion (F) is
        // signed with, now that `private_key_jwt` above is accepted.
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
    }))
    .into_response()
}

/// `GET /.well-known/oauth-protected-resource` (stage 2, E).
///
/// The base domain's answer: this origin is its own authorization server. A
/// single origin URL, no path — the draft's requirement — so a client that
/// finds this document is told where to take OAuth, not left guessing at an
/// AS on some other host.
pub async fn protected_resource(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let origin = format!("https://{}", state.base_domain);
    Json(json!({
        "resource": origin,
        "authorization_servers": [origin],
    }))
    .into_response()
}

// --- pushed authorization request --------------------------------------------------

#[derive(Deserialize, Default)]
pub struct ParForm {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    response_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    login_hint: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

/// `POST /oauth/atproto/par`
pub async fn par(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let jkt = match proof_thumbprint(&state, &headers, "POST", "/oauth/atproto/par").await {
        ProofCheck::Spent(jkt) => jkt,
        ProofCheck::NeedNonce => return use_dpop_nonce(&state),
        ProofCheck::Missing => return missing_proof(),
    };
    let form: ParForm = serde_urlencoded::from_bytes(&body).unwrap_or_default();

    // The request's own checks first. They cost nothing, and a request that
    // fails them must not make us fetch anything.
    let Some(redirect_uri) = form.redirect_uri else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        );
    };
    if form.response_type.as_deref() != Some("code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let Some(code_challenge) = form.code_challenge else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PKCE is required",
        );
    };
    if form.code_challenge_method.as_deref() != Some("S256") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }

    // Then the client: who it is, what its metadata says, and whether this
    // request is within it. Only then is anything stored.
    let Some(raw_client_id) = form.client_id else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id is required",
        );
    };
    let client_id = match parse_client_id(&raw_client_id) {
        Ok(id) => id,
        Err(e) => return client_refusal(&e),
    };
    let metadata = match lookup_client(state.clients.as_ref(), &client_id).await {
        Ok(metadata) => metadata,
        Err(e) => return lookup_refusal(&e),
    };
    let scope = form.scope.as_deref().unwrap_or("atproto");
    if let Err(e) = check_request(&metadata, &redirect_uri, scope) {
        return client_refusal(&e);
    }
    // The server's own allowlist too (stage 2, E): requested ⊆ client-declared
    // *and* ⊆ `scopes_supported`. A scope the server does not grant is refused
    // `invalid_scope` at push time, not echoed in a token response the
    // metadata then lies about.
    if scope
        .split(' ')
        .any(|s| !s.is_empty() && !SCOPES_SUPPORTED.contains(&s))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "a requested scope is not one this server grants",
        );
    }
    // A loopback redirect matched after URL parsing (ports ignored), and
    // parsing strips tabs and newlines and normalises the host, so the raw
    // string may not be the URL that was checked. It is stored, sent as
    // Location, and compared as an exact string at the token endpoint, so
    // require it to be its own serialization. (Storing the serialization
    // instead would refuse, at the token endpoint, a client that repeats what
    // it sent.) A discoverable client's redirect already equals, byte for
    // byte, a string its own metadata declares.
    if client_id.is_loopback()
        && !Url::parse(&redirect_uri).is_ok_and(|u| u.as_str() == redirect_uri)
    {
        return client_refusal(&ClientError::RedirectUriNotAllowed);
    }

    // A code_challenge is single-use within 24 hours (stage 2, H): the
    // profile's PKCE "must", defense in depth against a challenge-carrying
    // interceptor. Last check before storing, so a refused push above does not
    // burn the challenge a corrected retry carries.
    match oauth::use_code_challenge(&state.pool, &code_challenge, now()).await {
        Ok(true) => {}
        Ok(false) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "this code_challenge has already been used within the last 24 hours",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "recording a code_challenge failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not store the request",
            );
        }
    }

    // The client authenticates here (stage 2, F): a confidential client's
    // assertion is verified and its `jti` spent before anything is stored,
    // the DPoP discipline — a request refused later has still used it. The
    // thumbprint of the signing key is what the session binds to.
    let client_jkt = match push_authentication(
        &state,
        &metadata,
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    )
    .await
    {
        Ok(jkt) => jkt,
        Err(response) => return response,
    };

    match oauth::push_request(
        &state.pool,
        &raw_client_id,
        &redirect_uri,
        scope,
        form.state.as_deref(),
        &code_challenge,
        &jkt,
        form.login_hint.as_deref(),
        client_jkt.as_deref(),
    )
    .await
    {
        // The 201 carries the nonce (stage 2, C): the profile's own flow —
        // "including a DPoP nonce via HTTP header" — so the client stays
        // current without waiting for a refusal to teach it.
        Ok(request_uri) => match nonce_header(&state) {
            Some((name, value)) => (
                StatusCode::CREATED,
                [(name, value)],
                Json(json!({"request_uri": request_uri, "expires_in": 300})),
            )
                .into_response(),
            None => (
                StatusCode::CREATED,
                Json(json!({"request_uri": request_uri, "expires_in": 300})),
            )
                .into_response(),
        },
        Err(e) => {
            tracing::error!(error = %e, "storing a pushed request failed");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not store the request",
            )
        }
    }
}

// --- authorize --------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeParams {
    client_id: Option<String>,
    request_uri: Option<String>,
}

/// `GET /oauth/atproto/authorize`
///
/// Carries only a `client_id` and a `request_uri`; everything else was pushed.
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let (Some(client_id), Some(request_uri)) = (params.client_id, params.request_uri) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id and request_uri are required; this endpoint requires PAR",
        );
    };

    let Ok(Some(pushed)) = oauth::read_request(&state.pool, &request_uri).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_uri",
            "this request has expired or was already used",
        );
    };
    // The client naming itself here must be the one that pushed. Otherwise a
    // client could ride another's pushed request.
    if pushed.client_id != client_id {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id does not match the pushed request",
        );
    }
    let Some(app_name) = app_name(&client_id) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "this request's client_id is not valid",
        );
    };

    let Some(user) = session_user(&state, &headers).await else {
        return login_redirect(&client_id, &request_uri);
    };
    // The hint is the account the client bound the session to (stage 2, H).
    // A member logged in as someone else never sees the consent screen —
    // they are sent to log in as the hinted account, the same redirect an
    // anonymous arrival gets. Consenting as someone else would only surface
    // later as the client's `sub` verification failure: a flow that completes
    // and then breaks, rather than one that never misleads.
    if let Some(hint) = pushed.login_hint.as_deref()
        && !hint_names(&state, &user, hint)
    {
        return login_redirect(&client_id, &request_uri);
    }

    let request_token = match state.provider_key.sign(&json!({
        "typ": "brolly:consent",
        "protocol": "atproto",
        "uid": user.id.to_string(),
        "request_uri": request_uri,
        "iat": now(),
        "exp": now() + CONSENT_TTL,
    })) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(error = %e, "signing the consent request failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "consent failed",
            );
        }
    };

    // The third protocol through one screen (ADR 0011).
    consent::render_consent(
        &state,
        Protocol::Atproto,
        &app_name,
        &user.username,
        &client_id,
        &pushed.scope,
        "/oauth/atproto/authorize",
        &request_token,
    )
}

#[derive(Deserialize, Default)]
pub struct Decision {
    request: Option<String>,
    decision: Option<String>,
}

fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        query.append_pair(k, v);
    }
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}{}", query.finish())
}

/// The login redirect an arrival that must (re-)authenticate gets (stage 2,
/// H): the authorize URL as `next`, so the flow resumes as the member the
/// `login_hint` named. The same shape for an anonymous arrival and for a
/// member who is logged in as someone else — the hint is the account the
/// *client* bound the session to, and only that account may consent.
fn login_redirect(client_id: &str, request_uri: &str) -> Response {
    let next = format!(
        "/oauth/atproto/authorize?{}",
        form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", client_id)
            .append_pair("request_uri", request_uri)
            .finish()
    );
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("next", &next)
        .finish();
    Redirect::to(&format!("/login?{query}")).into_response()
}

/// Whether a `login_hint` names this member (stage 2, H): any of their
/// identifier forms satisfies it — username, handle, either DID, email. The
/// comparison is case-insensitive because the forms themselves are: emails are
/// stored lowercased, handles and `did:web` hosts are case-insensitive
/// hostnames, and `did:plc` DIDs are lowercase base32 by construction — so an
/// exact comparison could only produce a redirect loop for the *right* member.
fn hint_names(state: &AppState, user: &User, hint: &str) -> bool {
    let hint = hint.trim().to_ascii_lowercase();
    [
        Some(user.username.clone()),
        Some(format!("{}.{}", user.username, state.base_domain)),
        user.did_plc.clone(),
        Some(format!("did:web:{}.{}", user.username, state.base_domain)),
        user.email.clone(),
    ]
    .into_iter()
    .flatten()
    .any(|form| form.to_ascii_lowercase() == hint)
}

/// `POST /oauth/atproto/authorize`
pub async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Host check before body parsing — an extractor rejection would answer
    // before it, leaking that the path exists on a subdomain (ADR 0009).
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let form: Decision = serde_urlencoded::from_bytes(&body).unwrap_or_default();

    let Some(user) = session_user(&state, &headers).await else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "your session has expired",
        );
    };
    let Some(request) = form.request else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing the request token",
        );
    };

    let Ok(claims) = state.provider_key.verify(&request, now()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this authorization request has expired or been tampered with",
        );
    };
    if claims["typ"] != "brolly:consent" || claims["protocol"] != "atproto" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "not an ATProtocol authorization request",
        );
    }
    if claims["uid"].as_str() != Some(&user.id.to_string()) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this request belongs to a different account",
        );
    }

    let request_uri = claims["request_uri"].as_str().unwrap_or_default();

    // Spent here, not at read time: the screen may render more than once, but
    // it may only be answered once.
    let Ok(Some(pushed)) = oauth::consume_request(&state.pool, request_uri).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_uri",
            "this request has expired or was already used",
        );
    };

    // The authoritative hint check (stage 2, H), on the pair the spec names:
    // `decide` compares the pushed `login_hint` against the consenting
    // member. Unreachable in practice — `authorize` refuses to render (and so
    // to mint a request token) for a mismatch — but the render-time check is
    // UX, and this one is the rule: a stale or forged request token must not
    // turn a hinted flow into someone else's session.
    if let Some(hint) = pushed.login_hint.as_deref()
        && !hint_names(&state, &user, hint)
    {
        return login_redirect(&pushed.client_id, request_uri);
    }

    if form.decision.as_deref() != Some("allow") {
        let mut params = vec![("error", "access_denied")];
        if let Some(s) = pushed.state.as_deref() {
            params.push(("state", s));
        }
        return Redirect::to(&redirect_with(&pushed.redirect_uri, &params)).into_response();
    }

    let code = match oauth::issue_code(
        &state.pool,
        &pushed.client_id,
        user.id,
        &pushed.redirect_uri,
        &pushed.scope,
        &pushed.code_challenge,
        &pushed.dpop_jkt,
        pushed.client_jkt.as_deref(),
    )
    .await
    {
        Ok(code) => code,
        Err(e) => {
            tracing::error!(error = %e, "issuing an authorization code failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "authorization failed",
            );
        }
    };

    let mut params = vec![("code", code.as_str()), ("iss", "")];
    let issuer = format!("https://{}", state.base_domain);
    params[1] = ("iss", issuer.as_str());
    if let Some(s) = pushed.state.as_deref() {
        params.push(("state", s));
    }
    Redirect::to(&redirect_with(&pushed.redirect_uri, &params)).into_response()
}

// --- token -------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

/// `POST /oauth/atproto/token`
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let jkt = match proof_thumbprint(&state, &headers, "POST", "/oauth/atproto/token").await {
        ProofCheck::Spent(jkt) => jkt,
        ProofCheck::NeedNonce => return use_dpop_nonce(&state),
        ProofCheck::Missing => return missing_proof(),
    };
    let form: TokenForm = serde_urlencoded::from_bytes(&body).unwrap_or_default();

    match form.grant_type.as_deref() {
        Some("authorization_code") => code_grant(&state, form, &jkt).await,
        Some("refresh_token") => refresh_grant(&state, form, &jkt).await,
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("{} is not supported", other.unwrap_or("no grant_type")),
        ),
    }
}

fn token_response(
    state: &AppState,
    access: String,
    refresh: String,
    scope: &str,
    did: &str,
) -> Response {
    // The 200 carries the nonce (stage 2, C), keeping the client's nonce
    // current across the session the way PAR's 201 does at its start.
    let nonce = nonce_header(state);
    let mut response = (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({
            "access_token": access,
            "token_type": "DPoP",
            "expires_in": oauth::ACCESS_TTL_SECONDS as i64,
            "refresh_token": refresh,
            "scope": scope,
            // ATProtocol clients read the subject DID straight off the token
            // response rather than making a second call for it.
            "sub": did,
        })),
    )
        .into_response();
    if let Some((name, value)) = nonce {
        response.headers_mut().insert(name, value);
    }
    response
}

fn did_of(user: &User, state: &AppState) -> String {
    user.did_plc
        .clone()
        .unwrap_or_else(|| format!("did:web:{}.{}", user.username, state.base_domain))
}

async fn code_grant(state: &AppState, form: TokenForm, jkt: &str) -> Response {
    let (Some(code), Some(verifier)) = (form.code.as_deref(), form.code_verifier.as_deref()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code and code_verifier are required",
        );
    };

    let Ok(Some(grant)) = oauth::redeem_code(&state.pool, code).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this code is expired, already used, or not one of ours",
        );
    };

    // A confidential session authenticates again here (stage 2, F): the same
    // kind of assertion and the same key — a different key is a different
    // client instance. A public session's code carries no binding, so an
    // assertion is a refusal rather than a requirement.
    match grant.client_jkt.as_deref() {
        Some(bound) => {
            if let Err(response) = token_authentication(
                state,
                &grant.client_id,
                bound,
                form.client_assertion_type.as_deref(),
                form.client_assertion.as_deref(),
                false,
            )
            .await
            {
                return response;
            }
        }
        None if carries_assertion(
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
        ) =>
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "a public client does not authenticate with a client assertion",
            );
        }
        None => {}
    }

    // The key that pushed the request is the key that gets the token. Without
    // this, PAR's key pledge would be decorative.
    if grant.dpop_jkt != jkt {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this authorization was pledged to a different key",
        );
    }

    use base64::Engine;
    use sha2::{Digest, Sha256};
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    if computed != grant.code_challenge {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the code_verifier does not match the code_challenge",
        );
    }
    if form
        .redirect_uri
        .as_deref()
        .is_some_and(|r| r != grant.redirect_uri)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match the authorization request",
        );
    }
    if form
        .client_id
        .as_deref()
        .is_some_and(|c| c != grant.client_id)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id does not match the authorization request",
        );
    }

    issue_pair(
        state,
        &grant.client_id,
        grant.user_id,
        &grant.scope,
        jkt,
        grant.client_jkt.as_deref(),
        time::OffsetDateTime::now_utc(),
    )
    .await
}

async fn refresh_grant(state: &AppState, form: TokenForm, jkt: &str) -> Response {
    let Some(token) = form.refresh_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    let Ok(Some(grant)) = oauth::rotate_refresh(&state.pool, token).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this refresh token is expired, already used, or not one of ours",
        );
    };
    if grant.dpop_jkt != jkt {
        tracing::warn!("a refresh token was presented by a key it was not issued to");
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this refresh token was issued to a different key",
        );
    }
    let assertion_fields = (
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    if let Some(bound) = grant.client_jkt.as_deref() {
        // A confidential session (stage 2, F). The metadata — and the key set
        // behind a `jwks_uri` — is re-fetched cache-bypassingly, and the
        // session is revoked if the key has left the JWKS: the profile's
        // "must revoke the session … if the client authentication key
        // becomes absent" — key removal is the kill switch. Then the
        // assertion, and the same key.
        let jwks = match confidential_keys(state, &grant.client_id, true).await {
            Ok(jwks) => jwks,
            Err(response) => return response,
        };
        if !jwks.contains(bound) {
            tracing::info!(
                client_id = %grant.client_id,
                "a confidential session's key has left its client's JWKS; session revoked"
            );
            if let Err(e) =
                oauth::revoke_bound_sessions(&state.pool, &grant.client_id, grant.user_id, bound)
                    .await
            {
                tracing::error!(error = %e, "revoking a confidential session failed");
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "could not refresh",
                );
            }
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this session's key is no longer in the client's JWKS",
            );
        }
        if let Err(response) =
            bound_assertion(state, &jwks, bound, assertion_fields.0, assertion_fields.1).await
        {
            return response;
        }
        // No anchor: the 2-week overall cap is the public client's rule (G) —
        // this is the profile's authenticated, key-bound, remotely-revocable
        // session, and the 180-day refresh token is its cap.
    } else {
        if carries_assertion(assertion_fields.0, assertion_fields.1) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "a public client does not authenticate with a client assertion",
            );
        }
        // The session anchor (stage 2, G): rotation copied `anchored_at`
        // forward, so the overall session lifetime is capped however much the
        // client refreshes. The presented token itself may be fresh — minted
        // seconds ago, weeks to run — and freshness launders nothing; the
        // anchor refuses it. The presented token was spent above either way.
        if time::OffsetDateTime::now_utc()
            > grant.anchored_at + time::Duration::seconds_f64(oauth::SESSION_TTL_SECONDS)
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this session has passed its overall lifetime",
            );
        }
    }
    issue_pair(
        state,
        &grant.client_id,
        grant.user_id,
        &grant.scope,
        jkt,
        grant.client_jkt.as_deref(),
        grant.anchored_at,
    )
    .await
}

async fn issue_pair(
    state: &AppState,
    client_id: &str,
    user_id: uuid::Uuid,
    scope: &str,
    jkt: &str,
    client_jkt: Option<&str>,
    anchored_at: time::OffsetDateTime,
) -> Response {
    let Ok(Some(user)) = db::find_by_id(&state.pool, user_id).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the account behind this grant no longer exists",
        );
    };

    let access = oauth::issue_token(
        &state.pool,
        "access",
        client_id,
        user_id,
        scope,
        jkt,
        client_jkt,
        anchored_at,
    )
    .await;
    let refresh = oauth::issue_token(
        &state.pool,
        "refresh",
        client_id,
        user_id,
        scope,
        jkt,
        client_jkt,
        anchored_at,
    )
    .await;

    match (access, refresh) {
        (Ok(access), Ok(refresh)) => {
            token_response(state, access, refresh, scope, &did_of(&user, state))
        }
        _ => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "could not issue tokens",
        ),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route("/oauth/atproto/par", post(par))
        .route("/oauth/atproto/authorize", get(authorize).post(decide))
        .route("/oauth/atproto/token", post(token))
}
