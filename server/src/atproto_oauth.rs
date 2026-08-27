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
use axum_extra::extract::CookieJar;
use brolly_atproto::oauth;
use brolly_identity::db::{self, User};
use brolly_identity::oauth::Protocol;
use brolly_identity::{dpop, extract};
use serde::Deserialize;
use serde_json::json;

use crate::auth::SESSION_COOKIE;
use crate::{AppState, consent};

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

async fn session_user(state: &AppState, jar: &CookieJar) -> Option<User> {
    let cookie = jar.get(SESSION_COOKIE)?;
    db::user_for_session(&state.pool, cookie.value())
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

/// Verify the DPoP proof on a request to one of these endpoints.
///
/// Returns the key thumbprint the token will be bound to.
/// `Option`, not `Result<_, Response>`: a `Response` is a large `Err` to
/// carry, and both callers want the same error anyway — [`missing_proof`].
fn proof_thumbprint(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Option<String> {
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok())?;
    let url = format!("https://{}{path}", state.base_domain);
    match dpop::verify(proof, method, &url, None, now()) {
        Ok(verified) => Some(verified.thumbprint),
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof rejected");
            None
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

// --- discovery -------------------------------------------------------------------

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
        "token_endpoint_auth_methods_supported": ["none"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["atproto", "transition:generic"],
        "client_id_metadata_document_supported": true,
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
    let Some(jkt) = proof_thumbprint(&state, &headers, "POST", "/oauth/atproto/par") else {
        return missing_proof();
    };

    let form: ParForm = serde_urlencoded::from_bytes(&body).unwrap_or_default();

    let Some(client_id) = form.client_id.filter(|c| oauth::is_valid_client_id(c)) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id must be an https URL serving client metadata",
        );
    };
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

    match oauth::push_request(
        &state.pool,
        &client_id,
        &redirect_uri,
        form.scope.as_deref().unwrap_or("atproto"),
        form.state.as_deref(),
        &code_challenge,
        &jkt,
        form.login_hint.as_deref(),
    )
    .await
    {
        Ok(request_uri) => (
            StatusCode::CREATED,
            Json(json!({"request_uri": request_uri, "expires_in": 300})),
        )
            .into_response(),
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
    jar: CookieJar,
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

    let Some(user) = session_user(&state, &jar).await else {
        let next = format!(
            "/oauth/atproto/authorize?{}",
            form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", &client_id)
                .append_pair("request_uri", &request_uri)
                .finish()
        );
        let query: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("next", &next)
            .finish();
        return Redirect::to(&format!("/login?{query}")).into_response();
    };

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
        "Brolly",
        Protocol::Atproto,
        &client_id,
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

/// `POST /oauth/atproto/authorize`
pub async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: axum::body::Bytes,
) -> Response {
    // Host check before body parsing — an extractor rejection would answer
    // before it, leaking that the path exists on a subdomain (ADR 0009).
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let form: Decision = serde_urlencoded::from_bytes(&body).unwrap_or_default();

    let Some(user) = session_user(&state, &jar).await else {
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
    let Some(jkt) = proof_thumbprint(&state, &headers, "POST", "/oauth/atproto/token") else {
        return missing_proof();
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

fn token_response(access: String, refresh: String, scope: &str, did: &str) -> Response {
    (
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
        .into_response()
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

    issue_pair(state, &grant.client_id, grant.user_id, &grant.scope, jkt).await
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
    issue_pair(state, &grant.client_id, grant.user_id, &grant.scope, jkt).await
}

async fn issue_pair(
    state: &AppState,
    client_id: &str,
    user_id: uuid::Uuid,
    scope: &str,
    jkt: &str,
) -> Response {
    let Ok(Some(user)) = db::find_by_id(&state.pool, user_id).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the account behind this grant no longer exists",
        );
    };

    let access = oauth::issue_token(&state.pool, "access", client_id, user_id, scope, jkt).await;
    let refresh = oauth::issue_token(&state.pool, "refresh", client_id, user_id, scope, jkt).await;

    match (access, refresh) {
        (Ok(access), Ok(refresh)) => token_response(access, refresh, scope, &did_of(&user, state)),
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
        .route("/oauth/atproto/par", post(par))
        .route("/oauth/atproto/authorize", get(authorize).post(decide))
        .route("/oauth/atproto/token", post(token))
}
