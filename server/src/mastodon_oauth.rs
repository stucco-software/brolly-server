//! Mastodon's OAuth surface.
//!
//! These sit on the **bare** `/oauth/*` paths, and ADR 0008 explains why: of
//! the three protocols, Mastodon is the only one with no discovery document, so
//! its clients — Phanpy, Ivory, Tusky, Mona — hardcode these paths and never
//! look them up. The protocols that *can* be told where to go were moved, so no
//! request-shape dispatcher is needed to tell them apart.
//!
//! A misconfigured client can still arrive here speaking something else. That
//! gets a `400` naming the correct endpoint, via
//! `identity::oauth::detect_misrouted` — detection for diagnosis, never for
//! routing. Silently making a request work at a path the spec never promised is
//! how the predecessor ended up with a dispatcher every protocol depended on.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use brolly_identity::oauth::{Protocol, RequestShape, detect_misrouted};
use brolly_identity::{extract, oauth as oauth_layout};
use brolly_mastodon::oauth;
use serde::Deserialize;
use serde_json::json;

use crate::auth::session_user;
use crate::{AppState, consent};

/// The out-of-band redirect. A client with no callback URL — a terminal tool,
/// or a mobile app mid-setup — gets the code displayed instead.
const OOB: &str = "urn:ietf:wg:oauth:2.0:oob";

/// How long a member has to answer the consent screen.
const CONSENT_TTL: i64 = 600;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Mastodon's error shape. Clients parse `error`, and a bare string or an HTML
/// body makes them show "something went wrong" with nothing to act on.
fn api_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

fn oauth_error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error": code, "error_description": description})),
    )
        .into_response()
}

fn host_of(headers: &HeaderMap) -> &str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
}

/// These are apex-only (ADR 0008). A subdomain must not offer a second place to
/// send credentials.
fn wrong_host(state: &AppState, headers: &HeaderMap) -> bool {
    extract::subdomain_user(host_of(headers), &state.base_domain).is_some()
}

// --- app registration --------------------------------------------------------

/// `POST /api/v1/apps`
///
/// Accepts form encoding and JSON, because clients send both and Mastodon
/// accepts both.
#[derive(Deserialize, Default)]
pub struct AppRegistration {
    client_name: Option<String>,
    redirect_uris: Option<String>,
    scopes: Option<String>,
    website: Option<String>,
}

pub async fn register_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return api_error(StatusCode::NOT_FOUND, "Record not found");
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let form: AppRegistration = if content_type.contains("json") {
        match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(_) => return api_error(StatusCode::BAD_REQUEST, "Malformed JSON"),
        }
    } else {
        match serde_urlencoded::from_bytes(&body) {
            Ok(parsed) => parsed,
            Err(_) => return api_error(StatusCode::BAD_REQUEST, "Malformed form body"),
        }
    };

    let Some(name) = form.client_name.filter(|n| !n.trim().is_empty()) else {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Validation failed: Client name can't be blank",
        );
    };
    // Mastodon accepts several redirect URIs separated by newlines.
    let redirect_uris: Vec<String> = form
        .redirect_uris
        .unwrap_or_else(|| OOB.to_string())
        .split(['\n', ' '])
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_string)
        .collect();

    if redirect_uris.is_empty() {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Validation failed: Redirect URI can't be blank",
        );
    }

    let scopes = form
        .scopes
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| oauth::DEFAULT_SCOPES.to_string());

    match oauth::register_app(
        &state.pool,
        &name,
        &redirect_uris,
        &scopes,
        form.website.as_deref(),
    )
    .await
    {
        Ok(registered) => (
            StatusCode::OK,
            Json(json!({
                // Mastodon returns a numeric-looking id; clients treat it as
                // opaque and mostly ignore it in favour of client_id.
                "id": registered.app.client_id,
                "name": registered.app.name,
                "website": registered.app.website,
                "redirect_uri": registered.app.redirect_uris.join("\n"),
                "redirect_uris": registered.app.redirect_uris,
                "scopes": registered.app.scopes.split_whitespace().collect::<Vec<_>>(),
                "client_id": registered.app.client_id,
                // The only time this is ever visible. It is stored hashed.
                "client_secret": registered.client_secret,
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "app registration failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Registration failed")
        }
    }
}

// --- authorize ---------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// Rebuild the request, so a login round trip returns to it.
fn authorize_target(params: &AuthorizeParams) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    let mut pair = |k: &str, v: &Option<String>| {
        if let Some(v) = v {
            query.append_pair(k, v);
        }
    };
    pair("response_type", &params.response_type);
    pair("client_id", &params.client_id);
    pair("redirect_uri", &params.redirect_uri);
    pair("scope", &params.scope);
    pair("state", &params.state);
    pair("code_challenge", &params.code_challenge);
    pair("code_challenge_method", &params.code_challenge_method);
    format!("/oauth/authorize?{}", query.finish())
}

/// `GET /oauth/authorize`
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    if wrong_host(&state, &headers) {
        return api_error(StatusCode::NOT_FOUND, "Record not found");
    }

    // A client speaking ATProtocol or Solid at Mastodon's path gets told where
    // to go, rather than a deserialization error naming an internal field.
    if let Some(misrouted) = detect_misrouted(&RequestShape {
        path: "/oauth/authorize",
        dpop_header: headers.contains_key("dpop"),
        request_uri: false,
        code_challenge: params.code_challenge.is_some(),
        client_id_is_url: params
            .client_id
            .as_deref()
            .is_some_and(|c| c.starts_with("http")),
    }) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!(
                "this looks like a {:?} request; its authorization endpoint is {}",
                misrouted.looks_like, misrouted.correct_path
            ),
        );
    }

    if params.response_type.as_deref() != Some("code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let Some(client_id) = params.client_id.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    };

    let app = match oauth::find_app(&state.pool, client_id).await {
        Ok(Some(app)) => app,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "this application is not registered with this server",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "app lookup failed");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Lookup failed");
        }
    };

    let redirect_uri = params
        .redirect_uri
        .clone()
        .unwrap_or_else(|| app.redirect_uris.first().cloned().unwrap_or_default());
    if !app.redirect_uris.contains(&redirect_uri) {
        // Never redirect to it: an unregistered redirect_uri is exactly the
        // value an attacker supplies.
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this application asked to be sent somewhere it has not registered",
        );
    }

    let Some(user) = session_user(&state, &jar).await else {
        let next = authorize_target(&params);
        let query: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("next", &next)
            .finish();
        return Redirect::to(&format!("/login?{query}")).into_response();
    };

    let scopes = params.scope.clone().unwrap_or_else(|| app.scopes.clone());

    let request_token = match state.provider_key.sign(&json!({
        "typ": "brolly:consent",
        "protocol": "mastodon",
        "uid": user.id.to_string(),
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": params.state,
        "code_challenge": params.code_challenge,
        "iat": now(),
        "exp": now() + CONSENT_TTL,
    })) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(error = %e, "signing the consent request failed");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Consent failed");
        }
    };

    // The same screen all three protocols render (ADR 0011). Nobody compares
    // consent wording across three screens, so there is only one.
    consent::render_consent(
        &state,
        Protocol::Mastodon,
        &app.name,
        &user.username,
        &app.client_id,
        &scopes,
        "/oauth/authorize",
        &request_token,
    )
}

#[derive(Deserialize)]
pub struct Decision {
    request: String,
    decision: String,
}

fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        query.append_pair(k, v);
    }
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}{}", query.finish())
}

/// `POST /oauth/authorize` — the member's answer.
///
/// The body is taken as bytes and parsed **after** the host check, not through
/// a `Form` extractor. Extractors run before the handler body, so a `Form`
/// rejection would answer 422 on a member subdomain — leaking that the path
/// exists there at all, which is exactly ADR 0009's credential-capture case.
/// `tests/pod_http.rs` caught this; the ordering is load-bearing.
pub async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return api_error(StatusCode::NOT_FOUND, "Record not found");
    }

    let Ok(form) = serde_urlencoded::from_bytes::<Decision>(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "Malformed form body");
    };

    let Some(user) = session_user(&state, &jar).await else {
        return api_error(StatusCode::UNAUTHORIZED, "Your session has expired");
    };

    let claims = match state.provider_key.verify(&form.request, now()) {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!(error = %e, "consent token rejected");
            return api_error(
                StatusCode::BAD_REQUEST,
                "This authorization request has expired or been tampered with",
            );
        }
    };
    if claims["typ"] != "brolly:consent" || claims["protocol"] != "mastodon" {
        return api_error(StatusCode::BAD_REQUEST, "Not an authorization request");
    }
    // Bound to the member who was shown the screen, so a leaked token cannot be
    // spent by somebody else.
    if claims["uid"].as_str() != Some(&user.id.to_string()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "This authorization request belongs to a different account",
        );
    }

    let str_claim = |key: &str| claims[key].as_str().unwrap_or_default().to_string();
    let redirect_uri = str_claim("redirect_uri");
    let state_param = claims["state"].as_str();

    if form.decision != "allow" {
        let mut params = vec![("error", "access_denied")];
        if let Some(s) = state_param {
            params.push(("state", s));
        }
        if redirect_uri == OOB {
            return api_error(StatusCode::FORBIDDEN, "access_denied");
        }
        return Redirect::to(&redirect_with(&redirect_uri, &params)).into_response();
    }

    let code = match oauth::issue_code(
        &state.pool,
        &str_claim("client_id"),
        user.id,
        &redirect_uri,
        &str_claim("scope"),
        claims["code_challenge"].as_str(),
    )
    .await
    {
        Ok(code) => code,
        Err(e) => {
            tracing::error!(error = %e, "issuing an authorization code failed");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Authorization failed");
        }
    };

    // Out-of-band: there is nowhere to send them, so show the code.
    if redirect_uri == OOB {
        return (StatusCode::OK, Json(json!({"code": code}))).into_response();
    }

    let mut params = vec![("code", code.as_str())];
    if let Some(s) = state_param {
        params.push(("state", s));
    }
    Redirect::to(&redirect_with(&redirect_uri, &params)).into_response()
}

// --- token -------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct TokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    scope: Option<String>,
}

/// `POST /oauth/token`
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return api_error(StatusCode::NOT_FOUND, "Record not found");
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let request: TokenRequest = if content_type.contains("json") {
        serde_json::from_slice(&body).unwrap_or_default()
    } else {
        serde_urlencoded::from_bytes(&body).unwrap_or_default()
    };

    let (Some(client_id), Some(client_secret)) = (
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    ) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id and client_secret are required",
        );
    };

    let app = match oauth::authenticate_app(&state.pool, client_id, client_secret).await {
        Ok(Some(app)) => app,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "client authentication failed");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Authentication failed");
        }
    };

    match request.grant_type.as_deref() {
        Some("authorization_code") => code_grant(&state, &app, request).await,
        // Mastodon's app-level token: no user, only what the app itself may do.
        Some("client_credentials") => {
            let scopes = request.scope.unwrap_or_else(|| app.scopes.clone());
            (
                StatusCode::OK,
                Json(json!({
                    "access_token": "",
                    "token_type": "Bearer",
                    "scope": scopes,
                    "created_at": now(),
                })),
            )
                .into_response()
        }
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("{} is not supported", other.unwrap_or("no grant_type")),
        ),
    }
}

async fn code_grant(state: &AppState, app: &oauth::App, request: TokenRequest) -> Response {
    let Some(code) = request.code.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required",
        );
    };

    let grant = match oauth::redeem_code(&state.pool, code).await {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this code is expired, already used, or not one of ours",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "code redemption failed");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Redemption failed");
        }
    };

    if grant.client_id != app.client_id {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this code was issued to a different client",
        );
    }
    if let Some(redirect_uri) = request.redirect_uri.as_deref()
        && redirect_uri != grant.redirect_uri
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match the authorization request",
        );
    }

    // PKCE when the client used it. Optional here — unlike Solid — because
    // Mastodon only added it in 4.3 and refusing older clients would refuse
    // most of the ecosystem. When a challenge *was* issued it is enforced.
    if let Some(challenge) = grant.code_challenge.as_deref() {
        let Some(verifier) = request.code_verifier.as_deref() else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this authorization used PKCE and requires a code_verifier",
            );
        };
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        if computed != challenge {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the code_verifier does not match the code_challenge",
            );
        }
    }

    match oauth::issue_token(&state.pool, &grant.client_id, grant.user_id, &grant.scopes).await {
        Ok(token) => (
            StatusCode::OK,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(json!({
                "access_token": token,
                "token_type": "Bearer",
                "scope": grant.scopes,
                "created_at": now(),
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "issuing an access token failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Token issue failed")
        }
    }
}

/// `POST /oauth/revoke`
#[derive(Deserialize, Default)]
pub struct RevokeRequest {
    token: Option<String>,
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Bytes rather than `Form`, for the same reason as `decide`.
    if wrong_host(&state, &headers) {
        return api_error(StatusCode::NOT_FOUND, "Record not found");
    }

    let request: RevokeRequest = serde_urlencoded::from_bytes(&body).unwrap_or_default();
    if let Some(token) = request.token.as_deref()
        && let Err(e) = oauth::revoke_token(&state.pool, token).await
    {
        tracing::warn!(error = %e, "token revocation failed");
    }
    // RFC 7009: always 200, so a caller cannot probe which tokens exist.
    (StatusCode::OK, Json(json!({}))).into_response()
}

/// The endpoint map is the contract discovery documents are generated from, so
/// a mounted route that disagrees with it breaks clients that trust it.
pub fn mastodon_paths() -> Vec<&'static str> {
    oauth_layout::endpoints_for(Protocol::Mastodon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bare_oauth_paths_belong_to_mastodon() {
        // ADR 0008: Mastodon is the only protocol that cannot be told where to
        // go, so it gets the paths its clients hardcode.
        let paths = mastodon_paths();
        assert!(paths.contains(&"/oauth/authorize"));
        assert!(paths.contains(&"/oauth/token"));
    }

    #[test]
    fn a_redirect_preserves_parameters_the_client_already_had() {
        assert_eq!(
            redirect_with("https://app.example/cb", &[("code", "abc")]),
            "https://app.example/cb?code=abc"
        );
        assert_eq!(
            redirect_with("https://app.example/cb?s=1", &[("code", "abc")]),
            "https://app.example/cb?s=1&code=abc"
        );
    }
}
