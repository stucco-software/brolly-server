//! The Solid-OIDC provider: discovery, JWKS, registration, authorize, token.
//!
//! Path layout is ADR 0008's — `/oauth/solid/*`, advertised in
//! `/.well-known/openid-configuration` rather than guessed. Nothing here
//! inspects request shape to decide what protocol it is speaking.
//!
//! Two decisions run through the whole module:
//!
//! * **Every token is DPoP-bound.** The token endpoint refuses to issue without
//!   a proof, and `token_type` is `DPoP` rather than `Bearer`, so a client has
//!   no reading of the response under which dropping the proof is correct.
//! * **The consent screen's state is signed, not stored.** The authorization
//!   request travels to the decision POST inside a short-lived JWT signed by the
//!   provider key and bound to the session that was shown the screen. It cannot
//!   be edited, cannot be replayed by another member, and needs no table.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use axum_extra::extract::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db::{self, User};
use brolly_identity::oauth::Protocol;
use brolly_identity::{extract, webid};
use brolly_solid::oidc::{dpop, store, tokens};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::SESSION_COOKIE;
use crate::{AppState, consent};

/// How long a member has to answer the consent screen.
const CONSENT_TTL: i64 = 600;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn issuer(state: &AppState) -> String {
    format!("https://{}", state.base_domain)
}

/// An OAuth error object (RFC 6749 §5.2). Machine-readable, because the caller
/// is a program.
fn oauth_error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error": code, "error_description": description})),
    )
        .into_response()
}

/// A human is looking at this one, so it is prose rather than an error object.
///
/// Reached when the client is unknown or its `redirect_uri` is not registered —
/// exactly the cases where redirecting the error back would be handing an
/// attacker an open redirect.
fn authorize_refusal(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, message.to_string()).into_response()
}

/// These endpoints are apex-only (ADR 0008). Answering on `alice.brolly.id`
/// would offer a client somewhere to send credentials that the issuer in the
/// discovery document never named.
///
/// This is middleware rather than a check inside each handler because a
/// handler body runs *after* extraction: a request with the wrong method or an
/// unparseable body is rejected by axum first, and a guard in the handler would
/// never see it. Those rejections leak the endpoint's existence on a host where
/// it is supposed to be absent.
pub async fn apex_only(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if extract::subdomain_user(host, &state.base_domain).is_some() {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    next.run(request).await
}

// --- discovery --------------------------------------------------------------

/// `GET /.well-known/openid-configuration`
pub async fn discovery(State(state): State<AppState>) -> Response {
    Json(tokens::discovery_document(&issuer(&state))).into_response()
}

/// `GET /oauth/solid/jwks`
pub async fn jwks(State(state): State<AppState>) -> Response {
    Json(state.provider_key.jwks()).into_response()
}

// --- dynamic client registration (RFC 7591) ---------------------------------

#[derive(Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

/// `POST /oauth/solid/register`
///
/// No client secret is issued: these are browser apps, and a browser app cannot
/// keep one. PKCE and DPoP are what actually authenticate the client.
pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    if request.redirect_uris.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "at least one redirect_uri is required",
        );
    }
    if let Some(bad) = request
        .redirect_uris
        .iter()
        .find(|u| !u.starts_with("https://") && !u.starts_with("http://localhost"))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!("{bad} is not https, and only localhost may be plain http"),
        );
    }

    match store::register_client(
        &state.pool,
        request.client_name.as_deref(),
        &request.redirect_uris,
    )
    .await
    {
        Ok(client) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": client.client_id,
                "client_name": client.client_name,
                "redirect_uris": client.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "client registration failed");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "registration failed",
            )
        }
    }
}

// --- authorization ----------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    #[serde(default)]
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    /// Optional pre-registration of the key the token will be bound to.
    dpop_jkt: Option<String>,
}

/// Rebuild the query string, so the login redirect can send the member back to
/// exactly the request they arrived with.
fn authorize_target(params: &AuthorizeParams) -> String {
    let scope = (!params.scope.is_empty()).then(|| params.scope.clone());
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in [
        ("response_type", &params.response_type),
        ("client_id", &params.client_id),
        ("redirect_uri", &params.redirect_uri),
        ("scope", &scope),
        ("state", &params.state),
        ("nonce", &params.nonce),
        ("code_challenge", &params.code_challenge),
        ("code_challenge_method", &params.code_challenge_method),
        ("dpop_jkt", &params.dpop_jkt),
    ] {
        if let Some(value) = value {
            query.append_pair(key, value);
        }
    }
    format!("/oauth/solid/authorize?{}", query.finish())
}

/// Who is at the keyboard, from the session cookie.
async fn session_user(state: &AppState, jar: &CookieJar) -> Option<User> {
    let cookie = jar.get(SESSION_COOKIE)?;
    db::user_for_session(&state.pool, cookie.value())
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

/// `GET /oauth/solid/authorize`
pub async fn authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    // Validate before rendering anything, and validate the client before
    // trusting its redirect_uri — the order is the open-redirect defence.
    if params.response_type.as_deref() != Some("code") {
        return authorize_refusal("Only response_type=code is supported.");
    }
    let Some(client_id) = params.client_id.as_deref() else {
        return authorize_refusal("A client_id is required.");
    };
    let Some(redirect_uri) = params.redirect_uri.as_deref() else {
        return authorize_refusal("A redirect_uri is required.");
    };

    let client = match store::find_client(&state.pool, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return authorize_refusal(
                "This application is not registered with this server. \
                 It needs to register before it can ask for access.",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "client lookup failed");
            return authorize_refusal("Something went wrong. Try again.");
        }
    };
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        // Never redirect here: an unregistered redirect_uri is precisely the
        // value an attacker supplies.
        return authorize_refusal(
            "This application asked to be sent somewhere it has not registered. \
             The request has been refused.",
        );
    }

    // PKCE is mandatory and S256 is the only method discovery advertises.
    let Some(code_challenge) = params.code_challenge.as_deref() else {
        return authorize_refusal("A code_challenge is required (PKCE).");
    };
    if params.code_challenge_method.as_deref() != Some("S256") {
        return authorize_refusal("code_challenge_method must be S256.");
    }

    let Some(user) = session_user(&state, &jar).await else {
        // Send them to log in, and back to this exact request afterwards.
        let next = authorize_target(&params);
        let query: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("next", &next)
            .finish();
        return Redirect::to(&format!("/login?{query}")).into_response();
    };

    let request_token = match sign_consent(&state, &user, &params, code_challenge) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(error = %e, "signing the consent request failed");
            return authorize_refusal("Something went wrong. Try again.");
        }
    };

    consent::render_consent(
        "Brolly",
        Protocol::SolidOidc,
        client.client_name.as_deref().unwrap_or("An application"),
        &user.username,
        &client.client_id,
        &params.scope,
        "/oauth/solid/authorize",
        &request_token,
    )
}

/// Seal the authorization request into a short-lived token bound to this member.
fn sign_consent(
    state: &AppState,
    user: &User,
    params: &AuthorizeParams,
    code_challenge: &str,
) -> Result<String, brolly_solid::oidc::keys::JwtError> {
    let now = now();
    state.provider_key.sign(&json!({
        // Namespaced so this can never be mistaken for an access token by a
        // verifier that only checks the signature.
        "typ": "brolly:consent",
        "uid": user.id.to_string(),
        "client_id": params.client_id,
        "redirect_uri": params.redirect_uri,
        "code_challenge": code_challenge,
        "scope": params.scope,
        "state": params.state,
        "nonce": params.nonce,
        "dpop_jkt": params.dpop_jkt,
        "iat": now,
        "exp": now + CONSENT_TTL,
    }))
}

#[derive(Deserialize)]
pub struct Decision {
    request: String,
    decision: String,
}

/// Append parameters to the client's redirect_uri, preserving any it already has.
fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        query.append_pair(k, v);
    }
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}{}", query.finish())
}

/// `POST /oauth/solid/authorize` — the member's answer.
pub async fn decide(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<Decision>,
) -> Response {
    let Some(user) = session_user(&state, &jar).await else {
        return authorize_refusal("Your session has expired. Log in and try again.");
    };

    let claims = match state.provider_key.verify(&form.request, now()) {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!(error = %e, "consent token rejected");
            return authorize_refusal(
                "This authorization request has expired or been tampered with. \
                 Start again from the application.",
            );
        }
    };
    if claims["typ"] != "brolly:consent" {
        return authorize_refusal("That is not an authorization request.");
    }
    // Bound to the member who was shown the screen: a signature alone would let
    // anyone who obtained the token spend it.
    if claims["uid"].as_str() != Some(&user.id.to_string()) {
        return authorize_refusal("This authorization request belongs to a different account.");
    }

    let str_claim = |key: &str| claims[key].as_str().unwrap_or_default().to_string();
    let redirect_uri = str_claim("redirect_uri");
    let state_param = claims["state"].as_str();

    let mut params: Vec<(&str, &str)> = Vec::new();
    if form.decision != "allow" {
        params.push(("error", "access_denied"));
        // The client needs `state` back even on a refusal, or it cannot
        // correlate the answer with the request it made.
        if let Some(s) = state_param {
            params.push(("state", s));
        }
        return Redirect::to(&redirect_with(&redirect_uri, &params)).into_response();
    }

    let code = match store::issue_code(
        &state.pool,
        &str_claim("client_id"),
        user.id,
        &webid::webid(&user.username, &state.base_domain),
        &redirect_uri,
        &str_claim("code_challenge"),
        &str_claim("scope"),
        claims["nonce"].as_str(),
        claims["dpop_jkt"].as_str(),
    )
    .await
    {
        Ok(code) => code,
        Err(e) => {
            tracing::error!(error = %e, "issuing an authorization code failed");
            return authorize_refusal("Something went wrong. Try again.");
        }
    };

    params.push(("code", &code));
    if let Some(s) = state_param {
        params.push(("state", s));
    }
    Redirect::to(&redirect_with(&redirect_uri, &params)).into_response()
}

// --- the token endpoint -----------------------------------------------------

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

/// `POST /oauth/solid/token`
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Response {
    // Every grant here is DPoP-bound, so the proof is checked before the grant
    // is even looked up. There is no path that issues an unbound token.
    let url = format!("https://{}/oauth/solid/token", state.base_domain);
    let Some(proof) = headers.get("dpop").and_then(|h| h.to_str().ok()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "this endpoint requires a DPoP proof",
        );
    };
    let jkt = match dpop::verify(proof, "POST", &url, None, now()) {
        Ok(verified) => verified.thumbprint,
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof rejected at the token endpoint");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                &e.to_string(),
            );
        }
    };

    match request.grant_type.as_str() {
        "authorization_code" => authorization_code_grant(&state, request, &jkt).await,
        "refresh_token" => refresh_token_grant(&state, request, &jkt).await,
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("{other} is not supported"),
        ),
    }
}

/// Assemble the token response, minting only what the granted scope asked for.
fn token_response(
    state: &AppState,
    subject_webid: &str,
    client_id: &str,
    scope: &str,
    jkt: &str,
    nonce: Option<&str>,
    refresh_token: Option<String>,
) -> Response {
    let issuer = issuer(state);
    let now = now();
    let key = &state.provider_key;

    let access = match tokens::issue_access(key, &issuer, subject_webid, client_id, scope, jkt, now)
    {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(error = %e, "minting an access token failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not issue a token",
            );
        }
    };

    let mut body = json!({
        "access_token": access,
        // Not "Bearer": there is no reading of this response under which
        // dropping the proof is correct.
        "token_type": "DPoP",
        "expires_in": tokens::ACCESS_TOKEN_TTL,
        "scope": scope,
    });

    if scope.split_whitespace().any(|s| s == "openid") {
        match tokens::issue_id_token(key, &issuer, subject_webid, client_id, nonce, now) {
            Ok(id_token) => body["id_token"] = json!(id_token),
            Err(e) => {
                tracing::error!(error = %e, "minting an ID token failed");
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "could not issue a token",
                );
            }
        }
    }
    if let Some(refresh) = refresh_token {
        body["refresh_token"] = json!(refresh);
    }

    (
        StatusCode::OK,
        // RFC 6749 §5.1: token responses must not be cached anywhere.
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

async fn authorization_code_grant(state: &AppState, request: TokenRequest, jkt: &str) -> Response {
    let (Some(code), Some(verifier)) = (request.code.as_deref(), request.code_verifier.as_deref())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code and code_verifier are required",
        );
    };

    let grant = match store::redeem_code(&state.pool, code).await {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            // Distinguishing replay from nonsense is why the row is kept.
            if matches!(store::code_was_used(&state.pool, code).await, Ok(true)) {
                tracing::warn!("an already-redeemed authorization code was presented again");
            }
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this code is expired, already used, or not one of ours",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "code redemption failed");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed");
        }
    };

    // PKCE: S256 only, and compared against the challenge stored at authorize
    // time rather than anything the client sends now.
    let computed = B64.encode(Sha256::digest(verifier.as_bytes()));
    if computed != grant.code_challenge {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the code_verifier does not match the code_challenge",
        );
    }
    if request.redirect_uri.as_deref() != Some(grant.redirect_uri.as_str()) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match the authorization request",
        );
    }
    if let Some(client_id) = request.client_id.as_deref()
        && client_id != grant.client_id
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id does not match the authorization request",
        );
    }
    // If the client named its key up front, the key presenting the code must be
    // that one.
    if let Some(expected) = grant.dpop_jkt.as_deref()
        && expected != jkt
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this code was issued to a different key",
        );
    }

    let refresh = if grant
        .scope
        .split_whitespace()
        .any(|s| s == "offline_access")
    {
        match store::issue_refresh(
            &state.pool,
            &grant.client_id,
            grant.user_id,
            &grant.webid,
            &grant.scope,
            Some(jkt),
        )
        .await
        {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::error!(error = %e, "issuing a refresh token failed");
                return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed");
            }
        }
    } else {
        None
    };

    token_response(
        state,
        &grant.webid,
        &grant.client_id,
        &grant.scope,
        jkt,
        grant.nonce.as_deref(),
        refresh,
    )
}

async fn refresh_token_grant(state: &AppState, request: TokenRequest, jkt: &str) -> Response {
    let Some(token) = request.refresh_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };

    let grant = match store::rotate_refresh(&state.pool, token).await {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this refresh token is expired, already used, or not one of ours",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "refresh rotation failed");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed");
        }
    };

    // The refresh token is bound to a key too, so stealing the token alone does
    // not let the thief mint access tokens.
    if let Some(expected) = grant.dpop_jkt.as_deref()
        && expected != jkt
    {
        tracing::warn!("a refresh token was presented by a key it was not issued to");
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this refresh token was issued to a different key",
        );
    }

    let replacement = match store::issue_refresh(
        &state.pool,
        &grant.client_id,
        grant.user_id,
        &grant.webid,
        &grant.scope,
        Some(jkt),
    )
    .await
    {
        Ok(token) => Some(token),
        Err(e) => {
            tracing::error!(error = %e, "issuing a replacement refresh token failed");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed");
        }
    };

    token_response(
        state,
        &grant.webid,
        &grant.client_id,
        &grant.scope,
        jkt,
        None,
        replacement,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redirect_preserves_query_parameters_the_client_already_had() {
        assert_eq!(
            redirect_with("https://app.example/cb", &[("code", "abc")]),
            "https://app.example/cb?code=abc"
        );
        assert_eq!(
            redirect_with("https://app.example/cb?session=1", &[("code", "abc")]),
            "https://app.example/cb?session=1&code=abc"
        );
    }

    #[test]
    fn the_login_redirect_reconstructs_the_whole_request() {
        let params = AuthorizeParams {
            response_type: Some("code".into()),
            client_id: Some("urn:uuid:abc".into()),
            redirect_uri: Some("https://app.example/cb".into()),
            scope: "openid webid".into(),
            state: Some("xyz".into()),
            nonce: None,
            code_challenge: Some("chal".into()),
            code_challenge_method: Some("S256".into()),
            dpop_jkt: None,
        };
        let target = authorize_target(&params);
        assert!(target.starts_with("/oauth/solid/authorize?"));
        for expected in [
            "response_type=code",
            "client_id=urn%3Auuid%3Aabc",
            "scope=openid+webid",
            "state=xyz",
            "code_challenge=chal",
            "code_challenge_method=S256",
        ] {
            assert!(
                target.contains(expected),
                "{expected} missing from {target}"
            );
        }
        // An absent optional parameter must not appear as an empty one.
        assert!(!target.contains("nonce="));
    }
}
