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
//! * **`prompt=none` answers with the flow's own shapes** (spec 6, H4). Its two
//!   error redirects are the deny path's error redirect — `error`, then
//!   `state` — and its silent success is the allow path's issuance, code for
//!   code, so a client cannot tell a silent answer from an interactive one.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use axum_extra::extract::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db::User;
use brolly_identity::oauth::Protocol;
use brolly_identity::{extract, webid};
use brolly_solid::client_documents::{ClientIdDocument, allows_redirect};
use brolly_solid::oidc::{dpop, store, tokens};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::auth::session_user;
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

/// The one answer every unregistered-or-unusable client gets at `authorize`
/// (spec 6, H3).
///
/// One constant, byte-for-byte, for every cause — an unknown `urn:uuid:`, a
/// `client_id` that is neither kind, a Client ID Document that could not be
/// fetched, would not parse, or does not list the `redirect_uri` — so the
/// endpoint cannot be used as an oracle for which client documents exist on
/// the open web. The registered client's different prose for an unlisted
/// `redirect_uri` is deliberate: its URIs were fixed at registration, so
/// there is nothing to probe for.
const UNREGISTERED: &str = "This application is not registered with this server. \
     It needs to register before it can ask for access.";

/// The Client ID Document an `https://` client_id names (spec 6, H3): the
/// fetch branch of `authorize`'s three-way dispatch. `None` for every other
/// kind — `urn:uuid:` ids are looked up in the table dynamic registration
/// fills, and anything else is refused without a fetch. Userinfo and
/// fragments are refused here rather than parsed away: the fetch URL must be
/// the client_id as sent, because the document's subject has to be it.
fn client_document_url(client_id: &str) -> Option<Url> {
    let url = Url::parse(client_id).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url)
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
    /// The `prompt` parameter (spec 6, H4): `none` asks for no interaction at
    /// all, `login` forces the login page. Matched on exact values; any other
    /// value — or none at all — is today's behaviour.
    prompt: Option<String>,
}

/// Rebuild the query string, so the login redirect can send the member back to
/// exactly the request they arrived with — except `prompt`, deliberately (spec
/// 6, H4): a preserved `prompt=login` would loop the member through the login
/// page forever, and `prompt=none` never reaches the login redirect at all
/// (its no-session answer is an error redirect), so the member always returns
/// to a plain interactive authorization.
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

/// Which client is asking, once `authorize` has decided it may ask at all.
///
/// The grant remembers the same `client_id` string either way, so the token
/// endpoint's comparison against it is unchanged (spec 6, H3).
enum Client {
    /// Registered through RFC 7591; its redirect URIs were fixed at
    /// registration.
    Registered(store::Client),
    /// Fetched and validated as a Client ID Document (spec 6, H3).
    Document(ClientIdDocument),
}

impl Client {
    /// The name the consent screen shows in place of the raw IRI — the same
    /// path a registered client's `client_name` already takes (spec 6, H3).
    fn client_name(&self) -> Option<&str> {
        match self {
            Client::Registered(c) => c.client_name.as_deref(),
            Client::Document(d) => d.client_name(),
        }
    }

    /// May this client be sent to `redirect_uri`?
    ///
    /// A registered client must have listed the URI at registration. A
    /// document client must list it in the document — exactly, or as a
    /// loopback redirect with any port (RFC 8252 §7.3).
    fn allows_redirect(&self, redirect_uri: &str) -> bool {
        match self {
            Client::Registered(c) => c.redirect_uris.iter().any(|u| u == redirect_uri),
            Client::Document(d) => allows_redirect(d, redirect_uri),
        }
    }
}

/// Who is at the keyboard, from the session cookie.
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

    // `prompt`, matched on exact values (spec 6, H4). `none` and `login` are
    // the only values this provider gives meaning to; any other value — or
    // none at all — is today's behaviour. A value combining `none` with
    // anything else is a 400 here, before the client is even looked up and so
    // before any redirect this handler can produce: OIDC Core §3.1.2.1 forbids
    // the combination, and honouring the interactive half would quietly break
    // the no-interaction contract the `none` half asked for.
    let prompts: Vec<&str> = params
        .prompt
        .as_deref()
        .map(|p| p.split_whitespace().collect())
        .unwrap_or_default();
    if prompts.contains(&"none") && prompts.len() > 1 {
        return authorize_refusal("prompt=none cannot be combined with other prompt values.");
    }
    let silent = prompts.as_slice() == ["none"];
    let fresh_login = prompts.as_slice() == ["login"];

    // Three kinds of client_id, three paths (spec 6, H3): `urn:uuid:` is
    // looked up in the table dynamic registration fills, `https://` is
    // fetched and validated as a Client ID Document, and anything else is
    // refused outright. The document branch's every failure — the fetch, the
    // parse, the document's own rules — answers with the same words as an
    // unknown `urn:uuid:`, deliberately, so the endpoint is not an oracle
    // for which client documents exist on the open web.
    let client = if let Some(url) = client_document_url(client_id) {
        match state.solid_clients.fetch(&url).await {
            Ok(document) => Client::Document(document),
            Err(_) => return authorize_refusal(UNREGISTERED),
        }
    } else {
        match store::find_client(&state.pool, client_id).await {
            Ok(Some(client)) => Client::Registered(client),
            Ok(None) => return authorize_refusal(UNREGISTERED),
            Err(e) => {
                tracing::error!(error = %e, "client lookup failed");
                return authorize_refusal("Something went wrong. Try again.");
            }
        }
    };
    if !client.allows_redirect(redirect_uri) {
        // Never redirect here: an unlisted redirect_uri is precisely the
        // value an attacker supplies.
        return match client {
            Client::Registered(_) => authorize_refusal(
                "This application asked to be sent somewhere it has not registered. \
                 The request has been refused.",
            ),
            // A document client's listed URIs are part of what makes it the
            // client it claims to be, so their absence is the same refusal
            // as an unknown one (spec 6, H3).
            Client::Document(_) => authorize_refusal(UNREGISTERED),
        };
    }

    // PKCE is mandatory and S256 is the only method discovery advertises.
    let Some(code_challenge) = params.code_challenge.as_deref() else {
        return authorize_refusal("A code_challenge is required (PKCE).");
    };
    if params.code_challenge_method.as_deref() != Some("S256") {
        return authorize_refusal("code_challenge_method must be S256.");
    }

    let session = session_user(&state, &jar).await;

    // `prompt=none` (spec 6, H4): the client asked not to be interacted with,
    // so both of the flow's failure modes become error redirects it can
    // handle — never the login page, never the consent screen.
    if silent {
        let Some(user) = session else {
            return error_redirect(redirect_uri, "login_required", params.state.as_deref());
        };
        let covered = match store::remembered_consent(&state.pool, user.id, client_id).await {
            Ok(Some(consent)) => consent.covers(&params.scope, redirect_uri),
            Ok(None) => false,
            Err(e) => {
                tracing::error!(error = %e, "looking up a remembered consent failed");
                return authorize_refusal("Something went wrong. Try again.");
            }
        };
        if !covered {
            return error_redirect(redirect_uri, "consent_required", params.state.as_deref());
        }
        // Silent success: exactly what a consent-screen allow produces — the
        // same issuance, the same redirect. The consent needs no re-write:
        // coverage means the row already holds everything this request
        // asked for, at a URI that is already remembered.
        return issue_and_redirect(
            &state,
            &user,
            client_id,
            redirect_uri,
            code_challenge,
            &params.scope,
            params.nonce.as_deref(),
            params.dpop_jkt.as_deref(),
            params.state.as_deref(),
        )
        .await;
    }

    // `prompt=login` forces the login page even with a session (spec 6, H4) —
    // the one useful thing it does. Otherwise this is today's behaviour: no
    // session → log in, with `next` bringing the member back to exactly this
    // request; a session → the consent screen, always.
    let user = match session {
        Some(user) if !fresh_login => user,
        _ => {
            // Send them to log in, and back to this exact request afterwards.
            let next = authorize_target(&params);
            let query: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("next", &next)
                .finish();
            return Redirect::to(&format!("/login?{query}")).into_response();
        }
    };

    let request_token = match sign_consent(&state, &user, &params, code_challenge) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(error = %e, "signing the consent request failed");
            return authorize_refusal("Something went wrong. Try again.");
        }
    };

    consent::render_consent(
        &state,
        Protocol::SolidOidc,
        client.client_name().unwrap_or("An application"),
        &user.username,
        client_id,
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

/// Redirect the client to its `redirect_uri` with an OAuth error — the shape
/// `decide`'s deny path established, and the one `prompt=none`'s two error
/// answers reuse (spec 6, H4), so an error correlates the same way however
/// the flow was reached.
fn error_redirect(redirect_uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut params: Vec<(&str, &str)> = vec![("error", error)];
    // The client needs `state` back even on an error, or it cannot
    // correlate the answer with the request it made.
    if let Some(s) = state {
        params.push(("state", s));
    }
    Redirect::to(&redirect_with(redirect_uri, &params)).into_response()
}

/// Issue an authorization code and redirect the client to its `redirect_uri`
/// with it: the one shape every issuance takes — a consent-screen allow and a
/// `prompt=none` silent success (spec 6, H4) — so a silent answer is
/// byte-for-byte what an allow produces.
#[allow(clippy::too_many_arguments)]
async fn issue_and_redirect(
    state: &AppState,
    user: &User,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scope: &str,
    nonce: Option<&str>,
    dpop_jkt: Option<&str>,
    state_param: Option<&str>,
) -> Response {
    let code = match store::issue_code(
        &state.pool,
        client_id,
        user.id,
        &webid::webid(&user.username, &state.base_domain),
        redirect_uri,
        code_challenge,
        scope,
        nonce,
        dpop_jkt,
    )
    .await
    {
        Ok(code) => code,
        Err(e) => {
            tracing::error!(error = %e, "issuing an authorization code failed");
            return authorize_refusal("Something went wrong. Try again.");
        }
    };
    let mut redirect: Vec<(&str, &str)> = vec![("code", code.as_str())];
    if let Some(s) = state_param {
        redirect.push(("state", s));
    }
    Redirect::to(&redirect_with(redirect_uri, &redirect)).into_response()
}

/// `POST /oauth/solid/authorize` — the member's answer.
///
/// An allow remembers the consent (spec 6, H4) before it issues: the
/// remembering is the member's decision, and it stands even if the code
/// cannot be issued.
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

    if form.decision != "allow" {
        return error_redirect(&redirect_uri, "access_denied", state_param);
    }

    // Remember the consent (spec 6, H4): every allow widens the remembered
    // scope and redirect URIs monotonically. A failure to remember is logged
    // and survived — the allow stands, and a `prompt=none` request that finds
    // no covering consent falls back to `consent_required`, which is the safe
    // predecessor behaviour.
    if let Err(e) = store::remember_consent(
        &state.pool,
        user.id,
        &str_claim("client_id"),
        &str_claim("scope"),
        &redirect_uri,
    )
    .await
    {
        tracing::error!(error = %e, "remembering a consent failed");
    }

    issue_and_redirect(
        &state,
        &user,
        &str_claim("client_id"),
        &redirect_uri,
        &str_claim("code_challenge"),
        &str_claim("scope"),
        claims["nonce"].as_str(),
        claims["dpop_jkt"].as_str(),
        state_param,
    )
    .await
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
    let at = now();
    let unspent = match dpop::verify(proof, "POST", &url, None, at) {
        Ok(unspent) => unspent,
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof rejected at the token endpoint");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                &e.to_string(),
            );
        }
    };
    // Spent before the grant is looked at: a request that fails later has still
    // used its proof (see `Unspent::spend`).
    let jkt = match unspent.spend(&state.pool, at).await {
        Ok(verified) => verified.thumbprint,
        Err(dpop::DpopError::Storage(e)) => {
            tracing::error!(error = %e, "recording a DPoP proof failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not check the DPoP proof",
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "DPoP proof refused at the token endpoint");
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
            &store::Lineage::fresh(),
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

    // A grant is a grant to one client (RFC 6749 §6): the presenting client
    // is part of the lookup, as it is for a code.
    let Some(client_id) = request.client_id.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    };

    // The token is bound to a key too, and the key is part of the lookup
    // rather than checked after the token is spent: a thief with the token
    // but not the key is refused, and the owner's token survives the attempt.
    // A replay — the right client and key, a token already spent — ends the
    // whole family: one of the two holders is not the client.
    let grant = match store::rotate_refresh(&state.pool, token, client_id, Some(jkt)).await {
        Ok(store::Rotation::Rotated(grant)) => grant,
        Ok(store::Rotation::Replayed) => {
            tracing::warn!(
                client_id,
                "a spent refresh token was replayed; its grant is revoked"
            );
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this refresh token was already used; the grant has been revoked",
            );
        }
        Ok(store::Rotation::Refused) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "this refresh token is expired, not this client's, bound to another key, or not one of ours",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "refresh rotation failed");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed");
        }
    };

    let replacement = match store::issue_refresh(
        &state.pool,
        &grant.client_id,
        grant.user_id,
        &grant.webid,
        &grant.scope,
        Some(jkt),
        &grant.lineage(),
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
            prompt: Some("login".into()),
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
        // `prompt` is dropped deliberately (spec 6, H4): a preserved
        // `prompt=login` would loop the member through the login page
        // forever, and `prompt=none` never reaches the login redirect at
        // all — its no-session answer is an error redirect — so the member
        // always returns to a plain interactive authorization.
        assert!(!target.contains("prompt="));
    }
}
