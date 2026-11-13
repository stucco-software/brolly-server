//! The service API: what an app in front of the instance (`FrontEnd`) needs
//! to run the account lifecycle — create, check a username, find by WebID,
//! check a password, delete.
//!
//! Under `/internal/v1/`, not `/api/`, which the Mastodon catch-all owns.
//! Apex-only (ADR 0009), and mounted only when `BROLLY_SERVICE_TOKEN` is set.
//! Every call carries `Authorization: Bearer <token>`. The header is parsed by
//! `extract::credential` in `brolly-identity`, the one place that parses
//! credentials (`tests/architecture.rs`); here the token is only hashed and
//! compared. No `Subject` is made: the caller is the front end, not a member.

use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use brolly_identity::db::{self, DbError, User};
use brolly_identity::subject::Credential;
use brolly_identity::{extract, routing, webid};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::auth::{
    Admission, RegistrationError, create_member, is_reserved_username, validate_username,
};
use crate::ratelimit::{Gate, too_many};

/// How long a reset link works, and how soon another can be minted.
const RESET_TTL: time::Duration = time::Duration::hours(1);
const RESET_COOLDOWN: time::Duration = time::Duration::minutes(5);

/// The routes, guarded. Mounted by `app()` only when a token is configured.
pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/internal/v1/accounts",
            post(create_account).get(find_account),
        )
        .route("/internal/v1/accounts/{username}", delete(delete_account))
        .route(
            "/internal/v1/accounts/{username}/verify-password",
            post(verify_password),
        )
        .route(
            "/internal/v1/usernames/{username}",
            get(username_availability),
        )
        .route("/internal/v1/password-resets", post(issue_password_reset))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_service,
        ))
        // Outermost, so a member's subdomain answers 404 before the token is
        // looked at: the API does not exist there.
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::solid_oidc::apex_only,
        ))
}

/// The front end's token, or 401.
async fn require_service(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    // Comparing hashes, not tokens: the stored value is the hash, and a
    // timing difference in comparing two SHA-256 digests says nothing useful
    // about the token.
    let presented = match extract::credential(authorization, None) {
        Some(Credential::Bearer(token)) => Some(db::hash_secret(&token)),
        _ => None,
    };
    match (presented, state.front_end.service_token_hash.as_deref()) {
        (Some(presented), Some(expected)) if presented == expected => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response(),
    }
}

/// What the front end learns about an account.
fn account(user: &User, base_domain: &str) -> serde_json::Value {
    json!({
        "username": user.username,
        "email": user.email,
        "webId": webid::webid(&user.username, base_domain),
        "storage": routing::storage_root(&user.username, base_domain),
    })
}

fn validation(field: &str, reason: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "error": "validation", "field": field, "reason": reason })),
    )
        .into_response()
}

/// A body axum could not read (not JSON, wrong content type, a field
/// missing) answers in the API's own shape, not axum's plain text, so the
/// front end can always parse the error.
fn unreadable(rejection: JsonRejection) -> Response {
    validation("body", &rejection.body_text())
}

fn conflict(error: &str) -> Response {
    (StatusCode::CONFLICT, Json(json!({ "error": error }))).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "server_error" })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct NewAccount {
    username: String,
    email: String,
    password: String,
}

/// `POST /internal/v1/accounts`
///
/// No invite (`Admission::Service`) and no `Signup` gate: the front end holds
/// the token, runs its own door, and sends every signup from the same few
/// addresses.
async fn create_account(
    State(state): State<AppState>,
    body: Result<Json<NewAccount>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return unreadable(rejection),
    };
    let email = body.email.trim();
    if email.is_empty() {
        return validation("email", "An email is required.");
    }
    match create_member(
        &state,
        &body.username,
        Some(email),
        &body.password,
        Admission::Service,
    )
    .await
    {
        Ok(user) => (
            StatusCode::CREATED,
            Json(account(&user, &state.base_domain)),
        )
            .into_response(),
        Err(RegistrationError::Username(reason)) => validation("username", &reason),
        Err(RegistrationError::PasswordShort) => {
            validation("password", "Use at least 12 characters.")
        }
        Err(RegistrationError::UsernameTaken) => conflict("username_taken"),
        Err(RegistrationError::EmailTaken) => conflict("email_taken"),
        // `Admission::Service` never asks for an invite, so this is a bug.
        Err(RegistrationError::InviteInvalid) | Err(RegistrationError::ServerError) => {
            server_error()
        }
    }
}

/// `GET /internal/v1/usernames/{username}`
async fn username_availability(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Response {
    let body = if validate_username(&username).is_err() {
        let reason = if is_reserved_username(&username) {
            "reserved"
        } else {
            "invalid"
        };
        json!({ "available": false, "reason": reason })
    } else {
        match db::find_by_username(&state.pool, &username).await {
            Ok(Some(_)) => json!({ "available": false, "reason": "taken" }),
            Ok(None) => json!({ "available": true }),
            Err(e) => {
                tracing::error!(error = %e, "username lookup failed");
                return server_error();
            }
        }
    };
    Json(body).into_response()
}

#[derive(Deserialize)]
pub struct ByWebId {
    #[serde(rename = "webId")]
    web_id: String,
}

/// The username a WebID of this instance names, or `None` for anything that
/// is not exactly `webid::webid(username, base)`.
fn username_for_webid(web_id: &str, base_domain: &str) -> Option<String> {
    let url = url::Url::parse(web_id).ok()?;
    let username = extract::subdomain_user(url.host_str()?, base_domain)?;
    (webid::webid(&username, base_domain) == web_id).then_some(username)
}

/// `GET /internal/v1/accounts?webId=`
async fn find_account(State(state): State<AppState>, Query(query): Query<ByWebId>) -> Response {
    let Some(username) = username_for_webid(&query.web_id, &state.base_domain) else {
        return not_found();
    };
    match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) => Json(account(&user, &state.base_domain)).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!(error = %e, "account lookup failed");
            server_error()
        }
    }
}

#[derive(Deserialize)]
pub struct PasswordCheck {
    password: String,
}

/// `POST /internal/v1/accounts/{username}/verify-password`
///
/// The front end's delete page asks for the password; this is that check.
/// Unknown members and wrong passwords answer alike (`db::authenticate`).
async fn verify_password(
    State(state): State<AppState>,
    Path(username): Path<String>,
    body: Result<Json<PasswordCheck>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return unreadable(rejection),
    };
    if let Err(wait) = state.limiter.check(
        Gate::ServicePassword,
        &format!("user:{}", username.to_lowercase()),
    ) {
        return too_many(wait);
    }
    match db::authenticate(&state.pool, &username, &body.password).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(DbError::BadCredentials) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "bad_credentials" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "password check failed");
            server_error()
        }
    }
}

/// `DELETE /internal/v1/accounts/{username}`
async fn delete_account(State(state): State<AppState>, Path(username): Path<String>) -> Response {
    let user = match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) => user,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "account lookup failed before deletion");
            return server_error();
        }
    };
    match crate::provision::delete_account(&state.pool, &state.stores, &state.commits, &user).await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => server_error(),
    }
}

#[derive(Deserialize)]
pub struct ResetRequest {
    email: String,
}

/// `POST /internal/v1/password-resets`
///
/// The front end emails the link; brolly sends no mail (spec D5). An unknown
/// or disabled email and a request inside the cooldown both answer `204`, so
/// the answer never says which addresses have accounts and the front end's
/// form cannot flood an inbox.
async fn issue_password_reset(
    State(state): State<AppState>,
    body: Result<Json<ResetRequest>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return unreadable(rejection),
    };
    let user = match db::find_by_email(&state.pool, body.email.trim()).await {
        Ok(Some(user)) if user.status == "active" => user,
        Ok(_) => return StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "email lookup failed for a password reset");
            return server_error();
        }
    };
    match db::issue_password_reset(&state.pool, user.id, RESET_TTL, RESET_COOLDOWN).await {
        Ok(Some((token, expires_at))) => {
            let mut reset_url =
                match url::Url::parse(&format!("https://{}/reset", state.base_domain)) {
                    Ok(url) => url,
                    Err(e) => {
                        tracing::error!(error = %e, "the reset URL does not parse");
                        return server_error();
                    }
                };
            reset_url.query_pairs_mut().append_pair("token", &token);
            let expires_at = expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            (
                StatusCode::CREATED,
                Json(json!({ "resetUrl": reset_url.as_str(), "expiresAt": expires_at })),
            )
                .into_response()
        }
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "minting a reset link failed");
            server_error()
        }
    }
}
