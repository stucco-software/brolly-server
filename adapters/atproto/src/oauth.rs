//! ATProtocol OAuth persistence.
//!
//! Three things separate this from the other two OAuth surfaces, and each is a
//! protocol requirement rather than a preference:
//!
//! * **PAR is mandatory.** The client pushes the whole authorization request
//!   here and receives an opaque `request_uri`. The parameters never travel
//!   through the browser, so nothing in the address bar can be edited.
//! * **DPoP is mandatory**, and the key is pledged at PAR time — so the token
//!   is bound to a key the client committed to before the member ever saw a
//!   consent screen.
//! * **`client_id` is an HTTPS URL** serving client metadata, not an opaque
//!   identifier we issue. There is no registration step and no client secret;
//!   the client's identity *is* a document anyone can fetch.

use brolly_identity::db::{DbError, generate_secret, hash_secret};
use sqlx::PgPool;
use uuid::Uuid;

/// How long a pushed request stays redeemable. Short: the client redirects the
/// member immediately.
const PAR_TTL_SECONDS: f64 = 300.0;
const CODE_TTL_SECONDS: f64 = 60.0;
/// Access tokens are short and refreshed, unlike Mastodon's non-expiring ones.
pub const ACCESS_TTL_SECONDS: f64 = 3600.0;
const REFRESH_TTL_SECONDS: f64 = 60.0 * 60.0 * 24.0 * 90.0;

/// A pushed authorization request.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Eq)]
pub struct PushedRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub dpop_jkt: String,
    pub login_hint: Option<String>,
}

/// Store a pushed request, returning its `request_uri`.
///
/// The handle is `urn:ietf:params:oauth:request_uri:` plus a random secret, per
/// RFC 9126 — a URN rather than a URL because it names a request we are holding
/// rather than a resource anyone can fetch.
#[allow(clippy::too_many_arguments)]
pub async fn push_request(
    pool: &PgPool,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: Option<&str>,
    code_challenge: &str,
    dpop_jkt: &str,
    login_hint: Option<&str>,
) -> Result<String, DbError> {
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", generate_secret());
    sqlx::query(
        "INSERT INTO atproto_par_requests
           (request_uri, client_id, redirect_uri, scope, state, code_challenge,
            dpop_jkt, login_hint, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))",
    )
    .bind(&request_uri)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(scope)
    .bind(state)
    .bind(code_challenge)
    .bind(dpop_jkt)
    .bind(login_hint)
    .bind(PAR_TTL_SECONDS)
    .execute(pool)
    .await?;
    Ok(request_uri)
}

/// Read a pushed request without consuming it.
///
/// The authorize endpoint may be loaded more than once — a member logs in, is
/// redirected back, and the screen renders again — so reading is separate from
/// spending.
pub async fn read_request(
    pool: &PgPool,
    request_uri: &str,
) -> Result<Option<PushedRequest>, DbError> {
    Ok(sqlx::query_as::<_, PushedRequest>(
        "SELECT client_id, redirect_uri, scope, state, code_challenge, dpop_jkt, login_hint
         FROM atproto_par_requests
         WHERE request_uri = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(request_uri)
    .fetch_optional(pool)
    .await?)
}

/// Spend a pushed request. One authorization per push.
pub async fn consume_request(
    pool: &PgPool,
    request_uri: &str,
) -> Result<Option<PushedRequest>, DbError> {
    Ok(sqlx::query_as::<_, PushedRequest>(
        "UPDATE atproto_par_requests SET used_at = now()
         WHERE request_uri = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING client_id, redirect_uri, scope, state, code_challenge, dpop_jkt, login_hint",
    )
    .bind(request_uri)
    .fetch_optional(pool)
    .await?)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthCode {
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub dpop_jkt: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn issue_code(
    pool: &PgPool,
    client_id: &str,
    user_id: Uuid,
    redirect_uri: &str,
    scope: &str,
    code_challenge: &str,
    dpop_jkt: &str,
) -> Result<String, DbError> {
    let code = generate_secret();
    sqlx::query(
        "INSERT INTO atproto_auth_codes
           (code_hash, client_id, user_id, redirect_uri, scope, code_challenge,
            dpop_jkt, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
    )
    .bind(hash_secret(&code))
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(scope)
    .bind(code_challenge)
    .bind(dpop_jkt)
    .bind(CODE_TTL_SECONDS)
    .execute(pool)
    .await?;
    Ok(code)
}

pub async fn redeem_code(pool: &PgPool, code: &str) -> Result<Option<AuthCode>, DbError> {
    Ok(sqlx::query_as::<_, AuthCode>(
        "UPDATE atproto_auth_codes SET used_at = now()
         WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING client_id, user_id, redirect_uri, scope, code_challenge, dpop_jkt",
    )
    .bind(hash_secret(code))
    .fetch_optional(pool)
    .await?)
}

/// What a presented token grants.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Eq)]
pub struct Grant {
    pub user_id: Uuid,
    pub client_id: String,
    pub scope: String,
    pub dpop_jkt: String,
}

pub async fn issue_token(
    pool: &PgPool,
    kind: &str,
    client_id: &str,
    user_id: Uuid,
    scope: &str,
    dpop_jkt: &str,
) -> Result<String, DbError> {
    let ttl = if kind == "refresh" {
        REFRESH_TTL_SECONDS
    } else {
        ACCESS_TTL_SECONDS
    };
    let token = generate_secret();
    sqlx::query(
        "INSERT INTO atproto_tokens
           (token_hash, kind, client_id, user_id, scope, dpop_jkt, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
    )
    .bind(hash_secret(&token))
    .bind(kind)
    .bind(client_id)
    .bind(user_id)
    .bind(scope)
    .bind(dpop_jkt)
    .bind(ttl)
    .execute(pool)
    .await?;
    Ok(token)
}

/// Resolve a token of a given kind.
///
/// The kind is part of the lookup, not checked afterwards: a refresh token
/// accepted as an access token would be a long-lived credential on a resource
/// endpoint, which is the whole reason the two have different lifetimes.
pub async fn verify_token(
    pool: &PgPool,
    kind: &str,
    token: &str,
) -> Result<Option<Grant>, DbError> {
    Ok(sqlx::query_as::<_, Grant>(
        "SELECT user_id, client_id, scope, dpop_jkt FROM atproto_tokens
         WHERE token_hash = $1 AND kind = $2 AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(hash_secret(token))
    .bind(kind)
    .fetch_optional(pool)
    .await?)
}

/// Spend a refresh token, so rotation makes theft visible.
pub async fn rotate_refresh(pool: &PgPool, token: &str) -> Result<Option<Grant>, DbError> {
    Ok(sqlx::query_as::<_, Grant>(
        "UPDATE atproto_tokens SET revoked_at = now()
         WHERE token_hash = $1 AND kind = 'refresh' AND revoked_at IS NULL
           AND expires_at > now()
         RETURNING user_id, client_id, scope, dpop_jkt",
    )
    .bind(hash_secret(token))
    .fetch_optional(pool)
    .await?)
}

pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE atproto_tokens SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
