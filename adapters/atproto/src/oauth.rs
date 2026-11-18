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
use time::OffsetDateTime;
use uuid::Uuid;

/// How long a pushed request stays redeemable. Short: the client redirects the
/// member immediately.
const PAR_TTL_SECONDS: f64 = 300.0;
const CODE_TTL_SECONDS: f64 = 60.0;
/// Access tokens live a quarter hour (stage 2, G). The profile's hard cap is
/// 30 minutes and its recommendation 5; brolly can revoke individual rows, but
/// the only revocation *wired* today is revoke-all, so a stolen token
/// realistically lives its full TTL — 900 s is the conservative end that keeps
/// refresh chatter low (one refresh per quarter hour, not per five minutes).
pub const ACCESS_TTL_SECONDS: f64 = 900.0;
/// A public client's refresh tokens live two weeks (stage 2, G). Confidential
/// clients earn 180 days (F, chunk 5).
pub const REFRESH_TTL_SECONDS: f64 = 60.0 * 60.0 * 24.0 * 14.0;
/// A confidential client's refresh tokens live 180 days (stage 2, F): the
/// profile's trade — an authenticated, key-bound, remotely-revocable client
/// earns the longer session.
pub const CONFIDENTIAL_REFRESH_TTL_SECONDS: f64 = 60.0 * 60.0 * 24.0 * 180.0;
/// The overall cap on a public client's session (stage 2, G): `anchored_at`
/// plus this is the last moment a refresh is answered. The profile caps
/// "overall session lifetime **and** individual refresh tokens", and rotation
/// alone caps only the second — the anchor, copied forward on every rotation,
/// is what caps the first. A confidential client's session is uncapped (F):
/// the anchor applies to public clients only.
pub const SESSION_TTL_SECONDS: f64 = 60.0 * 60.0 * 24.0 * 14.0;
/// How long a spent code_challenge is remembered (stage 2, H): the profile's
/// own window — "at least … a 24 hour period".
pub const CODE_CHALLENGE_WINDOW_SECONDS: i64 = 24 * 60 * 60;

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
    /// The thumbprint of the key that signed the client assertion, for a
    /// confidential client (stage 2, F). `None` for a public client's push.
    pub client_jkt: Option<String>,
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
    client_jkt: Option<&str>,
) -> Result<String, DbError> {
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", generate_secret());
    sqlx::query(
        "INSERT INTO atproto_par_requests
           (request_uri, client_id, redirect_uri, scope, state, code_challenge,
            dpop_jkt, login_hint, client_jkt, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + make_interval(secs => $10))",
    )
    .bind(&request_uri)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(scope)
    .bind(state)
    .bind(code_challenge)
    .bind(dpop_jkt)
    .bind(login_hint)
    .bind(client_jkt)
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
        "SELECT client_id, redirect_uri, scope, state, code_challenge, dpop_jkt, login_hint, client_jkt
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
         RETURNING client_id, redirect_uri, scope, state, code_challenge, dpop_jkt, login_hint, client_jkt",
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
    /// The client key the session is bound to, for a confidential client
    /// (stage 2, F). `None` for a public client's code.
    pub client_jkt: Option<String>,
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
    client_jkt: Option<&str>,
) -> Result<String, DbError> {
    let code = generate_secret();
    sqlx::query(
        "INSERT INTO atproto_auth_codes
           (code_hash, client_id, user_id, redirect_uri, scope, code_challenge,
            dpop_jkt, client_jkt, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))",
    )
    .bind(hash_secret(&code))
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(scope)
    .bind(code_challenge)
    .bind(dpop_jkt)
    .bind(client_jkt)
    .bind(CODE_TTL_SECONDS)
    .execute(pool)
    .await?;
    Ok(code)
}

pub async fn redeem_code(pool: &PgPool, code: &str) -> Result<Option<AuthCode>, DbError> {
    Ok(sqlx::query_as::<_, AuthCode>(
        "UPDATE atproto_auth_codes SET used_at = now()
         WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING client_id, user_id, redirect_uri, scope, code_challenge, dpop_jkt, client_jkt",
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
    /// The client key the session is bound to, for a confidential client's
    /// session (stage 2, F). `None` marks a public client's session — the
    /// marker the refresh path's rules key on: no anchor cap, and an
    /// assertion is a refusal rather than a requirement.
    pub client_jkt: Option<String>,
    /// The session's anchor (stage 2, G): set at the code grant, copied
    /// forward on every rotation — the cap on overall session lifetime that
    /// rotation alone cannot give. A confidential session carries it too,
    /// uncapped; only a public session's refresh is refused past it.
    pub anchored_at: OffsetDateTime,
}

#[allow(clippy::too_many_arguments)]
pub async fn issue_token(
    pool: &PgPool,
    kind: &str,
    client_id: &str,
    user_id: Uuid,
    scope: &str,
    dpop_jkt: &str,
    client_jkt: Option<&str>,
    anchored_at: OffsetDateTime,
) -> Result<String, DbError> {
    // A confidential session's refresh tokens live 180 days (stage 2, F):
    // the one lifetime the client's key binding changes.
    let ttl = match (kind, client_jkt) {
        ("refresh", Some(_)) => CONFIDENTIAL_REFRESH_TTL_SECONDS,
        ("refresh", None) => REFRESH_TTL_SECONDS,
        _ => ACCESS_TTL_SECONDS,
    };
    let token = generate_secret();
    sqlx::query(
        "INSERT INTO atproto_tokens
           (token_hash, kind, client_id, user_id, scope, dpop_jkt, client_jkt, anchored_at,
            expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))",
    )
    .bind(hash_secret(&token))
    .bind(kind)
    .bind(client_id)
    .bind(user_id)
    .bind(scope)
    .bind(dpop_jkt)
    .bind(client_jkt)
    .bind(anchored_at)
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
        "SELECT user_id, client_id, scope, dpop_jkt, client_jkt, anchored_at FROM atproto_tokens
         WHERE token_hash = $1 AND kind = $2 AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(hash_secret(token))
    .bind(kind)
    .fetch_optional(pool)
    .await?)
}

/// Spend a refresh token, so rotation makes theft visible. The anchor rides
/// back with the grant (stage 2, G): the caller copies it onto the new pair,
/// so rotation cannot reset it.
pub async fn rotate_refresh(pool: &PgPool, token: &str) -> Result<Option<Grant>, DbError> {
    Ok(sqlx::query_as::<_, Grant>(
        "UPDATE atproto_tokens SET revoked_at = now()
         WHERE token_hash = $1 AND kind = 'refresh' AND revoked_at IS NULL
           AND expires_at > now()
         RETURNING user_id, client_id, scope, dpop_jkt, client_jkt, anchored_at",
    )
    .bind(hash_secret(token))
    .fetch_optional(pool)
    .await?)
}

/// Revoke a confidential session whose client key has left its JWKS (stage
/// 2, F): every token row that key was bound to. The profile's "must revoke
/// the session … if the client authentication key becomes absent" — key
/// removal is the kill switch, so the revocation is keyed on the binding,
/// not the client: another session of the same client, bound to a key still
/// in the set, survives.
pub async fn revoke_bound_sessions(
    pool: &PgPool,
    client_id: &str,
    user_id: Uuid,
    client_jkt: &str,
) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE atproto_tokens SET revoked_at = now()
         WHERE client_id = $1 AND user_id = $2 AND client_jkt = $3
           AND revoked_at IS NULL",
    )
    .bind(client_id)
    .bind(user_id)
    .bind(client_jkt)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
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

// --- PKCE challenge reuse ---------------------------------------------------------

/// Record a code_challenge and prune expired ones, in one statement — the
/// `dpop_jti` pattern (S7).
///
/// `$2` is the prune cutoff and `$3` the row's expiry. Both come from the
/// application's clock. No row back means the challenge was already used
/// within the window.
const SPEND_CHALLENGE: &str = "\
    WITH pruned AS (DELETE FROM atproto_used_code_challenges WHERE expires_at < to_timestamp($2)) \
    INSERT INTO atproto_used_code_challenges (code_challenge, expires_at) \
    VALUES ($1, to_timestamp($3)) \
    ON CONFLICT DO NOTHING \
    RETURNING code_challenge";

/// Refuse a `code_challenge` that has been used within the window (stage 2,
/// H). The profile's PKCE section makes this a "must" — defense in depth
/// against a challenge-carrying interceptor, and one indexed insert: the
/// challenge value is itself a SHA-256, so it is its own primary key.
///
/// A challenge is spent only when the push stores: a request refused earlier
/// (a bad redirect URI, a scope the client or the server refuses) must not
/// burn the challenge a corrected retry carries.
///
/// `now` is the application's clock — the `dpop_jti` rule: the database's
/// clock would let a running-ahead prune forget a row the application still
/// counts. Returns `false` when the challenge was already used within the
/// window; callers must treat that as a refusal.
pub async fn use_code_challenge(
    pool: &PgPool,
    code_challenge: &str,
    now: i64,
) -> Result<bool, DbError> {
    let recorded: Option<String> = sqlx::query_scalar(SPEND_CHALLENGE)
        .bind(code_challenge)
        .bind(now)
        .bind(now.saturating_add(CODE_CHALLENGE_WINDOW_SECONDS))
        .fetch_optional(pool)
        .await?;
    Ok(recorded.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_tokens_live_a_quarter_hour() {
        // `black_box` so the comparison is not folded away — the service_auth
        // trap: a budget assertion that optimizes to nothing is worse than
        // none, because it reads as covered. The number is the profile's own
        // (its hard cap is 30 minutes); changing it is a deliberate act.
        assert_eq!(
            std::hint::black_box(ACCESS_TTL_SECONDS),
            900.0,
            "a longer access token is a stolen token that lives longer: the \
             only revocation wired today is revoke-all"
        );
    }

    #[test]
    fn a_public_session_is_capped_at_a_fortnight() {
        // Both halves of the profile's sentence: it caps "overall session
        // lifetime **and** individual refresh tokens" — `SESSION_TTL` is the
        // first (the anchor's cap), `REFRESH_TTL` the second.
        assert_eq!(
            std::hint::black_box(REFRESH_TTL_SECONDS),
            60.0 * 60.0 * 24.0 * 14.0,
            "a public client's refresh tokens live two weeks"
        );
        assert_eq!(
            std::hint::black_box(SESSION_TTL_SECONDS),
            60.0 * 60.0 * 24.0 * 14.0,
            "rotation copies the anchor forward, so the overall session is \
             capped at two weeks however much the client refreshes"
        );
    }

    #[test]
    fn a_confidential_refresh_token_lives_180_days_uncapped() {
        // The profile's trade (F): an authenticated, key-bound,
        // remotely-revocable client earns the longer refresh — and the
        // uncapped session, which is why no `CONFIDENTIAL_SESSION_TTL`
        // exists to assert here: the anchor's cap is the public client's
        // rule, and a constant for its absence would be a lie with a name.
        assert_eq!(
            std::hint::black_box(CONFIDENTIAL_REFRESH_TTL_SECONDS),
            60.0 * 60.0 * 24.0 * 180.0,
            "a confidential client's refresh tokens live 180 days"
        );
    }

    #[test]
    fn a_spent_challenge_is_remembered_for_a_day() {
        // The profile's own floor: "at least … a 24 hour period".
        assert_eq!(
            std::hint::black_box(CODE_CHALLENGE_WINDOW_SECONDS),
            24 * 60 * 60,
            "a shorter window re-opens the challenge-reuse hole the profile \
             closes with its 24-hour floor"
        );
    }
}
