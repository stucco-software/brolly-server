//! The legacy session surface: `com.atproto.server`'s opaque token pairs and
//! the app passwords that log into them.
//!
//! The HTTP API spec's own words are the design: clients "should treat the
//! tokens as opaque string tokens", and JWT shape "is not a stable part of the
//! specification". So the tokens are 32 random bytes, hex, stored
//! SHA-256-hashed like every other credential in the tree, in their own table
//! — `atproto_tokens` is `dpop_jkt NOT NULL` and `client_id NOT NULL`, two
//! columns a legacy session can never fill, and ADR 0008's rule for surfaces
//! that disagree is separate tables, not mostly-null columns (stage 2, A).
//!
//! App passwords (stage 2, B) are the same decision at a smaller scale: a
//! server-chosen high-entropy secret, SHA-256-hashed for the indexed lookup
//! `createSession` reads first, created once, shown once, revoked by row.

use brolly_identity::db::{DbError, generate_secret, hash_secret};
use sqlx::PgConnection;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Access tokens live as long as the OAuth ones the profile caps (stage 2, A
/// and G): 900 s, the value the OAuth constant converges to.
pub const ACCESS_TTL_SECONDS: f64 = 900.0;
/// Refresh tokens live two weeks, rolling (stage 2, A): every refresh issues
/// a new pair, so a client that keeps refreshing stays signed in and an idle
/// one re-enters its password after a fortnight.
pub const REFRESH_TTL_SECONDS: f64 = 60.0 * 60.0 * 24.0 * 14.0;

// --- app passwords ---------------------------------------------------------

/// One app password as the list endpoint shows it (stage 2, B): everything
/// but the password, which the lexicon's list schema omits and which the
/// stored hash could not return anyway.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Eq)]
pub struct AppPassword {
    pub name: String,
    pub privileged: bool,
    pub created_at: OffsetDateTime,
}

/// Mint an app password: `xxxx-xxxx-xxxx-xxxx`, 16 characters from
/// `[a-z0-9]` — the HTTP API spec's own format, ~82 bits.
///
/// Rejection-sampled per character so no modulo bias; not because 82 bits
/// care, but because the unbiased loop is as short as the biased one.
fn mint_app_password() -> String {
    const GROUPS: usize = 4;
    const GROUP_LEN: usize = 4;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    // 252 = 36 × 7: the largest multiple of the alphabet's length a byte
    // holds, so every accepted byte maps onto it uniformly.
    const UNBIASED_LIMIT: u8 = 252;

    let mut chars: Vec<char> = Vec::with_capacity(GROUPS * GROUP_LEN);
    while chars.len() < GROUPS * GROUP_LEN {
        let byte: u8 = rand::random();
        if byte < UNBIASED_LIMIT {
            chars.push(ALPHABET[(byte % ALPHABET.len() as u8) as usize] as char);
        }
    }
    chars
        .chunks(GROUP_LEN)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// Create an app password. The plaintext appears exactly once, here (stage
/// 2, B) — afterwards only its hash exists.
pub async fn create_app_password(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
    privileged: bool,
) -> Result<(AppPassword, String), DbError> {
    let password = mint_app_password();
    let row = sqlx::query_as::<_, AppPassword>(
        "INSERT INTO atproto_app_passwords (id, user_id, name, password_hash, privileged)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING name, privileged, created_at",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(name)
    .bind(hash_secret(&password))
    .bind(privileged)
    .fetch_one(pool)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => DbError::AppPasswordNameTaken,
        _ => DbError::Sql(e),
    })?;
    Ok((row, password))
}

/// The app passwords as the list endpoint shows them (stage 2, B).
pub async fn list_app_passwords(pool: &PgPool, user_id: Uuid) -> Result<Vec<AppPassword>, DbError> {
    Ok(sqlx::query_as::<_, AppPassword>(
        "SELECT name, privileged, created_at FROM atproto_app_passwords
         WHERE user_id = $1 ORDER BY created_at, name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Revoke by name: the row dies, and the `ON DELETE CASCADE` kills its
/// sessions with it — immediately, which is the property an opaque-token
/// server has and a self-asserting-JWT one does not (stage 2, B).
///
/// `false` when no password of that name existed, for the caller that answers
/// the lexicon's success shape either way.
pub async fn revoke_app_password(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
) -> Result<bool, DbError> {
    let result = sqlx::query("DELETE FROM atproto_app_passwords WHERE user_id = $1 AND name = $2")
        .bind(user_id)
        .bind(name)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// The login path's first password check (stage 2, A): an indexed SHA-256
/// lookup against the presented password, before any Argon2 run. Scoped to
/// the member the identifier resolved to, so one member's app password is
/// never another member's credential.
///
/// Returns the app password's id (the session's provenance) and its
/// `privileged` flag.
pub async fn find_app_password(
    pool: &PgPool,
    user_id: Uuid,
    password: &str,
) -> Result<Option<(Uuid, bool)>, DbError> {
    Ok(sqlx::query_as::<_, (Uuid, bool)>(
        "SELECT id, privileged FROM atproto_app_passwords
         WHERE user_id = $1 AND password_hash = $2",
    )
    .bind(user_id)
    .bind(hash_secret(password))
    .fetch_optional(pool)
    .await?)
}

// --- legacy tokens ----------------------------------------------------------

/// What a legacy token grants: the member, the session it belongs to, and —
/// the provenance the privilege matrix reads (stage 2, B) — the app password
/// it was created through, if any, with that password's `privileged` flag.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Eq)]
pub struct LegacyGrant {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub app_password_id: Option<Uuid>,
    pub privileged: bool,
}

impl LegacyGrant {
    /// The email half of the privilege matrix (stage 2, B): primary sessions
    /// see the email fields, app-password sessions only when the app password
    /// is privileged.
    pub fn may_see_email(&self) -> bool {
        self.app_password_id.is_none() || self.privileged
    }
}

/// A freshly issued pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPair {
    pub access: String,
    pub refresh: String,
}

/// Insert one half of a pair.
async fn insert_token(
    con: &mut PgConnection,
    kind: &str,
    token: &str,
    user_id: Uuid,
    app_password_id: Option<Uuid>,
    session_id: Uuid,
    ttl: f64,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO atproto_legacy_tokens
           (token_hash, kind, user_id, app_password_id, session_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(hash_secret(token))
    .bind(kind)
    .bind(user_id)
    .bind(app_password_id)
    .bind(session_id)
    .bind(ttl)
    .execute(con)
    .await?;
    Ok(())
}

/// Issue a session's first pair (stage 2, A): one `session_id`, two opaque
/// tokens, both rows or neither.
pub async fn issue_pair(
    pool: &PgPool,
    user_id: Uuid,
    app_password_id: Option<Uuid>,
) -> Result<LegacyPair, DbError> {
    let session_id = Uuid::new_v4();
    let access = generate_secret();
    let refresh = generate_secret();
    let mut tx = pool.begin().await?;
    insert_token(
        &mut tx,
        "access",
        &access,
        user_id,
        app_password_id,
        session_id,
        ACCESS_TTL_SECONDS,
    )
    .await?;
    insert_token(
        &mut tx,
        "refresh",
        &refresh,
        user_id,
        app_password_id,
        session_id,
        REFRESH_TTL_SECONDS,
    )
    .await?;
    tx.commit().await?;
    Ok(LegacyPair { access, refresh })
}

/// Resolve an access token (stage 2, A). The kind is part of the lookup: a
/// refresh token presented as an access one fails the query, not a check
/// after it — the domain separation the spec's `typ` headers approximate, and
/// the pattern `oauth::verify_token` already proved.
pub async fn verify_access(pool: &PgPool, token: &str) -> Result<Option<LegacyGrant>, DbError> {
    Ok(sqlx::query_as::<_, LegacyGrant>(
        "SELECT t.user_id, t.session_id, t.app_password_id,
                COALESCE(p.privileged, false) AS privileged
         FROM atproto_legacy_tokens t
         LEFT JOIN atproto_app_passwords p ON p.id = t.app_password_id
         WHERE t.token_hash = $1 AND t.kind = 'access'
           AND t.revoked_at IS NULL AND t.expires_at > now()",
    )
    .bind(hash_secret(token))
    .fetch_optional(pool)
    .await?)
}

/// What a presented refresh token is worth, in the lexicon's own two error
/// names (stage 2, A): `InvalidToken` for unknown or revoked, `ExpiredToken`
/// for expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshToken {
    Valid(LegacyGrant),
    Expired,
    Invalid,
}

/// One refresh row, with the fields the lexicon's two error names ask for:
/// `expires_at` and `revoked_at` classify, the rest become the grant.
#[derive(Debug, Clone, sqlx::FromRow)]
struct RefreshRow {
    user_id: Uuid,
    session_id: Uuid,
    app_password_id: Option<Uuid>,
    privileged: bool,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

/// Classify a refresh token without spending it: `refreshSession` and
/// `deleteSession` authenticate with it, and their lexicons answer the two
/// failure names distinctly.
pub async fn inspect_refresh(pool: &PgPool, token: &str) -> Result<RefreshToken, DbError> {
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT t.user_id, t.session_id, t.app_password_id,
                COALESCE(p.privileged, false) AS privileged,
                t.expires_at, t.revoked_at
         FROM atproto_legacy_tokens t
         LEFT JOIN atproto_app_passwords p ON p.id = t.app_password_id
         WHERE t.token_hash = $1 AND t.kind = 'refresh'",
    )
    .bind(hash_secret(token))
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(RefreshToken::Invalid);
    };
    if row.revoked_at.is_some() {
        return Ok(RefreshToken::Invalid);
    }
    if row.expires_at <= OffsetDateTime::now_utc() {
        return Ok(RefreshToken::Expired);
    }
    Ok(RefreshToken::Valid(LegacyGrant {
        user_id: row.user_id,
        session_id: row.session_id,
        app_password_id: row.app_password_id,
        privileged: row.privileged,
    }))
}

/// Rotate (stage 2, A): revoke every row of the session, issue a new pair
/// under the same `session_id`.
///
/// The revoke's row count is the race's arbiter: two concurrent refreshes of
/// one token both classify it valid, but only the first's UPDATE finds
/// `revoked_at IS NULL` rows — the second gets `None` and answers
/// `InvalidToken`, which is the replay answer the rotation exists to give.
pub async fn rotate_pair(
    pool: &PgPool,
    grant: &LegacyGrant,
) -> Result<Option<LegacyPair>, DbError> {
    let mut tx = pool.begin().await?;
    let revoked = sqlx::query(
        "UPDATE atproto_legacy_tokens SET revoked_at = now()
         WHERE session_id = $1 AND revoked_at IS NULL",
    )
    .bind(grant.session_id)
    .execute(&mut *tx)
    .await?;
    if revoked.rows_affected() == 0 {
        return Ok(None);
    }
    let access = generate_secret();
    let refresh = generate_secret();
    insert_token(
        &mut tx,
        "access",
        &access,
        grant.user_id,
        grant.app_password_id,
        grant.session_id,
        ACCESS_TTL_SECONDS,
    )
    .await?;
    insert_token(
        &mut tx,
        "refresh",
        &refresh,
        grant.user_id,
        grant.app_password_id,
        grant.session_id,
        REFRESH_TTL_SECONDS,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(LegacyPair { access, refresh }))
}

/// Revoke every row of a session (stage 2, A): `deleteSession` kills the
/// access token with the session, not at expiry.
pub async fn revoke_session(pool: &PgPool, session_id: Uuid) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE atproto_legacy_tokens SET revoked_at = now()
         WHERE session_id = $1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Revoke every legacy token of a member — the password-change wiring
/// (stage 2, G), alongside `oauth::revoke_all_for_user` for the OAuth table.
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE atproto_legacy_tokens SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `^[a-z0-9]{4}(-[a-z0-9]{4}){3}$`, asserted by hand rather than with a
    /// regex crate: the tree carries no regex dependency, and the format is
    /// four groups of four from `[a-z0-9]`.
    #[test]
    fn an_app_password_matches_the_http_api_specs_own_format() {
        for _ in 0..64 {
            let password = mint_app_password();
            let groups: Vec<&str> = password.split('-').collect();
            assert_eq!(groups.len(), 4, "{password}");
            for group in &groups {
                assert_eq!(group.len(), 4, "{password}");
                assert!(
                    group
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                    "{password}"
                );
            }
        }
    }

    #[test]
    fn app_passwords_do_not_repeat() {
        // 82 bits: a repeat within 256 draws is a broken RNG, not bad luck.
        let seen: std::collections::HashSet<String> =
            (0..256).map(|_| mint_app_password()).collect();
        assert_eq!(seen.len(), 256);
    }
}
