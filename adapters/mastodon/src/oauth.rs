//! Mastodon OAuth persistence.
//!
//! Postgres, not an RDF store — this is operational state, and the
//! projection-only rule is about pod content (`server/tests/architecture.rs`
//! checks the store write API, not this). It mirrors `solid::oidc::store`
//! deliberately: the same properties matter, so they are solved the same way.
//!
//! Where Mastodon genuinely differs from Solid-OIDC:
//!
//! * **Clients get a secret.** Browser apps registering against Solid cannot
//!   keep one; Mastodon's confidential clients can and do.
//! * **Access tokens do not expire.** Clients store one and use it for years.
//!   Inventing an expiry would log the ecosystem out on a schedule nobody asked
//!   for, so revocation is explicit instead.
//! * **PKCE is optional.** Mastodon added it in 4.3 and older clients still
//!   authenticate without it. Requiring it would refuse most of the ecosystem.

use brolly_identity::db::{DbError, generate_secret, hash_secret};
use sqlx::PgPool;
use uuid::Uuid;

/// The default scope when a client asks for none, per Mastodon's API.
pub const DEFAULT_SCOPES: &str = "read";

/// How long an authorization code lives. Codes are exchanged immediately.
const CODE_TTL_SECONDS: i64 = 600;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct App {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: String,
    pub website: Option<String>,
}

/// A newly registered app, including the one time its secret is visible.
pub struct Registered {
    pub app: App,
    pub client_secret: String,
}

/// Register a client application (`POST /api/v1/apps`).
pub async fn register_app(
    pool: &PgPool,
    name: &str,
    redirect_uris: &[String],
    scopes: &str,
    website: Option<&str>,
) -> Result<Registered, DbError> {
    let client_id = generate_secret();
    let client_secret = generate_secret();

    sqlx::query(
        "INSERT INTO mastodon_apps
           (client_id, client_secret_hash, name, redirect_uris, scopes, website)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&client_id)
    .bind(hash_secret(&client_secret))
    .bind(name)
    .bind(redirect_uris)
    .bind(scopes)
    .bind(website)
    .execute(pool)
    .await?;

    Ok(Registered {
        app: App {
            client_id,
            name: name.to_string(),
            redirect_uris: redirect_uris.to_vec(),
            scopes: scopes.to_string(),
            website: website.map(str::to_string),
        },
        client_secret,
    })
}

pub async fn find_app(pool: &PgPool, client_id: &str) -> Result<Option<App>, DbError> {
    Ok(sqlx::query_as::<_, App>(
        "SELECT client_id, name, redirect_uris, scopes, website
         FROM mastodon_apps WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?)
}

/// Check a presented client secret against the stored hash.
///
/// Returns the app only when the secret matches, so a caller cannot
/// accidentally proceed with an unverified client.
pub async fn authenticate_app(
    pool: &PgPool,
    client_id: &str,
    client_secret: &str,
) -> Result<Option<App>, DbError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT client_secret_hash FROM mastodon_apps WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(pool)
            .await?;

    match row {
        Some((stored,)) if stored == hash_secret(client_secret) => find_app(pool, client_id).await,
        _ => Ok(None),
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthCode {
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: Option<String>,
}

pub async fn issue_code(
    pool: &PgPool,
    client_id: &str,
    user_id: Uuid,
    redirect_uri: &str,
    scopes: &str,
    code_challenge: Option<&str>,
) -> Result<String, DbError> {
    let code = generate_secret();
    sqlx::query(
        "INSERT INTO mastodon_auth_codes
           (code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
    )
    .bind(hash_secret(&code))
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(scopes)
    .bind(code_challenge)
    .bind(CODE_TTL_SECONDS as f64)
    .execute(pool)
    .await?;
    Ok(code)
}

/// Redeem a code exactly once.
///
/// The check and the mark are one statement, so two simultaneous redemptions
/// cannot both succeed.
pub async fn redeem_code(pool: &PgPool, code: &str) -> Result<Option<AuthCode>, DbError> {
    Ok(sqlx::query_as::<_, AuthCode>(
        "UPDATE mastodon_auth_codes SET used_at = now()
         WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING client_id, user_id, redirect_uri, scopes, code_challenge",
    )
    .bind(hash_secret(code))
    .fetch_optional(pool)
    .await?)
}

/// Mint an access token.
pub async fn issue_token(
    pool: &PgPool,
    client_id: &str,
    user_id: Uuid,
    scopes: &str,
) -> Result<String, DbError> {
    let token = generate_secret();
    sqlx::query(
        "INSERT INTO mastodon_tokens (token_hash, client_id, user_id, scopes)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(hash_secret(&token))
    .bind(client_id)
    .bind(user_id)
    .bind(scopes)
    .execute(pool)
    .await?;
    Ok(token)
}

/// What a presented bearer token grants.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Eq)]
pub struct Grant {
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: String,
}

/// Resolve a bearer token.
///
/// `None` for unknown *and* revoked, deliberately: a caller must not be able to
/// tell a token that never existed from one that was withdrawn.
pub async fn verify_token(pool: &PgPool, token: &str) -> Result<Option<Grant>, DbError> {
    Ok(sqlx::query_as::<_, Grant>(
        "SELECT user_id, client_id, scopes FROM mastodon_tokens
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(hash_secret(token))
    .fetch_optional(pool)
    .await?)
}

/// Revoke one token (`POST /oauth/revoke`).
pub async fn revoke_token(pool: &PgPool, token: &str) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE mastodon_tokens SET revoked_at = now()
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(hash_secret(token))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Revoke every token a member holds — the "log out everywhere" of the
/// dashboard's security page.
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE mastodon_tokens SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Every app a member has granted access to, for the dashboard.
pub async fn apps_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<(String, String)>, DbError> {
    Ok(sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT a.client_id, a.name
         FROM mastodon_tokens t JOIN mastodon_apps a ON a.client_id = t.client_id
         WHERE t.user_id = $1 AND t.revoked_at IS NULL
         ORDER BY a.name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Does this grant carry `required`?
///
/// Mastodon's coarse scopes stand in for their finer ones — `read` satisfies
/// `read:statuses` — but never the other way round, and `write` never implies
/// `read`. Getting the direction wrong hands a posting-only app the ability to
/// read direct messages.
pub fn has_scope(granted: &str, required: &str) -> bool {
    let (family, _) = required.split_once(':').unwrap_or((required, ""));
    granted
        .split_whitespace()
        .any(|scope| scope == required || scope == family)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coarse_scope_satisfies_its_finer_ones() {
        assert!(has_scope("read write", "read:statuses"));
        assert!(has_scope("read write", "write:media"));
        assert!(has_scope("read", "read"));
    }

    #[test]
    fn a_finer_scope_does_not_satisfy_the_coarse_one() {
        // Holding `read:statuses` must not unlock everything `read` covers.
        assert!(!has_scope("read:statuses", "read"));
        assert!(!has_scope("write:media", "write"));
    }

    #[test]
    fn scope_families_do_not_leak_into_each_other() {
        // The direction that matters: a posting-only app must not gain the
        // ability to read direct messages.
        assert!(!has_scope("write", "read"));
        assert!(!has_scope("write write:statuses", "read:statuses"));
        assert!(!has_scope("read", "follow"));
    }

    #[test]
    fn an_empty_grant_satisfies_nothing() {
        assert!(!has_scope("", "read"));
        assert!(!has_scope("   ", "read"));
    }
}
