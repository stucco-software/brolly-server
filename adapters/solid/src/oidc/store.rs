//! Persistence for the OIDC provider.

use brolly_identity::db::{DbError, generate_secret, hash_secret};
use sqlx::PgPool;
use uuid::Uuid;

use super::keys::ProviderKey;

/// Load the provider's signing key, generating one on first start.
///
/// The key must outlive a restart: regenerating would invalidate every live
/// access token and log everyone out.
pub async fn load_or_create_key(pool: &PgPool) -> Result<ProviderKey, DbError> {
    let existing: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT private_key FROM solid_provider_keys
         WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    if let Some((bytes,)) = existing
        && let Ok(key) = ProviderKey::from_bytes(&bytes)
    {
        return Ok(key);
    }

    let key = ProviderKey::generate();
    sqlx::query("INSERT INTO solid_provider_keys (kid, private_key) VALUES ($1, $2)")
        .bind(&key.kid)
        .bind(key.to_bytes())
        .execute(pool)
        .await?;
    Ok(key)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Client {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
}

/// Register a client (RFC 7591). Returns the `urn:uuid:` identifier.
pub async fn register_client(
    pool: &PgPool,
    name: Option<&str>,
    redirect_uris: &[String],
) -> Result<Client, DbError> {
    let client_id = format!("urn:uuid:{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO solid_clients (client_id, client_name, redirect_uris) VALUES ($1, $2, $3)",
    )
    .bind(&client_id)
    .bind(name)
    .bind(redirect_uris)
    .execute(pool)
    .await?;

    Ok(Client {
        client_id,
        client_name: name.map(str::to_string),
        redirect_uris: redirect_uris.to_vec(),
    })
}

pub async fn find_client(pool: &PgPool, client_id: &str) -> Result<Option<Client>, DbError> {
    Ok(sqlx::query_as::<_, Client>(
        "SELECT client_id, client_name, redirect_uris FROM solid_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?)
}

/// What a redeemed authorization code yields.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthCode {
    pub client_id: String,
    pub user_id: Uuid,
    pub webid: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub dpop_jkt: Option<String>,
}

/// Issue an authorization code, returning the plaintext.
#[allow(clippy::too_many_arguments)]
pub async fn issue_code(
    pool: &PgPool,
    client_id: &str,
    user_id: Uuid,
    webid: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scope: &str,
    nonce: Option<&str>,
    dpop_jkt: Option<&str>,
) -> Result<String, DbError> {
    let code = generate_secret();
    sqlx::query(
        "INSERT INTO solid_auth_codes
           (code_hash, client_id, user_id, webid, redirect_uri, code_challenge,
            scope, nonce, dpop_jkt, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + interval '60 seconds')",
    )
    .bind(hash_secret(&code))
    .bind(client_id)
    .bind(user_id)
    .bind(webid)
    .bind(redirect_uri)
    .bind(code_challenge)
    .bind(scope)
    .bind(nonce)
    .bind(dpop_jkt)
    .execute(pool)
    .await?;
    Ok(code)
}

/// Redeem a code exactly once.
///
/// The check and the mark are one statement, so two simultaneous redemptions
/// cannot both succeed. A code already used returns `None` rather than its
/// contents — the row is kept rather than deleted so replay is *detectable*.
pub async fn redeem_code(pool: &PgPool, code: &str) -> Result<Option<AuthCode>, DbError> {
    Ok(sqlx::query_as::<_, AuthCode>(
        "UPDATE solid_auth_codes SET used_at = now()
         WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING client_id, user_id, webid, redirect_uri, code_challenge,
                   scope, nonce, dpop_jkt",
    )
    .bind(hash_secret(code))
    .fetch_optional(pool)
    .await?)
}

/// Was this code already redeemed? Used to distinguish replay from nonsense.
pub async fn code_was_used(pool: &PgPool, code: &str) -> Result<bool, DbError> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT used_at IS NOT NULL FROM solid_auth_codes WHERE code_hash = $1")
            .bind(hash_secret(code))
            .fetch_optional(pool)
            .await?;
    Ok(matches!(row, Some((true,))))
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshGrant {
    pub client_id: String,
    pub user_id: Uuid,
    pub webid: String,
    pub scope: String,
    pub dpop_jkt: Option<String>,
}

pub async fn issue_refresh(
    pool: &PgPool,
    client_id: &str,
    user_id: Uuid,
    webid: &str,
    scope: &str,
    dpop_jkt: Option<&str>,
) -> Result<String, DbError> {
    let token = generate_secret();
    sqlx::query(
        "INSERT INTO solid_refresh_tokens
           (token_hash, client_id, user_id, webid, scope, dpop_jkt, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + interval '30 days')",
    )
    .bind(hash_secret(&token))
    .bind(client_id)
    .bind(user_id)
    .bind(webid)
    .bind(scope)
    .bind(dpop_jkt)
    .execute(pool)
    .await?;
    Ok(token)
}

/// Redeem and revoke a refresh token in one statement.
///
/// Rotation: the old token is spent by the act of using it, so a stolen refresh
/// token and the legitimate one cannot both keep working — whichever is used
/// second fails, which is how theft becomes visible.
pub async fn rotate_refresh(pool: &PgPool, token: &str) -> Result<Option<RefreshGrant>, DbError> {
    Ok(sqlx::query_as::<_, RefreshGrant>(
        "UPDATE solid_refresh_tokens SET revoked_at = now()
         WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
         RETURNING client_id, user_id, webid, scope, dpop_jkt",
    )
    .bind(hash_secret(token))
    .fetch_optional(pool)
    .await?)
}

/// Revoke every refresh token for a user — used when a grant is withdrawn.
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE solid_refresh_tokens SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
