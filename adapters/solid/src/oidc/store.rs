//! Persistence for the OIDC provider.

use brolly_identity::db::{DbError, generate_secret, hash_secret};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
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

/// How long one refresh token is good for, unused. Rotation issues a fresh
/// one with a fresh window — bounded by the family's absolute lifetime.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::days(30);

/// How long a grant lives from the day it was made, however often it is
/// refreshed. Rotation alone would make a grant immortal — each replacement
/// starts a fresh sliding window — so the family carries one absolute date,
/// copied forward through every rotation, past which no replacement is
/// issued and none is accepted.
pub const REFRESH_GRANT_LIFETIME: Duration = Duration::days(90);

/// What a refresh token inherits: the family it belongs to — the grant it
/// descends from through rotation — and when that grant ends for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lineage {
    pub family: Uuid,
    pub grant_expires_at: OffsetDateTime,
}

impl Lineage {
    /// A new grant: its own family, the full lifetime ahead of it.
    pub fn fresh() -> Self {
        Lineage {
            family: Uuid::new_v4(),
            grant_expires_at: OffsetDateTime::now_utc() + REFRESH_GRANT_LIFETIME,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshGrant {
    pub client_id: String,
    pub user_id: Uuid,
    pub webid: String,
    pub scope: String,
    pub dpop_jkt: Option<String>,
    pub family: Uuid,
    pub grant_expires_at: OffsetDateTime,
}

impl RefreshGrant {
    /// What a replacement for this token inherits.
    pub fn lineage(&self) -> Lineage {
        Lineage {
            family: self.family,
            grant_expires_at: self.grant_expires_at,
        }
    }
}

/// Mint a refresh token in `lineage`'s family. Its own expiry is the sliding
/// window or the family's end, whichever is sooner.
pub async fn issue_refresh(
    pool: &PgPool,
    client_id: &str,
    user_id: Uuid,
    webid: &str,
    scope: &str,
    dpop_jkt: Option<&str>,
    lineage: &Lineage,
) -> Result<String, DbError> {
    let token = generate_secret();
    sqlx::query(
        "INSERT INTO solid_refresh_tokens
           (token_hash, client_id, user_id, webid, scope, dpop_jkt,
            family, grant_expires_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, LEAST(now() + $9, $8))",
    )
    .bind(hash_secret(&token))
    .bind(client_id)
    .bind(user_id)
    .bind(webid)
    .bind(scope)
    .bind(dpop_jkt)
    .bind(lineage.family)
    .bind(lineage.grant_expires_at)
    .bind(REFRESH_TOKEN_LIFETIME)
    .execute(pool)
    .await?;
    Ok(token)
}

/// What presenting a refresh token came to.
#[derive(Debug, Clone)]
pub enum Rotation {
    /// Spent, and its grant is the caller's to replace.
    Rotated(RefreshGrant),
    /// Already spent — and now its whole family is revoked. One of the two
    /// holders of a rotated token is not the client; ending the grant is the
    /// answer, not just refusing the replay.
    Replayed,
    /// Unknown, expired, past its grant's end, another client's, or bound to
    /// another key. Nothing was spent: a thief with the token but not the
    /// key must not be able to log the owner out by trying.
    Refused,
}

/// Redeem and revoke a refresh token in one statement.
///
/// Rotation: the old token is spent by the act of using it, so a stolen
/// refresh token and the legitimate one cannot both keep working — whichever
/// is used second fails, which is how theft becomes visible. The client and
/// the key are part of the `WHERE`, not checked afterwards: a token presented
/// by the wrong client or the wrong key is not spent, so the attempt costs its
/// owner nothing.
pub async fn rotate_refresh(
    pool: &PgPool,
    token: &str,
    client_id: &str,
    dpop_jkt: Option<&str>,
) -> Result<Rotation, DbError> {
    let hash = hash_secret(token);
    let rotated = sqlx::query_as::<_, RefreshGrant>(
        "UPDATE solid_refresh_tokens SET revoked_at = now()
         WHERE token_hash = $1
           AND revoked_at IS NULL
           AND expires_at > now()
           AND grant_expires_at > now()
           AND client_id = $2
           AND dpop_jkt IS NOT DISTINCT FROM $3
         RETURNING client_id, user_id, webid, scope, dpop_jkt, family, grant_expires_at",
    )
    .bind(&hash)
    .bind(client_id)
    .bind(dpop_jkt)
    .fetch_optional(pool)
    .await?;
    if let Some(grant) = rotated {
        return Ok(Rotation::Rotated(grant));
    }

    // Not rotated. A replay — this exact token, already spent, by the client
    // and key it belongs to — ends the family. Anything else is refused and
    // leaves the family alone: a wrong key or a wrong client is not evidence
    // that the right one's token has leaked, only that someone tried.
    sqlx::query(
        "UPDATE solid_refresh_tokens SET revoked_at = now()
         WHERE family = (SELECT family FROM solid_refresh_tokens
                          WHERE token_hash = $1 AND revoked_at IS NOT NULL
                            AND client_id = $2 AND dpop_jkt IS NOT DISTINCT FROM $3)
           AND revoked_at IS NULL",
    )
    .bind(&hash)
    .bind(client_id)
    .bind(dpop_jkt)
    .execute(pool)
    .await?;
    let spent_before = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM solid_refresh_tokens
                        WHERE token_hash = $1 AND revoked_at IS NOT NULL
                          AND client_id = $2 AND dpop_jkt IS NOT DISTINCT FROM $3)",
    )
    .bind(&hash)
    .bind(client_id)
    .bind(dpop_jkt)
    .fetch_one(pool)
    .await?;
    Ok(if spent_before {
        Rotation::Replayed
    } else {
        Rotation::Refused
    })
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

/// An app a member has authorised, as the dashboard lists it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorisedApp {
    pub client_id: String,
    pub client_name: Option<String>,
    pub scope: String,
}

/// Apps holding a live grant for this user.
///
/// A grant is "live" when it still has an unexpired, unrevoked refresh token:
/// that is what an app can actually still use, so it is what the member should
/// see. One row per client, not per token, because rotation means a long-lived
/// grant has issued many.
pub async fn apps_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<AuthorisedApp>, DbError> {
    Ok(sqlx::query_as::<_, AuthorisedApp>(
        "SELECT DISTINCT c.client_id, c.client_name, r.scope
           FROM solid_refresh_tokens r
           JOIN solid_clients c ON c.client_id = r.client_id
          WHERE r.user_id = $1 AND r.revoked_at IS NULL AND r.expires_at > now()
          ORDER BY c.client_name NULLS LAST",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Withdraw one app's access for one member.
///
/// Scoped by both, so a member revoking an app cannot touch anyone else's
/// grant to it.
pub async fn revoke_app_for_user(
    pool: &PgPool,
    user_id: Uuid,
    client_id: &str,
) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE solid_refresh_tokens SET revoked_at = now()
         WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(client_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// What one member has allowed one client: the remembered half of a
/// consent-screen allow (spec 6, H4), consulted only by `prompt=none`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RememberedConsent {
    pub scope: String,
    pub redirect_uris: Vec<String>,
}

impl RememberedConsent {
    /// Does this consent cover a request (spec 6, H4)? Subset matching, not
    /// string equality, in both directions: the request's scope must be a
    /// subset of the remembered scope — exact matching would refuse a
    /// remembered `openid webid` consent for a bare `webid` request, and
    /// superset matching the other way would silently grant what was never
    /// approved — and its `redirect_uri` must be among the remembered URIs,
    /// which is what keeps a remembered consent from outliving the Client ID
    /// Document that earned it: a changed document falls back to the consent
    /// screen once, rather than carrying a code to a URI the member never
    /// saw. (Registered clients' URIs are fixed at registration, so for them
    /// the column is constant.)
    pub fn covers(&self, scope: &str, redirect_uri: &str) -> bool {
        let remembered: std::collections::HashSet<&str> = self.scope.split_whitespace().collect();
        scope.split_whitespace().all(|s| remembered.contains(s))
            && self.redirect_uris.iter().any(|u| u == redirect_uri)
    }
}

/// Record a consent-screen allow (spec 6, H4).
///
/// The write is the union, never the overwrite: both the scope and the
/// redirect URIs widen monotonically, so a narrower re-grant cannot shrink
/// what the member already approved. One statement, so two simultaneous
/// allows cannot race each other into a narrowing; the union is sorted, so
/// the stored row is deterministic.
pub async fn remember_consent(
    pool: &PgPool,
    user_id: Uuid,
    client_id: &str,
    scope: &str,
    redirect_uri: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO solid_consents (user_id, client_id, scope, redirect_uris)
         VALUES ($1, $2, $3, ARRAY[$4]::text[])
         ON CONFLICT (user_id, client_id) DO UPDATE SET
           granted_at = now(),
           scope = COALESCE((
             SELECT string_agg(word, ' ' ORDER BY word) FROM (
               SELECT DISTINCT unnest(string_to_array(
                        solid_consents.scope || ' ' || EXCLUDED.scope, ' ')) AS word
             ) words
             WHERE word <> ''
           ), ''),
           redirect_uris = (
             SELECT array_agg(uri ORDER BY uri) FROM (
               SELECT DISTINCT unnest(
                        solid_consents.redirect_uris || EXCLUDED.redirect_uris) AS uri
             ) uris
           )",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(scope)
    .bind(redirect_uri)
    .execute(pool)
    .await?;
    Ok(())
}

/// The member's remembered consent for one client, if any.
///
/// `None` is absence, not an error — the caller's answer to absence is
/// `consent_required`, not a failure page.
pub async fn remembered_consent(
    pool: &PgPool,
    user_id: Uuid,
    client_id: &str,
) -> Result<Option<RememberedConsent>, DbError> {
    Ok(sqlx::query_as::<_, RememberedConsent>(
        "SELECT scope, redirect_uris FROM solid_consents
          WHERE user_id = $1 AND client_id = $2",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(pool)
    .await?)
}
