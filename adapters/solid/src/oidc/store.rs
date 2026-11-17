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

// --- WebID links and client credentials (ADR 0020) --------------------------
//
// The CSS model for non-interactive agents: an account links a WebID — one
// this instance typically does not host, whose own document names this
// issuer — and id/secret pairs are minted against the link. A
// `client_credentials` token names the linked WebID, so a customer pod's
// access control answers to it exactly. The link's proof (the dereference
// of the WebID's `solid:oidcIssuer`) is the server layer's to gather — it is
// a network round trip — so what lives here is the write and the lookup.

/// What linking a WebID came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linked {
    /// Recorded now.
    Now,
    /// Already linked, to this same account. Re-running an operator command
    /// is not an error.
    Already,
    /// Linked to another account. One WebID, one account: the link is the
    /// WebID's delegation of its identity, and moving it is the owner's act,
    /// not a side effect of an operator command run against another handle.
    AnotherAccount,
}

/// Link a WebID to an account. The WebID's own document has already named
/// this issuer — that check is `brolly_server::solid_oidc::link_webid`'s;
/// this is the write it follows.
///
/// Looked up before it is written, so the two cases an operator re-run hits
/// — this account's own link, and another account's — answer without a
/// write. The insert still takes the conflict into itself (`DO NOTHING`),
/// so a link that appears between the read and the write is classified by
/// one more read, never lost and never moved.
pub async fn link_webid(pool: &PgPool, user_id: Uuid, webid: &str) -> Result<Linked, DbError> {
    if let Some(owner) = webid_link_owner(pool, webid).await? {
        return Ok(linked_with(user_id, owner));
    }
    let inserted = sqlx::query(
        "INSERT INTO solid_webid_links (webid, user_id) VALUES ($1, $2)
         ON CONFLICT (webid) DO NOTHING",
    )
    .bind(webid)
    .bind(user_id)
    .execute(pool)
    .await?;
    if inserted.rows_affected() > 0 {
        return Ok(Linked::Now);
    }
    // Another account linked it between the read and the write.
    Ok(linked_with(
        user_id,
        webid_link_owner(pool, webid).await?.unwrap_or(user_id),
    ))
}

/// Which account a WebID is linked to, if any. The operator path's good
/// error before a write: minting credentials for an unlinked WebID is
/// refused by the schema too, but by then the message is a constraint's
/// name rather than an instruction.
pub async fn webid_link_owner(pool: &PgPool, webid: &str) -> Result<Option<Uuid>, DbError> {
    Ok(
        sqlx::query_scalar("SELECT user_id FROM solid_webid_links WHERE webid = $1")
            .bind(webid)
            .fetch_optional(pool)
            .await?,
    )
}

fn linked_with(user_id: Uuid, owner: Uuid) -> Linked {
    if owner == user_id {
        Linked::Already
    } else {
        Linked::AnotherAccount
    }
}

/// Unlink a WebID — and, by cascade, retire every credential minted for it:
/// the unlink is this WebID's kill switch, not just a bookkeeping delete.
/// Scoped to the account, so one member cannot unlink another's WebID.
/// Whether a link was removed.
pub async fn unlink_webid(pool: &PgPool, user_id: Uuid, webid: &str) -> Result<bool, DbError> {
    let removed = sqlx::query("DELETE FROM solid_webid_links WHERE webid = $1 AND user_id = $2")
        .bind(webid)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(removed.rows_affected() > 0)
}

/// One linked WebID, as the admin console lists it: whose account it names,
/// how many credential pairs still answer for it, and when one last did.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentLink {
    pub webid: String,
    pub username: String,
    pub linked_at: OffsetDateTime,
    pub credentials: i64,
    pub last_used_at: Option<OffsetDateTime>,
}

/// Every link on the instance, newest first — the console's Agents page.
pub async fn agent_links(pool: &PgPool) -> Result<Vec<AgentLink>, DbError> {
    Ok(sqlx::query_as::<_, AgentLink>(
        "SELECT l.webid, u.username, l.created_at AS linked_at, \
         count(c.credential_id) FILTER (WHERE c.revoked_at IS NULL) AS credentials, \
         max(c.last_used_at) AS last_used_at \
         FROM solid_webid_links l \
         JOIN users u ON u.id = l.user_id \
         LEFT JOIN solid_client_credentials c ON c.webid = l.webid \
         GROUP BY l.webid, u.username, l.created_at \
         ORDER BY l.created_at DESC",
    )
    .fetch_all(pool)
    .await?)
}

/// Every WebID linked to an account.
pub async fn webids_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<String>, DbError> {
    Ok(
        sqlx::query_scalar("SELECT webid FROM solid_webid_links WHERE user_id = $1 ORDER BY webid")
            .bind(user_id)
            .fetch_all(pool)
            .await?,
    )
}

/// Mint a client_credentials id/secret pair naming a linked WebID (RFC 6749
/// §4.4). Returns both; only the hash is stored. The foreign key to the
/// link is the backstop: minting for a WebID nobody linked is refused by
/// the schema, not by a check that can drift.
pub async fn issue_client_credentials(
    pool: &PgPool,
    webid: &str,
) -> Result<(String, String), DbError> {
    let credential_id = generate_secret();
    let secret = generate_secret();
    sqlx::query(
        "INSERT INTO solid_client_credentials (credential_id, secret_hash, webid)
         VALUES ($1, $2, $3)",
    )
    .bind(&credential_id)
    .bind(hash_secret(&secret))
    .bind(webid)
    .execute(pool)
    .await?;
    Ok((credential_id, secret))
}

/// What a verified id/secret pair names: the linked WebID its tokens carry,
/// or `None` when the pair is unknown, the secret is wrong, the credential
/// is revoked, or the WebID's link is gone.
///
/// The id and the hash of the secret are one lookup — the shape
/// [`redeem_code`][super::store::redeem_code] established — so an unknown id
/// and a wrong secret are the same statement to the database and the same
/// answer to the caller: no oracle for which ids exist. The comparison is
/// over hashes (SHA-256 of a 256-bit random secret), never over a stored
/// secret. `last_used_at` rides the same write, so a grant is also the
/// record that the credential was used.
pub async fn client_credentials_webid(
    pool: &PgPool,
    credential_id: &str,
    secret: &str,
) -> Result<Option<String>, DbError> {
    Ok(sqlx::query_scalar(
        "UPDATE solid_client_credentials SET last_used_at = now()
         WHERE credential_id = $1 AND secret_hash = $2 AND revoked_at IS NULL
         RETURNING webid",
    )
    .bind(credential_id)
    .bind(hash_secret(secret))
    .fetch_optional(pool)
    .await?)
}

/// An application a member has authorised, rolled up to one row however
/// many registrations or tokens it holds.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorisedApp {
    /// The application's identity, as the dashboard shows it and revocation
    /// targets it: the client's registered name where it has one, otherwise
    /// its client_id — a document client's URL, or an unnamed registration's
    /// `urn:uuid:`.
    pub key: String,
    /// The client's registered name, if any. `None` means `key` is a
    /// client_id, shown as the row's identifier instead.
    pub client_name: Option<String>,
    /// The distinct scope strings among the application's live tokens.
    pub scope_strings: Vec<String>,
}

impl AuthorisedApp {
    /// Everything the application can still do: the union of its live
    /// tokens' scopes, deduplicated and sorted — so the same scopes granted
    /// in different orders read as one.
    pub fn scopes(&self) -> String {
        let mut all: Vec<&str> = self
            .scope_strings
            .iter()
            .flat_map(|s| s.split_whitespace())
            .collect();
        all.sort_unstable();
        all.dedup();
        all.join(" ")
    }
}

/// The applications a member has granted access to, one row each.
///
/// A grant is "live" when it still has an unexpired, unrevoked refresh
/// token: that is what an app can actually still use, so it is what the
/// member should see.
///
/// One row per *application*, not per client or per token. Rotation means a
/// long-lived grant has issued many tokens, and dynamic registration mints a
/// fresh client_id per registration, so both are folded into the identity
/// the member knows the application by: its registered name, or its
/// client_id when it has none. That a document client has no row in
/// `solid_clients` — its client_id *is* its document (spec 6, H3) — is why
/// the join is a LEFT one: an inner join would leave it invisible, and a
/// grant the member can neither see nor revoke is neither.
pub async fn apps_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<AuthorisedApp>, DbError> {
    Ok(sqlx::query_as::<_, AuthorisedApp>(
        "SELECT COALESCE(c.client_name, r.client_id) AS key,
                MIN(c.client_name) AS client_name,
                array_agg(DISTINCT r.scope) AS scope_strings
           FROM solid_refresh_tokens r
           LEFT JOIN solid_clients c ON c.client_id = r.client_id
          WHERE r.user_id = $1 AND r.revoked_at IS NULL AND r.expires_at > now()
          GROUP BY key
          ORDER BY client_name NULLS LAST, key",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Withdraw an application's access for one member: every live token it
/// holds, across every registration it has made.
///
/// `app` is what [`apps_for_user`] listed — the application's name or, when
/// it has none, its client_id — so the button revokes exactly the row the
/// member saw. Scoped by member too, so revoking an application cannot
/// touch anyone else's grant to it.
///
/// The subquery mirrors the listing's join deliberately: the same expression
/// decides what a row is called, so a row and its revoke button can never
/// disagree about what they name — and an inner join here would leave a
/// document client unrevokable, exactly as it would leave it invisible.
pub async fn revoke_app_for_user(pool: &PgPool, user_id: Uuid, app: &str) -> Result<u64, DbError> {
    let result = sqlx::query(
        "UPDATE solid_refresh_tokens AS r
            SET revoked_at = now()
           FROM (
                SELECT t.token_hash, COALESCE(c.client_name, t.client_id) AS key
                  FROM solid_refresh_tokens t
                  LEFT JOIN solid_clients c ON c.client_id = t.client_id
                 WHERE t.user_id = $1 AND t.revoked_at IS NULL
           ) live
          WHERE r.token_hash = live.token_hash AND live.key = $2",
    )
    .bind(user_id)
    .bind(app)
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
