//! The instance's own identity (D4).
//!
//! The instance is an agent: it has a WebID, a DID, a keypair and a store, and
//! it appears in federation as an actor like any member. That is what gives the
//! shared inbox something behind it, and what lets the server-agent index be
//! populated by delivery rather than by crawling — the instance actor is simply
//! another recipient.
//!
//! **This module stores keys; it does not make them.** Key generation is the
//! ActivityPub adapter's business, because the algorithm is a protocol decision
//! (RSA, for cavage-09) rather than an identity one. Callers pass a generator
//! and it runs only when there is nothing to load.

use sqlx::PgPool;
use uuid::Uuid;

use crate::db::DbError;

/// Purpose tag for an ActivityPub signing key in `user_keys`.
pub const ACTIVITYPUB_RSA: &str = "activitypub_rsa";

/// A signing identity: the PEM pair that signs and verifies HTTP signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorKeys {
    pub private_key_pem: String,
    pub public_key_pem: String,
    /// Present on the instance actor once PLC registration has happened.
    pub did_plc: Option<String>,
}

/// A freshly generated PEM keypair: `(private, public)`.
pub type GeneratedKeys = Result<(String, String), DbError>;

/// Load the instance actor, creating it on first start.
///
/// `generate` runs only when the row is absent. Regenerating on every boot
/// would change the public key in the actor document while remote instances
/// still cache the old one, and every signature we sent would start failing
/// verification at once — silently, because a signature failure looks like a
/// delivery failure.
pub async fn load_or_create<F>(pool: &PgPool, generate: F) -> Result<ActorKeys, DbError>
where
    F: FnOnce() -> GeneratedKeys,
{
    if let Some(existing) = load(pool).await? {
        return Ok(existing);
    }

    let (private_key_pem, public_key_pem) = generate()?;
    // ON CONFLICT DO NOTHING, then read back: two processes starting together
    // must converge on one keypair rather than one of them winning and the
    // other returning a key that was never stored.
    sqlx::query(
        "INSERT INTO instance_actor (private_key_pem, public_key_pem)
         VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&private_key_pem)
    .bind(&public_key_pem)
    .execute(pool)
    .await?;

    load(pool)
        .await?
        // Selected and got nothing back, which is exactly what RowNotFound
        // means. A dedicated variant would exist only for this line.
        .ok_or(DbError::Sql(sqlx::Error::RowNotFound))
}

async fn load(pool: &PgPool) -> Result<Option<ActorKeys>, DbError> {
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT private_key_pem, public_key_pem, did_plc FROM instance_actor WHERE id",
    )
    .fetch_optional(pool)
    .await?;

    Ok(
        row.map(|(private_key_pem, public_key_pem, did_plc)| ActorKeys {
            private_key_pem,
            public_key_pem,
            did_plc,
        }),
    )
}

/// Record the instance's `did:plc` once PLC registration has happened.
pub async fn set_did(pool: &PgPool, did: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE instance_actor SET did_plc = $1 WHERE id")
        .bind(did)
        .execute(pool)
        .await?;
    Ok(())
}

/// Load a user's ActivityPub keypair, creating it on first use.
///
/// Same property as the instance's, for the same reason: a member's public key
/// is published in their actor document and cached by every instance that has
/// seen them.
pub async fn load_or_create_actor_keys<F>(
    pool: &PgPool,
    user_id: Uuid,
    generate: F,
) -> Result<ActorKeys, DbError>
where
    F: FnOnce() -> GeneratedKeys,
{
    if let Some(keys) = crate::db::load_key(pool, user_id, ACTIVITYPUB_RSA).await? {
        return Ok(pem_keys(keys));
    }

    let (private_key_pem, public_key_pem) = generate()?;
    crate::db::store_key(
        pool,
        user_id,
        ACTIVITYPUB_RSA,
        private_key_pem.as_bytes(),
        public_key_pem.as_bytes(),
    )
    .await?;

    crate::db::load_key(pool, user_id, ACTIVITYPUB_RSA)
        .await?
        .map(pem_keys)
        .ok_or(DbError::Sql(sqlx::Error::RowNotFound))
}

/// `user_keys` is `BYTEA`, because ATProtocol's keys genuinely are bytes.
/// ActivityPub's are PEM, which is text that happens to be stored there too.
fn pem_keys((private, public): (Vec<u8>, Vec<u8>)) -> ActorKeys {
    ActorKeys {
        private_key_pem: String::from_utf8_lossy(&private).into_owned(),
        public_key_pem: String::from_utf8_lossy(&public).into_owned(),
        did_plc: None,
    }
}
