//! Persistence for identity: users, sessions, invites, keys.
//!
//! Postgres holds **operational state only** (D2). No user content, no
//! display names, no bios — those live in pods and are projected. See
//! `migrations/README.md`.

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use sqlx::PgPool;
use uuid::Uuid;

pub const MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../migrations");

#[derive(Debug)]
pub enum DbError {
    Sql(sqlx::Error),
    Hash(String),
    /// The credential did not match. Deliberately one variant for "no such
    /// user" and "wrong password" so callers cannot leak which.
    BadCredentials,
    UsernameTaken,
    InviteInvalid,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Sql(e) => write!(f, "database: {e}"),
            DbError::Hash(e) => write!(f, "password hashing: {e}"),
            DbError::BadCredentials => write!(f, "invalid credentials"),
            DbError::UsernameTaken => write!(f, "username taken"),
            DbError::InviteInvalid => write!(f, "invite is invalid, expired, or used up"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<sqlx::Error> for DbError {
    fn from(e: sqlx::Error) -> Self {
        DbError::Sql(e)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub did_plc: Option<String>,
    pub role: String,
    pub status: String,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

fn hash_password(password: &str) -> Result<String, DbError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| DbError::Hash(e.to_string()))
}

fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Hash a bearer-style secret (session token, invite code) for storage.
///
/// SHA-256 rather than Argon2 on purpose: these are high-entropy random values,
/// not user-chosen passwords, so there is nothing to brute-force and the lookup
/// must be a fast indexed equality check.
pub fn hash_secret(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Generate a URL-safe random secret.
pub fn generate_secret() -> String {
    // rand 0.10: the free function fills from the thread RNG.
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

// --- users -----------------------------------------------------------------

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    email: Option<&str>,
    password: &str,
    role: &str,
) -> Result<User, DbError> {
    let hash = hash_password(password)?;
    let id = Uuid::new_v4();

    sqlx::query_as::<_, User>(
        "INSERT INTO users (id, username, email, password_hash, role)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, username, email, email_verified, did_plc, role, status",
    )
    .bind(id)
    .bind(username)
    .bind(email)
    .bind(&hash)
    .bind(role)
    .fetch_one(pool)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => DbError::UsernameTaken,
        _ => DbError::Sql(e),
    })
}

pub async fn find_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, DbError> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, did_plc, role, status
         FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?)
}

/// Verify a username/password pair.
///
/// Returns [`DbError::BadCredentials`] for an unknown user, a wrong password,
/// and a disabled account alike — the caller must not be able to enumerate
/// accounts from the error.
pub async fn authenticate(pool: &PgPool, username: &str, password: &str) -> Result<User, DbError> {
    let row: Option<(String, String, String)> =
        sqlx::query_as("SELECT password_hash, status, id::text FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(pool)
            .await?;

    let Some((hash, status, _)) = row else {
        // Hash anyway so a missing user and a wrong password take similar time.
        let _ = verify_password(
            password,
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$0000000000000000000000000000000000000000000",
        );
        return Err(DbError::BadCredentials);
    };

    if !verify_password(password, &hash) || status != "active" {
        return Err(DbError::BadCredentials);
    }

    find_by_username(pool, username)
        .await?
        .ok_or(DbError::BadCredentials)
}

/// Record the user's `did:plc` once PLC registration succeeds (D11).
pub async fn set_did_plc(pool: &PgPool, user_id: Uuid, did: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE users SET did_plc = $1 WHERE id = $2")
        .bind(did)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// --- sessions --------------------------------------------------------------

/// Create a session, returning the plaintext token. Only its hash is stored.
pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    ttl: time::Duration,
    user_agent: Option<&str>,
) -> Result<String, DbError> {
    let token = generate_secret();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, user_agent)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(hash_secret(&token))
    .bind(time::OffsetDateTime::now_utc() + ttl)
    .bind(user_agent)
    .execute(pool)
    .await?;
    Ok(token)
}

/// Resolve a session token to its user, if the session is live.
pub async fn user_for_session(pool: &PgPool, token: &str) -> Result<Option<User>, DbError> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT u.id, u.username, u.email, u.email_verified, u.did_plc, u.role, u.status
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now() AND u.status = 'active'",
    )
    .bind(hash_secret(token))
    .fetch_optional(pool)
    .await?)
}

pub async fn revoke_session(pool: &PgPool, token: &str) -> Result<(), DbError> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(hash_secret(token))
        .execute(pool)
        .await?;
    Ok(())
}

// --- invites ---------------------------------------------------------------

/// Mint an invite, returning the plaintext code.
pub async fn create_invite(
    pool: &PgPool,
    created_by: Option<Uuid>,
    max_uses: i32,
    expires_in: Option<time::Duration>,
) -> Result<String, DbError> {
    let code = generate_secret();
    sqlx::query(
        "INSERT INTO invites (code_hash, created_by, max_uses, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(hash_secret(&code))
    .bind(created_by)
    .bind(max_uses)
    .bind(expires_in.map(|d| time::OffsetDateTime::now_utc() + d))
    .execute(pool)
    .await?;
    Ok(code)
}

/// Consume one use of an invite.
///
/// The check and the increment are a single statement, so two simultaneous
/// registrations cannot both claim the last use of a one-use invite.
pub async fn redeem_invite(pool: &PgPool, code: &str) -> Result<(), DbError> {
    let updated = sqlx::query(
        "UPDATE invites SET uses = uses + 1
         WHERE code_hash = $1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > now())
           AND uses < max_uses",
    )
    .bind(hash_secret(code))
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(DbError::InviteInvalid);
    }
    Ok(())
}

pub async fn revoke_invite(pool: &PgPool, code: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE invites SET revoked_at = now() WHERE code_hash = $1")
        .bind(hash_secret(code))
        .execute(pool)
        .await?;
    Ok(())
}

// --- keys ------------------------------------------------------------------

pub async fn store_key(
    pool: &PgPool,
    user_id: Uuid,
    purpose: &str,
    private_key: &[u8],
    public_key: &[u8],
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO user_keys (user_id, purpose, private_key, public_key)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, purpose) DO UPDATE
           SET private_key = EXCLUDED.private_key,
               public_key  = EXCLUDED.public_key",
    )
    .bind(user_id)
    .bind(purpose)
    .bind(private_key)
    .bind(public_key)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn load_key(
    pool: &PgPool,
    user_id: Uuid,
    purpose: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, DbError> {
    Ok(sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT private_key, public_key FROM user_keys WHERE user_id = $1 AND purpose = $2",
    )
    .bind(user_id)
    .bind(purpose)
    .fetch_optional(pool)
    .await?)
}
