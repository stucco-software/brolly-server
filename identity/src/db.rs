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
    /// The email already belongs to an account. Unique because `createSession`
    /// accepts an email as an identifier; its own variant because the member
    /// retyping a free username must not be told the username is the problem.
    EmailTaken,
    InviteInvalid,
    /// An app password of that name already exists for the member (stage 2,
    /// B). A variant of its own, like `UsernameTaken`, because the caller
    /// answers it on its wire rather than logging it.
    AppPasswordNameTaken,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Sql(e) => write!(f, "database: {e}"),
            DbError::Hash(e) => write!(f, "password hashing: {e}"),
            DbError::BadCredentials => write!(f, "invalid credentials"),
            DbError::UsernameTaken => write!(f, "username taken"),
            DbError::EmailTaken => write!(f, "email taken"),
            DbError::InviteInvalid => write!(f, "invite is invalid, expired, or used up"),
            DbError::AppPasswordNameTaken => {
                write!(f, "an app password with that name already exists")
            }
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
        // Two unique columns, two answers: the constraint names which.
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            if db.constraint() == Some("users_email_key") {
                DbError::EmailTaken
            } else {
                DbError::UsernameTaken
            }
        }
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

/// Look a member up by their primary key.
///
/// This is the second half of resolving a Mastodon status or account id
/// (ADR 0015): the id decodes to a UUID, and this turns it into the member —
/// which is what lets that whole scheme work with no routing table and no
/// index.
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, DbError> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, did_plc, role, status
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

/// The hash a login for a missing member is verified against, so a login for
/// nobody and a wrong password for somebody cost the same one Argon2 run.
/// (`authenticate`'s pattern; the legacy session surface shares it — stage 2, A.)
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$0000000000000000000000000000000000000000000";

/// Cost one Argon2 verification and answer nothing, for a login whose
/// identifier resolved to nobody (stage 2, A).
pub fn dummy_verify(password: &str) {
    let _ = verify_password(password, DUMMY_HASH);
}

/// Find a member by email — the last identifier form `createSession` accepts
/// (stage 2, A), after the DID forms and the handle.
pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, DbError> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, did_plc, role, status
         FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?)
}

/// Verify a member's primary password (stage 2, A).
///
/// `Ok(None)`: no such member — the caller that cares burns a
/// [`dummy_verify`] first. `Ok(false)`: wrong password. The account's status
/// is deliberately not consulted here: the caller decides what a disabled
/// account's *valid* credentials answer, which is a different question from
/// what bad credentials answer.
pub async fn verify_primary_password(
    pool: &PgPool,
    user_id: Uuid,
    password: &str,
) -> Result<Option<bool>, DbError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(hash,)| verify_password(password, &hash)))
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
        dummy_verify(password);
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
/// Mint an invite code.
///
/// `grants_role` is the role the redeemer receives. `None` means the default,
/// which is what an ordinary invite does; `Some("admin")` is how an instance is
/// handed to someone who should not also be handed the database password.
pub async fn create_invite(
    pool: &PgPool,
    created_by: Option<Uuid>,
    max_uses: i32,
    expires_in: Option<time::Duration>,
    grants_role: Option<&str>,
) -> Result<String, DbError> {
    let code = generate_secret();
    sqlx::query(
        "INSERT INTO invites (code_hash, created_by, max_uses, expires_at, grants_role)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(hash_secret(&code))
    .bind(created_by)
    .bind(max_uses)
    .bind(expires_in.map(|d| time::OffsetDateTime::now_utc() + d))
    .bind(grants_role)
    .execute(pool)
    .await?;
    Ok(code)
}

/// Consume one use of an invite.
///
/// The check and the increment are a single statement, so two simultaneous
/// registrations cannot both claim the last use of a one-use invite.
/// Consume one use of an invite, returning the role it grants.
///
/// The check and the increment are a single statement, so two simultaneous
/// registrations cannot both claim the last use of a one-use invite. The
/// granted role comes back from the same statement for the same reason: reading
/// it separately would let a revoke land in between and grant a role from an
/// invite that no longer exists.
pub async fn redeem_invite(pool: &PgPool, code: &str) -> Result<Option<String>, DbError> {
    let granted: Option<(Option<String>,)> = sqlx::query_as(
        "UPDATE invites SET uses = uses + 1
         WHERE code_hash = $1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > now())
           AND uses < max_uses
         RETURNING grants_role",
    )
    .bind(hash_secret(code))
    .fetch_optional(pool)
    .await?;

    match granted {
        Some((role,)) => Ok(role),
        None => Err(DbError::InviteInvalid),
    }
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

// --- account management ----------------------------------------------------

/// Change a password, verifying the current one first.
///
/// Verification happens here rather than in the handler so there is no way to
/// reach the update without it.
pub async fn change_password(
    pool: &PgPool,
    user_id: Uuid,
    current: &str,
    new: &str,
) -> Result<(), DbError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    let Some((hash,)) = row else {
        return Err(DbError::BadCredentials);
    };
    if !verify_password(current, &hash) {
        return Err(DbError::BadCredentials);
    }

    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user_id)
        .bind(hash_password(new)?)
        .execute(pool)
        .await?;
    Ok(())
}

/// How many sessions are currently live for a user.
pub async fn count_sessions(pool: &PgPool, user_id: Uuid) -> Result<i64, DbError> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM sessions WHERE user_id = $1 AND expires_at > now()")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// End every session except the one making the request.
///
/// Someone changing their password is often doing it because they believe
/// another session is not theirs, so the change has to end those sessions —
/// but not the one they are using, or they are logged out mid-task.
pub async fn revoke_other_sessions(
    pool: &PgPool,
    user_id: Uuid,
    keep_token: &str,
) -> Result<u64, DbError> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(user_id)
        .bind(hash_secret(keep_token))
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Delete a user outright.
///
/// Sessions, invites, keys and OAuth grants cascade. The pod is a separate
/// `rm -rf` the caller performs — content lives in exactly one place (D2), and
/// it is not this one.
/// How many accounts exist at all.
///
/// The bootstrap depends on this: an instance with none has nobody who could
/// have granted the first role, so the first one has to come from somewhere
/// else (see `brolly_server::admin::bootstrap`).
pub async fn count_users(pool: &PgPool) -> Result<i64, DbError> {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// How many *active* admins there are.
///
/// Disabled accounts do not count, because a disabled admin cannot log in to
/// undo anything — treating them as cover would let the last usable admin be
/// demoted.
pub async fn count_admins(pool: &PgPool) -> Result<i64, DbError> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM users WHERE role = 'admin' AND status = 'active'")
            .fetch_one(pool)
            .await?;
    Ok(n)
}

/// Set a member's role.
///
/// Deliberately not "promote"/"demote": the caller decides, and the guard
/// against removing the last admin lives with the caller that can explain it
/// to a human, not down here.
pub async fn set_role(pool: &PgPool, user_id: Uuid, role: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await?;
    Ok(())
}

/// One row of the admin user list (ADR 0005, R5).
///
/// Postgres answers this alone. `display_name` is deliberately absent: it lives
/// in each member's pod, and opening one store per row to render a table is the
/// exact mistake ADR 0005 exists to prevent. It arrives with the actor index.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub status: String,
    pub did_plc: Option<String>,
    pub created_at: time::OffsetDateTime,
}

/// Every account, newest first.
///
/// Unpaginated, and that is a decision with a shelf life: it is correct for the
/// instance sizes this serves today and wrong for a large one. The list is
/// pointers only, so the fix is a LIMIT and a cursor rather than a new store.
pub async fn list_users(pool: &PgPool) -> Result<Vec<UserRow>, DbError> {
    Ok(sqlx::query_as::<_, UserRow>(
        "SELECT id, username, role, status, did_plc, created_at
         FROM users ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn delete_user(pool: &PgPool, user_id: Uuid) -> Result<(), DbError> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}
