//! Where a member's repo currently points.
//!
//! One row: the root CID and a revision. The blocks are on disk and
//! content-addressed; this is the pointer to the newest commit, which is the
//! only piece atrium leaves to us.
//!
//! Operational rather than content, and it has to stay that way: losing this
//! table must cost a rebuild from the block set, not data. Putting a record
//! body here would quietly make Postgres a second source of truth, which is the
//! thing D2 and ADR 0005 exist to prevent.
//!
//! The revision is the commit's own — a TID, stored in the same 13-character
//! form every consumer compares and echoes, never a counter this table invents
//! beside the signed commits (1, A). And the pointer moves only by
//! compare-and-set: a write names the root it read, and a head that moved first
//! is refused rather than overwritten (1, C).

use atrium_api::types::string::Tid;
use brolly_identity::db::DbError;
use sqlx::PgPool;
use uuid::Uuid;

/// A repo's current position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    pub root_cid: String,
    pub rev: Tid,
}

/// Why an advance failed.
///
/// A conflict is a protocol outcome — the head moved first — not a database
/// fault, and it is a distinct error so the write handlers can answer it as
/// one (1, C).
#[derive(Debug)]
pub enum AdvanceError {
    /// Zero rows matched: the root was not where the writer left it, or the
    /// new rev does not clear the stored one. Another write landed first.
    /// The plain writes retry the whole write (chunk 2); the swap writes
    /// answer the lexicon's `InvalidSwap` (chunk 2).
    Conflict,
    Db(DbError),
}

impl std::fmt::Display for AdvanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdvanceError::Conflict => write!(
                f,
                "the head moved first: the root or the rev did not match the write's"
            ),
            AdvanceError::Db(e) => write!(f, "database: {e}"),
        }
    }
}

impl std::error::Error for AdvanceError {}

impl From<sqlx::Error> for AdvanceError {
    fn from(e: sqlx::Error) -> Self {
        AdvanceError::Db(DbError::Sql(e))
    }
}

/// A stored rev, parsed.
///
/// The column only ever holds revs written from `Tid`s, so a row that does not
/// parse is corruption — reported as a decode fault rather than guessed around.
fn parse_rev(text: String) -> Result<Tid, DbError> {
    Tid::new(text).map_err(|e| {
        DbError::Sql(sqlx::Error::Decode(
            format!("a stored rev is not a TID: {e}").into(),
        ))
    })
}

/// Record a newly created repo, at its genesis commit's own rev (1, A).
///
/// Fails if one already exists, rather than overwriting — a second genesis
/// commit would orphan every existing block.
pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    root_cid: &str,
    rev: &Tid,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO atproto_repos (user_id, root_cid, rev) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(root_cid)
        .bind(rev.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load(pool: &PgPool, user_id: Uuid) -> Result<Option<RepoState>, DbError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT root_cid, rev FROM atproto_repos WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;

    row.map(|(root_cid, rev)| {
        Ok(RepoState {
            root_cid,
            rev: parse_rev(rev)?,
        })
    })
    .transpose()
}

/// Advance the repo to a new commit, compare-and-set on the head (1, C).
///
/// Both the root and the rev must line up: the root from where the writer read
/// it — a second writer's commit moved it, otherwise — and the rev strictly
/// greater, which is the monotonicity guard. Monotonicity lives here rather
/// than at the mint because this is the one place every write passes through,
/// and a mint-time check cannot survive clock skew or a restart (1, A).
///
/// Zero rows is a conflict, not a database failure: the write raced another
/// write and lost, and the caller decides what that means — a retry for the
/// plain writes, a refusal for the swaps.
pub async fn advance(
    pool: &PgPool,
    user_id: Uuid,
    expected_root: &str,
    new_root: &str,
    new_rev: &Tid,
) -> Result<Tid, AdvanceError> {
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE atproto_repos
            SET root_cid = $3, rev = $4, updated_at = now()
          WHERE user_id = $1 AND root_cid = $2 AND rev < $4
        RETURNING rev",
    )
    .bind(user_id)
    .bind(expected_root)
    .bind(new_root)
    .bind(new_rev.as_str())
    .fetch_optional(pool)
    .await?;

    match row {
        // The rev as the row now holds it: the commit's own, read back from
        // the head the CAS just moved.
        Some((rev,)) => parse_rev(rev).map_err(AdvanceError::Db),
        None => Err(AdvanceError::Conflict),
    }
}
