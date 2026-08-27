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

use brolly_identity::db::DbError;
use sqlx::PgPool;
use uuid::Uuid;

/// A repo's current position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    pub root_cid: String,
    pub rev: i64,
}

/// Record a newly created repo. Fails if one already exists, rather than
/// overwriting — a second genesis commit would orphan every existing block.
pub async fn create(pool: &PgPool, user_id: Uuid, root_cid: &str) -> Result<(), DbError> {
    sqlx::query("INSERT INTO atproto_repos (user_id, root_cid, rev) VALUES ($1, $2, 0)")
        .bind(user_id)
        .bind(root_cid)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load(pool: &PgPool, user_id: Uuid) -> Result<Option<RepoState>, DbError> {
    Ok(sqlx::query_as::<_, (String, i64)>(
        "SELECT root_cid, rev FROM atproto_repos WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .map(|(root_cid, rev)| RepoState { root_cid, rev }))
}

/// Advance the repo to a new commit.
///
/// The revision increments in the same statement that moves the root, so a
/// reader can never observe a new root at an old revision — which is what a
/// sync consumer uses to decide whether it is behind.
pub async fn advance(pool: &PgPool, user_id: Uuid, root_cid: &str) -> Result<i64, DbError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE atproto_repos SET root_cid = $2, rev = rev + 1, updated_at = now()
         WHERE user_id = $1 RETURNING rev",
    )
    .bind(user_id)
    .bind(root_cid)
    .fetch_optional(pool)
    .await?;

    row.map(|(rev,)| rev)
        .ok_or(DbError::Sql(sqlx::Error::RowNotFound))
}
