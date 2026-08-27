//! Provisioning an ATProtocol identity, and the operation log behind it.
//!
//! A member's identity is three things created together: a signing key, a
//! `did:plc` derived from a genesis operation, and a repository whose commits
//! that key signs. Creating any two without the third leaves an account that
//! looks fine and cannot participate.
//!
//! The operation log exists because PLC operations form a **chain** — each
//! names its predecessor by CID, so rotating a key requires knowing the current
//! head. Keeping it locally means recovery does not depend on the directory
//! being reachable at the exact moment something has gone wrong.

use brolly_identity::db::DbError;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::plc::{self, Operation};

/// One entry in a member's PLC chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedOperation {
    pub cid: String,
    pub did: String,
    pub operation: Operation,
    pub prev: Option<String>,
    pub submitted: bool,
}

/// Record an operation we produced.
pub async fn record_operation(
    pool: &PgPool,
    user_id: Option<Uuid>,
    did: &str,
    signed: &Operation,
) -> Result<String, DbError> {
    let cid = plc::operation_cid(signed).map_err(|e| DbError::Hash(e.to_string()))?;
    let json = serde_json::to_value(signed).map_err(|e| DbError::Hash(e.to_string()))?;

    sqlx::query(
        "INSERT INTO atproto_plc_operations (cid, user_id, did, operation, prev)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (cid) DO NOTHING",
    )
    .bind(&cid)
    .bind(user_id)
    .bind(did)
    .bind(&json)
    .bind(signed.prev.as_deref())
    .execute(pool)
    .await?;

    Ok(cid)
}

/// Mark an operation as accepted by the directory.
pub async fn mark_submitted(pool: &PgPool, cid: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE atproto_plc_operations SET submitted_at = now() WHERE cid = $1")
        .bind(cid)
        .execute(pool)
        .await?;
    Ok(())
}

/// A row of the operation log, as it comes off the query.
type OperationRow = (
    String,
    String,
    Value,
    Option<String>,
    Option<time::OffsetDateTime>,
);

/// The head of a member's chain — what the next rotation's `prev` must name.
pub async fn head(pool: &PgPool, user_id: Uuid) -> Result<Option<LoggedOperation>, DbError> {
    let row: Option<OperationRow> = sqlx::query_as(
        "SELECT cid, did, operation, prev, submitted_at FROM atproto_plc_operations
             WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(cid, did, operation, prev, submitted_at)| {
        serde_json::from_value(operation)
            .ok()
            .map(|operation| LoggedOperation {
                cid,
                did,
                operation,
                prev,
                submitted: submitted_at.is_some(),
            })
    }))
}

/// Operations the directory has not accepted yet.
///
/// The retry queue, and the answer to "which members are not resolvable". A
/// state that is invisible cannot be repaired.
pub async fn unsubmitted(pool: &PgPool) -> Result<Vec<LoggedOperation>, DbError> {
    let rows: Vec<(String, String, Value, Option<String>)> = sqlx::query_as(
        "SELECT cid, did, operation, prev FROM atproto_plc_operations
         WHERE submitted_at IS NULL ORDER BY created_at",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(cid, did, operation, prev)| {
            serde_json::from_value(operation)
                .ok()
                .map(|operation| LoggedOperation {
                    cid,
                    did,
                    operation,
                    prev,
                    submitted: false,
                })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    #[test]
    fn a_logged_operation_keeps_the_bytes_that_made_its_cid() {
        // Re-deriving the operation instead of storing it verbatim would
        // re-derive the CID too, and any drift there breaks the chain
        // silently — `prev` would name something nobody can find.
        let (signed, _) = plc::create(
            &SigningKey::generate(),
            &SigningKey::generate(),
            "alice.brolly.test",
            "https://brolly.test",
        )
        .unwrap();

        let json = serde_json::to_value(&signed).unwrap();
        let restored: Operation = serde_json::from_value(json).unwrap();
        assert_eq!(restored, signed);
        assert_eq!(
            plc::operation_cid(&restored).unwrap(),
            plc::operation_cid(&signed).unwrap()
        );
    }
}
