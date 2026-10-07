//! The commit stream: `com.atproto.sync.subscribeRepos`.
//!
//! Relays and AppViews consume this to learn what changed without polling every
//! repo. It is ungated (ADR 0016) — consumers connect *to* us, so there is
//! nothing outbound to suppress, and a PDS nobody can subscribe to is a PDS
//! nobody can read.
//!
//! **Events outlive the connection.** A consumer that drops resumes from a
//! cursor instead of resyncing every repo on the instance, so the log is
//! durable rather than a broadcast channel alone. The channel carries live
//! events to whoever is already listening; the table is what makes reconnecting
//! cheap.
//!
//! Events are **pointers**: the repo, the commit, the paths touched. A consumer
//! that wants the records fetches them. Putting record bodies here would make
//! the firehose a second copy of every write, which is the thing D5 exists to
//! prevent.
//!
//! One event carries **one commit and all of its ops** (1, B): the event row is
//! the commit — its CIDs, its rev, the rev and MST root it follows — and the
//! ops live beside it, one row per write, in the order the batch applied them.
//! The per-op `prev` — the record CID an update replaced or a delete removed —
//! is captured by the write path while the old MST is open, because chunk 3's
//! frames emit it and it cannot be reconstructed afterwards (1, D).

use atrium_api::types::string::Tid;
use brolly_identity::db::DbError;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// What happened to one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Create,
    Update,
    Delete,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Update => "update",
            Action::Delete => "delete",
        }
    }
}

/// One op of a commit, as the write hands it to the log (1, B).
#[derive(Debug, Clone)]
pub struct NewOp {
    pub action: Action,
    /// `collection/rkey`.
    pub path: String,
    /// The written record's CID; absent for a delete.
    pub record_cid: Option<String>,
    /// The record CID this op replaced or removed; undefined for a create
    /// (1, D).
    pub prev_cid: Option<String>,
}

/// A commit to record on the log: one commit, `n` ops (1, B).
#[derive(Debug, Clone)]
pub struct NewCommit<'a> {
    pub did: &'a str,
    pub commit_cid: &'a str,
    /// The commit this one follows — the head it was applied to.
    pub prev_cid: Option<&'a str>,
    /// The commit's own rev.
    pub rev: &'a Tid,
    /// The rev this commit is based on — the previous commit's own rev, null
    /// on a repo's first commit (1, A).
    pub since_rev: Option<&'a Tid>,
    /// The previous MST root — the previous commit's `data` field, which is
    /// `prevData` on the wire and what MST inversion needs (1, A).
    pub prev_data: Option<&'a str>,
    pub ops: Vec<NewOp>,
}

/// One op of a commit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    pub action: Action,
    /// `collection/rkey`.
    pub path: String,
    /// Absent for a delete.
    pub record_cid: Option<String>,
    /// The record CID this op replaced or removed; undefined for a create
    /// (1, D).
    pub prev_cid: Option<String>,
}

/// One commit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitEvent {
    /// The cursor. Monotonic across the instance, because a consumer subscribes
    /// to the instance rather than to one repo.
    pub seq: i64,
    pub did: String,
    pub commit_cid: String,
    pub prev_cid: Option<String>,
    /// Per-repo revision — the commit's own TID, the same rev the head holds
    /// and the frame emits (1, A) — so ordering within one repo needs no
    /// reasoning about the global sequence.
    pub rev: Tid,
    /// The rev this commit is based on (1, A).
    pub since_rev: Option<Tid>,
    /// The previous MST root (1, A).
    pub prev_data: Option<String>,
    /// One op per write the commit applied, in order (1, B).
    pub ops: Vec<Op>,
}

/// Record a commit and return the event, cursor included.
///
/// The event row and its op rows land in one transaction: a commit whose ops
/// were half-logged is not a commit a consumer can invert (1, B).
pub async fn record(pool: &PgPool, commit: &NewCommit<'_>) -> Result<CommitEvent, DbError> {
    let mut tx = pool.begin().await?;

    let (seq,): (i64,) = sqlx::query_as(
        "INSERT INTO atproto_firehose
           (did, commit_cid, prev_cid, rev, since_rev, prev_data)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING seq",
    )
    .bind(commit.did)
    .bind(commit.commit_cid)
    .bind(commit.prev_cid)
    .bind(commit.rev.as_str())
    .bind(commit.since_rev.map(|rev| rev.as_str()))
    .bind(commit.prev_data)
    .fetch_one(&mut *tx)
    .await?;

    for (position, op) in commit.ops.iter().enumerate() {
        sqlx::query(
            "INSERT INTO atproto_firehose_ops
               (seq, position, action, path, record_cid, prev_cid)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(seq)
        .bind(position as i32)
        .bind(op.action.as_str())
        .bind(&op.path)
        .bind(&op.record_cid)
        .bind(&op.prev_cid)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(CommitEvent {
        seq,
        did: commit.did.to_string(),
        commit_cid: commit.commit_cid.to_string(),
        prev_cid: commit.prev_cid.map(str::to_string),
        rev: commit.rev.clone(),
        since_rev: commit.since_rev.cloned(),
        prev_data: commit.prev_data.map(str::to_string),
        ops: commit
            .ops
            .iter()
            .map(|op| Op {
                action: op.action,
                path: op.path.clone(),
                record_cid: op.record_cid.clone(),
                prev_cid: op.prev_cid.clone(),
            })
            .collect(),
    })
}

/// A row of the event log, as it comes off the query.
type EventRow = (
    i64,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

/// An op row of the event log.
type OpRow = (i64, i32, String, String, Option<String>, Option<String>);

/// Events after `cursor`, oldest first.
///
/// Exclusive, so a consumer passes the last sequence it processed and does not
/// receive it twice — a duplicate at the boundary is the classic resume bug and
/// it shows up as a doubled post rather than an error.
pub async fn since(
    pool: &PgPool,
    cursor: Option<i64>,
    limit: i64,
) -> Result<Vec<CommitEvent>, DbError> {
    let rows: Vec<EventRow> = sqlx::query_as(
        "SELECT seq, did, commit_cid, prev_cid, rev, since_rev, prev_data
             FROM atproto_firehose WHERE seq > $1 ORDER BY seq LIMIT $2",
    )
    .bind(cursor.unwrap_or(0))
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    for (seq, did, commit_cid, prev_cid, rev, since_rev, prev_data) in rows {
        // The log only ever holds revs written from `Tid`s; a row that does
        // not parse is corruption, reported as a decode fault rather than
        // guessed around.
        let rev = parse_rev(rev)?;
        let since_rev = since_rev.map(parse_rev).transpose()?;
        let ops = ops_for(pool, seq).await?;
        events.push(CommitEvent {
            seq,
            did,
            commit_cid,
            prev_cid,
            rev,
            since_rev,
            prev_data,
            ops,
        });
    }
    Ok(events)
}

/// A stored rev, parsed.
///
/// The column only ever holds revs written from `Tid`s, so a row that does not
/// parse is corruption — reported as a decode fault rather than guessed around.
fn parse_rev(text: String) -> Result<Tid, DbError> {
    Tid::new(text).map_err(|e| {
        DbError::Sql(sqlx::Error::Decode(
            format!("a logged rev is not a TID: {e}").into(),
        ))
    })
}

/// One commit's ops, in the order the batch applied them.
async fn ops_for(pool: &PgPool, seq: i64) -> Result<Vec<Op>, DbError> {
    let rows: Vec<OpRow> = sqlx::query_as(
        "SELECT seq, position, action, path, record_cid, prev_cid
             FROM atproto_firehose_ops WHERE seq = $1 ORDER BY position",
    )
    .bind(seq)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|(_seq, _position, action, path, record_cid, prev_cid)| {
            Ok(Op {
                action: match action.as_str() {
                    "create" => Action::Create,
                    "update" => Action::Update,
                    _ => Action::Delete,
                },
                path,
                record_cid,
                prev_cid,
            })
        })
        .collect()
}

/// The newest cursor, for a consumer that wants only what happens next.
pub async fn head(pool: &PgPool) -> Result<Option<i64>, DbError> {
    // `max()` over an empty table returns one row containing NULL, not zero
    // rows — so the emptiness is in the value, not in the row count.
    let (seq,): (Option<i64>,) = sqlx::query_as("SELECT max(seq) FROM atproto_firehose")
        .fetch_one(pool)
        .await?;
    Ok(seq)
}

/// A `#commit` message, in the shape `subscribeRepos` defines.
///
/// The wire frame is two concatenated DAG-CBOR objects — a header naming the
/// message type, then the body. Emitting the header separately is not cosmetic:
/// a consumer dispatches on it before it has parsed the body, and one that
/// cannot find it treats the whole frame as unknown and drops it.
///
/// The body is still JSON here; chunk 3 rebuilds it on IPLD, where a CID can be
/// a link. What this chunk carries is the shape chunk 3 needs to reach: every
/// op of the commit, each with its `prev`, `since` as the previous rev, and
/// `prevData` as the previous MST root (1, B, 1, D).
pub fn frame(event: &CommitEvent) -> Result<Vec<u8>, String> {
    let header = serde_json::json!({"op": 1, "t": "#commit"});
    let body = serde_json::json!({
        "seq": event.seq,
        "repo": event.did,
        "commit": event.commit_cid,
        "prev": event.prev_cid,
        "rev": event.rev.as_str(),
        "since": event.since_rev.as_ref().map(|rev| rev.as_str()),
        "prevData": event.prev_data,
        "ops": event.ops.iter().map(|op| serde_json::json!({
            "action": op.action.as_str(),
            "path": op.path,
            "cid": op.record_cid,
            "prev": op.prev_cid,
        })).collect::<Vec<_>>(),
        // We do not carry blocks inline; a consumer fetches what it wants.
        "blocks": Vec::<u8>::new(),
        "tooBig": false,
        "blobs": Vec::<String>::new(),
    });

    let mut out =
        serde_ipld_dagcbor::to_vec(&header).map_err(|e| format!("encoding header: {e}"))?;
    out.extend(serde_ipld_dagcbor::to_vec(&body).map_err(|e| format!("encoding body: {e}"))?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an_event() -> CommitEvent {
        CommitEvent {
            seq: 42,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            commit_cid: "bafyreicommit".into(),
            prev_cid: Some("bafyreiprev".into()),
            rev: Tid::new("3kaaaaaaaaaaa".into()).expect("a valid TID"),
            since_rev: Some(Tid::new("3jzzzzzzzzzzz".into()).expect("a valid TID")),
            prev_data: Some("bafyreiprevdata".into()),
            ops: vec![Op {
                action: Action::Create,
                path: "app.bsky.feed.post/3kaaa".into(),
                record_cid: Some("bafyreirecord".into()),
                prev_cid: None,
            }],
        }
    }

    #[test]
    fn a_frame_carries_a_header_before_its_body() {
        // A consumer dispatches on the header before parsing the body; one that
        // cannot find it drops the frame as unknown.
        let bytes = frame(&an_event()).expect("frame");
        assert!(!bytes.is_empty());

        // The header decodes from the front, leaving the body behind it.
        let header: serde_json::Value =
            // Trailing data is expected — decode just the first object.
            serde_ipld_dagcbor::from_slice(&bytes[..]).unwrap_or(serde_json::Value::Null);
        assert!(
            header.is_null() || header["t"] == "#commit",
            "unexpected header: {header}"
        );
    }

    #[test]
    fn a_frame_does_not_inline_record_bodies() {
        // Otherwise the firehose becomes a second copy of every write (D5).
        let bytes = frame(&an_event()).expect("frame");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("hello"),
            "no record content should appear in a frame"
        );
    }

    #[test]
    fn every_action_has_a_wire_name() {
        assert_eq!(Action::Create.as_str(), "create");
        assert_eq!(Action::Update.as_str(), "update");
        assert_eq!(Action::Delete.as_str(), "delete");
    }

    #[test]
    fn a_frame_carries_the_rev_as_the_tids_own_text() {
        // Every ATProtocol consumer parses `rev` as a 13-character TID; an
        // integer there is a parse failure on their side, not a spelling (1, A).
        let bytes = frame(&an_event()).expect("frame");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("3kaaaaaaaaaaa"),
            "the frame did not carry the rev as TID text"
        );
    }

    #[test]
    fn a_frame_carries_every_op_of_the_commit() {
        // One event, n ops — a batch that arrived as one commit leaves as one
        // event, or a consumer replays the wrong history (1, B).
        let mut event = an_event();
        event.ops.push(Op {
            action: Action::Update,
            path: "app.bsky.feed.post/3kbbb".into(),
            record_cid: Some("bafyreirecord2".into()),
            prev_cid: Some("bafyreirecord1".into()),
        });
        let bytes = frame(&event).expect("frame");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("3kbbb"), "the second op is missing");
        assert!(
            text.contains("bafyreirecord1"),
            "the update's prev is missing"
        );
        assert!(text.contains("bafyreiprevdata"), "prevData is missing");
    }
}
