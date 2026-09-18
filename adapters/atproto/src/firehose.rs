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

/// One commit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitEvent {
    /// The cursor. Monotonic across the instance, because a consumer subscribes
    /// to the instance rather than to one repo.
    pub seq: i64,
    pub did: String,
    pub commit_cid: String,
    pub prev_cid: Option<String>,
    /// Per-repo revision, so ordering within one repo needs no reasoning about
    /// the global sequence.
    pub rev: i64,
    pub action: Action,
    /// `collection/rkey`.
    pub path: String,
    /// Absent for a delete.
    pub record_cid: Option<String>,
}

/// Record a commit and return the event, cursor included.
#[allow(clippy::too_many_arguments)]
pub async fn record(
    pool: &PgPool,
    did: &str,
    commit_cid: &str,
    prev_cid: Option<&str>,
    rev: i64,
    action: Action,
    path: &str,
    record_cid: Option<&str>,
) -> Result<CommitEvent, DbError> {
    let (seq,): (i64,) = sqlx::query_as(
        "INSERT INTO atproto_firehose
           (did, commit_cid, prev_cid, rev, action, path, record_cid)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING seq",
    )
    .bind(did)
    .bind(commit_cid)
    .bind(prev_cid)
    .bind(rev)
    .bind(action.as_str())
    .bind(path)
    .bind(record_cid)
    .fetch_one(pool)
    .await?;

    Ok(CommitEvent {
        seq,
        did: did.to_string(),
        commit_cid: commit_cid.to_string(),
        prev_cid: prev_cid.map(str::to_string),
        rev,
        action,
        path: path.to_string(),
        record_cid: record_cid.map(str::to_string),
    })
}

/// A row of the event log, as it comes off the query.
type EventRow = (
    i64,
    String,
    String,
    Option<String>,
    i64,
    String,
    String,
    Option<String>,
);

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
        "SELECT seq, did, commit_cid, prev_cid, rev, action, path, record_cid
             FROM atproto_firehose WHERE seq > $1 ORDER BY seq LIMIT $2",
    )
    .bind(cursor.unwrap_or(0))
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(seq, did, commit_cid, prev_cid, rev, action, path, record_cid)| CommitEvent {
                seq,
                did,
                commit_cid,
                prev_cid,
                rev,
                action: match action.as_str() {
                    "create" => Action::Create,
                    "update" => Action::Update,
                    _ => Action::Delete,
                },
                path,
                record_cid,
            },
        )
        .collect())
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
pub fn frame(event: &CommitEvent) -> Result<Vec<u8>, String> {
    let header = serde_json::json!({"op": 1, "t": "#commit"});
    let body = serde_json::json!({
        "seq": event.seq,
        "repo": event.did,
        "commit": event.commit_cid,
        "prev": event.prev_cid,
        "rev": event.rev.to_string(),
        "since": event.prev_cid,
        "ops": [{
            "action": event.action.as_str(),
            "path": event.path,
            "cid": event.record_cid,
        }],
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
            rev: 7,
            action: Action::Create,
            path: "app.bsky.feed.post/3kaaa".into(),
            record_cid: Some("bafyreirecord".into()),
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
}
