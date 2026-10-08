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
//! prevent. The one thing the log does not hold but a frame needs — the CAR
//! diff slice — is derived, not stored: built at emission time from the event's
//! pointers plus the member's blocks (D5, 1, D), which content addressing makes
//! reconstructible whenever a consumer asks.
//!
//! One event carries **one commit and all of its ops** (1, B): the event row is
//! the commit — its CIDs, its rev, the rev and MST root it follows — and the
//! ops live beside it, one row per write, in the order the batch applied them.
//! The per-op `prev` — the record CID an update replaced or a delete removed —
//! is captured by the write path while the old MST is open, because chunk 3's
//! frames emit it and it cannot be reconstructed afterwards (1, D).

use atrium_api::types::string::Tid;
use brolly_identity::db::DbError;
use ipld_core::ipld::Ipld;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::BTreeMap;
use time::OffsetDateTime;

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
    /// When the event was logged — `time` on the wire, the timestamp of the
    /// broadcast the Sync spec names (1, D).
    pub time: OffsetDateTime,
    /// One op per write the commit applied, in order (1, B).
    pub ops: Vec<Op>,
}

/// Record a commit and return the event, cursor included.
///
/// The event row and its op rows land in one transaction: a commit whose ops
/// were half-logged is not a commit a consumer can invert (1, B).
pub async fn record(pool: &PgPool, commit: &NewCommit<'_>) -> Result<CommitEvent, DbError> {
    let mut tx = pool.begin().await?;

    let (seq, time): (i64, OffsetDateTime) = sqlx::query_as(
        "INSERT INTO atproto_firehose
           (did, commit_cid, prev_cid, rev, since_rev, prev_data)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING seq, created_at",
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
        time,
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
    OffsetDateTime,
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
        "SELECT seq, did, commit_cid, prev_cid, rev, since_rev, prev_data, created_at
             FROM atproto_firehose WHERE seq > $1 ORDER BY seq LIMIT $2",
    )
    .bind(cursor.unwrap_or(0))
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    for (seq, did, commit_cid, prev_cid, rev, since_rev, prev_data, time) in rows {
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
            time,
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

/// A `#commit` message, in the shape `subscribeRepos` defines (1, D).
///
/// The wire frame is two concatenated DAG-CBOR objects — a header naming the
/// message type, then the body. Emitting the header separately is not cosmetic:
/// a consumer dispatches on it before it has parsed the body, and one that
/// cannot find it treats the whole frame as unknown and drops it.
///
/// The body is built as `Ipld`, not JSON, and that is the point: a CID is a
/// link (DAG-CBOR tag 42), which JSON cannot express — the structural flaw
/// that made every frame before this one unreadable by the reference stack.
/// The commit, each op's `cid`, each op's `prev` and `prevData` are
/// `Ipld::Link`s on the wire, decoded by consumers as strict CID links.
///
/// `blocks` is the CAR diff slice — built by [`crate::repo::diff_car`] from
/// the event's pointers plus the member's blocks, and passed in because the
/// log holds pointers, never blocks (D5). Its size was measured at the write
/// against the Sync spec's 2,000,000-byte cap (1, B), and every other field
/// is bounded by the batch limits, so the whole frame sits far under the
/// spec's 5 MB.
///
/// The deprecated fields are emitted at their fixed values, not used as
/// mechanisms (1, D): `tooBig` is always `false` because the size limit bites
/// at the write, and the top-level `blobs` array is always empty because a
/// blob ref lives as a CID link inside the record block itself (1, H).
///
/// There is deliberately no top-level `prev` — the previous commit's CID —
/// even though the event row carries it: the lexicon's own `CommitData` has
/// no such field, and a v3 repo's history travels as `since`/`prevData` in
/// the events instead (1, A).
pub fn frame(event: &CommitEvent, blocks: &[u8]) -> Result<Vec<u8>, String> {
    let mut header = BTreeMap::new();
    header.insert("op".to_string(), Ipld::Integer(1));
    header.insert("t".to_string(), Ipld::String("#commit".to_string()));

    let mut body = BTreeMap::new();
    body.insert("seq".to_string(), Ipld::Integer(event.seq as i128));
    body.insert("repo".to_string(), Ipld::String(event.did.clone()));
    body.insert("commit".to_string(), link(&event.commit_cid)?);
    body.insert(
        "rev".to_string(),
        Ipld::String(event.rev.as_str().to_string()),
    );
    // `since` is the rev this commit is based on, and `prevData` the MST root
    // it replaced — both absent on a repo's first commit (1, A).
    if let Some(since) = &event.since_rev {
        body.insert(
            "since".to_string(),
            Ipld::String(since.as_str().to_string()),
        );
    }
    if let Some(prev_data) = &event.prev_data {
        body.insert("prevData".to_string(), link(prev_data)?);
    }
    // `time` is the event's timestamp, as RFC 3339 — the subset the lexicon's
    // datetime accepts (1, D).
    let time = event
        .time
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| format!("the event's timestamp: {e}"))?;
    body.insert("time".to_string(), Ipld::String(time));
    body.insert("tooBig".to_string(), Ipld::Bool(false));
    body.insert("blobs".to_string(), Ipld::List(Vec::new()));
    body.insert("rebase".to_string(), Ipld::Bool(false));
    body.insert("blocks".to_string(), Ipld::Bytes(blocks.to_vec()));
    let mut ops = Vec::with_capacity(event.ops.len());
    for op in &event.ops {
        ops.push(op_ipld(op)?);
    }
    body.insert("ops".to_string(), Ipld::List(ops));

    let header = serde_ipld_dagcbor::to_vec(&Ipld::Map(header))
        .map_err(|e| format!("encoding header: {e}"))?;
    let body =
        serde_ipld_dagcbor::to_vec(&Ipld::Map(body)).map_err(|e| format!("encoding body: {e}"))?;
    let mut out = header;
    out.extend(body);
    Ok(out)
}

/// A CID from its stored text, as a link — the thing JSON could not do (1, D).
fn link(cid: &str) -> Result<Ipld, String> {
    cid.parse::<ipld_core::cid::Cid>()
        .map(Ipld::Link)
        .map_err(|e| format!("a CID on the event does not parse ({cid}): {e}"))
}

/// One op, as the wire carries it: `cid` present for a create or update,
/// `prev` present for an update or delete, and neither key present at all
/// where it is undefined — the shape the lexicon's own `RepoOp` decodes (1, D).
fn op_ipld(op: &Op) -> Result<Ipld, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "action".to_string(),
        Ipld::String(op.action.as_str().to_string()),
    );
    map.insert("path".to_string(), Ipld::String(op.path.clone()));
    if let Some(cid) = &op.record_cid {
        map.insert("cid".to_string(), link(cid)?);
    }
    if let Some(prev) = &op.prev_cid {
        map.insert("prev".to_string(), link(prev)?);
    }
    Ok(Ipld::Map(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_api::com::atproto::sync::subscribe_repos;

    /// A real CID, so the frame's links are links a decoder can read (1, D).
    fn a_cid(seed: &str) -> String {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(seed.as_bytes());
        let mh = atrium_repo::Multihash::wrap(atrium_repo::blockstore::SHA2_256, &digest)
            .expect("a digest always wraps");
        atrium_repo::Cid::new_v1(atrium_repo::blockstore::DAG_CBOR, mh).to_string()
    }

    fn an_event() -> CommitEvent {
        CommitEvent {
            seq: 42,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            commit_cid: a_cid("commit"),
            prev_cid: Some(a_cid("prev")),
            rev: Tid::new("3kaaaaaaaaaaa".into()).expect("a valid TID"),
            since_rev: Some(Tid::new("3jzzzzzzzzzzz".into()).expect("a valid TID")),
            prev_data: Some(a_cid("prevdata")),
            time: OffsetDateTime::parse(
                "2026-10-07T12:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("a valid timestamp"),
            ops: vec![Op {
                action: Action::Create,
                path: "app.bsky.feed.post/3kaaa".into(),
                record_cid: Some(a_cid("record")),
                prev_cid: None,
            }],
        }
    }

    /// The header a consumer dispatches on, decoded the way it reads it: one
    /// DAG-CBOR object off the front, with the body still behind it (1, D).
    #[derive(Deserialize)]
    struct FrameHeader {
        op: i64,
        t: String,
    }

    fn decode(frame: &[u8]) -> subscribe_repos::Commit {
        let mut reader = std::io::Cursor::new(frame);
        let header: FrameHeader =
            serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the header decodes");
        assert_eq!(header.op, 1, "a commit frame is op 1");
        assert_eq!(header.t, "#commit", "this is a #commit frame");
        // The body decodes as atrium-api's own type — not our frame's inverse.
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the body decodes")
    }

    #[test]
    fn a_frame_decodes_as_atriums_own_commit_type() {
        // A frame our encoder and their decoder disagree on is a bug in our
        // encoder, full stop — so the unit of assertion here is their type
        // (1, D).
        let event = an_event();
        let car = b"a car, more or less";
        let decoded = decode(&frame(&event, car).expect("frame"));

        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.repo.as_str(), "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(decoded.commit.0.to_string(), event.commit_cid);
        assert_eq!(decoded.rev, event.rev);
        assert_eq!(
            decoded.since.as_ref().map(|rev| rev.as_str()),
            event.since_rev.as_ref().map(|rev| rev.as_str())
        );
        assert_eq!(
            decoded.prev_data.as_ref().map(|l| l.0.to_string()),
            event.prev_data
        );
        assert_eq!(decoded.time.as_str(), "2026-10-07T12:00:00Z");
        assert_eq!(decoded.blocks, car);
        assert!(!decoded.too_big, "tooBig is deprecated and always false");
        assert!(
            decoded.blobs.is_empty(),
            "the deprecated blobs array is always empty"
        );
        assert!(!decoded.rebase);
        assert_eq!(decoded.ops.len(), 1);
        assert_eq!(decoded.ops[0].action, "create");
        assert_eq!(decoded.ops[0].path, "app.bsky.feed.post/3kaaa");
        assert_eq!(
            decoded.ops[0].cid.as_ref().map(|l| l.0.to_string()),
            event.ops[0].record_cid
        );
        assert_eq!(decoded.ops[0].prev, None, "a create has no prev");
    }

    #[test]
    fn a_first_commits_frame_omits_since_and_prevdata() {
        // `since` and `prevData` are undefined on a repo's first commit, and
        // undefined on this wire means absent, not null (1, A).
        let mut event = an_event();
        event.since_rev = None;
        event.prev_data = None;
        let decoded = decode(&frame(&event, b"").expect("frame"));
        assert_eq!(decoded.since, None);
        assert_eq!(decoded.prev_data, None);
    }

    #[test]
    fn every_action_has_a_wire_name() {
        assert_eq!(Action::Create.as_str(), "create");
        assert_eq!(Action::Update.as_str(), "update");
        assert_eq!(Action::Delete.as_str(), "delete");
    }
}
