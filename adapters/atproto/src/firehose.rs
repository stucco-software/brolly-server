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
//!
//! The log holds **three kinds on one sequence** (1, E): `#commit` for repo
//! writes, `#identity` when a member's identity changes — a PLC operation
//! landing, which today is the genesis and will be rotations and renames when
//! those surfaces exist — and `#account` on hosting-status transitions. One
//! sequence, not one per kind, because a consumer subscribes to the instance,
//! not to a kind: its cursor has to order a commit against a takedown. `#sync`
//! is a frame type with no row and no emitter — the Sync spec reserves it for
//! state resets, which a first-party PDS performing ordinary writes does not
//! have — and `#info` is advice about one connection's cursor, synthesized per
//! connection and never logged: logging it would replay advice at whoever
//! reconnects (1, E).

use atrium_api::types::string::{Did, Handle, Tid};
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

/// An `#identity` event: a member's identity changed — re-resolve it (1, E).
///
/// Recorded by the identity layer when a PLC operation lands, because every
/// operation we record is an identity change (the genesis sets the handle and
/// the keys; a rotation or rename will change them). The event does not say
/// what changed — that is the Sync spec's own semantics: the handle is a
/// convenience, the instruction is to re-resolve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityEvent {
    /// The cursor (1, E).
    pub seq: i64,
    pub did: String,
    /// The handle the DID now claims. Optional on the wire and best-effort by
    /// the Sync spec's own admission; a first-party PDS's is not — ours is
    /// carried whenever it can ride the wire, and omitted when it cannot (1, E).
    pub handle: Option<String>,
    /// When the event was logged — `time` on the wire (1, D).
    pub time: OffsetDateTime,
}

/// An `#account` event: a hosting-status transition (1, E).
///
/// Recorded on the transitions the admin layers own — today that is deletion;
/// suspension, reinstatement and deactivation ride the same function when
/// those surfaces exist. The event describes the *new* status, not the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEvent {
    /// The cursor (1, E).
    pub seq: i64,
    pub did: String,
    /// Whether the repo is available and can be redistributed. The whole
    /// message, in one bit (1, E).
    pub active: bool,
    /// Why not, when it is not: the Sync spec's known values — `takendown`,
    /// `suspended`, `deleted`, `deactivated` (1, E).
    pub status: Option<String>,
    /// When the event was logged — `time` on the wire (1, D).
    pub time: OffsetDateTime,
}

/// A `#sync` event: a state reset, asserted rather than diffed (1, E).
///
/// A frame type only. Nothing records or emits it — repo transfer is a
/// non-goal, and the Sync spec reserves `#sync` for resets (a repo whose
/// history cannot be trusted to apply as a diff); a first-party PDS performing
/// ordinary writes has none. It exists so the reset path, when it exists,
/// emits a frame a consumer already decodes rather than a new shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEvent {
    /// The cursor (1, E).
    pub seq: i64,
    pub did: String,
    /// The revision of the commit the reset lands on. A string on the wire —
    /// the lexicon types it as one, unlike `#commit`'s TID (1, E).
    pub rev: String,
    /// When the event was logged — `time` on the wire (1, D).
    pub time: OffsetDateTime,
}

/// One logged event, of any kind the stream defines (1, E).
///
/// The log's rows are all three kinds on one sequence, so its reader answers
/// in the same shape: `since` returns these, mixed, in sequence order — a
/// consumer's cursor does not care what kind it crossed, and neither does the
/// table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Event {
    Commit(CommitEvent),
    Identity(IdentityEvent),
    Account(AccountEvent),
}

impl Event {
    /// The cursor — the one field every kind shares, and the one the stream's
    /// position tracking needs (1, E).
    pub fn seq(&self) -> i64 {
        match self {
            Event::Commit(event) => event.seq,
            Event::Identity(event) => event.seq,
            Event::Account(event) => event.seq,
        }
    }
}

/// Record a commit and return the event, cursor included.
///
/// The event row and its op rows land in one transaction: a commit whose ops
/// were half-logged is not a commit a consumer can invert (1, B).
pub async fn record(pool: &PgPool, commit: &NewCommit<'_>) -> Result<CommitEvent, DbError> {
    let mut tx = pool.begin().await?;

    let (seq, time): (i64, OffsetDateTime) = sqlx::query_as(
        "INSERT INTO atproto_firehose
           (kind, did, commit_cid, prev_cid, rev, since_rev, prev_data)
         VALUES ('commit', $1, $2, $3, $4, $5, $6) RETURNING seq, created_at",
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

/// A row of the event log, as it comes off the query — any kind (1, E).
///
/// Named fields rather than the tuple the ops reader uses: at twelve columns
/// the tuple is a position game, and `kind` decides what half of them mean.
#[derive(Debug, sqlx::FromRow)]
struct EventRow {
    seq: i64,
    /// `commit`, `identity` or `account` — what the rest of the row means.
    kind: String,
    did: String,
    commit_cid: Option<String>,
    prev_cid: Option<String>,
    rev: Option<String>,
    since_rev: Option<String>,
    prev_data: Option<String>,
    handle: Option<String>,
    active: Option<bool>,
    status: Option<String>,
    created_at: OffsetDateTime,
}

/// An op row of the event log.
type OpRow = (i64, i32, String, String, Option<String>, Option<String>);

/// Events after `cursor`, oldest first — all kinds, mixed on the one sequence
/// (1, E).
///
/// Exclusive, so a consumer passes the last sequence it processed and does not
/// receive it twice — a duplicate at the boundary is the classic resume bug and
/// it shows up as a doubled post rather than an error. The kinds interleave in
/// sequence order, because a consumer's cursor has to order a commit against a
/// takedown (1, E).
pub async fn since(pool: &PgPool, cursor: Option<i64>, limit: i64) -> Result<Vec<Event>, DbError> {
    let rows: Vec<EventRow> = sqlx::query_as(
        "SELECT seq, kind, did, commit_cid, prev_cid, rev, since_rev, prev_data,
                handle, active, status, created_at
         FROM atproto_firehose WHERE seq > $1 ORDER BY seq LIMIT $2",
    )
    .bind(cursor.unwrap_or(0))
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        events.push(match row.kind.as_str() {
            "commit" => {
                // The log only ever holds revs written from `Tid`s; a row that
                // does not parse is corruption, reported as a decode fault
                // rather than guessed around.
                let rev = parse_rev(
                    row.rev
                        .ok_or_else(|| decode_fault("a commit row with no rev"))?,
                )?;
                let since_rev = row.since_rev.map(parse_rev).transpose()?;
                let ops = ops_for(pool, row.seq).await?;
                Event::Commit(CommitEvent {
                    seq: row.seq,
                    did: row.did,
                    commit_cid: row
                        .commit_cid
                        .ok_or_else(|| decode_fault("a commit row with no commit CID"))?,
                    prev_cid: row.prev_cid,
                    rev,
                    since_rev,
                    prev_data: row.prev_data,
                    time: row.created_at,
                    ops,
                })
            }
            "identity" => Event::Identity(IdentityEvent {
                seq: row.seq,
                did: row.did,
                handle: row.handle,
                time: row.created_at,
            }),
            "account" => Event::Account(AccountEvent {
                seq: row.seq,
                did: row.did,
                active: row
                    .active
                    .ok_or_else(|| decode_fault("an account row with no active flag"))?,
                status: row.status,
                time: row.created_at,
            }),
            // The kind column's own CHECK holds the values; a row outside
            // them is corruption, not a kind to pass through silently.
            _ => {
                return Err(decode_fault(
                    "a logged kind that is not one of the stream's",
                ));
            }
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

/// A row that violates the shape its kind promises.
///
/// Impossible through the record functions and the table's own CHECK
/// constraints — so corruption, reported as a decode fault rather than guessed
/// around (the `parse_rev` discipline).
fn decode_fault(what: &str) -> DbError {
    DbError::Sql(sqlx::Error::Decode(what.into()))
}

/// Record an `#identity` event on the caller's connection (1, E).
///
/// Connection-scoped, unlike [`record`], because the identity layer records
/// the event inside the transaction that lands the PLC operation it announces
/// — an operation logged without its event is a change the stream never heard
/// (the same discipline that puts a commit's ops in its own transaction).
///
/// The handle is best-effort at the write, not just on the wire: a handle that
/// cannot ride the wire at all (a username that cannot form one) is omitted
/// with a warning rather than stored unframeable — the Sync spec makes the
/// field optional for exactly this case, and a first-party PDS carries the
/// handle whenever it can (1, E).
pub async fn record_identity(
    conn: &mut sqlx::PgConnection,
    did: &str,
    handle: Option<&str>,
) -> Result<IdentityEvent, DbError> {
    let handle = handle.filter(|handle| {
        let rides = handle.parse::<Handle>().is_ok();
        if !rides {
            tracing::warn!(%did, handle, "a handle that cannot ride the wire is omitted from its identity event");
        }
        rides
    });

    let (seq, time): (i64, OffsetDateTime) = sqlx::query_as(
        "INSERT INTO atproto_firehose (kind, did, handle)
         VALUES ('identity', $1, $2) RETURNING seq, created_at",
    )
    .bind(did)
    .bind(handle)
    .fetch_one(conn)
    .await?;

    Ok(IdentityEvent {
        seq,
        did: did.to_string(),
        handle: handle.map(str::to_string),
        time,
    })
}

/// Record an `#account` event on the caller's connection (1, E).
///
/// Connection-scoped for the same reason [`record_identity`] is: the hosting
/// transitions that emit it are deletions and status changes the account and
/// admin layers already transact, and the event belongs in the transaction
/// that makes it true — an account event for a deletion that did not happen
/// makes a relay drop a live repo, and a deletion without its event leaves the
/// network serving a deleted one.
///
/// `status` takes the Sync spec's known values; the column's own CHECK holds
/// the vocabulary, so an invented status is refused at the write (1, E).
pub async fn record_account(
    conn: &mut sqlx::PgConnection,
    did: &str,
    active: bool,
    status: Option<&str>,
) -> Result<AccountEvent, DbError> {
    let (seq, time): (i64, OffsetDateTime) = sqlx::query_as(
        "INSERT INTO atproto_firehose (kind, did, active, status)
         VALUES ('account', $1, $2, $3) RETURNING seq, created_at",
    )
    .bind(did)
    .bind(active)
    .bind(status)
    .fetch_one(conn)
    .await?;

    Ok(AccountEvent {
        seq,
        did: did.to_string(),
        active,
        status: status.map(str::to_string),
        time,
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
    let time = wire_time(event.time)?;
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

    frame_bytes(header, body)
}

/// A CID from its stored text, as a link — the thing JSON could not do (1, D).
fn link(cid: &str) -> Result<Ipld, String> {
    cid.parse::<ipld_core::cid::Cid>()
        .map(Ipld::Link)
        .map_err(|e| format!("a CID on the event does not parse ({cid}): {e}"))
}

/// A DID from its stored text, validated the way the body's decoder will
/// validate it (1, E).
///
/// The commit frame's links are refused at encode if a consumer could not
/// read them, and the other bodies' `did` (and `handle`) get the same
/// discipline: a frame our encoder and their decoder disagree on is a bug in
/// our encoder, full stop — so the disagreement is found at the write, not as
/// a skipped frame on someone's stream.
fn did_ipld(did: &str) -> Result<Ipld, String> {
    did.parse::<Did>()
        .map_err(|e| format!("a DID on the event does not parse ({did}): {e}"))
        .map(|_| Ipld::String(did.to_string()))
}

/// An event's timestamp, as RFC 3339 — the subset the lexicon's datetime
/// accepts (1, D).
fn wire_time(time: OffsetDateTime) -> Result<String, String> {
    time.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| format!("the event's timestamp: {e}"))
}

/// An `#identity` message, in the shape `subscribeRepos` defines (1, E).
///
/// Same framing as a commit — the header names the type, the body carries no
/// `$type` tag — and the same link discipline: the DID and handle are validated
/// here the way atrium's own `IdentityData` will validate them on the other
/// end. The handle is absent, not null, when there is none: undefined on this
/// wire means absent (1, A).
pub fn identity_frame(event: &IdentityEvent) -> Result<Vec<u8>, String> {
    let mut header = BTreeMap::new();
    header.insert("op".to_string(), Ipld::Integer(1));
    header.insert("t".to_string(), Ipld::String("#identity".to_string()));

    let mut body = BTreeMap::new();
    body.insert("seq".to_string(), Ipld::Integer(event.seq as i128));
    body.insert("did".to_string(), did_ipld(&event.did)?);
    if let Some(handle) = &event.handle {
        handle
            .parse::<Handle>()
            .map_err(|e| format!("a handle on the event does not parse ({handle}): {e}"))?;
        body.insert("handle".to_string(), Ipld::String(handle.clone()));
    }
    body.insert("time".to_string(), Ipld::String(wire_time(event.time)?));

    frame_bytes(header, body)
}

/// An `#account` message, in the shape `subscribeRepos` defines (1, E).
///
/// `active` is the whole message and always present; `status` is absent when
/// the account is simply active — an `#account` event with no status and
/// `active: true` is a reinstatement, which is what the admin layers will emit
/// when those transitions exist.
pub fn account_frame(event: &AccountEvent) -> Result<Vec<u8>, String> {
    let mut header = BTreeMap::new();
    header.insert("op".to_string(), Ipld::Integer(1));
    header.insert("t".to_string(), Ipld::String("#account".to_string()));

    let mut body = BTreeMap::new();
    body.insert("seq".to_string(), Ipld::Integer(event.seq as i128));
    body.insert("did".to_string(), did_ipld(&event.did)?);
    body.insert("active".to_string(), Ipld::Bool(event.active));
    if let Some(status) = &event.status {
        body.insert("status".to_string(), Ipld::String(status.clone()));
    }
    body.insert("time".to_string(), Ipld::String(wire_time(event.time)?));

    frame_bytes(header, body)
}

/// A `#sync` message, in the shape `subscribeRepos` defines (1, E).
///
/// Buildable and decodable, and emitted by nothing: the Sync spec reserves it
/// for state resets, and a first-party PDS performing ordinary writes has
/// none. The `blocks` carry only the commit object the reset lands on — the
/// contents are not the event's to carry; a consumer re-synchronizes by
/// fetching the full CAR.
pub fn sync_frame(event: &SyncEvent, blocks: &[u8]) -> Result<Vec<u8>, String> {
    let mut header = BTreeMap::new();
    header.insert("op".to_string(), Ipld::Integer(1));
    header.insert("t".to_string(), Ipld::String("#sync".to_string()));

    let mut body = BTreeMap::new();
    body.insert("seq".to_string(), Ipld::Integer(event.seq as i128));
    body.insert("did".to_string(), did_ipld(&event.did)?);
    // A string on the wire — the lexicon types `#sync`'s rev as one, unlike
    // `#commit`'s TID (1, E).
    body.insert("rev".to_string(), Ipld::String(event.rev.clone()));
    body.insert("blocks".to_string(), Ipld::Bytes(blocks.to_vec()));
    body.insert("time".to_string(), Ipld::String(wire_time(event.time)?));

    frame_bytes(header, body)
}

/// Header and body, encoded and concatenated — the frame every kind shares
/// (1, D): a consumer dispatches on the header before it has parsed the body.
fn frame_bytes(
    header: BTreeMap<String, Ipld>,
    body: BTreeMap<String, Ipld>,
) -> Result<Vec<u8>, String> {
    let header = serde_ipld_dagcbor::to_vec(&Ipld::Map(header))
        .map_err(|e| format!("encoding header: {e}"))?;
    let body =
        serde_ipld_dagcbor::to_vec(&Ipld::Map(body)).map_err(|e| format!("encoding body: {e}"))?;
    let mut out = header;
    out.extend(body);
    Ok(out)
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

    /// A frame's header and body, the way a consumer reads them: dispatch on
    /// the header, then decode the body as atrium-api's own type — never our
    /// frame function's inverse (1, D, 1, E).
    fn decode_as<T: serde::de::DeserializeOwned>(frame: &[u8], t: &str) -> T {
        let mut reader = std::io::Cursor::new(frame);
        let header: FrameHeader =
            serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the header decodes");
        assert_eq!(header.op, 1, "an event frame is op 1");
        assert_eq!(header.t, t, "this is a {t} frame");
        // The body decodes as atrium-api's own type — not our frame's inverse.
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the body decodes")
    }

    fn decode(frame: &[u8]) -> subscribe_repos::Commit {
        decode_as(frame, "#commit")
    }

    #[test]
    fn an_identity_frame_decodes_as_atriums_own_identity_type() {
        // The foreign-decoder discipline, on the second kind: their
        // `IdentityData`, not our encoder walked backwards (1, E).
        let event = IdentityEvent {
            seq: 43,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            handle: Some("alice.brolly.test".into()),
            time: OffsetDateTime::parse(
                "2026-10-08T12:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("a valid timestamp"),
        };
        let decoded = decode_as::<subscribe_repos::Identity>(
            &identity_frame(&event).expect("frame"),
            "#identity",
        );

        assert_eq!(decoded.seq, 43);
        assert_eq!(decoded.did.as_str(), "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            decoded.handle.as_ref().map(|h| h.as_str()),
            Some("alice.brolly.test")
        );
        assert_eq!(decoded.time.as_str(), "2026-10-08T12:00:00Z");
    }

    #[test]
    fn an_identity_frame_without_a_handle_omits_it() {
        // The handle is optional on the wire, and undefined there means
        // absent, not null (1, E).
        let event = IdentityEvent {
            seq: 43,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            handle: None,
            time: OffsetDateTime::parse(
                "2026-10-08T12:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("a valid timestamp"),
        };
        let decoded = decode_as::<subscribe_repos::Identity>(
            &identity_frame(&event).expect("frame"),
            "#identity",
        );
        assert_eq!(decoded.handle, None);
    }

    #[test]
    fn an_account_frame_decodes_as_atriums_own_account_type() {
        // A deletion, the transition this instance actually emits today (1, E).
        let event = AccountEvent {
            seq: 44,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            active: false,
            status: Some("deleted".into()),
            time: OffsetDateTime::parse(
                "2026-10-08T12:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("a valid timestamp"),
        };
        let decoded = decode_as::<subscribe_repos::Account>(
            &account_frame(&event).expect("frame"),
            "#account",
        );

        assert_eq!(decoded.seq, 44);
        assert_eq!(decoded.did.as_str(), "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(!decoded.active);
        assert_eq!(decoded.status.as_deref(), Some("deleted"));
        assert_eq!(decoded.time.as_str(), "2026-10-08T12:00:00Z");
    }

    #[test]
    fn an_active_accounts_frame_carries_no_status() {
        // A reinstatement: `active` alone is the whole message, and a status
        // of nothing is not a status a consumer can dispatch on (1, E).
        let event = AccountEvent {
            seq: 44,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            active: true,
            status: None,
            time: OffsetDateTime::parse(
                "2026-10-08T12:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("a valid timestamp"),
        };
        let decoded = decode_as::<subscribe_repos::Account>(
            &account_frame(&event).expect("frame"),
            "#account",
        );
        assert!(decoded.active);
        assert_eq!(decoded.status, None);
    }

    #[test]
    fn a_sync_frame_decodes_as_atriums_own_sync_type() {
        // Typed and decodable, and emitted by nothing — the reset path emits
        // a frame a consumer already understands, when it exists (1, E).
        let event = SyncEvent {
            seq: 45,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            rev: "3kaaaaaaaaaaa".into(),
            time: OffsetDateTime::parse(
                "2026-10-08T12:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("a valid timestamp"),
        };
        let blocks = b"the commit object and nothing else";
        let decoded = decode_as::<subscribe_repos::Sync>(
            &sync_frame(&event, blocks).expect("frame"),
            "#sync",
        );

        assert_eq!(decoded.seq, 45);
        assert_eq!(decoded.did.as_str(), "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(decoded.rev, "3kaaaaaaaaaaa");
        assert_eq!(decoded.blocks, blocks);
        assert_eq!(decoded.time.as_str(), "2026-10-08T12:00:00Z");
    }

    #[test]
    fn a_frame_refuses_what_their_decoder_would_reject() {
        // The encode-side half of the discipline: a did or handle their type
        // would refuse is refused here first, as a write-time error rather
        // than a frame skipped on someone's stream (1, E).
        let time = OffsetDateTime::parse(
            "2026-10-08T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("a valid timestamp");
        let bad_did = IdentityEvent {
            seq: 1,
            did: "not-a-did".into(),
            handle: None,
            time,
        };
        assert!(identity_frame(&bad_did).is_err());
        let bad_handle = IdentityEvent {
            seq: 1,
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            handle: Some("not a handle".into()),
            time,
        };
        assert!(identity_frame(&bad_handle).is_err());
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
