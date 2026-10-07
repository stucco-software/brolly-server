//! The member's ATProtocol repository: records in an MST under signed commits.
//!
//! Every structural piece is atrium's (D14, ADR 0002) — MST, DAG-CBOR, CAR,
//! commit shape. The predecessor hand-rolled these and it was the single
//! largest source of "works until it meets a real client", because the failures
//! are structural and silent: a repo that is subtly wrong still round-trips
//! against itself.
//!
//! What stays ours is the key and the root. Signing happens here, and the root
//! CID is persisted by the caller, because atrium holds a repo open but does
//! not decide where the pointer to it lives.
//!
//! The write path is the lexicon's (1, B): every write — one record or a
//! batch — is applied to the MST with atrium's own tree ops and sealed in
//! **one commit envelope of ours**. atrium-repo 0.1.8 cannot build a multi-op
//! commit (its `CommitBuilder` and commit schema are private, and each
//! `*_raw` stages a single op from `latest_commit`), so the envelope — the
//! unsigned commit, the signature, the signed block — is mirrored here, field
//! for field, and used by *every* write so single- and multi-op commits
//! cannot diverge. The tests hold the envelope byte-identical to atrium's own
//! and to atrium-crypto's verifier. atrium keeps the MST, the block store,
//! and CAR framing (D14); the envelope is not an MST.

use std::collections::{BTreeMap, HashSet};

use atrium_api::types::string::{Did, Nsid, RecordKey, Tid};
use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite, DiffBlockStore};
use atrium_repo::{Cid, Repository};
use ipld_core::ipld::Ipld;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;

use crate::blocks::PodBlocks;
use crate::firehose::Action;
use crate::keys::SigningKey;
use crate::tid;

/// A record block over this many bytes is refused rather than written (1, B).
pub const MAX_RECORD_BYTES: usize = 1_000_000;

/// A batch over this many ops is refused rather than applied (1, B).
pub const MAX_BATCH_OPS: usize = 200;

/// A commit whose CAR diff slice would exceed this many bytes is refused at
/// the write rather than emitted with `tooBig` — the Sync spec deprecates
/// `tooBig` ("producers should always set it to `false`"), so the limit has to
/// bite somewhere, and the write is where (1, B).
pub const MAX_DIFF_BYTES: usize = 2_000_000;

#[derive(Debug)]
pub enum RepoError {
    /// atrium refused the operation — a malformed path, a missing block, a
    /// commit that does not apply.
    Repo(String),
    /// A signature could not be produced.
    Signing(String),
    /// The DID is not a well-formed `did:plc:` or `did:web:`.
    BadDid(String),
    /// A record path that failed the lexicon's own grammar (1, B).
    BadPath(String),
    /// A write's compare-and-set did not hold: the record was not where the
    /// write required it to be — occupied where it had to be empty, or
    /// missing or moved where it had to be exact (1, B, 1, C). The lexicon's
    /// own `InvalidSwap` answer, as the write handlers serve it.
    InvalidSwap(String),
    /// A write the spec's size limits refuse: a record block over
    /// [`MAX_RECORD_BYTES`], or a commit whose CAR diff slice would exceed
    /// [`MAX_DIFF_BYTES`] (1, B).
    TooLarge(String),
}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoError::Repo(e) => write!(f, "repo: {e}"),
            RepoError::Signing(e) => write!(f, "signing: {e}"),
            RepoError::BadDid(d) => write!(f, "not a usable DID: {d}"),
            RepoError::BadPath(p) => write!(f, "record path must be collection/rkey, got {p}"),
            RepoError::InvalidSwap(p) => {
                write!(f, "the record was not where this write required it: {p}")
            }
            RepoError::TooLarge(what) => write!(f, "the write is too large: {what}"),
        }
    }
}

impl std::error::Error for RepoError {}

impl From<atrium_repo::repo::Error> for RepoError {
    fn from(e: atrium_repo::repo::Error) -> Self {
        RepoError::Repo(e.to_string())
    }
}

impl From<atrium_repo::mst::Error> for RepoError {
    fn from(e: atrium_repo::mst::Error) -> Self {
        RepoError::Repo(e.to_string())
    }
}

impl From<atrium_repo::blockstore::Error> for RepoError {
    fn from(e: atrium_repo::blockstore::Error) -> Self {
        RepoError::Repo(e.to_string())
    }
}

// --- the commit envelope -------------------------------------------------------

/// The unsigned commit, mirrored field for field from atrium's private commit
/// schema (1, B).
///
/// Field order is byte order in DAG-CBOR, so this must not be reordered: the
/// tests hold the envelope byte-identical to what atrium's own
/// `CommitBuilder` produces, and a divergence is a fork in the commit format
/// that no consumer would notice until a signature check fails.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct UnsignedCommit {
    did: Did,
    /// Fixed value of 3 for this repo format version.
    version: i64,
    /// The MST root this commit points at.
    data: Cid,
    /// The commit's own revision, a TID.
    rev: Tid,
    /// Always null here: a v3 repo's history chain travels as
    /// `since`/`prevData` in the events (1, A), and nothing may "fix" this
    /// field.
    prev: Option<Cid>,
}

/// The signed commit — [`UnsignedCommit`] plus the signature, appended
/// exactly as atrium appends it (1, B).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct SignedCommit {
    did: Did,
    version: i64,
    data: Cid,
    rev: Tid,
    prev: Option<Cid>,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
}

/// Read a commit block: the DID, the MST root it points at, and its rev (1, B).
async fn read_commit(blocks: &mut PodBlocks, root: Cid) -> Result<SignedCommit, RepoError> {
    let bytes = blocks
        .read_block(root)
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?;
    serde_ipld_dagcbor::from_slice::<SignedCommit>(&bytes)
        .map_err(|e| RepoError::Repo(format!("the commit block does not parse: {e}")))
}

// --- records as they are stored -------------------------------------------------

/// A record value as it will live in its block: a `$blob`-typed value's `ref`
/// is a CID link, and everything else is carried verbatim (1, H).
///
/// The JSON the wire carries cannot name a link; the block can. This is the
/// whole of the conversion — the deprecated top-level `blobs` array stays
/// empty, ops carry no blob list, and a record referencing a blob CID that
/// has no bytes in the store is accepted, because the repo is a pointer set,
/// not an oracle.
pub fn record_ipld(value: &Value) -> Result<Ipld, RepoError> {
    match value {
        Value::Null => Ok(Ipld::Null),
        Value::Bool(b) => Ok(Ipld::Bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Ipld::Integer(i as i128))
            } else if let Some(u) = n.as_u64() {
                Ok(Ipld::Integer(u as i128))
            } else {
                n.as_f64()
                    .map(Ipld::Float)
                    .ok_or_else(|| RepoError::Repo("a number the data model cannot carry".into()))
            }
        }
        Value::String(s) => Ok(Ipld::String(s.clone())),
        Value::Array(items) => items
            .iter()
            .map(record_ipld)
            .collect::<Result<Vec<_>, _>>()
            .map(Ipld::List),
        Value::Object(fields) => {
            // A `$blob`-typed value's `ref` becomes the link; its other fields
            // (`mimeType`, `size`) are carried as they arrived (1, H).
            let is_blob = fields.get("$type").and_then(Value::as_str) == Some("blob");
            let mut out = BTreeMap::new();
            for (name, field) in fields {
                let converted = if is_blob && name == "ref" {
                    blob_ref(field)?
                } else {
                    record_ipld(field)?
                };
                out.insert(name.clone(), converted);
            }
            Ok(Ipld::Map(out))
        }
    }
}

/// A blob ref's `ref`, as a link (1, H).
///
/// A plain CID string is what brolly's own clients send; `{"$link": "…"}` is
/// the JSON form the reference stack uses for a CID, and a client echoing one
/// back must round-trip too.
fn blob_ref(value: &Value) -> Result<Ipld, RepoError> {
    let text = match value {
        Value::String(s) => Some(s.as_str()),
        Value::Object(fields) if fields.len() == 1 => fields.get("$link").and_then(Value::as_str),
        _ => None,
    };
    text.and_then(|s| s.parse::<Cid>().ok())
        .map(Ipld::Link)
        .ok_or_else(|| RepoError::Repo(format!("a blob ref is not a CID: {value}")))
}

/// A stored record as the wire sees it: links become CID strings again, so a
/// record written with a blob ref reads back as the JSON that named it (1, H).
pub fn ipld_to_json(ipld: &Ipld) -> Value {
    match ipld {
        Ipld::Null => Value::Null,
        Ipld::Bool(b) => Value::Bool(*b),
        Ipld::Integer(i) => i64::try_from(*i)
            .ok()
            .map(serde_json::Number::from)
            .or_else(|| u64::try_from(*i).ok().map(serde_json::Number::from))
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Ipld::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Ipld::String(s) => Value::String(s.clone()),
        // Nothing on the write path produces bytes — JSON cannot carry them —
        // and a block that somehow does has no JSON spelling to invent here.
        Ipld::Bytes(_) => Value::Null,
        Ipld::List(items) => Value::Array(items.iter().map(ipld_to_json).collect()),
        Ipld::Map(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, field)| (name.clone(), ipld_to_json(field)))
                .collect(),
        ),
        Ipld::Link(cid) => Value::String(cid.to_string()),
    }
}

// --- the write plan -------------------------------------------------------------

/// What a write requires of the record it names, from `putRecord`'s
/// `swapRecord` parameter — deliberately nullable *and* optional in the
/// lexicon (1, B).
#[derive(Debug, Clone)]
pub enum RecordSwap {
    /// No requirement: the record may be there or not.
    Any,
    /// `swapRecord: null` — the record must not exist.
    MustNotExist,
    /// `swapRecord: <cid>` — the record must be at exactly this CID.
    MustBe(Cid),
}

impl RecordSwap {
    /// From the parameter as it arrives on the wire: absent, `null`, or a
    /// CID (1, B).
    pub fn parse(swap_record: Option<Option<&str>>) -> Result<Self, RepoError> {
        match swap_record {
            None => Ok(RecordSwap::Any),
            Some(None) => Ok(RecordSwap::MustNotExist),
            Some(Some(cid)) => cid
                .parse::<Cid>()
                .map(RecordSwap::MustBe)
                .map_err(|e| RepoError::BadPath(format!("swapRecord is not a CID: {e}"))),
        }
    }
}

/// Which lexicon verb a planned write is (1, B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAction {
    /// `createRecord`: the path must be empty.
    Create,
    /// `putRecord`: absent creates, present replaces.
    Put,
    /// `applyWrites#update`: the path must be occupied.
    Update,
    /// `applyWrites#delete`: the path must be occupied.
    Delete,
}

/// One write in a batch, its grammar already validated (1, B).
///
/// Constructed only through the named constructors, so no caller can assemble
/// an invalid one: the collection and rkey are checked against atrium's own
/// `Nsid`/`RecordKey` grammars and refused before any block is written.
#[derive(Debug, Clone)]
pub struct PlannedWrite {
    action: WriteAction,
    collection: Nsid,
    rkey: Option<RecordKey>,
    record: Option<Ipld>,
    swap: RecordSwap,
}

impl PlannedWrite {
    /// A `createRecord` write. The rkey is minted when the caller supplies
    /// none — a TID, minted past the head's rev, so neither two writes in one
    /// batch nor two writes racing one head can mint the same one (1, B).
    pub fn create(collection: &str, rkey: Option<&str>, record: &Value) -> Result<Self, RepoError> {
        Ok(PlannedWrite {
            action: WriteAction::Create,
            collection: parse_nsid(collection)?,
            rkey: parse_rkey(rkey)?,
            record: Some(record_ipld(record)?),
            swap: RecordSwap::Any,
        })
    }

    /// A `putRecord` write: upsert, with the record-level compare-and-set its
    /// `swapRecord` parameter expresses (1, B).
    pub fn put(
        collection: &str,
        rkey: &str,
        record: &Value,
        swap: RecordSwap,
    ) -> Result<Self, RepoError> {
        Ok(PlannedWrite {
            action: WriteAction::Put,
            collection: parse_nsid(collection)?,
            rkey: parse_rkey(Some(rkey))?,
            record: Some(record_ipld(record)?),
            swap,
        })
    }

    /// An `applyWrites#update` write: the path must be occupied (1, B).
    pub fn update(collection: &str, rkey: &str, record: &Value) -> Result<Self, RepoError> {
        Ok(PlannedWrite {
            action: WriteAction::Update,
            collection: parse_nsid(collection)?,
            rkey: parse_rkey(Some(rkey))?,
            record: Some(record_ipld(record)?),
            swap: RecordSwap::Any,
        })
    }

    /// An `applyWrites#delete` write: the path must be occupied (1, B).
    pub fn delete(collection: &str, rkey: &str) -> Result<Self, RepoError> {
        Ok(PlannedWrite {
            action: WriteAction::Delete,
            collection: parse_nsid(collection)?,
            rkey: parse_rkey(Some(rkey))?,
            record: None,
            swap: RecordSwap::Any,
        })
    }

    /// The record path this write names, once its rkey is known.
    fn path(&self) -> Result<String, RepoError> {
        let rkey = self
            .rkey
            .as_ref()
            .map(|r| r.as_str().to_string())
            .ok_or_else(|| RepoError::Repo("the rkey was never minted".into()))?;
        Ok(format!("{}/{rkey}", self.collection.as_str()))
    }
}

/// The collection, under the lexicon's own grammar (1, B).
fn parse_nsid(collection: &str) -> Result<Nsid, RepoError> {
    Nsid::new(collection.to_string()).map_err(|e| RepoError::BadPath(format!("{e}: {collection}")))
}

/// The rkey, under the lexicon's own grammar — `^[a-zA-Z0-9.\-_:~]{1,512}$`
/// minus `.` and `..` (1, B).
fn parse_rkey(rkey: Option<&str>) -> Result<Option<RecordKey>, RepoError> {
    rkey.map(|r| RecordKey::new(r.to_string()).map_err(|e| RepoError::BadPath(format!("{e}: {r}"))))
        .transpose()
}

/// A record's location in a repo: `collection/rkey`, validated by atrium's
/// own grammars rather than checked by hand — a hand-rolled approximation
/// accepts what the network rejects, and that failure is structural and
/// silent (1, B).
pub fn record_path(collection: &str, rkey: &str) -> Result<String, RepoError> {
    let collection = parse_nsid(collection)?;
    let rkey =
        RecordKey::new(rkey.to_string()).map_err(|e| RepoError::BadPath(format!("{e}: {rkey}")))?;
    Ok(format!("{}/{}", collection.as_str(), rkey.as_str()))
}

// --- applying a batch -----------------------------------------------------------

/// One op as it landed: what the event log's op row carries (1, B, 1, D).
#[derive(Debug, Clone)]
pub struct AppliedOp {
    /// The action as it resolved — a `putRecord` lands as `create` or
    /// `update` by whether the path was occupied.
    pub action: Action,
    /// `collection/rkey`.
    pub path: String,
    /// The written record's CID; absent for a delete.
    pub record_cid: Option<Cid>,
    /// The previous record CID, captured while the tree was open — what an
    /// inductive consumer needs and what chunk 3's frames emit. Undefined for
    /// a create (1, D).
    pub prev_cid: Option<Cid>,
}

/// A batch as it landed: one commit, one signature, one event (1, B).
#[derive(Debug, Clone)]
pub struct Applied {
    /// The signed commit's CID — the new root.
    pub commit: Cid,
    /// The commit's own rev, minted past the head's.
    pub rev: Tid,
    /// The rev this commit is based on — the head's own rev, which the
    /// compare-and-set verified (1, A).
    pub since_rev: Tid,
    /// The MST root this commit replaced — the previous commit's `data`
    /// field, which is `prevData` on the wire and what MST inversion needs
    /// (1, A).
    pub prev_data: Cid,
    /// One op per write, in order.
    pub ops: Vec<AppliedOp>,
}

/// A sentinel for "occupied by a record this batch is writing": the
/// simulation below needs to know a path is taken, and the CID it will have
/// is not minted until the apply pass. Only existence is ever simulated —
/// CID-exact swaps arrive one write at a time, never in a batch (1, B).
fn occupied() -> Option<Cid> {
    Some(Cid::default())
}

/// Apply a batch of writes to the repo at `root` in **one commit** — one MST
/// revision, one signature, one event (1, B).
///
/// The whole batch is validated against the old tree before anything is
/// written, so an invalid op — a create on an occupied path, a swap that does
/// not hold, an update on a missing record — refuses the batch unsigned and
/// leaves no blocks behind. The commit that seals the batch is built through
/// brolly's envelope, the same path a single write takes: there is no
/// single-op code path to diverge from.
///
/// `head_rev` is the floor the commit's rev must clear; the mint guarantees it
/// can (1, A), and the head's compare-and-set guarantees it must (1, C).
pub async fn apply(
    mut blocks: PodBlocks,
    root: Cid,
    key: &SigningKey,
    writes: Vec<PlannedWrite>,
    head_rev: &Tid,
) -> Result<Applied, RepoError> {
    if writes.len() > MAX_BATCH_OPS {
        return Err(RepoError::TooLarge(format!(
            "a batch is capped at {MAX_BATCH_OPS} ops, got {}",
            writes.len()
        )));
    }

    let old_commit = read_commit(&mut blocks, root).await?;
    let mut writes = writes;

    // Mint the rkeys the caller left to the server, past the head's rev and
    // past each other, so no two writes — in this batch or racing it — mint
    // the same one (1, B).
    let mut floor = head_rev.clone();
    for write in &mut writes {
        if write.rkey.is_none() {
            let minted = tid::mint_after(&floor);
            floor = minted.clone();
            write.rkey = parse_rkey(Some(minted.as_str()))?;
        }
    }

    // Serialize the records before anything is written, so the record limit
    // refuses with no side effects at all (1, B).
    let mut record_blocks = Vec::with_capacity(writes.len());
    for write in &writes {
        let Some(record) = &write.record else {
            record_blocks.push(Vec::new());
            continue;
        };
        let bytes = serde_ipld_dagcbor::to_vec(record)
            .map_err(|e| RepoError::Repo(format!("a record cannot be encoded: {e}")))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RepoError::TooLarge(format!(
                "a record block is capped at {MAX_RECORD_BYTES} bytes, got {}",
                bytes.len()
            )));
        }
        record_blocks.push(bytes);
    }

    let mut store = DiffBlockStore::wrap(blocks);

    // Validate the whole batch against the old tree, simulating the writes in
    // order so a batch that touches one path twice is judged on the state the
    // first touch leaves (1, B).
    let mut simulated: BTreeMap<String, Option<Cid>> = BTreeMap::new();
    {
        let mut tree = atrium_repo::mst::Tree::open(&mut store, old_commit.data);
        for write in &writes {
            let path = write.path()?;
            let current = match simulated.get(&path) {
                Some(current) => *current,
                None => tree.get(&path).await?,
            };
            validate(write, &path, current)?;
            simulated.insert(
                path,
                match write.action {
                    WriteAction::Delete => None,
                    _ => occupied(),
                },
            );
        }
    }

    // Apply: write each record block, then move the tree. One tree per op —
    // a tree holds its storage handle while open, and an MST op rewrites only
    // the path it touches, so the trees are cheap.
    let mut mst_root = old_commit.data;
    let mut ops = Vec::with_capacity(writes.len());
    for (write, bytes) in writes.iter().zip(&record_blocks) {
        let path = write.path()?;
        let record_cid = match write.record.as_ref() {
            Some(_) => {
                let cid = store
                    .write_block(
                        atrium_repo::blockstore::DAG_CBOR,
                        atrium_repo::blockstore::SHA2_256,
                        bytes,
                    )
                    .await?;
                Some(cid)
            }
            None => None,
        };
        let mut tree = atrium_repo::mst::Tree::open(&mut store, mst_root);
        // The state the path is in right now — the real tree, so an op on a
        // path an earlier op in this batch touched sees that op's record.
        let current = tree.get(&path).await?;
        // A write that carries a record writes one; a delete carries none.
        // The constructors keep the pairing with the action, so this cannot
        // be wrong at runtime — and is not `expect`ed at a library's runtime.
        let (action, record_cid) = match (write.action, record_cid) {
            (WriteAction::Delete, None) => {
                tree.delete(&path).await?;
                (Action::Delete, None)
            }
            (WriteAction::Create, Some(record_cid)) => {
                tree.add(&path, record_cid).await?;
                (Action::Create, Some(record_cid))
            }
            // A replace is `update` — the MST verb atrium-repo ships and
            // brolly had never called until this stage (1, B).
            (WriteAction::Put, Some(record_cid)) if current.is_some() => {
                tree.update(&path, record_cid).await?;
                (Action::Update, Some(record_cid))
            }
            (WriteAction::Put, Some(record_cid)) => {
                tree.add(&path, record_cid).await?;
                (Action::Create, Some(record_cid))
            }
            (WriteAction::Update, Some(record_cid)) => {
                tree.update(&path, record_cid).await?;
                (Action::Update, Some(record_cid))
            }
            _ => {
                return Err(RepoError::Repo(format!(
                    "{path}: the write and its record disagree"
                )));
            }
        };
        mst_root = tree.root();
        ops.push(AppliedOp {
            action,
            path,
            record_cid,
            // The per-op prev, captured while the old MST was open (1, D).
            prev_cid: current,
        });
    }

    // The envelope: mint the rev, serialize the unsigned commit, sign, write
    // the signed block — the same path atrium's `CommitBuilder` walks (1, B).
    let rev = tid::mint_after(head_rev);
    let unsigned = UnsignedCommit {
        did: old_commit.did.clone(),
        version: 3,
        data: mst_root,
        rev: rev.clone(),
        prev: None,
    };
    let payload = serde_ipld_dagcbor::to_vec(&unsigned)
        .map_err(|e| RepoError::Repo(format!("the commit cannot be encoded: {e}")))?;
    let sig = key
        .sign(&payload)
        .map_err(|e| RepoError::Signing(e.to_string()))?;
    let signed = SignedCommit {
        did: unsigned.did,
        version: unsigned.version,
        data: unsigned.data,
        rev: unsigned.rev,
        prev: None,
        sig,
    };
    let signed_bytes = serde_ipld_dagcbor::to_vec(&signed)
        .map_err(|e| RepoError::Repo(format!("the commit cannot be encoded: {e}")))?;

    // The CAR diff slice this commit implies, sized at the write: every block
    // the write stored (the new MST nodes and the new record values), the
    // contextual path blocks of the old tree each op needs for inversion, and
    // the commit block itself (1, B). Chunk 3 emits the slice this measures.
    let commit_cid = Cid::new_v1(
        atrium_repo::blockstore::DAG_CBOR,
        atrium_repo::Multihash::wrap(
            atrium_repo::blockstore::SHA2_256,
            &sha2::Sha256::digest(&signed_bytes),
        )
        .map_err(|e| RepoError::Repo(format!("hashing the commit: {e}")))?,
    );
    let mut diff = car_frame_size(&commit_cid, &signed_bytes);
    let mut counted: HashSet<Cid> = HashSet::new();
    // Every block the write stored: the new MST nodes and the new record
    // values. Collected first — the differencing store lends its blocks out
    // only while it is not being read.
    let written: Vec<Cid> = store.blocks().collect();
    for cid in written {
        if counted.insert(cid) {
            let bytes = store.read_block(cid).await?;
            diff += car_frame_size(&cid, &bytes);
        }
    }
    for op in &ops {
        // The contextual chain to this op's key in the old tree, collected
        // before the store is read back, because the tree holds it while
        // open.
        let path_cids = {
            let mut tree = atrium_repo::mst::Tree::open(&mut store, old_commit.data);
            tree.extract_path(&op.path).await?.collect::<Vec<_>>()
        };
        for cid in path_cids {
            if counted.insert(cid) {
                let bytes = store.read_block(cid).await?;
                diff += car_frame_size(&cid, &bytes);
            }
        }
    }
    if diff > MAX_DIFF_BYTES {
        return Err(RepoError::TooLarge(format!(
            "the commit's CAR diff slice would be {diff} bytes, over the {MAX_DIFF_BYTES}-byte limit"
        )));
    }

    let written = store
        .write_block(
            atrium_repo::blockstore::DAG_CBOR,
            atrium_repo::blockstore::SHA2_256,
            &signed_bytes,
        )
        .await?;

    Ok(Applied {
        commit: written,
        rev,
        since_rev: old_commit.rev,
        prev_data: old_commit.data,
        ops,
    })
}

/// Whether one write may proceed against the state its path is in (1, B).
///
/// This is where the lexicon's verbs differ, and where the refusal is
/// `InvalidSwap`-shaped: the client named the state the record had to be in,
/// and the mismatch is the answer.
fn validate(write: &PlannedWrite, path: &str, current: Option<Cid>) -> Result<(), RepoError> {
    match (write.action, &write.swap) {
        (WriteAction::Create, _) if current.is_some() => Err(RepoError::InvalidSwap(format!(
            "{path} already exists, and createRecord does not replace"
        ))),
        (WriteAction::Create, _) => Ok(()),
        (WriteAction::Put, RecordSwap::Any) => Ok(()),
        (WriteAction::Put, RecordSwap::MustNotExist) if current.is_some() => {
            Err(invalid_swap(path, "it already exists"))
        }
        (WriteAction::Put, RecordSwap::MustNotExist) => Ok(()),
        (WriteAction::Put, RecordSwap::MustBe(expected)) if current != Some(*expected) => Err(
            invalid_swap(path, "it is not at the CID this write required"),
        ),
        (WriteAction::Put, RecordSwap::MustBe(_)) => Ok(()),
        (WriteAction::Update, _) if current.is_none() => Err(RepoError::Repo(format!(
            "{path} does not exist, and an update cannot create it"
        ))),
        (WriteAction::Update, _) => Ok(()),
        (WriteAction::Delete, _) if current.is_none() => Err(RepoError::Repo(format!(
            "{path} does not exist, and there is nothing to delete"
        ))),
        (WriteAction::Delete, _) => Ok(()),
    }
}

fn invalid_swap(path: &str, why: &str) -> RepoError {
    RepoError::InvalidSwap(format!("swapRecord did not hold for {path}: {why}"))
}

/// The space one block occupies in a CAR: a varint length, the CID bytes, the
/// data (1, B).
fn car_frame_size(cid: &Cid, bytes: &[u8]) -> usize {
    let cid_len = cid.to_bytes().len();
    let body = cid_len + bytes.len();
    let mut varint = 1;
    let mut rest = body >> 7;
    while rest > 0 {
        varint += 1;
        rest >>= 7;
    }
    varint + body
}

/// Create a member's repo and sign its genesis commit.
///
/// Returns the root CID and the genesis commit's own rev, which the caller
/// persists together — that pointer is what makes the repo findable again,
/// and atrium does not decide where it lives. The rev travels with it so the
/// stored rev is the commit's own from the first row (1, A).
pub async fn create(
    blocks: PodBlocks,
    did: &str,
    key: &SigningKey,
) -> Result<(Cid, Tid), RepoError> {
    let builder = Repository::create(blocks, did_for(did)?).await?;

    // atrium hands out the bytes and takes back a signature; the private key
    // never crosses the boundary (ADR 0002).
    let payload = builder.bytes();
    let signature = key
        .sign(&payload)
        .map_err(|e| RepoError::Signing(e.to_string()))?;

    let repo = builder.finalize(signature).await?;
    Ok((repo.root(), repo.commit().rev()))
}

fn did_for(did: &str) -> Result<Did, RepoError> {
    Did::new(did.to_string()).map_err(|_| RepoError::BadDid(did.to_string()))
}

/// Read a record back, as the JSON the wire carries: a block's CID links come
/// back as CID strings, so a record written with a blob ref reads back as the
/// JSON that named it (1, H).
pub async fn get_record(
    blocks: PodBlocks,
    root: Cid,
    collection: &str,
    rkey: &str,
) -> Result<Option<Value>, RepoError> {
    let path = record_path(collection, rkey)?;
    let mut repo = Repository::open(blocks, root).await?;
    match repo.get_raw::<Ipld>(&path).await? {
        Some(ipld) => Ok(Some(ipld_to_json(&ipld))),
        None => Ok(None),
    }
}

/// Export the repo as a CARv1 archive.
///
/// The archive is what `com.atproto.sync.getRepo` serves and what a member's
/// data export is: every block reachable from the root, framed with the root
/// as the CAR's single root. atrium writes it (D14) — CAR framing is exactly
/// the kind of structural detail that is easy to get subtly wrong and
/// impossible to notice locally, because a malformed archive still reads back
/// with the same code that wrote it.
pub async fn export_car(blocks: PodBlocks, root: Cid) -> Result<Vec<u8>, RepoError> {
    use atrium_repo::blockstore::CarStore;

    let mut repo = Repository::open(blocks, root).await?;

    // `CarStore` keeps its storage private, so the buffer is shared rather
    // than recovered afterwards.
    let buffer = SharedBuffer::default();
    let mut car = CarStore::create_with_roots(buffer.clone(), [root])
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?;

    repo.export_into(&mut car).await?;
    Ok(buffer.take())
}

/// An in-memory file the CAR writer can seek around in.
///
/// CAR writing seeks — it revisits offsets as it frames blocks — so a plain
/// `Vec` is not enough and the whole archive is built before anything is
/// returned. That is fine at a member's repo size and wrong at a large one;
/// when export needs to stream, this is the piece that changes.
#[derive(Clone, Default)]
struct SharedBuffer {
    inner: std::sync::Arc<std::sync::Mutex<std::io::Cursor<Vec<u8>>>>,
}

impl SharedBuffer {
    fn take(&self) -> Vec<u8> {
        self.lock().get_ref().clone()
    }

    /// Poisoning is recovered from rather than panicked on.
    ///
    /// A poisoned lock here means an earlier export panicked while holding it.
    /// The cursor is still a structurally valid buffer, the export that failed
    /// is already an error on its own path, and panicking a second time in a
    /// library crate would turn a failed export into a downed server.
    fn lock(&self) -> std::sync::MutexGuard<'_, std::io::Cursor<Vec<u8>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn with<T>(&self, f: impl FnOnce(&mut std::io::Cursor<Vec<u8>>) -> T) -> T {
        f(&mut self.lock())
    }
}

impl tokio::io::AsyncRead for SharedBuffer {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::io::Read;
        std::task::Poll::Ready(self.with(|cursor| {
            let read = cursor.read(buf.initialize_unfilled())?;
            buf.advance(read);
            Ok(())
        }))
    }
}

impl tokio::io::AsyncWrite for SharedBuffer {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::Write;
        std::task::Poll::Ready(self.with(|cursor| cursor.write(data)))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncSeek for SharedBuffer {
    fn start_seek(
        self: std::pin::Pin<&mut Self>,
        position: std::io::SeekFrom,
    ) -> std::io::Result<()> {
        use std::io::Seek;
        self.with(|cursor| cursor.seek(position)).map(|_| ())
    }

    fn poll_complete(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        use std::io::Seek;
        std::task::Poll::Ready(self.with(|cursor| cursor.stream_position()))
    }
}

/// Every CID reachable from the root — the block set a CAR export carries.
pub async fn reachable(blocks: PodBlocks, root: Cid) -> Result<Vec<Cid>, RepoError> {
    let mut repo = Repository::open(blocks, root).await?;
    Ok(repo.export().await?.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_crypto::verify::verify_signature;
    use serde_json::json;

    const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture() -> (tempfile::TempDir, brolly_store::StoreManager, uuid::Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
        (dir, manager, uuid::Uuid::new_v4())
    }

    fn blocks(manager: &brolly_store::StoreManager, user: uuid::Uuid) -> PodBlocks {
        PodBlocks::new(manager.repo_blocks(user).unwrap())
    }

    /// Every file under the fixture — the blocks a refused write must not
    /// leave behind. Only repo blocks ever land there.
    fn block_count(dir: &tempfile::TempDir) -> usize {
        fn walk(path: &std::path::Path, count: &mut usize) {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.path().is_dir() {
                    walk(&entry.path(), count);
                } else {
                    *count += 1;
                }
            }
        }
        let mut count = 0;
        walk(dir.path(), &mut count);
        count
    }

    fn a_put(collection: &str, rkey: &str, text: &str) -> Result<PlannedWrite, RepoError> {
        PlannedWrite::put(
            collection,
            rkey,
            &json!({"$type": collection, "text": text}),
            RecordSwap::Any,
        )
    }

    #[tokio::test]
    async fn a_repo_is_created_and_its_root_is_stable() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();

        let (root, _rev) = create(blocks(&manager, user), DID, &key)
            .await
            .expect("create");
        assert!(
            root.to_string().starts_with("bafy"),
            "expected a CIDv1, got {root}"
        );
    }

    #[tokio::test]
    async fn a_record_written_reads_back_identically() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let record = json!({
            "$type": "app.bsky.feed.post",
            "text": "hello atproto",
            "createdAt": "2026-08-26T12:00:00Z",
        });
        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &record,
                    RecordSwap::Any,
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("put");

        let read = get_record(
            blocks(&manager, user),
            applied.commit,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .expect("get");
        assert_eq!(read, Some(record));
    }

    #[tokio::test]
    async fn a_write_advances_the_root() {
        // The root is the repo's version. A write that leaves it unchanged
        // has produced a commit nobody can observe.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "one").unwrap()],
            &genesis,
        )
        .await
        .unwrap();

        assert_ne!(root, applied.commit);
    }

    #[tokio::test]
    async fn the_stored_rev_is_the_signed_commits_own() {
        // One source of truth: the rev a write returns is the one the commit
        // block itself carries, and it clears the head it was minted past
        // (1, A). A counter invented beside the commits is the divergence
        // this replaces.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "one").unwrap()],
            &genesis,
        )
        .await
        .unwrap();

        assert!(
            applied.rev.as_str() > genesis.as_str(),
            "the commit's rev did not clear the head's: {} -> {}",
            genesis.as_str(),
            applied.rev.as_str()
        );
        assert_eq!(
            applied.since_rev, genesis,
            "since is the rev this commit is based on"
        );

        // Read back through atrium, from the root alone: the commit block
        // must carry that same rev, and `prev_data` must be the MST root of
        // the commit this one replaced.
        let repo = Repository::open(blocks(&manager, user), applied.commit)
            .await
            .unwrap();
        assert_eq!(repo.commit().rev(), applied.rev);
        let before = Repository::open(blocks(&manager, user), root)
            .await
            .unwrap();
        assert_eq!(applied.prev_data, before.commit().data());
    }

    #[tokio::test]
    async fn the_rev_mints_forward_across_writes() {
        // Chained writes, each minted past the previous commit's rev:
        // strictly increasing, the property the head's `rev <` guard
        // enforces (1, C).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (mut root, mut rev) = create(blocks(&manager, user), DID, &key).await.unwrap();

        for (n, rkey) in ["3kaaaaaaaaaaa", "3kbbbbbbbbbbb"].iter().enumerate() {
            let applied = apply(
                blocks(&manager, user),
                root,
                &key,
                vec![a_put("app.bsky.feed.post", rkey, &format!("post {n}")).unwrap()],
                &rev,
            )
            .await
            .unwrap();
            assert!(
                applied.rev.as_str() > rev.as_str(),
                "a remint did not clear the previous rev: {} -> {}",
                rev.as_str(),
                applied.rev.as_str()
            );
            root = applied.commit;
            rev = applied.rev;
        }
    }

    #[tokio::test]
    async fn the_envelope_is_atriums_bytes() {
        // The spec's own hold on the envelope: a single-op commit built
        // through brolly's envelope must be byte-identical to one built
        // through atrium's `add_raw` path — same ops, same key, same rev —
        // which the CIDs assert, content-addressed as they are (1, B).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let record = json!({"$type": "app.bsky.feed.post", "text": "one"});
        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &record,
                    RecordSwap::Any,
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("brolly's envelope");

        // atrium's own path, on a second fixture so its blocks cannot be
        // mistaken for ours: open the repo atrium just created, add_raw,
        // set the same rev, sign, finalize.
        let (_dir2, manager2, user2) = fixture();
        let (root2, _genesis2) = create(blocks(&manager2, user2), DID, &key).await.unwrap();
        let mut atrium_repo = Repository::open(blocks(&manager2, user2), root2)
            .await
            .unwrap();
        let (mut commit, _record_cid) = atrium_repo
            .add_raw("app.bsky.feed.post/3kaaaaaaaaaaa", &record)
            .await
            .unwrap();
        commit.rev(applied.rev.clone());
        let sig = key.sign(&commit.bytes()).unwrap();
        let atrium_root = commit.finalize(sig).await.unwrap();

        assert_eq!(
            applied.commit, atrium_root,
            "the envelope diverged from atrium's bytes"
        );
    }

    #[tokio::test]
    async fn every_commit_verifies_under_atriums_verifier() {
        // Signed here must mean verifiable by the reference stack's own
        // crypto, against the key that signed it (1, B).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "one").unwrap(),
                a_put("app.bsky.feed.post", "3kbbbbbbbbbbb", "two").unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("a multi-op commit verifies too");

        let repo = Repository::open(blocks(&manager, user), applied.commit)
            .await
            .unwrap();
        let commit = repo.commit();
        verify_signature(&key.did_key(), &commit.bytes(), commit.sig())
            .expect("the commit must verify under atrium-crypto");
    }

    #[tokio::test]
    async fn an_unmapped_third_party_lexicon_writes_like_any_other() {
        // Phase 7's third exit criterion, at the repo layer: there is no
        // mapping table, so a lexicon nobody has heard of is not a special
        // case — it is the same call.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let record = json!({
            "$type": "site.standard.doc",
            "text": "a wholly unrelated lexicon",
            "nested": {"depth": 2, "list": [1, 2, 3]},
        });
        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::put(
                    "site.standard.doc",
                    "3kbbbbbbbbbbb",
                    &record,
                    RecordSwap::Any,
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("an unmapped lexicon must write");

        let read = get_record(
            blocks(&manager, user),
            applied.commit,
            "site.standard.doc",
            "3kbbbbbbbbbbb",
        )
        .await
        .unwrap();
        assert_eq!(read, Some(record), "nested structure must survive verbatim");
    }

    #[tokio::test]
    async fn two_records_coexist_and_both_read_back() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "post 0").unwrap(),
                a_put("app.bsky.feed.post", "3kbbbbbbbbbbb", "post 1").unwrap(),
            ],
            &genesis,
        )
        .await
        .unwrap();

        for (n, rkey) in ["3kaaaaaaaaaaa", "3kbbbbbbbbbbb"].iter().enumerate() {
            let read = get_record(
                blocks(&manager, user),
                applied.commit,
                "app.bsky.feed.post",
                rkey,
            )
            .await
            .unwrap();
            assert_eq!(read.unwrap()["text"], format!("post {n}"));
        }
    }

    #[tokio::test]
    async fn a_deleted_record_is_gone_and_the_root_moves() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let with_record = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "delete me").unwrap()],
            &genesis,
        )
        .await
        .unwrap();

        let after = apply(
            blocks(&manager, user),
            with_record.commit,
            &key,
            vec![PlannedWrite::delete("app.bsky.feed.post", "3kaaaaaaaaaaa").unwrap()],
            &with_record.rev,
        )
        .await
        .expect("delete");

        assert_ne!(with_record.commit, after.commit);
        let read = get_record(
            blocks(&manager, user),
            after.commit,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(read, None);
    }

    #[tokio::test]
    async fn a_missing_record_is_none_rather_than_an_error() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, _) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let read = get_record(
            blocks(&manager, user),
            root,
            "app.bsky.feed.post",
            "nothing-here",
        )
        .await
        .unwrap();
        assert_eq!(read, None);
    }

    #[tokio::test]
    async fn a_repo_reopens_from_its_root_alone() {
        // The property that makes persisting only the root sufficient: given
        // the CID and the blocks, the repo is fully recoverable.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();
        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "durable").unwrap()],
            &genesis,
        )
        .await
        .unwrap();

        // Nothing carried over but the CID and the on-disk blocks.
        let read = get_record(
            blocks(&manager, user),
            applied.commit,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(read.unwrap()["text"], "durable");
    }

    #[test]
    fn a_malformed_record_path_is_refused() {
        // A wrong-shaped path produces a repo that looks fine locally and is
        // rejected by every consumer — so the grammar is atrium's own (1, B).
        assert!(record_path("app.bsky.feed.post", "3kaaa").is_ok());
        // Not an NSID: one segment, a bad character, too long by half.
        assert!(record_path("notanNSID", "3kaaa").is_err());
        assert!(record_path("app.bsky.feed.post", "has/slash").is_err());
        // Not a record key: empty, disallowed characters, the reserved
        // `.` and `..`.
        assert!(record_path("app.bsky.feed.post", "").is_err());
        assert!(record_path("app.bsky.feed.post", "has space").is_err());
        assert!(record_path("app.bsky.feed.post", ".").is_err());
        assert!(record_path("app.bsky.feed.post", "..").is_err());
    }

    #[tokio::test]
    async fn a_bad_did_is_refused_before_anything_is_written() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        assert!(
            create(blocks(&manager, user), "not-a-did", &key)
                .await
                .is_err()
        );
    }

    // --- the write path's own semantics (1, B) ---------------------------------

    #[tokio::test]
    async fn a_create_on_an_occupied_path_refuses_with_no_blocks_written() {
        // `createRecord` creates; an occupied path is `InvalidSwap`-style,
        // and the refusal must leave no orphan blocks behind (1, B).
        let (dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::create(
                    "app.bsky.feed.post",
                    Some("3kaaaaaaaaaaa"),
                    &json!({"$type": "app.bsky.feed.post", "text": "first"}),
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("the first create lands");

        let before = block_count(&dir);
        let refused = apply(
            blocks(&manager, user),
            applied.commit,
            &key,
            vec![
                PlannedWrite::create(
                    "app.bsky.feed.post",
                    Some("3kaaaaaaaaaaa"),
                    &json!({"$type": "app.bsky.feed.post", "text": "second"}),
                )
                .unwrap(),
            ],
            &applied.rev,
        )
        .await;
        match &refused {
            Err(RepoError::InvalidSwap(_)) => {}
            other => panic!("a create on an occupied path must be InvalidSwap: {other:?}"),
        }
        assert_eq!(
            block_count(&dir),
            before,
            "a refused create must write no blocks"
        );
    }

    #[tokio::test]
    async fn a_put_creates_then_replaces() {
        // `putRecord` is upsert: absent creates, present replaces — and the
        // event's action and per-op prev say which happened (1, B, 1, D).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let created = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &json!({"$type": "app.bsky.feed.post", "text": "created"}),
                    RecordSwap::MustNotExist,
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("a put on an empty path creates");
        assert_eq!(created.ops[0].action, Action::Create);
        assert_eq!(created.ops[0].prev_cid, None);

        let replaced = apply(
            blocks(&manager, user),
            created.commit,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &json!({"$type": "app.bsky.feed.post", "text": "replaced"}),
                    RecordSwap::MustBe(created.ops[0].record_cid.unwrap()),
                )
                .unwrap(),
            ],
            &created.rev,
        )
        .await
        .expect("a put on an occupied path replaces");
        assert_eq!(replaced.ops[0].action, Action::Update);
        assert_eq!(
            replaced.ops[0].prev_cid, created.ops[0].record_cid,
            "the update's prev is the record it replaced"
        );

        let read = get_record(
            blocks(&manager, user),
            replaced.commit,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(read.unwrap()["text"], "replaced");
    }

    #[tokio::test]
    async fn a_record_swap_that_does_not_hold_refuses_invalid_swap() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "one").unwrap()],
            &genesis,
        )
        .await
        .unwrap();
        let real = applied.ops[0].record_cid.unwrap();
        let stale = "bafkreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy"
            .parse::<Cid>()
            .unwrap();

        // `swapRecord: null` on an occupied path.
        let refused = apply(
            blocks(&manager, user),
            applied.commit,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &json!({"$type": "app.bsky.feed.post", "text": "x"}),
                    RecordSwap::MustNotExist,
                )
                .unwrap(),
            ],
            &applied.rev,
        )
        .await;
        assert!(
            matches!(&refused, Err(RepoError::InvalidSwap(_))),
            "swapRecord: null on an occupied path must be InvalidSwap: {refused:?}"
        );

        // `swapRecord` naming a CID that is not the record's.
        let refused = apply(
            blocks(&manager, user),
            applied.commit,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &json!({"$type": "app.bsky.feed.post", "text": "x"}),
                    RecordSwap::MustBe(stale),
                )
                .unwrap(),
            ],
            &applied.rev,
        )
        .await;
        assert!(
            matches!(&refused, Err(RepoError::InvalidSwap(_))),
            "a stale swapRecord must be InvalidSwap: {refused:?}"
        );

        // The same write at the record's real CID proceeds.
        apply(
            blocks(&manager, user),
            applied.commit,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &json!({"$type": "app.bsky.feed.post", "text": "two"}),
                    RecordSwap::MustBe(real),
                )
                .unwrap(),
            ],
            &applied.rev,
        )
        .await
        .expect("an exact swapRecord proceeds");
    }

    #[tokio::test]
    async fn a_batch_applies_as_one_commit() {
        // `applyWrites` is one commit: one MST revision, one signature, one
        // event with one op per write (1, B).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "a one").unwrap(),
                a_put("app.bsky.feed.post", "3kbbbbbbbbbbb", "b one").unwrap(),
                PlannedWrite::update(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &json!({"$type": "app.bsky.feed.post", "text": "a two"}),
                )
                .unwrap(),
                PlannedWrite::delete("app.bsky.feed.post", "3kbbbbbbbbbbb").unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("the batch applies");

        assert_eq!(applied.ops.len(), 4, "one op per write");
        let actions: Vec<Action> = applied.ops.iter().map(|op| op.action).collect();
        assert_eq!(
            actions,
            vec![
                Action::Create,
                Action::Create,
                Action::Update,
                Action::Delete
            ]
        );

        let a_first = applied.ops[0].record_cid;
        let b_first = applied.ops[1].record_cid;
        assert_eq!(applied.ops[0].prev_cid, None, "a create has no prev");
        assert_eq!(
            applied.ops[2].prev_cid, a_first,
            "the update's prev is the record this batch wrote there"
        );
        assert_eq!(
            applied.ops[3].prev_cid, b_first,
            "the delete's prev is the record it removed"
        );
        assert_eq!(applied.ops[3].record_cid, None, "a delete writes no record");

        // One commit: both records live under it, the deleted one is gone,
        // and the updated one reads at its second value.
        let a = get_record(
            blocks(&manager, user),
            applied.commit,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(a["text"], "a two");
        let b = get_record(
            blocks(&manager, user),
            applied.commit,
            "app.bsky.feed.post",
            "3kbbbbbbbbbbb",
        )
        .await
        .unwrap();
        assert_eq!(b, None);
    }

    #[tokio::test]
    async fn an_invalid_op_refuses_the_whole_batch_unsigned() {
        // A batch is atomic: one invalid op refuses everything, before
        // anything is signed and with no blocks written (1, B).
        let (dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let before = block_count(&dir);
        let refused = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", "would land").unwrap(),
                // A create on a path the first op just took.
                PlannedWrite::create(
                    "app.bsky.feed.post",
                    Some("3kaaaaaaaaaaa"),
                    &json!({"$type": "app.bsky.feed.post", "text": "collision"}),
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await;
        assert!(
            matches!(&refused, Err(RepoError::InvalidSwap(_))),
            "a colliding op must refuse the batch: {refused:?}"
        );
        assert_eq!(
            block_count(&dir),
            before,
            "a refused batch must write no blocks — not even the valid op's"
        );
    }

    #[tokio::test]
    async fn an_update_or_delete_on_a_missing_record_refuses_the_batch() {
        let (dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        for write in [
            PlannedWrite::update(
                "app.bsky.feed.post",
                "3kaaaaaaaaaaa",
                &json!({"$type": "app.bsky.feed.post", "text": "ghost"}),
            )
            .unwrap(),
            PlannedWrite::delete("app.bsky.feed.post", "3kaaaaaaaaaaa").unwrap(),
        ] {
            let before = block_count(&dir);
            let refused = apply(blocks(&manager, user), root, &key, vec![write], &genesis).await;
            assert!(
                matches!(&refused, Err(RepoError::Repo(_))),
                "a missing record must refuse the write: {refused:?}"
            );
            assert_eq!(block_count(&dir), before);
        }
    }

    #[tokio::test]
    async fn a_record_over_a_megabyte_is_refused() {
        let (dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let big = "x".repeat(MAX_RECORD_BYTES + 1);
        let before = block_count(&dir);
        let refused = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", &big).unwrap()],
            &genesis,
        )
        .await;
        assert!(
            matches!(&refused, Err(RepoError::TooLarge(_))),
            "an oversized record must be refused: {refused:?}"
        );
        assert_eq!(block_count(&dir), before);
    }

    #[tokio::test]
    async fn a_commit_whose_diff_would_exceed_two_megabytes_is_refused() {
        // Three records of 900 KB each are individually fine and together a
        // diff slice over the 2 MB the Sync spec allows — refused at the
        // write, because `tooBig` is deprecated and cannot absorb it (1, B).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let refused = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                a_put("app.bsky.feed.post", "3kaaaaaaaaaaa", &"x".repeat(900_000)).unwrap(),
                a_put("app.bsky.feed.post", "3kbbbbbbbbbbb", &"y".repeat(900_000)).unwrap(),
                a_put("app.bsky.feed.post", "3kccccccccccc", &"z".repeat(900_000)).unwrap(),
            ],
            &genesis,
        )
        .await;
        assert!(
            matches!(&refused, Err(RepoError::TooLarge(_))),
            "a diff over the slice limit must be refused: {refused:?}"
        );
    }

    #[tokio::test]
    async fn a_batch_over_two_hundred_ops_is_refused() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let writes: Vec<PlannedWrite> = (0..=MAX_BATCH_OPS)
            .map(|n| a_put("app.bsky.feed.post", &format!("3ka{n:011}"), "too many").unwrap())
            .collect();
        let refused = apply(blocks(&manager, user), root, &key, writes, &genesis).await;
        assert!(
            matches!(&refused, Err(RepoError::TooLarge(_))),
            "a batch over the op limit must be refused: {refused:?}"
        );
    }

    #[tokio::test]
    async fn a_blob_ref_lands_as_a_cid_link_and_round_trips() {
        // The whole of H: the ref is a real CID link in the record's
        // DAG-CBOR block, and the record reads back as the JSON that named
        // it (1, H).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let record = json!({
            "$type": "app.bsky.feed.post",
            "text": "with an image",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [{
                    "alt": "a blob nothing uploaded yet",
                    "image": {
                        "$type": "blob",
                        "ref": "bafkreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy",
                        "mimeType": "image/png",
                        "size": 1234,
                    },
                }],
            },
        });
        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &record,
                    RecordSwap::Any,
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("a record with a blob ref writes");

        // The block carries the ref as a link, not a string.
        let mut repo = Repository::open(blocks(&manager, user), applied.commit)
            .await
            .unwrap();
        let stored: Ipld = repo
            .get_raw("app.bsky.feed.post/3kaaaaaaaaaaa")
            .await
            .unwrap()
            .expect("the record");
        let image = stored
            .get("embed")
            .unwrap()
            .and_then(|e| e.get("images").unwrap())
            .and_then(|l| l.get(0).unwrap())
            .and_then(|i| i.get("image").unwrap())
            .and_then(|i| i.get("ref").unwrap())
            .expect("the blob ref");
        assert!(
            matches!(image, Ipld::Link(_)),
            "the blob ref must be a CID link in the block, got {image:?}"
        );

        // And it reads back as the JSON that named it.
        let read = get_record(
            blocks(&manager, user),
            applied.commit,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(read, Some(record));
    }

    #[tokio::test]
    async fn a_blob_ref_in_atriums_link_form_round_trips_too() {
        // A client that echoes back the reference stack's `{"$link": …}`
        // spelling must not lose its blob.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let record = json!({
            "$type": "app.bsky.feed.post",
            "text": "echoed",
            "image": {"$type": "blob", "ref": {"$link": "bafkreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy"}},
        });
        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    "3kaaaaaaaaaaa",
                    &record,
                    RecordSwap::Any,
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .unwrap();

        let read = get_record(
            blocks(&manager, user),
            applied.commit,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(
            read.unwrap()["image"]["ref"],
            "bafkreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy"
        );
    }

    #[tokio::test]
    async fn rkeys_left_to_the_server_are_minted_as_tids() {
        // The reference PDS mints TID rkeys; the mint is floored past the
        // head's rev so no two can collide, in a batch or racing one (1, B).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let applied = apply(
            blocks(&manager, user),
            root,
            &key,
            vec![
                PlannedWrite::create(
                    "app.bsky.feed.post",
                    None,
                    &json!({"$type": "app.bsky.feed.post", "text": "one"}),
                )
                .unwrap(),
                PlannedWrite::create(
                    "app.bsky.feed.post",
                    None,
                    &json!({"$type": "app.bsky.feed.post", "text": "two"}),
                )
                .unwrap(),
            ],
            &genesis,
        )
        .await
        .expect("rkey-less creates mint");

        let mut rkeys = Vec::new();
        for op in &applied.ops {
            let rkey = op.path.rsplit('/').next().expect("a path with an rkey");
            assert!(
                Tid::new(rkey.to_string()).is_ok(),
                "a minted rkey must be a TID: {rkey}"
            );
            assert!(
                rkey > genesis.as_str(),
                "a minted rkey must clear the head's rev, like a rev does (1, B)"
            );
            rkeys.push(rkey.to_string());
        }
        assert_ne!(rkeys[0], rkeys[1], "two mints must not collide");
    }
}
