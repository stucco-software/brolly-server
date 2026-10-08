//! The commit event log behind `subscribeRepos`.
//!
//! The property that matters is resumption: a relay that drops must be able to
//! come back with a cursor and receive exactly what it missed — no gap, no
//! duplicate. A gap loses posts silently; a duplicate at the page boundary is
//! the classic resume bug, and it shows up as a doubled post rather than an
//! error anyone notices.
//!
//! The frames themselves are held to a foreign decoder: every frame test
//! decodes with atrium-api's own `subscribeRepos` types, not our frame
//! function's inverse, and every diff is inverted — the ops applied in reverse
//! onto the frame's own blocks must recompute `prevData` (1, D). A frame our
//! encoder and their decoder disagree on is a bug in our encoder; a diff that
//! cannot be inverted is not a diff.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use atrium_api::com::atproto::sync::subscribe_repos;
use atrium_api::types::string::Tid;
use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite};
use brolly_atproto::blocks::PodBlocks;
use brolly_atproto::firehose::{self, Action, CommitEvent, NewCommit, NewOp, Op};
use brolly_atproto::keys::SigningKey;
use brolly_atproto::repo::{self, PlannedWrite, RecordSwap};
use brolly_identity::db::MIGRATOR;
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;

const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

/// A real CID, so frames built over logged rows carry links a decoder can
/// read (1, D). Deterministic in the seed, so a commit and its predecessor
/// keep naming each other.
fn a_cid(seed: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(seed.as_bytes());
    let mh = atrium_repo::Multihash::wrap(atrium_repo::blockstore::SHA2_256, &digest)
        .expect("a digest always wraps");
    atrium_repo::Cid::new_v1(atrium_repo::blockstore::DAG_CBOR, mh).to_string()
}

/// A commit event with `n` ops, one op per write, in apply order (1, B).
async fn commit(
    pool: &PgPool,
    did: &str,
    n: i64,
    rev: &Tid,
    ops: Vec<NewOp>,
) -> firehose::CommitEvent {
    firehose::record(
        pool,
        &NewCommit {
            did,
            commit_cid: &a_cid(&format!("commit{n}")),
            prev_cid: (n > 1)
                .then(|| a_cid(&format!("commit{}", n - 1)))
                .as_deref(),
            rev,
            since_rev: None,
            prev_data: (n > 1).then(|| a_cid(&format!("data{}", n - 1))).as_deref(),
            ops,
        },
    )
    .await
    .expect("record")
}

/// One create op, the shape every event carried before batches existed.
fn an_op(n: i64) -> NewOp {
    NewOp {
        action: Action::Create,
        path: format!("app.bsky.feed.post/3k{n}"),
        record_cid: Some(a_cid(&format!("record{n}"))),
        prev_cid: None,
    }
}

/// A chain of mints, one per row, so each repo's revs stay strictly
/// increasing the way real commits' do (1, A).
struct Revs {
    current: Tid,
}

impl Revs {
    fn new() -> Self {
        Revs {
            current: Tid::new("3kaaaaaaaaaaa".into()).expect("a valid TID"),
        }
    }
    fn next(&mut self) -> Tid {
        self.current = brolly_atproto::tid::mint_after(&self.current);
        self.current.clone()
    }
}

#[tokio::test]
async fn the_cursor_increases_across_the_whole_instance() {
    // A consumer subscribes to the instance, not to one repo, so the sequence
    // has to be global or two repos' events cannot be ordered against each
    // other.
    let (_db, pool) = fresh().await;

    let mut alice = Revs::new();
    let mut bob = Revs::new();
    let first = commit(&pool, DID, 1, &alice.next(), vec![an_op(1)]).await;
    let other = commit(
        &pool,
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        1,
        &bob.next(),
        vec![an_op(1)],
    )
    .await;
    let third = commit(&pool, DID, 2, &alice.next(), vec![an_op(2)]).await;

    assert!(first.seq < other.seq, "sequence must span repos");
    assert!(other.seq < third.seq);
}

#[tokio::test]
async fn a_repo_events_revs_increase_per_repo() {
    // A rev is a TID and it is per-repo: a consumer orders a repo's events by
    // it without reasoning about the global sequence (1, A).
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    let mut previous = revs.next();
    for n in 1..=3 {
        commit(&pool, DID, n, &previous, vec![an_op(n)]).await;
        previous = revs.next();
    }

    let events = firehose::since(&pool, None, 10).await.unwrap();
    for pair in events.windows(2) {
        assert!(
            pair[1].rev.as_str() > pair[0].rev.as_str(),
            "a repo's revs must increase: {} -> {}",
            pair[0].rev.as_str(),
            pair[1].rev.as_str()
        );
    }
}

#[tokio::test]
async fn an_event_carries_all_of_its_commits_ops_in_order() {
    // One commit, n ops: a batch that applied as one commit leaves the log as
    // one event with one op per write, or a consumer replays the wrong
    // history (1, B).
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    commit(
        &pool,
        DID,
        1,
        &revs.next(),
        vec![
            NewOp {
                action: Action::Create,
                path: "app.bsky.feed.post/3ka".into(),
                record_cid: Some("bafyreirecorda".into()),
                prev_cid: None,
            },
            NewOp {
                action: Action::Update,
                path: "app.bsky.feed.post/3kb".into(),
                record_cid: Some("bafyreirecordb2".into()),
                prev_cid: Some("bafyreirecordb1".into()),
            },
            NewOp {
                action: Action::Delete,
                path: "app.bsky.feed.post/3kc".into(),
                record_cid: None,
                prev_cid: Some("bafyreirecordc".into()),
            },
        ],
    )
    .await;

    let events = firehose::since(&pool, None, 10).await.unwrap();
    assert_eq!(events.len(), 1, "one commit is one event");
    let ops = &events[0].ops;
    assert_eq!(ops.len(), 3, "one op per write");
    assert_eq!(ops[0].action, Action::Create);
    assert_eq!(ops[0].prev_cid, None, "a create has no prev");
    assert_eq!(ops[1].action, Action::Update);
    assert_eq!(
        ops[1].prev_cid.as_deref(),
        Some("bafyreirecordb1"),
        "an update's prev is the record it replaced (1, D)"
    );
    assert_eq!(ops[2].action, Action::Delete);
    assert_eq!(ops[2].record_cid, None, "a delete writes no record");
    assert_eq!(
        ops[2].prev_cid.as_deref(),
        Some("bafyreirecordc"),
        "a delete's prev is the record it removed (1, D)"
    );
}

#[tokio::test]
async fn a_consumer_resumes_from_its_cursor_without_a_gap_or_a_duplicate() {
    // The whole point of the log outliving the connection.
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    for n in 1..=5 {
        commit(&pool, DID, n, &revs.next(), vec![an_op(n)]).await;
    }

    let first_page = firehose::since(&pool, None, 2).await.unwrap();
    assert_eq!(first_page.len(), 2);

    let cursor = first_page.last().unwrap().seq;
    let second_page = firehose::since(&pool, Some(cursor), 10).await.unwrap();

    assert_eq!(second_page.len(), 3, "a gap would silently lose posts");
    assert!(
        second_page.iter().all(|e| e.seq > cursor),
        "the cursor must be exclusive, or the boundary event arrives twice"
    );

    // Together, exactly the five, each once.
    let mut all: Vec<i64> = first_page
        .iter()
        .chain(second_page.iter())
        .map(|e| e.seq)
        .collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 5);
}

#[tokio::test]
async fn a_fresh_consumer_receives_everything() {
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    for n in 1..=3 {
        commit(&pool, DID, n, &revs.next(), vec![an_op(n)]).await;
    }
    assert_eq!(firehose::since(&pool, None, 100).await.unwrap().len(), 3);
}

#[tokio::test]
async fn a_consumer_at_the_head_receives_nothing_until_something_happens() {
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    commit(&pool, DID, 1, &revs.next(), vec![an_op(1)]).await;

    let head = firehose::head(&pool).await.unwrap().expect("a head");
    assert!(
        firehose::since(&pool, Some(head), 100)
            .await
            .unwrap()
            .is_empty()
    );

    let second = revs.next();
    commit(&pool, DID, 2, &second, vec![an_op(2)]).await;
    let next = firehose::since(&pool, Some(head), 100).await.unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].rev, second);
}

#[tokio::test]
async fn an_empty_log_has_no_head() {
    let (_db, pool) = fresh().await;
    assert_eq!(firehose::head(&pool).await.unwrap(), None);
}

#[tokio::test]
async fn events_arrive_in_sequence_order() {
    // Out-of-order delivery would make `prev` unverifiable on the consumer's
    // side: it would see a commit before the one it follows.
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    for n in 1..=5 {
        commit(&pool, DID, n, &revs.next(), vec![an_op(n)]).await;
    }

    let events = firehose::since(&pool, None, 100).await.unwrap();
    let seqs: Vec<i64> = events.iter().map(|e| e.seq).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted);
}

#[tokio::test]
async fn an_event_carries_pointers_rather_than_records() {
    // D5 at the firehose: a consumer that wants the record fetches it. Inlining
    // would make this a second copy of every write.
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    let event = commit(&pool, DID, 1, &revs.next(), vec![an_op(1)]).await;

    assert_eq!(event.did, DID);
    assert!(event.commit_cid.starts_with("bafy"));
    assert_eq!(event.ops[0].path, "app.bsky.feed.post/3k1");
    assert!(event.ops[0].record_cid.is_some());

    for table in ["atproto_firehose", "atproto_firehose_ops"] {
        let columns: Vec<(String,)> = sqlx::query_as(
            "SELECT column_name FROM information_schema.columns WHERE table_name = $1",
        )
        .bind(table)
        .fetch_all(&pool)
        .await
        .unwrap();
        let names: Vec<&str> = columns.iter().map(|(c,)| c.as_str()).collect();
        for forbidden in ["record_body", "content", "value", "json"] {
            assert!(
                !names.iter().any(|n| n.contains(forbidden)),
                "{table} has a {forbidden}-shaped column: {names:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_delete_op_carries_no_record_cid() {
    let (_db, pool) = fresh().await;
    let event = firehose::record(
        &pool,
        &NewCommit {
            did: DID,
            commit_cid: "bafyreicommit1",
            prev_cid: None,
            rev: &Tid::new("3kaaaaaaaaaaa".into()).unwrap(),
            since_rev: None,
            prev_data: None,
            ops: vec![NewOp {
                action: Action::Delete,
                path: "app.bsky.feed.post/3k1".into(),
                record_cid: None,
                prev_cid: Some("bafyreirecord1".into()),
            }],
        },
    )
    .await
    .unwrap();

    assert_eq!(event.ops[0].action, Action::Delete);
    assert_eq!(event.ops[0].record_cid, None);

    let read = firehose::since(&pool, None, 10).await.unwrap();
    assert_eq!(read[0].ops[0].action, Action::Delete);
    assert_eq!(read[0].ops[0].record_cid, None);
}

#[tokio::test]
async fn every_action_survives_the_round_trip() {
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    for action in [Action::Create, Action::Update, Action::Delete] {
        firehose::record(
            &pool,
            &NewCommit {
                did: DID,
                commit_cid: "bafyreicommit",
                prev_cid: None,
                rev: &revs.next(),
                since_rev: None,
                prev_data: None,
                ops: vec![NewOp {
                    action,
                    path: "app.bsky.feed.post/3k1".into(),
                    record_cid: None,
                    prev_cid: None,
                }],
            },
        )
        .await
        .unwrap();
    }

    let events = firehose::since(&pool, None, 10).await.unwrap();
    let actions: Vec<Action> = events
        .iter()
        .flat_map(|e| e.ops.iter().map(|op| op.action))
        .collect();
    assert_eq!(
        actions,
        vec![Action::Create, Action::Update, Action::Delete]
    );
}

#[tokio::test]
async fn an_events_timestamp_survives_the_log_round_trip() {
    // `time` is the event's timestamp, plumbed from the row's `created_at`
    // (1, D): what `record` hands back is what `since` reads, and it renders
    // as the RFC 3339 the lexicon's datetime accepts.
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    let logged = commit(&pool, DID, 1, &revs.next(), vec![an_op(1)]).await;

    let read = firehose::since(&pool, None, 10).await.unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(
        read[0].time, logged.time,
        "the timestamp the log hands back must be the one the row kept"
    );
    assert!(
        read[0].time < OffsetDateTime::now_utc() + time::Duration::hours(1)
            && read[0].time > OffsetDateTime::now_utc() - time::Duration::hours(1),
        "the timestamp should be now-ish, not a default or an epoch"
    );

    // And the frame carries it in the form the wire wants.
    let decoded = decode(&frame_of(&read[0], &[]));
    assert_eq!(
        decoded.time.as_str(),
        read[0]
            .time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
}

// --- frames, against a foreign decoder (1, D) -------------------------------------

/// A store fixture, the same arrangement the repo and CAR-export tests use.
fn fixture() -> (tempfile::TempDir, brolly_store::StoreManager, uuid::Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    (dir, manager, uuid::Uuid::new_v4())
}

fn blocks(manager: &brolly_store::StoreManager, user: uuid::Uuid) -> PodBlocks {
    PodBlocks::new(manager.repo_blocks(user).unwrap())
}

/// The header a consumer dispatches on, decoded the way it reads it: one
/// DAG-CBOR object off the front, with the body still behind it (1, D).
#[derive(serde::Deserialize)]
struct FrameHeader {
    op: i64,
    t: String,
}

/// Decode a frame the way a foreign consumer does — dispatch on the header,
/// then decode the body as atrium-api's own `subscribeRepos` commit type, not
/// our frame function's inverse (1, D).
fn decode(frame: &[u8]) -> subscribe_repos::Commit {
    let mut reader = std::io::Cursor::new(frame);
    let header: FrameHeader =
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("the header decodes");
    assert_eq!(header.op, 1, "a commit frame is op 1");
    assert_eq!(header.t, "#commit", "this is a #commit frame");
    serde_ipld_dagcbor::de::from_reader_once(&mut reader)
        .expect("the body decodes as atrium's own type")
}

/// The event a write's announcement would log, built directly because the
/// framing is the subject here, not the log — the same fields `announce`
/// hands `record`, with a fixed timestamp.
fn the_event(seq: i64, applied: &repo::Applied, prev_cid: Option<&str>) -> CommitEvent {
    CommitEvent {
        seq,
        did: DID.into(),
        commit_cid: applied.commit.to_string(),
        prev_cid: prev_cid.map(str::to_string),
        rev: applied.rev.clone(),
        since_rev: Some(applied.since_rev.clone()),
        prev_data: Some(applied.prev_data.to_string()),
        time: OffsetDateTime::parse(
            "2026-10-07T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
        ops: applied
            .ops
            .iter()
            .map(|op| Op {
                action: op.action,
                path: op.path.clone(),
                record_cid: op.record_cid.map(|cid| cid.to_string()),
                prev_cid: op.prev_cid.map(|cid| cid.to_string()),
            })
            .collect(),
    }
}

/// The frame for an event: its CAR diff slice, built from the member's blocks
/// at emission time exactly as the subscriber path builds it (1, D, D5).
fn frame_of(event: &CommitEvent, car: &[u8]) -> Vec<u8> {
    firehose::frame(event, car).expect("the frame encodes")
}

/// The Sync spec's own validation, as our test (1, D): parse the frame's
/// blocks as a partial MST, apply the ops in reverse — a create deletes its
/// key; an update restores its `prev`; a delete re-adds its `prev`, pointers
/// only, no old record bytes, which is what the contextual nodes are for —
/// and require the recomputed root to equal `prevData`.
///
/// The CAR is parsed by `rs-car-sync` — not atrium's writer — with block-hash
/// validation on, and the reversal is driven through atrium's own tree ops,
/// so the test proves the slice is sufficient using nothing but itself.
async fn inverts_to_prev_data(decoded: &subscribe_repos::Commit) {
    let mut cursor = std::io::Cursor::new(&decoded.blocks[..]);
    let (car_blocks, header) = rs_car_sync::car_read_all(&mut cursor, true)
        .expect("an independent CAR reader must accept the diff slice");
    assert_eq!(header.roots.len(), 1, "a diff slice has exactly one root");
    assert_eq!(
        header.roots[0].to_string(),
        decoded.commit.0.to_string(),
        "the CAR's only root is the commit block"
    );

    let mut store = atrium_repo::blockstore::MemoryBlockStore::new();
    for (cid, bytes) in car_blocks {
        let written = store
            .write_block(
                atrium_repo::blockstore::DAG_CBOR,
                atrium_repo::blockstore::SHA2_256,
                &bytes,
            )
            .await
            .unwrap();
        assert_eq!(
            written.to_string(),
            cid.to_string(),
            "a block must hash to the CID it was filed under"
        );
    }

    // The new MST root hangs off the commit block.
    let commit_ipld: ipld_core::ipld::Ipld =
        serde_ipld_dagcbor::from_slice(&store.read_block(decoded.commit.0).await.unwrap()).unwrap();
    let new_root = match commit_ipld
        .get("data")
        .expect("an indexable map")
        .expect("the data field")
    {
        ipld_core::ipld::Ipld::Link(cid) => *cid,
        other => panic!("the commit block must name its MST root, got {other:?}"),
    };

    let mut tree = atrium_repo::mst::Tree::open(store, new_root);
    for op in decoded.ops.iter().rev() {
        let result = match op.action.as_str() {
            "create" => tree.delete(&op.path).await,
            "update" => {
                tree.update(&op.path, op.prev.clone().expect("an update carries prev").0)
                    .await
            }
            "delete" => {
                tree.add(&op.path, op.prev.clone().expect("a delete carries prev").0)
                    .await
            }
            other => panic!("an unknown action on the wire: {other}"),
        };
        match op.action.as_str() {
            "create" => result.expect("a create inverts"),
            "update" => result.expect("an update inverts"),
            "delete" => result.expect("a delete inverts"),
            _ => unreachable!(),
        }
    }
    assert_eq!(
        tree.root(),
        decoded
            .prev_data
            .clone()
            .expect("a commit with ops has a prevData")
            .0,
        "the reversed ops must recompute the previous MST root"
    );
}

/// A repo with one post in it, and the write that put it there.
async fn a_repo_with_a_post() -> (
    tempfile::TempDir,
    brolly_store::StoreManager,
    uuid::Uuid,
    SigningKey,
    repo::Applied,
    String,
) {
    let (dir, manager, user) = fixture();
    let key = SigningKey::generate();
    let (root, genesis) = repo::create(blocks(&manager, user), DID, &key)
        .await
        .unwrap();
    let applied = repo::apply(
        blocks(&manager, user),
        root,
        &key,
        vec![
            PlannedWrite::put(
                "app.bsky.feed.post",
                "3kaaaaaaaaaaa",
                &json!({"$type": "app.bsky.feed.post", "text": "hello atproto"}),
                RecordSwap::Any,
            )
            .unwrap(),
        ],
        &genesis,
    )
    .await
    .unwrap();
    (dir, manager, user, key, applied, root.to_string())
}

#[tokio::test]
async fn a_frame_is_what_atriums_decoder_expects() {
    // One create, end to end: the event's pointers become links, the slice
    // rides as bytes, and atrium's own type reads it all back (1, D).
    let (_dir, manager, user, _key, applied, prev_cid) = a_repo_with_a_post().await;
    let event = the_event(1, &applied, Some(&prev_cid));

    let mut member = blocks(&manager, user);
    let car = repo::event_diff_car(&mut member, &event).await.unwrap();
    let decoded = decode(&frame_of(&event, &car));

    assert_eq!(decoded.seq, 1);
    assert_eq!(decoded.repo.as_str(), DID);
    assert_eq!(decoded.commit.0, applied.commit);
    assert_eq!(decoded.rev, applied.rev);
    assert_eq!(decoded.since.as_ref(), Some(&applied.since_rev));
    assert_eq!(
        decoded.prev_data.as_ref().map(|l| l.0),
        Some(applied.prev_data)
    );
    assert_eq!(decoded.time.as_str(), "2026-10-07T12:00:00Z");
    assert_eq!(decoded.blocks, car);
    assert!(!decoded.too_big);
    assert!(decoded.blobs.is_empty());
    assert!(!decoded.rebase);
    assert_eq!(decoded.ops.len(), 1);
    assert_eq!(decoded.ops[0].action, "create");
    assert_eq!(decoded.ops[0].path, "app.bsky.feed.post/3kaaaaaaaaaaa");
    assert_eq!(
        decoded.ops[0].cid.as_ref().map(|l| l.0),
        applied.ops[0].record_cid
    );
    assert_eq!(decoded.ops[0].prev, None, "a create has no prev");

    inverts_to_prev_data(&decoded).await;
}

#[tokio::test]
async fn every_op_kind_rides_the_frames_and_inverts() {
    // The fixture the frame work needed chunk 2 for: every action on the
    // wire, each with the `prev` it must carry, and a reversal per commit
    // that has to undo them all (1, B, 1, D). Two commits, so the second
    // deletes a record whose value predates it — the case where "never a
    // deleted record's old value" is a real exclusion rather than an
    // accident of the batch.
    let (_dir, manager, user) = fixture();
    let key = SigningKey::generate();
    let (root, genesis) = repo::create(blocks(&manager, user), DID, &key)
        .await
        .unwrap();

    let first = repo::apply(
        blocks(&manager, user),
        root,
        &key,
        vec![
            PlannedWrite::put(
                "app.bsky.feed.post",
                "3kaaaaaaaaaaa",
                &json!({"$type": "app.bsky.feed.post", "text": "a one"}),
                RecordSwap::Any,
            )
            .unwrap(),
            PlannedWrite::put(
                "app.bsky.feed.post",
                "3kbbbbbbbbbbb",
                &json!({"$type": "app.bsky.feed.post", "text": "b one"}),
                RecordSwap::Any,
            )
            .unwrap(),
        ],
        &genesis,
    )
    .await
    .unwrap();
    assert_eq!(first.ops.len(), 2);

    let second = repo::apply(
        blocks(&manager, user),
        first.commit,
        &key,
        vec![
            // An update of the first commit's record, and a delete of the
            // second's — both named by the `prev` they carry on the wire.
            PlannedWrite::update(
                "app.bsky.feed.post",
                "3kaaaaaaaaaaa",
                &json!({"$type": "app.bsky.feed.post", "text": "a two"}),
            )
            .unwrap(),
            PlannedWrite::delete("app.bsky.feed.post", "3kbbbbbbbbbbb").unwrap(),
        ],
        &first.rev,
    )
    .await
    .unwrap();
    assert_eq!(second.ops.len(), 2);

    // The first frame: two creates.
    let event = the_event(1, &first, Some(&root.to_string()));
    let mut member = blocks(&manager, user);
    let car = repo::event_diff_car(&mut member, &event).await.unwrap();
    let decoded = decode(&frame_of(&event, &car));
    assert_eq!(decoded.ops.len(), 2, "one op per write (1, B)");
    assert_eq!(decoded.ops[0].action, "create");
    assert_eq!(decoded.ops[0].prev, None);
    assert_eq!(decoded.ops[1].action, "create");
    assert_eq!(decoded.ops[1].prev, None);
    inverts_to_prev_data(&decoded).await;

    // The second frame: the update and the delete, with the `prev` each
    // requires (1, D).
    let event = the_event(2, &second, Some(&first.commit.to_string()));
    let mut member = blocks(&manager, user);
    let car = repo::event_diff_car(&mut member, &event).await.unwrap();
    let decoded = decode(&frame_of(&event, &car));

    assert_eq!(decoded.ops.len(), 2);
    assert_eq!(decoded.ops[0].action, "update");
    assert_eq!(
        decoded.ops[0].prev.as_ref().map(|l| l.0),
        first.ops[0].record_cid,
        "the update's prev is the record it replaced (1, D)"
    );
    assert_eq!(decoded.ops[1].action, "delete");
    assert_eq!(decoded.ops[1].cid, None, "a delete announces no record CID");
    assert_eq!(
        decoded.ops[1].prev.as_ref().map(|l| l.0),
        first.ops[1].record_cid,
        "the delete's prev is the record it removed (1, D)"
    );

    // The slice carries the new values and never the old ones: the update's
    // replacement is in, the record it replaced and the record the delete
    // removed are not (1, D).
    let mut cursor = std::io::Cursor::new(&decoded.blocks[..]);
    let (car_blocks, _) = rs_car_sync::car_read_all(&mut cursor, true).unwrap();
    let block_cids: Vec<String> = car_blocks.iter().map(|(cid, _)| cid.to_string()).collect();
    assert!(
        block_cids.contains(&second.ops[0].record_cid.unwrap().to_string()),
        "the updated record's new value is in the slice"
    );
    assert!(
        !block_cids.contains(&first.ops[0].record_cid.unwrap().to_string()),
        "the updated record's old value is not in the slice"
    );
    assert!(
        !block_cids.contains(&first.ops[1].record_cid.unwrap().to_string()),
        "a deleted record's old value is never in the slice"
    );

    inverts_to_prev_data(&decoded).await;
}

#[tokio::test]
async fn a_blob_link_rides_the_diff_and_inverts() {
    // H's seam in chunk 3: a record block carrying a CID link rides the slice
    // and inverts like any other block — the blob ref is a link inside the
    // record, not a mechanism of the event (1, H, 1, D).
    let (_dir, manager, user) = fixture();
    let key = SigningKey::generate();
    let (root, genesis) = repo::create(blocks(&manager, user), DID, &key)
        .await
        .unwrap();

    let record = json!({
        "$type": "app.bsky.feed.post",
        "text": "with an image",
        "image": {
            "$type": "blob",
            "ref": "bafkreig7fderwgqduywg2x3jlygcgszsozt4xcctjkykzkdxvxdvhxrdvy",
            "mimeType": "image/png",
            "size": 1234,
        },
    });
    let applied = repo::apply(
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

    let event = the_event(1, &applied, Some(&root.to_string()));
    let mut member = blocks(&manager, user);
    let car = repo::event_diff_car(&mut member, &event).await.unwrap();
    let decoded = decode(&frame_of(&event, &car));

    // The record block — blob link inside — is in the slice.
    let mut cursor = std::io::Cursor::new(&decoded.blocks[..]);
    let (car_blocks, _) = rs_car_sync::car_read_all(&mut cursor, true).unwrap();
    let record_cid = applied.ops[0].record_cid.unwrap().to_string();
    let record_block = car_blocks
        .iter()
        .find(|(cid, _)| cid.to_string() == record_cid)
        .expect("the blob-carrying record block is in the slice");
    let record_ipld: ipld_core::ipld::Ipld =
        serde_ipld_dagcbor::from_slice(record_block.1.as_slice()).unwrap();
    let image_ref = record_ipld
        .get("image")
        .expect("an indexable map")
        .expect("the image field")
        .get("ref")
        .expect("an indexable map")
        .expect("the ref field");
    assert!(
        matches!(image_ref, ipld_core::ipld::Ipld::Link(_)),
        "the blob ref must ride the slice as a CID link (1, H)"
    );

    inverts_to_prev_data(&decoded).await;
}

#[tokio::test]
async fn a_long_historys_commits_each_invert() {
    // The contextual-node set has to hold across real tree shape, not just the
    // first few keys: several commits over a repo of dozens of records, each
    // framed and inverted on its own slice (1, D).
    let (_dir, manager, user) = fixture();
    let key = SigningKey::generate();
    let (mut root, mut rev) = repo::create(blocks(&manager, user), DID, &key)
        .await
        .unwrap();

    let mut seq = 0;
    let mut history: Vec<String> = Vec::new();
    // Three commits over a growing repo: bulk creates, then updates and
    // deletes interleaved with more creates, then the same against a tree
    // that already has shape. Each round touches different keys than the last
    // round's deletes, so every op lands on a record that exists.
    for round in 0..3 {
        let mut writes = Vec::new();
        for n in 0..12 {
            let rkey = format!("3k{}{}", ["a", "b", "c"][round], n);
            writes.push(
                PlannedWrite::put(
                    "app.bsky.feed.post",
                    &rkey,
                    &json!({"$type": "app.bsky.feed.post", "text": format!("{rkey} one")}),
                    RecordSwap::Any,
                )
                .unwrap(),
            );
        }
        if round > 0 {
            // Updates and deletes of the previous round's creates — disjoint
            // key ranges, so every op lands on a record that exists and no
            // key is written twice within the stage.
            let prior = ["a", "a", "b"][round];
            for n in 0..4 {
                writes.push(
                    PlannedWrite::update(
                        "app.bsky.feed.post",
                        &format!("3k{prior}{n}"),
                        &json!({"$type": "app.bsky.feed.post", "text": format!("3k{prior}{n} two")}),
                    )
                    .unwrap(),
                );
            }
            for n in 4..8 {
                writes.push(
                    PlannedWrite::delete("app.bsky.feed.post", &format!("3k{prior}{n}")).unwrap(),
                );
            }
        }

        let applied = repo::apply(blocks(&manager, user), root, &key, writes, &rev)
            .await
            .unwrap();
        seq += 1;
        let event = the_event(seq, &applied, history.last().map(String::as_str));
        let mut member = blocks(&manager, user);
        let car = repo::event_diff_car(&mut member, &event).await.unwrap();
        let decoded = decode(&frame_of(&event, &car));
        assert_eq!(
            decoded.prev_data.as_ref().map(|l| l.0),
            Some(applied.prev_data),
            "prevData must be the MST root this commit replaced (1, A)"
        );
        inverts_to_prev_data(&decoded).await;

        history.push(applied.commit.to_string());
        root = applied.commit;
        rev = applied.rev;
    }
}

#[tokio::test]
async fn a_record_the_slice_needs_is_actually_there() {
    // The slice is a pointer set plus derived bytes, so say so concretely:
    // the CAR carries the commit block, and the record block, and the MST
    // nodes — and nothing from the previous revision's records (1, D).
    let (_dir, manager, user, _key, applied, _prev) = a_repo_with_a_post().await;
    let event = the_event(1, &applied, None);
    let mut member = blocks(&manager, user);
    let car = repo::event_diff_car(&mut member, &event).await.unwrap();
    let decoded = decode(&frame_of(&event, &car));

    let mut cursor = std::io::Cursor::new(&decoded.blocks[..]);
    let (car_blocks, _) = rs_car_sync::car_read_all(&mut cursor, true).unwrap();
    assert!(
        car_blocks.len() >= 3,
        "the slice should carry the commit block, the new MST nodes, and the record: {}",
        car_blocks.len()
    );
    assert!(
        car_blocks
            .iter()
            .any(|(_, bytes)| String::from_utf8_lossy(bytes).contains("hello atproto"))
    );
    // And the record reads back as the JSON that named it — via the member's
    // own store, the way a syncing consumer would rehydrate it.
    let read = repo::get_record(
        blocks(&manager, user),
        applied.commit,
        "app.bsky.feed.post",
        "3kaaaaaaaaaaa",
    )
    .await
    .unwrap();
    assert_eq!(
        read,
        Some(json!({"$type": "app.bsky.feed.post", "text": "hello atproto"}))
    );
}
