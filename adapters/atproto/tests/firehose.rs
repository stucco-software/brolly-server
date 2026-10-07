//! The commit event log behind `subscribeRepos`.
//!
//! The property that matters is resumption: a relay that drops must be able to
//! come back with a cursor and receive exactly what it missed — no gap, no
//! duplicate. A gap loses posts silently; a duplicate at the page boundary is
//! the classic resume bug, and it shows up as a doubled post rather than an
//! error anyone notices.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use atrium_api::types::string::Tid;
use brolly_atproto::firehose::{self, Action, NewCommit, NewOp};
use brolly_identity::db::MIGRATOR;
use sqlx::PgPool;

const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
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
            commit_cid: &format!("bafyreicommit{n}"),
            prev_cid: (n > 1)
                .then(|| format!("bafyreicommit{}", n - 1))
                .as_deref(),
            rev,
            since_rev: None,
            prev_data: (n > 1).then(|| format!("bafyreidata{}", n - 1)).as_deref(),
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
        record_cid: Some(format!("bafyreirecord{n}")),
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
