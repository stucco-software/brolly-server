//! The commit event log behind `subscribeRepos`.
//!
//! The property that matters is resumption: a relay that drops must be able to
//! come back with a cursor and receive exactly what it missed — no gap, no
//! duplicate. A gap loses posts silently; a duplicate at the page boundary is
//! the classic resume bug, and it shows up as a doubled post rather than an
//! error anyone notices.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use atrium_api::types::string::Tid;
use brolly_atproto::firehose::{self, Action};
use brolly_identity::db::MIGRATOR;
use sqlx::PgPool;

const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

async fn commit(pool: &PgPool, did: &str, n: i64, rev: &Tid) -> firehose::CommitEvent {
    firehose::record(
        pool,
        did,
        &format!("bafyreicommit{n}"),
        (n > 1)
            .then(|| format!("bafyreicommit{}", n - 1))
            .as_deref(),
        rev,
        Action::Create,
        &format!("app.bsky.feed.post/3k{n}"),
        Some(&format!("bafyreirecord{n}")),
    )
    .await
    .expect("record")
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
    let first = commit(&pool, DID, 1, &alice.next()).await;
    let other = commit(&pool, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", 1, &bob.next()).await;
    let third = commit(&pool, DID, 2, &alice.next()).await;

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
        commit(&pool, DID, n, &previous).await;
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
async fn a_consumer_resumes_from_its_cursor_without_a_gap_or_a_duplicate() {
    // The whole point of the log outliving the connection.
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    for n in 1..=5 {
        commit(&pool, DID, n, &revs.next()).await;
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
        commit(&pool, DID, n, &revs.next()).await;
    }
    assert_eq!(firehose::since(&pool, None, 100).await.unwrap().len(), 3);
}

#[tokio::test]
async fn a_consumer_at_the_head_receives_nothing_until_something_happens() {
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    commit(&pool, DID, 1, &revs.next()).await;

    let head = firehose::head(&pool).await.unwrap().expect("a head");
    assert!(
        firehose::since(&pool, Some(head), 100)
            .await
            .unwrap()
            .is_empty()
    );

    let second = revs.next();
    commit(&pool, DID, 2, &second).await;
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
        commit(&pool, DID, n, &revs.next()).await;
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
    let event = commit(&pool, DID, 1, &revs.next()).await;

    assert_eq!(event.did, DID);
    assert!(event.commit_cid.starts_with("bafy"));
    assert_eq!(event.path, "app.bsky.feed.post/3k1");
    assert!(event.record_cid.is_some());

    let columns: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'atproto_firehose'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let names: Vec<&str> = columns.iter().map(|(c,)| c.as_str()).collect();
    for forbidden in ["record_body", "content", "value", "json"] {
        assert!(
            !names.iter().any(|n| n.contains(forbidden)),
            "the firehose log has a {forbidden}-shaped column: {names:?}"
        );
    }
}

#[tokio::test]
async fn a_delete_carries_no_record_cid() {
    let (_db, pool) = fresh().await;
    let event = firehose::record(
        &pool,
        DID,
        "bafyreicommit1",
        None,
        &Tid::new("3kaaaaaaaaaaa".into()).unwrap(),
        Action::Delete,
        "app.bsky.feed.post/3k1",
        None,
    )
    .await
    .unwrap();

    assert_eq!(event.action, Action::Delete);
    assert_eq!(event.record_cid, None);

    let read = firehose::since(&pool, None, 10).await.unwrap();
    assert_eq!(read[0].action, Action::Delete);
    assert_eq!(read[0].record_cid, None);
}

#[tokio::test]
async fn every_action_survives_the_round_trip() {
    let (_db, pool) = fresh().await;
    let mut revs = Revs::new();
    for (n, action) in [Action::Create, Action::Update, Action::Delete]
        .into_iter()
        .enumerate()
    {
        firehose::record(
            &pool,
            DID,
            &format!("bafyreicommit{n}"),
            None,
            &revs.next(),
            action,
            "app.bsky.feed.post/3k1",
            None,
        )
        .await
        .unwrap();
    }

    let events = firehose::since(&pool, None, 10).await.unwrap();
    let actions: Vec<Action> = events.iter().map(|e| e.action).collect();
    assert_eq!(
        actions,
        vec![Action::Create, Action::Update, Action::Delete]
    );
}
