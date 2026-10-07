//! Repo state against a real Postgres.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use atrium_api::types::string::Tid;
use brolly_atproto::state;
use brolly_identity::db::{self, MIGRATOR};
use sqlx::PgPool;
use uuid::Uuid;

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

async fn a_user(pool: &PgPool, username: &str) -> Uuid {
    db::create_user(pool, username, None, "correct-horse-battery", "member")
        .await
        .expect("create user")
        .id
}

/// A fixed head to start from, so the guard's arithmetic is pinned rather than
/// racing the clock.
fn a_rev() -> Tid {
    Tid::new("3kaaaaaaaaaaa".into()).expect("a valid TID")
}

#[tokio::test]
async fn a_repo_records_where_it_points() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;

    let rev = a_rev();
    state::create(&pool, user, "bafyroot0", &rev)
        .await
        .expect("create");
    let loaded = state::load(&pool, user).await.unwrap().expect("a repo");
    assert_eq!(loaded.root_cid, "bafyroot0");
    assert_eq!(
        loaded.rev, rev,
        "the stored rev is the genesis commit's own"
    );
}

#[tokio::test]
async fn a_second_genesis_is_refused() {
    // Overwriting would orphan every block the first repo reached.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    state::create(&pool, user, "bafyroot0", &a_rev())
        .await
        .unwrap();

    assert!(
        state::create(&pool, user, "bafyother", &a_rev())
            .await
            .is_err(),
        "a member must not get a second genesis commit"
    );
    assert_eq!(
        state::load(&pool, user).await.unwrap().unwrap().root_cid,
        "bafyroot0"
    );
}

#[tokio::test]
async fn advancing_moves_the_root_and_the_revision_together() {
    // A reader must never see a new root at an old revision — that is what a
    // sync consumer uses to decide whether it is behind.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let genesis = a_rev();
    state::create(&pool, user, "bafyroot0", &genesis)
        .await
        .unwrap();

    let rev = state::advance(
        &pool,
        user,
        "bafyroot0",
        "bafyroot1",
        &brolly_atproto::tid::mint_after(&genesis),
    )
    .await
    .expect("advance");
    assert!(
        rev.as_str() > genesis.as_str(),
        "the new rev must clear the old: {} -> {}",
        genesis.as_str(),
        rev.as_str()
    );

    let loaded = state::load(&pool, user).await.unwrap().unwrap();
    assert_eq!(loaded.root_cid, "bafyroot1");
    assert_eq!(loaded.rev, rev);
}

#[tokio::test]
async fn revisions_increase_monotonically() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let mut previous = a_rev();
    state::create(&pool, user, "bafyroot0", &previous)
        .await
        .unwrap();

    let mut root = "bafyroot0".to_string();
    for n in 1..=5 {
        let next = format!("bafyroot{n}");
        let rev = brolly_atproto::tid::mint_after(&previous);
        let stored = state::advance(&pool, user, &root, &next, &rev)
            .await
            .unwrap();
        assert!(
            stored.as_str() > previous.as_str(),
            "revision went backwards: {} -> {}",
            previous.as_str(),
            stored.as_str()
        );
        previous = stored;
        root = next;
    }
}

#[tokio::test]
async fn advancing_from_a_stale_root_is_a_conflict() {
    // The lost update this stage exists to prevent: a second writer still
    // holding the root it read must not overwrite the first's commit (1, C).
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let genesis = a_rev();
    state::create(&pool, user, "bafyroot0", &genesis)
        .await
        .unwrap();

    let first = brolly_atproto::tid::mint_after(&genesis);
    state::advance(&pool, user, "bafyroot0", "bafyroot1", &first)
        .await
        .expect("the first writer moves the head");

    // The second writer's compare-and-set names the root it read — root0 —
    // which the head no longer holds.
    let second = brolly_atproto::tid::mint_after(&first);
    let raced = state::advance(&pool, user, "bafyroot0", "bafyroot2", &second).await;
    assert!(
        matches!(raced, Err(state::AdvanceError::Conflict)),
        "a stale root must conflict, not overwrite"
    );

    // No orphan: the head points at exactly the first writer's commit.
    let loaded = state::load(&pool, user).await.unwrap().unwrap();
    assert_eq!(loaded.root_cid, "bafyroot1");
    assert_eq!(loaded.rev, first);

    // From the *current* root, the same move succeeds and returns the new rev.
    let from_current = state::advance(&pool, user, "bafyroot1", "bafyroot2", &second).await;
    assert_eq!(from_current.unwrap(), second);
}

#[tokio::test]
async fn a_rev_that_does_not_clear_the_head_is_refused() {
    // The clock stepped backwards, or a retry landed in the same millisecond:
    // the minted rev does not clear the stored one, and the guard refuses it
    // (1, C). The retry — minted past the stored rev — then succeeds, which
    // is why the mint guarantees progress rather than the guard forgiving.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let genesis = a_rev();
    state::create(&pool, user, "bafyroot0", &genesis)
        .await
        .unwrap();

    let refused = state::advance(&pool, user, "bafyroot0", "bafyroot1", &genesis).await;
    assert!(
        matches!(refused, Err(state::AdvanceError::Conflict)),
        "a rev that does not clear the head must not move it"
    );
    assert_eq!(
        state::load(&pool, user).await.unwrap().unwrap().rev,
        genesis,
        "the refused write moved nothing"
    );

    let retry = brolly_atproto::tid::mint_after(&genesis);
    let stored = state::advance(&pool, user, "bafyroot0", "bafyroot1", &retry)
        .await
        .expect("the reminted rev moves the head");
    assert_eq!(stored, retry);
}

#[tokio::test]
async fn a_raced_head_loses_exactly_one_side() {
    // The spec's lost-update race, minus the chunk-2 retry: two writers from
    // the same root, and exactly one compare-and-set may succeed (1, C).
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let genesis = a_rev();
    state::create(&pool, user, "bafyroot0", &genesis)
        .await
        .unwrap();

    let rev_a = brolly_atproto::tid::mint_after(&genesis);
    let rev_b = brolly_atproto::tid::mint_after(&rev_a);
    let (a, b) = tokio::join!(
        state::advance(&pool, user, "bafyroot0", "bafyrootA", &rev_a),
        state::advance(&pool, user, "bafyroot0", "bafyrootB", &rev_b),
    );
    assert!(
        a.is_ok() ^ b.is_ok(),
        "exactly one racer may move the head: {a:?} vs {b:?}"
    );
    assert!(
        matches!(a, Err(state::AdvanceError::Conflict))
            || matches!(b, Err(state::AdvanceError::Conflict)),
        "the loser is a conflict, not a database failure"
    );

    // No orphan: the head holds exactly one of the two commits, at its rev.
    let loaded = state::load(&pool, user).await.unwrap().unwrap();
    match loaded.root_cid.as_str() {
        "bafyrootA" => assert_eq!(loaded.rev, rev_a),
        "bafyrootB" => assert_eq!(loaded.rev, rev_b),
        other => panic!("the head points at neither racer: {other}"),
    }
}

#[tokio::test]
async fn advancing_a_repo_that_does_not_exist_is_an_error() {
    // Not a silent no-op: that would mean a commit was written to blocks and
    // then forgotten, leaving the repo pointing at the previous root forever.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    assert!(
        state::advance(
            &pool,
            user,
            "bafyroot0",
            "bafyroot1",
            &brolly_atproto::tid::mint_after(&a_rev())
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn one_members_repo_is_not_anothers() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let bob = a_user(&pool, "bob").await;

    let alices = a_rev();
    let bobs = brolly_atproto::tid::mint_after(&alices);
    state::create(&pool, alice, "bafyalice", &alices)
        .await
        .unwrap();
    state::create(&pool, bob, "bafybob", &bobs).await.unwrap();
    state::advance(
        &pool,
        alice,
        "bafyalice",
        "bafyalice2",
        &brolly_atproto::tid::mint_after(&alices),
    )
    .await
    .unwrap();

    let bobs_state = state::load(&pool, bob).await.unwrap().unwrap();
    assert_eq!(bobs_state.root_cid, "bafybob");
    assert_eq!(bobs_state.rev, bobs);
}

#[tokio::test]
async fn deleting_a_member_takes_their_repo_pointer() {
    // The blocks go with the pod directory; this must not outlive them.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    state::create(&pool, user, "bafyroot0", &a_rev())
        .await
        .unwrap();

    db::delete_user(&pool, user).await.unwrap();

    assert_eq!(state::load(&pool, user).await.unwrap(), None);
}

#[tokio::test]
async fn no_record_content_is_stored_alongside_the_pointer() {
    // The test every Postgres table here has to pass: losing it costs a
    // rebuild, not data. A record body here would quietly make Postgres a
    // second source of truth (D2, ADR 0005).
    let (_db, pool) = fresh().await;
    let columns: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'atproto_repos'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let names: Vec<&str> = columns.iter().map(|(c,)| c.as_str()).collect();
    for forbidden in ["record", "content", "body", "json", "value"] {
        assert!(
            !names.iter().any(|n| n.contains(forbidden)),
            "atproto_repos has a {forbidden}-shaped column: {names:?}"
        );
    }
}
