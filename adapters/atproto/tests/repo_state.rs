//! Repo state against a real Postgres.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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

#[tokio::test]
async fn a_repo_records_where_it_points() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;

    state::create(&pool, user, "bafyroot0")
        .await
        .expect("create");
    let loaded = state::load(&pool, user).await.unwrap().expect("a repo");
    assert_eq!(loaded.root_cid, "bafyroot0");
    assert_eq!(loaded.rev, 0, "a fresh repo starts at revision zero");
}

#[tokio::test]
async fn a_second_genesis_is_refused() {
    // Overwriting would orphan every block the first repo reached.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    state::create(&pool, user, "bafyroot0").await.unwrap();

    assert!(
        state::create(&pool, user, "bafyother").await.is_err(),
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
    state::create(&pool, user, "bafyroot0").await.unwrap();

    let rev = state::advance(&pool, user, "bafyroot1")
        .await
        .expect("advance");
    assert_eq!(rev, 1);

    let loaded = state::load(&pool, user).await.unwrap().unwrap();
    assert_eq!(loaded.root_cid, "bafyroot1");
    assert_eq!(loaded.rev, 1);
}

#[tokio::test]
async fn revisions_increase_monotonically() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    state::create(&pool, user, "bafyroot0").await.unwrap();

    let mut previous = 0;
    for n in 1..=5 {
        let rev = state::advance(&pool, user, &format!("bafyroot{n}"))
            .await
            .unwrap();
        assert!(
            rev > previous,
            "revision went backwards: {previous} -> {rev}"
        );
        previous = rev;
    }
}

#[tokio::test]
async fn advancing_a_repo_that_does_not_exist_is_an_error() {
    // Not a silent no-op: that would mean a commit was written to blocks and
    // then forgotten, leaving the repo pointing at the previous root forever.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    assert!(state::advance(&pool, user, "bafyroot1").await.is_err());
}

#[tokio::test]
async fn one_members_repo_is_not_anothers() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let bob = a_user(&pool, "bob").await;

    state::create(&pool, alice, "bafyalice").await.unwrap();
    state::create(&pool, bob, "bafybob").await.unwrap();
    state::advance(&pool, alice, "bafyalice2").await.unwrap();

    let bobs = state::load(&pool, bob).await.unwrap().unwrap();
    assert_eq!(bobs.root_cid, "bafybob");
    assert_eq!(bobs.rev, 0);
}

#[tokio::test]
async fn deleting_a_member_takes_their_repo_pointer() {
    // The blocks go with the pod directory; this must not outlive them.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    state::create(&pool, user, "bafyroot0").await.unwrap();

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
