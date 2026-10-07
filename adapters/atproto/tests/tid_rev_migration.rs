//! The rev-conversion migration, against seeded rows.
//!
//! The migration's whole job is to take the tables as the old binary left
//! them — BIGINT counters, timestamps that collide — and leave them holding
//! per-repo strictly increasing TIDs (1, A). So the test builds the old shape
//! for real: everything before this stage's rev change applies, then rows the
//! old binary could have written, then the conversion itself through the full
//! migrator, exactly as a deploy would run it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use atrium_api::types::string::Tid;
use brolly_identity::db::{self, MIGRATOR};
use sqlx::PgPool;

/// Everything before the rev change. The full migrator then runs on top and
/// applies only the new migrations — the same sequence a deploy follows.
async fn pre_change_schema() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    let before = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|m| m.version < 20261007000001)
                .cloned()
                .collect(),
        ),
        ignore_missing: MIGRATOR.ignore_missing,
        locking: MIGRATOR.locking,
        no_tx: MIGRATOR.no_tx,
    };
    before.run(&db.pool).await.expect("the old schema applies");
    let pool = db.pool.clone();
    (db, pool)
}

/// The base32 of a 64-bit TID value — a local reimplementation, so the test
/// checks the migration's encoding against something the migration did not
/// use. `0` encodes as `"2222222222222"`, `1` as `"2222222222223"`, the
/// vectors atrium-api's own tests pin.
fn s32(mut value: i64) -> String {
    const ALPHABET: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::with_capacity(13);
    for _ in 0..13 {
        out.push(ALPHABET[(value & 0x1f) as usize]);
        value >>= 5;
    }
    out.reverse();
    String::from_utf8(out).expect("the alphabet is ascii")
}

async fn a_member(pool: &PgPool, username: &str, did: &str) -> uuid::Uuid {
    let user = db::create_user(pool, username, None, "correct-horse-battery", "member")
        .await
        .unwrap();
    sqlx::query("UPDATE users SET did_plc = $1 WHERE id = $2")
        .bind(did)
        .bind(user.id)
        .execute(pool)
        .await
        .unwrap();
    user.id
}

async fn an_event(pool: &PgPool, did: &str, n: i64, rev: i64, created_at: &str) {
    sqlx::query(
        "INSERT INTO atproto_firehose
           (did, commit_cid, prev_cid, rev, action, path, record_cid, created_at)
         VALUES ($1, $2, $3, $4, 'create', $5, $6, $7::timestamptz)",
    )
    .bind(did)
    .bind(format!("bafyreicommit{n}"))
    .bind((n > 1).then(|| format!("bafyreicommit{}", n - 1)))
    .bind(rev)
    .bind(format!("app.bsky.feed.post/3k{n}"))
    .bind(format!("bafyreirecord{n}"))
    .bind(created_at)
    .execute(pool)
    .await
    .unwrap();
}

/// Every rev a repo's events hold, in seq order.
async fn event_revs(pool: &PgPool, did: &str) -> Vec<String> {
    sqlx::query_as::<_, (String,)>("SELECT rev FROM atproto_firehose WHERE did = $1 ORDER BY seq")
        .bind(did)
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|(rev,)| rev)
        .collect()
}

#[tokio::test]
async fn seeded_rows_become_strictly_increasing_tids_per_repo() {
    let (_db, pool) = pre_change_schema().await;

    let alice = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let alice_id = a_member(&pool, "alice", alice).await;
    sqlx::query("INSERT INTO atproto_repos (user_id, root_cid, rev) VALUES ($1, $2, $3)")
        .bind(alice_id)
        .bind("bafyalice")
        .bind(5_i64)
        .execute(&pool)
        .await
        .unwrap();

    // Timestamps a real log produces: two rows in the same microsecond, then
    // one stamped *earlier* — the clock stepped backwards. Seq order must win.
    an_event(&pool, alice, 1, 1, "1970-01-01 00:00:01+00").await;
    an_event(&pool, alice, 2, 2, "1970-01-01 00:00:01+00").await;
    an_event(&pool, alice, 3, 3, "1970-01-01 00:00:00.5+00").await;

    // A second repo, so per-repo ordering is shown to be per-repo.
    let bob = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    let bob_id = a_member(&pool, "bob", bob).await;
    sqlx::query(
        "INSERT INTO atproto_repos (user_id, root_cid, rev, updated_at) VALUES ($1, $2, $3, $4::timestamptz)",
    )
    .bind(bob_id)
    .bind("bafybob")
    .bind(0_i64)
    // Bob's head was updated before his one (future-dated) event — the
    // case where the head must be raised to the event's rev, or the next
    // write could mint past the head but not past the log.
    .bind("2020-01-01 00:00:00+00")
    .execute(&pool)
    .await
    .unwrap();
    an_event(&pool, bob, 1, 1, "2026-10-01 00:00:00+00").await;

    // Carol provisioned but never posted: a head with no events at all.
    let carol = "did:plc:cccccccccccccccccccccccc";
    let carol_id = a_member(&pool, "carol", carol).await;
    sqlx::query(
        "INSERT INTO atproto_repos (user_id, root_cid, rev, updated_at) VALUES ($1, $2, $3, $4::timestamptz)",
    )
    .bind(carol_id)
    .bind("bafycarol")
    .bind(0_i64)
    .bind("1970-01-01 00:00:02+00")
    .execute(&pool)
    .await
    .unwrap();

    // The deploy: the full migrator applies the rev change on top.
    MIGRATOR.run(&pool).await.expect("the conversion applies");

    // Alice's events: all valid TIDs, strictly increasing in seq order —
    // the same-microsecond pair and the backwards clock both included.
    let alice_revs = event_revs(&pool, alice).await;
    assert_eq!(alice_revs.len(), 3);
    for rev in &alice_revs {
        assert!(Tid::new(rev.clone()).is_ok(), "{rev} is not a TID");
    }
    for pair in alice_revs.windows(2) {
        assert!(
            pair[1] > pair[0],
            "derived revs must increase per repo: {} -> {}",
            pair[0],
            pair[1]
        );
    }

    // The derivation is pinned, not just ordered: the first row is the TID of
    // its own timestamp, and the same-microsecond second row is one past it.
    let first = 1_000_000_i64 << 10; // 1970-01-01T00:00:01Z, in microseconds
    assert_eq!(alice_revs[0], s32(first));
    assert_eq!(
        alice_revs[1],
        s32(first + 1),
        "the same-millisecond tie must break by +1"
    );
    assert_eq!(
        alice_revs[2],
        s32(first + 2),
        "the backwards clock must not go backwards"
    );

    // Alice's head: at least her last event's rev — never below the log.
    let (alice_head,): (String,) =
        sqlx::query_as("SELECT rev FROM atproto_repos WHERE user_id = $1")
            .bind(alice_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        alice_head >= alice_revs[2],
        "the head must not sit below the log: {alice_head} < {}",
        alice_revs[2]
    );

    // Bob's head was raised to his event's rev, which his own updated_at
    // derivation would not have reached.
    let (bob_head,): (String,) = sqlx::query_as("SELECT rev FROM atproto_repos WHERE user_id = $1")
        .bind(bob_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let bob_revs = event_revs(&pool, bob).await;
    assert_eq!(
        bob_head, bob_revs[0],
        "a head older than the log must be raised to it"
    );

    // Carol's head is her own timestamp's TID: a repo with no events keeps a
    // valid rev.
    let (carol_head,): (String,) =
        sqlx::query_as("SELECT rev FROM atproto_repos WHERE user_id = $1")
            .bind(carol_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(carol_head, s32(2_000_000_i64 << 10));

    // The frame columns exist and hold nothing yet — chunk 2 and 3 write
    // them; an unwritten nullable column is the expected state at this stage.
    let unwritten: Vec<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT since_rev, prev_data FROM atproto_firehose ORDER BY seq")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(unwritten.len(), 4);
    assert!(
        unwritten
            .iter()
            .all(|(since, prev)| since.is_none() && prev.is_none())
    );
}
