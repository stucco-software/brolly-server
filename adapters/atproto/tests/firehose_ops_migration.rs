//! The ops-table migration, against seeded rows.
//!
//! The migration's job is to take the log as the old binary left it — one op
//! per event, carried on the event row itself — and leave it holding one event
//! row per commit with the ops beside it, one row per write (1, B). So the
//! test builds the old shape for real: everything before this stage's ops
//! change applies, then rows the old binary could have written, then the
//! conversion through the full migrator, exactly as a deploy would run it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::db::MIGRATOR;
use sqlx::PgPool;

/// Everything before the ops change. The full migrator then runs on top and
/// applies only the new migration — the same sequence a deploy follows.
async fn pre_change_schema() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    let before = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|m| m.version < 20261008000001)
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

#[tokio::test]
async fn single_op_events_become_ops_rows_and_the_columns_go() {
    let (_db, pool) = pre_change_schema().await;

    // Two events the old binary could have written: the log's whole shape
    // was one op per event, carried on the event row.
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    for (n, action, record_cid) in [(1, "create", Some("bafyreirecord1")), (2, "delete", None)] {
        sqlx::query(
            "INSERT INTO atproto_firehose
               (did, commit_cid, prev_cid, rev, action, path, record_cid)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(did)
        .bind(format!("bafyreicommit{n}"))
        .bind((n > 1).then(|| format!("bafyreicommit{}", n - 1)))
        .bind(if n == 1 {
            "3kaaaaaaaaaaa"
        } else {
            "3kaaaaaaaaaab"
        })
        .bind(action)
        .bind(format!("app.bsky.feed.post/3k{n}"))
        .bind(record_cid)
        .execute(&pool)
        .await
        .unwrap();
    }

    // The deploy: the full migrator applies the ops change on top.
    MIGRATOR.run(&pool).await.expect("the conversion applies");

    // The ops moved, values intact, at position 0 in seq order.
    let ops: Vec<(i64, i32, String, String, Option<String>)> = sqlx::query_as(
        "SELECT seq, position, action, path, record_cid
             FROM atproto_firehose_ops ORDER BY seq",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(ops.len(), 2, "one op row per old single-op event");
    assert_eq!(
        ops[0],
        (
            1,
            0,
            "create".into(),
            "app.bsky.feed.post/3k1".into(),
            Some("bafyreirecord1".into())
        )
    );
    assert_eq!(
        ops[1],
        (2, 0, "delete".into(), "app.bsky.feed.post/3k2".into(), None)
    );

    // The event rows keep the commit; the op columns are gone, not nullable
    // and dead — a shape the next migration would have to reason about.
    let columns: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'atproto_firehose'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let names: Vec<&str> = columns.iter().map(|(c,)| c.as_str()).collect();
    for gone in ["action", "path", "record_cid"] {
        assert!(
            !names.iter().any(|n| n == &gone),
            "atproto_firehose still carries {gone}: {names:?}"
        );
    }
    for kept in [
        "seq",
        "did",
        "commit_cid",
        "prev_cid",
        "rev",
        "since_rev",
        "prev_data",
    ] {
        assert!(
            names.iter().any(|n| n == &kept),
            "atproto_firehose lost {kept}: {names:?}"
        );
    }

    // And the log still reads as events, ops attached, through the crate's
    // own reader — the shape chunk 3's frames are built on.
    let events = brolly_atproto::firehose::since(&pool, None, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].ops.len(), 1);
    assert_eq!(
        events[0].ops[0].action,
        brolly_atproto::firehose::Action::Create
    );
    assert_eq!(events[0].ops[0].path, "app.bsky.feed.post/3k1");
    assert_eq!(
        events[1].ops[0].action,
        brolly_atproto::firehose::Action::Delete
    );
    assert_eq!(events[1].ops[0].record_cid, None);
}
