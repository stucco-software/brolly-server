//! The kinds migration, against seeded rows.
//!
//! The migration's job is to take the log as the old binary left it — commits
//! only, on a table with no `kind` — and leave it holding three kinds on one
//! sequence, with every existing row a commit (1, E). So the test builds the
//! old shape for real: everything before this stage's kinds change applies,
//! then rows the old binary could have written, then the conversion through
//! the full migrator, exactly as a deploy would run it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::db::MIGRATOR;
use sqlx::PgPool;

/// Everything before the kinds change. The full migrator then runs on top and
/// applies only the new migration — the same sequence a deploy follows.
async fn pre_change_schema() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    let before = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|m| m.version < 20261008000002)
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

/// One event row the old binary could have written: a commit, its ops beside
/// it — the shape after the ops change, before this one.
async fn a_commit_row(pool: &PgPool, n: i64) {
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let (seq,): (i64,) = sqlx::query_as(
        "INSERT INTO atproto_firehose (did, commit_cid, prev_cid, rev, since_rev, prev_data)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING seq",
    )
    .bind(did)
    .bind(format!("bafyreicommit{n}"))
    .bind((n > 1).then(|| format!("bafyreicommit{}", n - 1)))
    .bind(match n {
        1 => "3kaaaaaaaaaaa",
        2 => "3kaaaaaaaaaab",
        _ => "3kaaaaaaaaaac",
    })
    .bind((n > 1).then_some("3kaaaaaaaaaaa"))
    .bind((n > 1).then(|| format!("bafyreidata{}", n - 1)))
    .fetch_one(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO atproto_firehose_ops (seq, position, action, path, record_cid)
         VALUES ($1, 0, 'create', $2, $3)",
    )
    .bind(seq)
    .bind(format!("app.bsky.feed.post/3k{n}"))
    .bind(format!("bafyreirecord{n}"))
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn existing_rows_become_commits_and_the_other_kinds_move_in() {
    let (_db, pool) = pre_change_schema().await;

    // Two commits the old binary could have written — the log's whole
    // population, since no other kind existed.
    a_commit_row(&pool, 1).await;
    a_commit_row(&pool, 2).await;

    // The deploy: the full migrator applies the kinds change on top.
    MIGRATOR.run(&pool).await.expect("the conversion applies");

    // The old rows are commits — kind is backfilled in the migration, not at
    // first boot, so a rollback of the binary never sees a half-kindless
    // table (1, E).
    let kinds: Vec<(i64, String)> =
        sqlx::query_as("SELECT seq, kind FROM atproto_firehose ORDER BY seq")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        kinds,
        vec![(1, "commit".into()), (2, "commit".into())],
        "every row the log held was a commit"
    );

    // And they still read as commits, ops attached, through the crate's own
    // reader — the mixed-kind reader the stream is served from.
    let events = brolly_atproto::firehose::since(&pool, None, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    for event in &events {
        let commit = match event {
            brolly_atproto::firehose::Event::Commit(commit) => commit,
            other => panic!("an old row read back as {other:?}"),
        };
        assert_eq!(commit.ops.len(), 1);
        assert_eq!(
            commit.ops[0].action,
            brolly_atproto::firehose::Action::Create
        );
    }

    // The other kinds move in beside them: the columns the migration grew and
    // nullable'd are writable through the record functions, on the same
    // sequence, after the old rows.
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let mut tx = pool.begin().await.unwrap();
    let identity =
        brolly_atproto::firehose::record_identity(&mut tx, did, Some("alice.brolly.test"))
            .await
            .unwrap();
    let account = brolly_atproto::firehose::record_account(&mut tx, did, false, Some("deleted"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        identity.seq, 3,
        "the sequence continues where the commits left it"
    );
    assert_eq!(account.seq, 4);

    let events = brolly_atproto::firehose::since(&pool, Some(2), 10)
        .await
        .unwrap();
    assert!(matches!(
        events[0],
        brolly_atproto::firehose::Event::Identity(_)
    ));
    assert!(matches!(
        events[1],
        brolly_atproto::firehose::Event::Account(_)
    ));

    // A commit after the other kinds still lands — the nullable columns did
    // not take the old writer's shape with them.
    sqlx::query(
        "INSERT INTO atproto_firehose (kind, did, commit_cid, prev_cid, rev)
         VALUES ('commit', $1, $2, $3, $4)",
    )
    .bind(did)
    .bind("bafyreicommit3")
    .bind("bafyreicommit2")
    .bind("3kaaaaaaaaaa3")
    .execute(&pool)
    .await
    .unwrap();
}
