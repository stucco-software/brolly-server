//! The DPoP nonce secret (stage 2, C).
//!
//! One row, one secret, the HMAC key behind every nonce the instance hands
//! out. The properties that matter are the instance actor's: created once,
//! never regenerated on a restart, and one secret no matter how many processes
//! start together.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::db::MIGRATOR;
use brolly_identity::dpop;
use sqlx::PgPool;

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

#[tokio::test]
async fn the_secret_is_created_once_and_reused() {
    // Regenerating on boot would invalidate every nonce in flight at once —
    // survivable (clients retry the dance), but a boot storm of retries for
    // no gain. The row is the secret's whole lifecycle.
    let (_db, pool) = fresh().await;

    let first = dpop::load_or_create_nonce_secret(&pool)
        .await
        .expect("first boot");
    let second = dpop::load_or_create_nonce_secret(&pool)
        .await
        .expect("second boot");

    assert_eq!(first, second);
    assert_eq!(
        first.len(),
        64,
        "the secret is 64 random bytes — SHA-256's block size"
    );
}

#[tokio::test]
async fn two_processes_starting_together_converge_on_one_secret() {
    // `ON CONFLICT DO NOTHING`, then the read-back: whichever insert wins, both
    // processes load the same row. A lost race would mean one process handing
    // out nonces from a key that was never stored, and every proof against
    // them failing from then on.
    let (_db, pool) = fresh().await;

    let (a, b) = tokio::try_join!(
        dpop::load_or_create_nonce_secret(&pool),
        dpop::load_or_create_nonce_secret(&pool),
    )
    .expect("both boots");

    assert_eq!(a, b, "both processes must verify the same nonces");
}

#[tokio::test]
async fn the_schema_permits_only_one_secret() {
    // The `CHECK (id = 1)` makes a second secret a schema error rather than a
    // race outcome: which one a process loaded would depend on query order.
    let (_db, pool) = fresh().await;
    dpop::load_or_create_nonce_secret(&pool)
        .await
        .expect("create");

    let second = sqlx::query("INSERT INTO dpop_nonce_secrets (id, secret) VALUES (2, $1)")
        .bind(vec![0u8; 64])
        .execute(&pool)
        .await;

    assert!(
        second.is_err(),
        "the schema must make a second secret impossible, not merely unlikely"
    );
}
