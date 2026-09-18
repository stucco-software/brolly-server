//! A DPoP proof is good for one request (RFC 9449).
//!
//! `verify` checks a proof's signature, target and freshness. A proof that
//! passes all three could still be captured and sent again for as long as it
//! stays fresh. `Unspent::spend` records the `jti` so the second use fails.
//! These tests run against a real Postgres, because the guarantee comes from
//! its primary key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db::MIGRATOR;
use brolly_identity::dpop::{self, DpopError, MAX_AGE_SECONDS, VerifiedProof};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sqlx::PgPool;

const URL: &str = "https://brolly.test/oauth/solid/token";

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

/// A token-endpoint proof with the `jti` and `iat` the test chooses.
fn proof(key: &SigningKey, jti: &str, iat: i64) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "dpop+jwt",
        "jwk": {"kty": "EC", "crv": "P-256",
                "x": B64.encode(&sec1[1..33]), "y": B64.encode(&sec1[33..65])},
    });
    let claims = serde_json::json!({"htm": "POST", "htu": URL, "jti": jti, "iat": iat});
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// Verify and spend, as a call site does, with `now` as the application clock.
async fn present(pool: &PgPool, proof: &str, now: i64) -> Result<VerifiedProof, DpopError> {
    let unspent = dpop::verify(proof, "POST", URL, None, now).expect("the proof itself is valid");
    unspent.spend(pool, now).await
}

async fn rows_for(pool: &PgPool, jti: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dpop_jti WHERE jti = $1")
        .bind(jti)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_proof_is_spent_once_and_refused_the_second_time() {
    let (_db, pool) = fresh().await;
    let p = proof(&key(7), "only-once", 1000);

    assert!(present(&pool, &p, 1000).await.is_ok());
    assert_eq!(
        present(&pool, &p, 1001).await.err(),
        Some(DpopError::Replayed)
    );
}

#[tokio::test]
async fn two_keys_may_each_use_the_same_jti() {
    // The client picks the jti. Keying on (jkt, jti) means one client's choice
    // can't get another client's proofs refused.
    let (_db, pool) = fresh().await;

    assert!(
        present(&pool, &proof(&key(7), "shared", 1000), 1000)
            .await
            .is_ok()
    );
    assert!(
        present(&pool, &proof(&key(9), "shared", 1000), 1000)
            .await
            .is_ok()
    );
    assert_eq!(rows_for(&pool, "shared").await, 2);
}

#[tokio::test]
async fn a_proof_stays_spent_for_its_whole_window_whatever_the_database_clock_says() {
    // To Postgres, iat 1000 is 1970. Pruning by the database's now() would drop
    // the row at the next spend and let the replay through, even though the
    // application still considers the proof fresh.
    let (_db, pool) = fresh().await;
    let p = proof(&key(7), "early", 1000);
    present(&pool, &p, 1000).await.unwrap();

    // Another spend runs the prune, while the application clock is still
    // inside the first proof's window.
    let edge = 1000 + MAX_AGE_SECONDS;
    present(&pool, &proof(&key(7), "later", edge), edge)
        .await
        .unwrap();

    assert_eq!(rows_for(&pool, "early").await, 1);
    assert_eq!(
        present(&pool, &p, edge).await.err(),
        Some(DpopError::Replayed)
    );
}

#[tokio::test]
async fn the_next_spend_prunes_rows_past_their_window_by_the_application_clock() {
    // 2096 to Postgres. Only the application's clock can call this row expired,
    // so if it disappears, the prune used that clock.
    const FUTURE: i64 = 4_000_000_000;
    let (_db, pool) = fresh().await;
    present(&pool, &proof(&key(7), "old", FUTURE), FUTURE)
        .await
        .unwrap();

    let later = FUTURE + 2 * MAX_AGE_SECONDS + 1;
    present(&pool, &proof(&key(7), "new", later), later)
        .await
        .unwrap();

    assert_eq!(
        rows_for(&pool, "old").await,
        0,
        "a row past its window is pruned"
    );
    assert_eq!(rows_for(&pool, "new").await, 1);
}

#[tokio::test]
async fn a_storage_failure_refuses_the_proof() {
    // Fail closed. A proof that couldn't be recorded can't be known unspent.
    let (_db, pool) = fresh().await;
    let unspent = dpop::verify(&proof(&key(7), "unrecorded", 1000), "POST", URL, None, 1000)
        .expect("the proof itself is valid");
    pool.close().await;

    assert!(matches!(
        unspent.spend(&pool, 1000).await,
        Err(DpopError::Storage(_))
    ));
}
