//! The PLC operation log against a real Postgres.
//!
//! The log exists so a rotation knows what to name in `prev` without asking the
//! directory — recovery must not depend on the network being reachable at the
//! exact moment something has gone wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_atproto::identity;
use brolly_atproto::keys::SigningKey;
use brolly_atproto::plc;
use brolly_identity::db::{self, MIGRATOR};
use sqlx::PgPool;
use uuid::Uuid;

const HANDLE: &str = "alice.brolly.test";
const PDS: &str = "https://brolly.test";

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

fn a_genesis() -> (plc::Operation, String, SigningKey, SigningKey) {
    let signing = SigningKey::generate();
    let rotation = SigningKey::generate();
    let (signed, did) = plc::create(&signing, &rotation, HANDLE, PDS).expect("genesis");
    (signed, did, signing, rotation)
}

#[tokio::test]
async fn a_genesis_operation_is_logged_and_readable_back() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let (signed, did, _, _) = a_genesis();

    let cid = identity::record_operation(&pool, Some(user), &did, &signed)
        .await
        .expect("record");

    let head = identity::head(&pool, user).await.unwrap().expect("a head");
    assert_eq!(head.cid, cid);
    assert_eq!(head.did, did);
    assert_eq!(head.prev, None, "genesis follows nothing");
    assert_eq!(
        head.operation, signed,
        "the operation must survive verbatim, or its CID changes"
    );
}

#[tokio::test]
async fn the_head_is_what_a_rotation_chains_onto() {
    // The reason the log exists at all.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let (genesis, did, _, rotation) = a_genesis();
    let genesis_cid = identity::record_operation(&pool, Some(user), &did, &genesis)
        .await
        .unwrap();

    let head = identity::head(&pool, user).await.unwrap().unwrap();
    let rotated = plc::rotate_signing_key(
        &head.operation,
        &head.cid,
        &SigningKey::generate(),
        &rotation,
    )
    .expect("rotate");
    let rotated_cid = identity::record_operation(&pool, Some(user), &did, &rotated)
        .await
        .unwrap();

    let new_head = identity::head(&pool, user).await.unwrap().unwrap();
    assert_eq!(new_head.cid, rotated_cid);
    assert_eq!(
        new_head.prev.as_deref(),
        Some(genesis_cid.as_str()),
        "the chain must name its predecessor"
    );
}

#[tokio::test]
async fn an_unsubmitted_operation_is_visible_as_such() {
    // A DID that exists locally and not in the directory is a real state. It
    // has to be findable, or it cannot be retried and the member is quietly
    // unresolvable forever.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let (signed, did, _, _) = a_genesis();
    let cid = identity::record_operation(&pool, Some(user), &did, &signed)
        .await
        .unwrap();

    let pending = identity::unsubmitted(&pool).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].cid, cid);
    assert!(!pending[0].submitted);

    identity::mark_submitted(&pool, &cid).await.unwrap();

    assert!(identity::unsubmitted(&pool).await.unwrap().is_empty());
    assert!(
        identity::head(&pool, user)
            .await
            .unwrap()
            .unwrap()
            .submitted
    );
}

#[tokio::test]
async fn recording_the_same_operation_twice_is_idempotent() {
    // A retry that re-records before re-submitting must not fork the chain.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let (signed, did, _, _) = a_genesis();

    let first = identity::record_operation(&pool, Some(user), &did, &signed)
        .await
        .unwrap();
    let second = identity::record_operation(&pool, Some(user), &did, &signed)
        .await
        .unwrap();
    assert_eq!(first, second);

    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM atproto_plc_operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn one_members_chain_is_not_anothers() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let bob = a_user(&pool, "bob").await;

    let (alice_op, alice_did, _, _) = a_genesis();
    let (bob_op, bob_did, _, _) = a_genesis();
    identity::record_operation(&pool, Some(alice), &alice_did, &alice_op)
        .await
        .unwrap();
    identity::record_operation(&pool, Some(bob), &bob_did, &bob_op)
        .await
        .unwrap();

    assert_eq!(
        identity::head(&pool, alice).await.unwrap().unwrap().did,
        alice_did
    );
    assert_eq!(
        identity::head(&pool, bob).await.unwrap().unwrap().did,
        bob_did
    );
    assert_ne!(alice_did, bob_did);
}

#[tokio::test]
async fn deleting_a_member_takes_their_operation_log() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let (signed, did, _, _) = a_genesis();
    identity::record_operation(&pool, Some(user), &did, &signed)
        .await
        .unwrap();

    db::delete_user(&pool, user).await.unwrap();

    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM atproto_plc_operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn a_member_with_no_operations_has_no_head() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    assert_eq!(identity::head(&pool, user).await.unwrap(), None);
}
