//! The instance as an agent (D4).
//!
//! The learnings put it bluntly: today the server "has a shared inbox with
//! nothing behind it and five tables' worth of homeless state". The instance
//! needs an identity of its own — a WebID, a DID, a keypair and a store —
//! because it owns the cross-user query surface, the shared inbox, and every
//! piece of instance state that belongs to nobody in particular.
//!
//! Its keypair is the one that signs outbound delivery on the instance's own
//! behalf, so the properties that matter are the same as the Solid provider
//! key's: created once, never rotated by accident, and never regenerated on a
//! restart.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::db::{self, MIGRATOR};
use brolly_identity::instance;
use sqlx::PgPool;

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

/// Stand-in for a generated RSA keypair. The crypto lives in the ActivityPub
/// adapter; this layer only has to store opaque PEM and hand it back unchanged.
fn a_keypair() -> (String, String) {
    (
        "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n".into(),
        "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n".into(),
    )
}

#[tokio::test]
async fn the_instance_actor_is_created_once_and_reused() {
    // Regenerating on boot would change the public key in the actor document
    // while remote instances still cache the old one — every signature we sent
    // would start failing verification, silently and everywhere at once.
    let (_db, pool) = fresh().await;
    let (private, public) = a_keypair();

    let first = instance::load_or_create(&pool, || Ok((private.clone(), public.clone())))
        .await
        .expect("first boot");
    let second = instance::load_or_create(&pool, || {
        panic!("a second boot must not generate a new keypair")
    })
    .await
    .expect("second boot");

    assert_eq!(first.private_key_pem, second.private_key_pem);
    assert_eq!(first.public_key_pem, second.public_key_pem);
    assert_eq!(first.public_key_pem, public);
}

#[tokio::test]
async fn there_can_only_ever_be_one_instance_actor() {
    // A second row would mean two keypairs, and which one signs would depend on
    // whichever query happened to order first.
    let (_db, pool) = fresh().await;
    let (private, public) = a_keypair();
    instance::load_or_create(&pool, || Ok((private.clone(), public.clone())))
        .await
        .expect("create");

    let second =
        sqlx::query("INSERT INTO instance_actor (private_key_pem, public_key_pem) VALUES ($1, $2)")
            .bind("another private")
            .bind("another public")
            .execute(&pool)
            .await;

    assert!(
        second.is_err(),
        "the schema must make a second instance actor impossible, not merely unlikely"
    );
}

#[tokio::test]
async fn the_did_can_be_recorded_after_creation() {
    // D11 wants `did:plc` in every wire format, but PLC registration is a
    // network call that Phase 7 owns. The row exists before the DID does.
    let (_db, pool) = fresh().await;
    let (private, public) = a_keypair();

    let actor = instance::load_or_create(&pool, || Ok((private.clone(), public.clone())))
        .await
        .expect("create");
    assert_eq!(actor.did_plc, None, "no DID before PLC registration");

    instance::set_did(&pool, "did:plc:instance123")
        .await
        .expect("set did");

    let reloaded = instance::load_or_create(&pool, || panic!("already exists"))
        .await
        .expect("reload");
    assert_eq!(reloaded.did_plc.as_deref(), Some("did:plc:instance123"));
}

#[tokio::test]
async fn a_users_actor_keypair_survives_a_restart() {
    // Same property as the instance's, for the same reason: a user's public key
    // is published in their actor document and cached by every instance that
    // has seen them.
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let (private, public) = a_keypair();

    let first = instance::load_or_create_actor_keys(&pool, user.id, || {
        Ok((private.clone(), public.clone()))
    })
    .await
    .expect("first");
    let second =
        instance::load_or_create_actor_keys(&pool, user.id, || panic!("must not regenerate"))
            .await
            .expect("second");

    assert_eq!(first.public_key_pem, second.public_key_pem);
}

#[tokio::test]
async fn two_users_get_different_keys() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let bob = db::create_user(&pool, "bob", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let mut counter = 0;
    let mut generate = || {
        counter += 1;
        Ok((format!("private {counter}"), format!("public {counter}")))
    };

    let a = instance::load_or_create_actor_keys(&pool, alice.id, &mut generate)
        .await
        .unwrap();
    let b = instance::load_or_create_actor_keys(&pool, bob.id, &mut generate)
        .await
        .unwrap();

    assert_ne!(
        a.public_key_pem, b.public_key_pem,
        "actors must not share a signing key"
    );
}

#[tokio::test]
async fn deleting_a_user_takes_their_actor_key() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let (private, public) = a_keypair();
    instance::load_or_create_actor_keys(&pool, user.id, || Ok((private, public)))
        .await
        .unwrap();

    db::delete_user(&pool, user.id).await.unwrap();

    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "a deleted account must not leave a signing key");
}
