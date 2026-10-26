//! Identity persistence against a real Postgres, provisioned per test.
//!
//! Nothing here is `#[ignore]`d — testcontainers starts the database, so these
//! run on every `cargo test`. The predecessor had 228 ignored tests behind a
//! manual env var.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::db::{self, DbError, MIGRATOR};
use sqlx::PgPool;

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

#[tokio::test]
async fn migrations_apply_cleanly() {
    let (_db, pool) = fresh().await;
    // If the sqlx::migrate! expansion were stale, this fails with
    // VersionMissing — which is why identity/build.rs exists.
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'public' ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let names: Vec<&str> = tables.iter().map(|(t,)| t.as_str()).collect();
    for expected in ["users", "sessions", "invites", "user_keys"] {
        assert!(
            names.contains(&expected),
            "missing table {expected} in {names:?}"
        );
    }
}

#[tokio::test]
async fn postgres_holds_no_profile_content() {
    // D2/D5: display names, bios and avatars live in pods. The predecessor
    // added profile_display_name back to this table with a backfill; the read
    // that forced it now belongs to the server-agent index (ADR 0005 R5).
    let (_db, pool) = fresh().await;
    let columns: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let names: Vec<String> = columns.into_iter().map(|(c,)| c).collect();

    for banned in [
        "display_name",
        "profile_display_name",
        "bio",
        "summary",
        "avatar",
    ] {
        assert!(
            !names.iter().any(|c| c == banned),
            "users.{banned} is user content and belongs in the pod, not Postgres"
        );
    }
}

#[tokio::test]
async fn a_user_round_trips() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(
        &pool,
        "alice",
        Some("alice@example.com"),
        "hunter2!",
        "member",
    )
    .await
    .unwrap();

    assert_eq!(user.username, "alice");
    assert!(!user.is_admin());
    assert!(user.is_active());
    assert!(
        user.did_plc.is_none(),
        "PLC registration happens after creation"
    );

    let found = db::find_by_username(&pool, "alice").await.unwrap().unwrap();
    assert_eq!(found.id, user.id);
}

#[tokio::test]
async fn passwords_are_hashed_not_stored() {
    let (_db, pool) = fresh().await;
    db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();

    let (hash,): (String,) =
        sqlx::query_as("SELECT password_hash FROM users WHERE username = 'alice'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !hash.contains("hunter2"),
        "plaintext password in the database"
    );
    assert!(
        hash.starts_with("$argon2"),
        "expected an argon2 hash, got {hash}"
    );
}

#[tokio::test]
async fn authentication_accepts_the_right_password_and_rejects_the_rest() {
    let (_db, pool) = fresh().await;
    db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();

    assert!(db::authenticate(&pool, "alice", "hunter2!").await.is_ok());
    assert!(matches!(
        db::authenticate(&pool, "alice", "wrong").await,
        Err(DbError::BadCredentials)
    ));
}

#[tokio::test]
async fn an_unknown_user_is_indistinguishable_from_a_wrong_password() {
    let (_db, pool) = fresh().await;
    db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();

    let wrong_password = db::authenticate(&pool, "alice", "nope").await;
    let no_such_user = db::authenticate(&pool, "mallory", "nope").await;

    // Same error variant, so a caller cannot enumerate accounts.
    assert!(matches!(wrong_password, Err(DbError::BadCredentials)));
    assert!(matches!(no_such_user, Err(DbError::BadCredentials)));
}

#[tokio::test]
async fn a_disabled_account_cannot_authenticate() {
    let (_db, pool) = fresh().await;
    db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();
    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&pool)
        .await
        .unwrap();

    assert!(matches!(
        db::authenticate(&pool, "alice", "hunter2!").await,
        Err(DbError::BadCredentials)
    ));
}

#[tokio::test]
async fn usernames_are_unique() {
    let (_db, pool) = fresh().await;
    db::create_user(&pool, "alice", None, "a", "member")
        .await
        .unwrap();
    assert!(matches!(
        db::create_user(&pool, "alice", None, "b", "member").await,
        Err(DbError::UsernameTaken)
    ));
}

#[tokio::test]
async fn sessions_store_only_a_hash_and_resolve_to_their_user() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();

    let token = db::create_session(&pool, user.id, time::Duration::hours(1), Some("test"))
        .await
        .unwrap();

    let (stored,): (String,) = sqlx::query_as("SELECT token_hash FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, token, "the raw token must not be stored");
    assert_eq!(stored, db::hash_secret(&token));

    let resolved = db::user_for_session(&pool, &token).await.unwrap().unwrap();
    assert_eq!(resolved.id, user.id);

    db::revoke_session(&pool, &token).await.unwrap();
    assert!(db::user_for_session(&pool, &token).await.unwrap().is_none());
}

#[tokio::test]
async fn an_expired_session_does_not_resolve() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();
    let token = db::create_session(&pool, user.id, time::Duration::seconds(-1), None)
        .await
        .unwrap();
    assert!(db::user_for_session(&pool, &token).await.unwrap().is_none());
}

#[tokio::test]
async fn disabling_a_user_invalidates_their_live_sessions() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();
    let token = db::create_session(&pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    assert!(db::user_for_session(&pool, &token).await.unwrap().is_some());

    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();

    assert!(
        db::user_for_session(&pool, &token).await.unwrap().is_none(),
        "disabling an account must not leave live sessions working"
    );
}

#[tokio::test]
async fn an_invite_can_be_used_exactly_its_allowance() {
    let (_db, pool) = fresh().await;
    let code = db::create_invite(&pool, None, 2, None, None).await.unwrap();

    db::redeem_invite(&pool, &code).await.unwrap();
    db::redeem_invite(&pool, &code).await.unwrap();
    assert!(matches!(
        db::redeem_invite(&pool, &code).await,
        Err(DbError::InviteInvalid)
    ));
}

#[tokio::test]
async fn revoked_expired_and_unknown_invites_are_all_refused() {
    let (_db, pool) = fresh().await;

    let revoked = db::create_invite(&pool, None, 1, None, None).await.unwrap();
    db::revoke_invite(&pool, &revoked).await.unwrap();
    assert!(matches!(
        db::redeem_invite(&pool, &revoked).await,
        Err(DbError::InviteInvalid)
    ));

    let expired = db::create_invite(&pool, None, 1, Some(time::Duration::seconds(-1)), None)
        .await
        .unwrap();
    assert!(matches!(
        db::redeem_invite(&pool, &expired).await,
        Err(DbError::InviteInvalid)
    ));

    assert!(matches!(
        db::redeem_invite(&pool, "not-a-real-code").await,
        Err(DbError::InviteInvalid)
    ));
}

#[tokio::test]
async fn keys_round_trip_and_are_replaced_on_rotation() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();

    db::store_key(&pool, user.id, "atproto_signing", b"priv1", b"pub1")
        .await
        .unwrap();
    let (priv_key, pub_key) = db::load_key(&pool, user.id, "atproto_signing")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(priv_key, b"priv1");
    assert_eq!(pub_key, b"pub1");

    db::store_key(&pool, user.id, "atproto_signing", b"priv2", b"pub2")
        .await
        .unwrap();
    let (rotated, _) = db::load_key(&pool, user.id, "atproto_signing")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rotated, b"priv2",
        "rotation replaces rather than duplicating"
    );
}

#[tokio::test]
async fn deleting_a_user_cascades_to_sessions_and_keys() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();
    db::create_session(&pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    db::store_key(&pool, user.id, "atproto_signing", b"p", b"P")
        .await
        .unwrap();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();

    let (sessions,): (i64,) = sqlx::query_as("SELECT count(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (keys,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        sessions, 0,
        "account deletion must not leave sessions behind"
    );
    assert_eq!(keys, 0, "account deletion must not leave keys behind");
}

#[tokio::test]
async fn did_plc_is_recorded_after_registration() {
    let (_db, pool) = fresh().await;
    let user = db::create_user(&pool, "alice", None, "hunter2!", "member")
        .await
        .unwrap();
    db::set_did_plc(&pool, user.id, "did:plc:abc123")
        .await
        .unwrap();

    let found = db::find_by_username(&pool, "alice").await.unwrap().unwrap();
    assert_eq!(found.did_plc.as_deref(), Some("did:plc:abc123"));
    // D11: this is the identifier every wire format reads.
    assert!(brolly_identity::did::for_wire(found.did_plc.as_deref().unwrap()).is_ok());
}

#[tokio::test]
async fn a_member_is_findable_by_their_primary_key() {
    // The second half of resolving a Mastodon status id (ADR 0015): the id
    // decodes to a UUID and this turns it into a member, which is what lets
    // that scheme work with no routing table and no index.
    let (_db, pool) = fresh().await;
    let created = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let found = db::find_by_id(&pool, created.id)
        .await
        .unwrap()
        .expect("the member should be found");
    assert_eq!(found.username, "alice");
    assert_eq!(found.id, created.id);

    assert!(
        db::find_by_id(&pool, uuid::Uuid::nil())
            .await
            .unwrap()
            .is_none(),
        "an id we never issued must not resolve to anyone"
    );
}

// --- quotas -----------------------------------------------------------------

#[tokio::test]
async fn a_quota_override_round_trips_and_clears() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    assert_eq!(alice.quota_bytes, None, "a new member has no override");
    assert_eq!(alice.quota(1 << 30), 1 << 30, "so the default applies");

    db::set_quota(&pool, alice.id, Some(5 << 30), None)
        .await
        .unwrap();
    let alice = db::find_by_username(&pool, "alice").await.unwrap().unwrap();
    assert_eq!(alice.quota_bytes, Some(5 << 30));
    assert_eq!(alice.quota(1 << 30), 5 << 30, "the override wins");

    // Every path that loads a User carries it.
    assert_eq!(
        db::find_by_id(&pool, alice.id)
            .await
            .unwrap()
            .unwrap()
            .quota_bytes,
        Some(5 << 30)
    );
    let token = db::create_session(&pool, alice.id, time::Duration::hours(1), None)
        .await
        .unwrap();
    assert_eq!(
        db::user_for_session(&pool, &token)
            .await
            .unwrap()
            .unwrap()
            .quota_bytes,
        Some(5 << 30)
    );

    db::set_quota(&pool, alice.id, None, None).await.unwrap();
    let alice = db::find_by_username(&pool, "alice").await.unwrap().unwrap();
    assert_eq!(alice.quota_bytes, None, "cleared");
    assert_eq!(alice.quota(1 << 30), 1 << 30);
}

#[tokio::test]
async fn provenance_names_the_console_admin_and_not_the_cli() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let keeper = db::create_user(&pool, "keeper", None, "correct-horse-battery", "admin")
        .await
        .unwrap();

    assert!(
        db::quota_provenance(&pool, alice.id)
            .await
            .unwrap()
            .is_none(),
        "no override, no provenance"
    );

    db::set_quota(&pool, alice.id, Some(5 << 30), Some(keeper.id))
        .await
        .unwrap();
    let by_console = db::quota_provenance(&pool, alice.id)
        .await
        .unwrap()
        .expect("set");
    assert_eq!(by_console.set_by.as_deref(), Some("keeper"));

    db::set_quota(&pool, alice.id, Some(6 << 30), None)
        .await
        .unwrap();
    let by_cli = db::quota_provenance(&pool, alice.id)
        .await
        .unwrap()
        .expect("set");
    assert_eq!(by_cli.set_by, None, "the CLI is the database, not a person");
    assert!(by_cli.set_at >= by_console.set_at);
}

#[tokio::test]
async fn deleting_the_admin_keeps_the_quota_and_loses_the_name() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let keeper = db::create_user(&pool, "keeper", None, "correct-horse-battery", "admin")
        .await
        .unwrap();
    db::set_quota(&pool, alice.id, Some(5 << 30), Some(keeper.id))
        .await
        .unwrap();

    db::delete_user(&pool, keeper.id).await.unwrap();

    let alice = db::find_by_username(&pool, "alice").await.unwrap().unwrap();
    assert_eq!(
        alice.quota_bytes,
        Some(5 << 30),
        "ON DELETE SET NULL, not CASCADE"
    );
    let provenance = db::quota_provenance(&pool, alice.id)
        .await
        .unwrap()
        .expect("still set");
    assert_eq!(provenance.set_by, None);
}

#[tokio::test]
async fn a_negative_quota_cannot_be_stored() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let err = db::set_quota(&pool, alice.id, Some(-1), None)
        .await
        .expect_err("the CHECK refuses it; set_quota does not pretend otherwise");
    assert!(
        matches!(
            err,
            DbError::Sql(sqlx::Error::Database(ref db))
                if db.constraint() == Some("users_quota_bytes_nonnegative")
        ),
        "refused by the non-negative CHECK, not something else: {err:?}"
    );
}
