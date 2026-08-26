//! Solid-OIDC provider state against a real Postgres.
//!
//! The properties under test here are the ones that decide whether a stolen
//! credential is usable: a code redeems once, a refresh token is spent by
//! using it, and the signing key survives a restart. None of them are
//! observable from a unit test, because all three are single-statement
//! guarantees the database makes rather than the process.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::db::{self, MIGRATOR};
use brolly_solid::oidc::store;
use sqlx::PgPool;
use uuid::Uuid;

async fn fresh() -> (brolly_test_support::TestDb, PgPool) {
    let db = brolly_test_support::postgres().await;
    MIGRATOR.run(&db.pool).await.expect("migrations run");
    let pool = db.pool.clone();
    (db, pool)
}

/// A user to hang grants off, since every table here has a real FK to `users`.
async fn a_user(pool: &PgPool, username: &str) -> Uuid {
    db::create_user(pool, username, None, "correct-horse-battery", "member")
        .await
        .expect("create user")
        .id
}

async fn a_client(pool: &PgPool) -> String {
    store::register_client(pool, Some("Test App"), &["https://app.example/cb".into()])
        .await
        .expect("register client")
        .client_id
}

#[tokio::test]
async fn the_signing_key_survives_a_restart() {
    // Regenerating on boot would invalidate every live access token and log
    // the whole instance out — silently, since the failure looks like an
    // expired session.
    let (_db, pool) = fresh().await;

    let first = store::load_or_create_key(&pool).await.expect("first boot");
    let second = store::load_or_create_key(&pool).await.expect("second boot");

    assert_eq!(first.kid, second.kid, "a restart must not rotate the key");

    // Same key material, not merely the same id: a token signed before the
    // restart has to verify after it.
    let claims = serde_json::json!({"sub": "alice", "exp": 2_000_000_000i64});
    let token = first.sign(&claims).expect("sign");
    assert_eq!(
        second.verify(&token, 1_000_000_000).expect("verify")["sub"],
        "alice"
    );
}

#[tokio::test]
async fn a_registered_client_is_findable_by_its_identifier() {
    let (_db, pool) = fresh().await;

    let registered = store::register_client(
        &pool,
        Some("Podbrowser"),
        &[
            "https://pod.example/cb".into(),
            "http://localhost/cb".into(),
        ],
    )
    .await
    .expect("register");

    assert!(
        registered.client_id.starts_with("urn:uuid:"),
        "dynamic registration mints a urn:uuid:, got {}",
        registered.client_id
    );

    let found = store::find_client(&pool, &registered.client_id)
        .await
        .expect("lookup")
        .expect("registered client should be found");

    assert_eq!(found.client_name.as_deref(), Some("Podbrowser"));
    assert_eq!(found.redirect_uris.len(), 2);
    assert!(
        found
            .redirect_uris
            .contains(&"https://pod.example/cb".to_string())
    );
}

#[tokio::test]
async fn an_unregistered_client_is_absent_rather_than_an_error() {
    let (_db, pool) = fresh().await;
    assert!(
        store::find_client(&pool, "urn:uuid:00000000-0000-0000-0000-000000000000")
            .await
            .expect("lookup succeeds")
            .is_none()
    );
}

#[tokio::test]
async fn a_code_carries_the_whole_authorization_request_to_redemption() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    let code = store::issue_code(
        &pool,
        &client_id,
        user,
        "https://alice.brolly.id/profile#me",
        "https://app.example/cb",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "openid webid offline_access",
        Some("n-0S6_WzA2Mj"),
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
    )
    .await
    .expect("issue code");

    let redeemed = store::redeem_code(&pool, &code)
        .await
        .expect("redeem")
        .expect("a fresh code redeems");

    // Every one of these is load-bearing at the token endpoint: the challenge
    // verifies PKCE, the redirect_uri is re-checked against the request, and
    // the jkt binds the token to the client's key.
    assert_eq!(redeemed.client_id, client_id);
    assert_eq!(redeemed.user_id, user);
    assert_eq!(redeemed.webid, "https://alice.brolly.id/profile#me");
    assert_eq!(redeemed.redirect_uri, "https://app.example/cb");
    assert_eq!(
        redeemed.code_challenge,
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert_eq!(redeemed.scope, "openid webid offline_access");
    assert_eq!(redeemed.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    assert_eq!(
        redeemed.dpop_jkt.as_deref(),
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
    );
}

#[tokio::test]
async fn a_code_redeems_exactly_once() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    let code = store::issue_code(
        &pool,
        &client_id,
        user,
        "https://alice.brolly.id/profile#me",
        "https://app.example/cb",
        "challenge",
        "openid webid",
        None,
        None,
    )
    .await
    .expect("issue");

    assert!(
        store::redeem_code(&pool, &code)
            .await
            .expect("first redeem")
            .is_some()
    );
    assert!(
        store::redeem_code(&pool, &code)
            .await
            .expect("second redeem")
            .is_none(),
        "an intercepted code must be inert once the legitimate client has used it"
    );
}

#[tokio::test]
async fn a_replayed_code_is_distinguishable_from_a_fabricated_one() {
    // The row is kept rather than deleted precisely so this distinction
    // exists: a replay means a code leaked and the grant should be torn down,
    // while a nonsense code is just noise.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    let code = store::issue_code(
        &pool,
        &client_id,
        user,
        "https://alice.brolly.id/profile#me",
        "https://app.example/cb",
        "challenge",
        "openid webid",
        None,
        None,
    )
    .await
    .expect("issue");

    assert!(
        !store::code_was_used(&pool, &code).await.expect("check"),
        "an unredeemed code has not been used"
    );

    store::redeem_code(&pool, &code).await.expect("redeem");

    assert!(
        store::code_was_used(&pool, &code).await.expect("check"),
        "a redeemed code is recorded as used, so a replay is detectable"
    );
    assert!(
        !store::code_was_used(&pool, "never-issued")
            .await
            .expect("check"),
        "a code we never issued is not a replay"
    );
}

#[tokio::test]
async fn a_refresh_token_is_spent_by_using_it() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    let token = store::issue_refresh(
        &pool,
        &client_id,
        user,
        "https://alice.brolly.id/profile#me",
        "openid webid offline_access",
        Some("jkt-abc"),
    )
    .await
    .expect("issue refresh");

    let grant = store::rotate_refresh(&pool, &token)
        .await
        .expect("rotate")
        .expect("a fresh refresh token rotates");
    assert_eq!(grant.user_id, user);
    assert_eq!(grant.scope, "openid webid offline_access");
    assert_eq!(grant.dpop_jkt.as_deref(), Some("jkt-abc"));

    assert!(
        store::rotate_refresh(&pool, &token)
            .await
            .expect("second rotate")
            .is_none(),
        "rotation is what makes refresh-token theft visible; the old token must die"
    );
}

#[tokio::test]
async fn withdrawing_a_grant_revokes_every_refresh_token_for_that_user() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let bob = a_user(&pool, "bob").await;
    let client_id = a_client(&pool).await;

    let alice_one = store::issue_refresh(&pool, &client_id, alice, "webid-a", "openid", None)
        .await
        .expect("issue");
    let alice_two = store::issue_refresh(&pool, &client_id, alice, "webid-a", "openid", None)
        .await
        .expect("issue");
    let bobs = store::issue_refresh(&pool, &client_id, bob, "webid-b", "openid", None)
        .await
        .expect("issue");

    let revoked = store::revoke_all_for_user(&pool, alice)
        .await
        .expect("revoke");
    assert_eq!(revoked, 2);

    for token in [&alice_one, &alice_two] {
        assert!(
            store::rotate_refresh(&pool, token)
                .await
                .expect("rotate")
                .is_none(),
            "a withdrawn grant must not still refresh"
        );
    }
    assert!(
        store::rotate_refresh(&pool, &bobs)
            .await
            .expect("rotate")
            .is_some(),
        "one user's revocation must not touch another's"
    );
}

#[tokio::test]
async fn deleting_a_user_takes_their_grants_with_them() {
    // D2's delete story is `rm -rf` on the pod; the operational tables have to
    // clear themselves or a deleted account leaves live credentials behind.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    store::issue_refresh(&pool, &client_id, user, "webid", "openid", None)
        .await
        .expect("issue");
    store::issue_code(
        &pool,
        &client_id,
        user,
        "webid",
        "https://app.example/cb",
        "c",
        "openid",
        None,
        None,
    )
    .await
    .expect("issue code");

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .expect("delete user");

    let codes: (i64,) = sqlx::query_as("SELECT count(*) FROM solid_auth_codes")
        .fetch_one(&pool)
        .await
        .expect("count codes");
    let refreshes: (i64,) = sqlx::query_as("SELECT count(*) FROM solid_refresh_tokens")
        .fetch_one(&pool)
        .await
        .expect("count refreshes");

    assert_eq!(codes.0, 0, "authorization codes must cascade");
    assert_eq!(refreshes.0, 0, "refresh tokens must cascade");
}
