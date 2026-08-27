//! Mastodon OAuth state against a real Postgres.
//!
//! The same properties the Solid-OIDC persistence suite pins, because the same
//! things go wrong: a code must redeem once, a secret must not be readable out
//! of the database, and a revoked credential must stay revoked.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::db::{self, MIGRATOR};
use brolly_mastodon::oauth;
use sqlx::PgPool;
use uuid::Uuid;

const REDIRECT: &str = "https://app.example/cb";

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

async fn an_app(pool: &PgPool) -> oauth::Registered {
    oauth::register_app(
        pool,
        "Phanpy",
        &[REDIRECT.into()],
        "read write follow",
        None,
    )
    .await
    .expect("register app")
}

#[tokio::test]
async fn an_app_registers_and_authenticates_with_its_secret() {
    let (_db, pool) = fresh().await;
    let registered = an_app(&pool).await;

    let authenticated =
        oauth::authenticate_app(&pool, &registered.app.client_id, &registered.client_secret)
            .await
            .expect("authenticate")
            .expect("the secret should match");
    assert_eq!(authenticated.name, "Phanpy");
    assert_eq!(authenticated.scopes, "read write follow");
}

#[tokio::test]
async fn the_client_secret_is_not_recoverable_from_the_database() {
    // The reason it is hashed: a database read must not yield a usable
    // credential.
    let (_db, pool) = fresh().await;
    let registered = an_app(&pool).await;

    let (stored,): (String,) =
        sqlx::query_as("SELECT client_secret_hash FROM mastodon_apps WHERE client_id = $1")
            .bind(&registered.app.client_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_ne!(stored, registered.client_secret);
    assert!(
        !stored.contains(&registered.client_secret),
        "the secret is embedded in what was stored"
    );
}

#[tokio::test]
async fn a_wrong_secret_authenticates_nothing() {
    let (_db, pool) = fresh().await;
    let registered = an_app(&pool).await;

    assert!(
        oauth::authenticate_app(&pool, &registered.app.client_id, "not-the-secret")
            .await
            .expect("query")
            .is_none()
    );
    assert!(
        oauth::authenticate_app(&pool, "no-such-client", &registered.client_secret)
            .await
            .expect("query")
            .is_none()
    );
}

#[tokio::test]
async fn a_code_redeems_exactly_once() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let app = an_app(&pool).await;

    let code = oauth::issue_code(
        &pool,
        &app.app.client_id,
        user,
        REDIRECT,
        "read write",
        Some("a-challenge"),
    )
    .await
    .expect("issue");

    let redeemed = oauth::redeem_code(&pool, &code)
        .await
        .expect("redeem")
        .expect("a fresh code redeems");
    assert_eq!(redeemed.user_id, user);
    assert_eq!(redeemed.scopes, "read write");
    assert_eq!(redeemed.redirect_uri, REDIRECT);
    assert_eq!(redeemed.code_challenge.as_deref(), Some("a-challenge"));

    assert!(
        oauth::redeem_code(&pool, &code)
            .await
            .expect("second redeem")
            .is_none(),
        "an intercepted code must be inert once used"
    );
}

#[tokio::test]
async fn a_code_without_pkce_is_still_valid() {
    // Mastodon added PKCE in 4.3 and older clients still authenticate without
    // it. Requiring it would refuse most of the ecosystem.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let app = an_app(&pool).await;

    let code = oauth::issue_code(&pool, &app.app.client_id, user, REDIRECT, "read", None)
        .await
        .expect("issue");

    let redeemed = oauth::redeem_code(&pool, &code).await.unwrap().unwrap();
    assert_eq!(redeemed.code_challenge, None);
}

#[tokio::test]
async fn a_token_resolves_to_its_member_and_scopes() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let app = an_app(&pool).await;

    let token = oauth::issue_token(&pool, &app.app.client_id, user, "read write")
        .await
        .expect("issue token");

    let grant = oauth::verify_token(&pool, &token)
        .await
        .expect("verify")
        .expect("a fresh token verifies");
    assert_eq!(grant.user_id, user);
    assert_eq!(grant.scopes, "read write");
    assert_eq!(grant.client_id, app.app.client_id);
}

#[tokio::test]
async fn an_unknown_token_and_a_revoked_one_are_indistinguishable() {
    // A caller must not be able to tell a token that never existed from one
    // that was withdrawn.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let app = an_app(&pool).await;
    let token = oauth::issue_token(&pool, &app.app.client_id, user, "read")
        .await
        .unwrap();

    assert!(oauth::revoke_token(&pool, &token).await.unwrap());

    assert_eq!(oauth::verify_token(&pool, &token).await.unwrap(), None);
    assert_eq!(
        oauth::verify_token(&pool, "never-issued").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn revoking_twice_reports_that_nothing_changed() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let app = an_app(&pool).await;
    let token = oauth::issue_token(&pool, &app.app.client_id, user, "read")
        .await
        .unwrap();

    assert!(oauth::revoke_token(&pool, &token).await.unwrap());
    assert!(
        !oauth::revoke_token(&pool, &token).await.unwrap(),
        "a second revocation revoked nothing"
    );
}

#[tokio::test]
async fn logging_out_everywhere_leaves_other_members_alone() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let bob = a_user(&pool, "bob").await;
    let app = an_app(&pool).await;

    let a1 = oauth::issue_token(&pool, &app.app.client_id, alice, "read")
        .await
        .unwrap();
    let a2 = oauth::issue_token(&pool, &app.app.client_id, alice, "write")
        .await
        .unwrap();
    let b1 = oauth::issue_token(&pool, &app.app.client_id, bob, "read")
        .await
        .unwrap();

    assert_eq!(oauth::revoke_all_for_user(&pool, alice).await.unwrap(), 2);

    assert!(oauth::verify_token(&pool, &a1).await.unwrap().is_none());
    assert!(oauth::verify_token(&pool, &a2).await.unwrap().is_none());
    assert!(
        oauth::verify_token(&pool, &b1).await.unwrap().is_some(),
        "one member's logout must not touch another's"
    );
}

#[tokio::test]
async fn the_dashboard_can_list_the_apps_a_member_authorised() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let phanpy = an_app(&pool).await;
    let ivory = oauth::register_app(&pool, "Ivory", &[REDIRECT.into()], "read", None)
        .await
        .unwrap();

    // Two tokens from the same app must not list it twice.
    oauth::issue_token(&pool, &phanpy.app.client_id, alice, "read")
        .await
        .unwrap();
    oauth::issue_token(&pool, &phanpy.app.client_id, alice, "write")
        .await
        .unwrap();
    oauth::issue_token(&pool, &ivory.app.client_id, alice, "read")
        .await
        .unwrap();

    let apps = oauth::apps_for_user(&pool, alice).await.unwrap();
    let names: Vec<&str> = apps.iter().map(|(_, name)| name.as_str()).collect();
    assert_eq!(names, vec!["Ivory", "Phanpy"]);
}

#[tokio::test]
async fn a_revoked_grant_disappears_from_the_dashboard() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let app = an_app(&pool).await;
    let token = oauth::issue_token(&pool, &app.app.client_id, alice, "read")
        .await
        .unwrap();

    oauth::revoke_token(&pool, &token).await.unwrap();
    assert!(oauth::apps_for_user(&pool, alice).await.unwrap().is_empty());
}

#[tokio::test]
async fn deleting_a_member_takes_their_tokens_with_them() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let app = an_app(&pool).await;
    oauth::issue_token(&pool, &app.app.client_id, user, "read")
        .await
        .unwrap();
    oauth::issue_code(&pool, &app.app.client_id, user, REDIRECT, "read", None)
        .await
        .unwrap();

    db::delete_user(&pool, user).await.unwrap();

    for table in ["mastodon_tokens", "mastodon_auth_codes"] {
        let (count,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "{table} did not cascade");
    }
}
