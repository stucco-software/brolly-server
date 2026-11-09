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
        &store::Lineage::fresh(),
    )
    .await
    .expect("issue refresh");

    let store::Rotation::Rotated(grant) =
        store::rotate_refresh(&pool, &token, &client_id, Some("jkt-abc"))
            .await
            .expect("rotate")
    else {
        panic!("a fresh refresh token rotates");
    };
    assert_eq!(grant.user_id, user);
    assert_eq!(grant.scope, "openid webid offline_access");
    assert_eq!(grant.dpop_jkt.as_deref(), Some("jkt-abc"));

    assert!(
        matches!(
            store::rotate_refresh(&pool, &token, &client_id, Some("jkt-abc"))
                .await
                .expect("second rotate"),
            store::Rotation::Replayed
        ),
        "rotation is what makes refresh-token theft visible; the old token must die"
    );
}

#[tokio::test]
async fn a_grant_ends_on_its_absolute_date_however_often_it_is_refreshed() {
    // Rotation alone would make a grant immortal: each replacement starts a
    // fresh sliding window. The family's absolute date is copied forward, and
    // a token issued past it — or whose window would reach past it — is not
    // accepted.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    let ended = store::Lineage {
        family: Uuid::new_v4(),
        grant_expires_at: time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
    };
    let token = store::issue_refresh(&pool, &client_id, user, "webid-a", "openid", None, &ended)
        .await
        .expect("issue");

    assert!(
        matches!(
            store::rotate_refresh(&pool, &token, &client_id, None)
                .await
                .expect("rotate"),
            store::Rotation::Refused
        ),
        "a token in a family past its end is refused, not rotated"
    );
}

#[tokio::test]
async fn withdrawing_a_grant_revokes_every_refresh_token_for_that_user() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let bob = a_user(&pool, "bob").await;
    let client_id = a_client(&pool).await;

    let alice_one = store::issue_refresh(
        &pool,
        &client_id,
        alice,
        "webid-a",
        "openid",
        None,
        &store::Lineage::fresh(),
    )
    .await
    .expect("issue");
    let alice_two = store::issue_refresh(
        &pool,
        &client_id,
        alice,
        "webid-a",
        "openid",
        None,
        &store::Lineage::fresh(),
    )
    .await
    .expect("issue");
    let bobs = store::issue_refresh(
        &pool,
        &client_id,
        bob,
        "webid-b",
        "openid",
        None,
        &store::Lineage::fresh(),
    )
    .await
    .expect("issue");

    let revoked = store::revoke_all_for_user(&pool, alice)
        .await
        .expect("revoke");
    assert_eq!(revoked, 2);

    for token in [&alice_one, &alice_two] {
        assert!(
            !matches!(
                store::rotate_refresh(&pool, token, &client_id, None)
                    .await
                    .expect("rotate"),
                store::Rotation::Rotated(_)
            ),
            "a withdrawn grant must not still refresh"
        );
    }
    assert!(
        matches!(
            store::rotate_refresh(&pool, &bobs, &client_id, None)
                .await
                .expect("rotate"),
            store::Rotation::Rotated(_)
        ),
        "one user's revocation must not touch another's"
    );
}

/// The dashboard lists applications, not registrations and not tokens:
/// however many times an application has registered — and however many
/// tokens, in however many scopes, those registrations hold — it is one row,
/// and one withdrawal ends all of it.
#[tokio::test]
async fn the_dashboard_rolls_an_application_up_however_many_grants_it_holds() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let one = store::register_client(&pool, Some("Notes App"), &["https://one.example/cb".into()])
        .await
        .expect("register")
        .client_id;
    let two = store::register_client(&pool, Some("Notes App"), &["https://two.example/cb".into()])
        .await
        .expect("register")
        .client_id;
    let other = a_client(&pool).await; // "Test App", a different application

    for (client, scope) in [
        (&one, "openid webid"),
        (&one, "webid openid"),
        (&two, "openid"),
    ] {
        store::issue_refresh(
            &pool,
            client,
            alice,
            "webid-a",
            scope,
            None,
            &store::Lineage::fresh(),
        )
        .await
        .expect("issue");
    }
    store::issue_refresh(
        &pool,
        &other,
        alice,
        "webid-a",
        "openid",
        None,
        &store::Lineage::fresh(),
    )
    .await
    .expect("issue");

    let apps = store::apps_for_user(&pool, alice).await.expect("list");
    assert_eq!(
        apps.iter().map(|a| a.key.as_str()).collect::<Vec<_>>(),
        vec!["Notes App", "Test App"],
        "one row per application, not per registration or token"
    );
    let notes = &apps[0];
    assert_eq!(
        notes.scopes(),
        "openid webid",
        "the row carries the union of its live tokens' scopes, orderlessly"
    );

    // One withdrawal ends every registration's tokens, and only that
    // application's.
    let revoked = store::revoke_app_for_user(&pool, alice, "Notes App")
        .await
        .expect("revoke");
    assert_eq!(revoked, 3, "every token of every registration");
    let remaining: (i64,) =
        sqlx::query_as("SELECT count(*) FROM solid_refresh_tokens WHERE revoked_at IS NULL")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(remaining.0, 1, "another application's grant survives");
}

/// A document client's client_id is the URL of its document, and it has no
/// row in `solid_clients` (spec 6, H3) — so the join that lists and revokes
/// grants must be a LEFT one, or a document client's grant would be neither
/// visible nor withdrawable.
#[tokio::test]
async fn a_document_clients_grant_is_listed_and_revokable_by_its_url() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let url = "https://penny.example/id";

    store::issue_refresh(
        &pool,
        url,
        alice,
        "webid-a",
        "openid webid",
        None,
        &store::Lineage::fresh(),
    )
    .await
    .expect("issue");

    let apps = store::apps_for_user(&pool, alice).await.expect("list");
    assert_eq!(
        apps.iter()
            .map(|a| (a.key.as_str(), a.client_name.is_none()))
            .collect::<Vec<_>>(),
        vec![(url, true)],
        "a document client is listed by its URL, shown as unnamed"
    );

    let revoked = store::revoke_app_for_user(&pool, alice, url)
        .await
        .expect("revoke");
    assert_eq!(revoked, 1, "and withdrawn by it");
}

#[tokio::test]
async fn deleting_a_user_takes_their_grants_with_them() {
    // D2's delete story is `rm -rf` on the pod; the operational tables have to
    // clear themselves or a deleted account leaves live credentials behind.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    store::issue_refresh(
        &pool,
        &client_id,
        user,
        "webid",
        "openid",
        None,
        &store::Lineage::fresh(),
    )
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
    store::remember_consent(
        &pool,
        user,
        &client_id,
        "openid webid",
        "https://app.example/cb",
    )
    .await
    .expect("remember consent");

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
    let consents: (i64,) = sqlx::query_as("SELECT count(*) FROM solid_consents")
        .fetch_one(&pool)
        .await
        .expect("count consents");

    assert_eq!(codes.0, 0, "authorization codes must cascade");
    assert_eq!(refreshes.0, 0, "refresh tokens must cascade");
    assert_eq!(consents.0, 0, "remembered consents must cascade");
}

// --- remembered consents (spec 6, H4) ---------------------------------------

#[tokio::test]
async fn an_allow_is_remembered() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    store::remember_consent(
        &pool,
        user,
        &client_id,
        "openid webid",
        "https://app.example/cb",
    )
    .await
    .expect("remember");

    let consent = store::remembered_consent(&pool, user, &client_id)
        .await
        .expect("lookup")
        .expect("the consent was remembered");
    assert_eq!(consent.scope, "openid webid");
    assert_eq!(
        consent.redirect_uris,
        ["https://app.example/cb".to_string()]
    );
    assert!(consent.covers("openid webid", "https://app.example/cb"));
}

#[tokio::test]
async fn a_document_clients_consent_is_remembered_without_a_registration() {
    // The table's `client_id` deliberately carries no foreign key (spec 6,
    // H4): a document client has no row in `solid_clients` — its client_id
    // is the URL of the document fetched and validated at authorize time.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;

    store::remember_consent(
        &pool,
        user,
        "https://penny.example/id",
        "openid webid",
        "https://app.example/cb",
    )
    .await
    .expect("remember");

    assert!(
        store::remembered_consent(&pool, user, "https://penny.example/id")
            .await
            .expect("lookup")
            .is_some(),
        "an https:// client_id is remembered without a registration"
    );
}

#[tokio::test]
async fn a_new_grant_widens_the_remembered_scope_and_uris() {
    // Both widenings are monotonic (spec 6, H4): a new grant replaces the
    // row with the union — of the scope, and of the redirect URIs.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    store::remember_consent(
        &pool,
        user,
        &client_id,
        "openid webid",
        "https://app.example/cb",
    )
    .await
    .expect("first");
    store::remember_consent(
        &pool,
        user,
        &client_id,
        "offline_access",
        "https://app.example/other",
    )
    .await
    .expect("second");

    let consent = store::remembered_consent(&pool, user, &client_id)
        .await
        .expect("lookup")
        .expect("remembered");
    let scope: std::collections::BTreeSet<&str> = consent.scope.split_whitespace().collect();
    assert_eq!(
        scope,
        ["offline_access", "openid", "webid"].into_iter().collect()
    );
    assert!(consent.covers("openid webid", "https://app.example/cb"));
    assert!(
        consent.covers("webid offline_access", "https://app.example/other"),
        "both remembered URIs cover, and the union of both scopes"
    );
}

#[tokio::test]
async fn a_narrower_regrant_does_not_shrink_a_remembered_consent() {
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    store::remember_consent(
        &pool,
        user,
        &client_id,
        "openid webid offline_access",
        "https://app.example/cb",
    )
    .await
    .expect("wide");
    store::remember_consent(&pool, user, &client_id, "openid", "https://app.example/cb")
        .await
        .expect("narrow");

    let consent = store::remembered_consent(&pool, user, &client_id)
        .await
        .expect("lookup")
        .expect("remembered");
    assert!(
        consent.covers("openid webid offline_access", "https://app.example/cb"),
        "widening must be monotonic: a narrower re-grant cannot un-approve"
    );
}

#[tokio::test]
async fn coverage_is_subset_matching_not_string_equality() {
    // Both directions (spec 6, H4): a remembered `openid webid` consent
    // covers a bare `webid` request — exact matching would refuse it — and a
    // request for more than was remembered is not covered, so nothing is
    // silently granted that was never approved. And the redirect_uri must
    // be among the remembered URIs, whatever the scope.
    let (_db, pool) = fresh().await;
    let user = a_user(&pool, "alice").await;
    let client_id = a_client(&pool).await;

    store::remember_consent(
        &pool,
        user,
        &client_id,
        "openid webid",
        "https://app.example/cb",
    )
    .await
    .expect("remember");

    let consent = store::remembered_consent(&pool, user, &client_id)
        .await
        .expect("lookup")
        .expect("remembered");
    assert!(
        consent.covers("webid", "https://app.example/cb"),
        "a subset scope is covered"
    );
    assert!(
        !consent.covers("openid webid offline_access", "https://app.example/cb"),
        "a request for more than was remembered is not covered"
    );
    assert!(
        !consent.covers("openid webid", "https://attacker.example/collect"),
        "an unremembered redirect_uri is not covered"
    );
}

#[tokio::test]
async fn one_members_consent_is_not_anothers() {
    let (_db, pool) = fresh().await;
    let alice = a_user(&pool, "alice").await;
    let bob = a_user(&pool, "bob").await;
    let client_id = a_client(&pool).await;

    store::remember_consent(
        &pool,
        alice,
        &client_id,
        "openid webid",
        "https://app.example/cb",
    )
    .await
    .expect("remember");

    assert!(
        store::remembered_consent(&pool, bob, &client_id)
            .await
            .expect("lookup")
            .is_none(),
        "a consent is per member, per client"
    );
}
