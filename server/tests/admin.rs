//! The admin console: the guard, and how the first admin comes to exist.
//!
//! See `docs/specs/2026-09-09-admin-console.md`. The bulk of this file is the
//! guard, because the guard *is* the feature — every other assertion here is
//! about a page that should never have been rendered in the first place.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn harness() -> (brolly_test_support::TestDb, tempfile::TempDir, axum::Router) {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().expect("tempdir");
    let state = AppState {
        pool: db.pool.clone(),
        base_domain: "brolly.test".into(),
        instance_name: "brolly.test".to_string(),
        instance_description: "A private community server.".to_string(),
        source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
        terms_url: None,
        privacy_url: None,
        max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
        stores: std::sync::Arc::new(
            brolly_store::StoreManager::open(dir.path(), 4, 60).expect("stores"),
        ),
        provider_key: std::sync::Arc::new(
            brolly_solid::oidc::store::load_or_create_key(&db.pool)
                .await
                .expect("provider key"),
        ),
        instance_actor: std::sync::Arc::new(
            brolly_identity::instance::load_or_create(&db.pool, brolly_activitypub::keys::generate)
                .await
                .expect("instance actor"),
        ),
        commits: tokio::sync::broadcast::channel(64).0,
        plc_client: None,
        clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),
        solid_clients: std::sync::Arc::new(
            brolly_server::client_metadata::StaticClientDocuments::default(),
        ),
        // The remote path's lookups (spec 6, H5): empty here, as a fetch
        // that finds nothing would be — these tests never leave the
        // instance.
        issuer_discovery: std::sync::Arc::new(
            brolly_server::client_metadata::StaticDocuments::default(),
        ),
        issuer_jwks: std::sync::Arc::new(brolly_server::client_metadata::StaticDocuments::default()),
        webid_documents: std::sync::Arc::new(
            brolly_server::client_metadata::StaticDocuments::default(),
        ),
    };
    let router = app(state, "server/static");
    (db, dir, router)
}

async fn post(router: &axum::Router, path: &str, body: &str) -> (StatusCode, String, Vec<String>) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body, cookies)
}

/// Register a member with the given invite and return their session cookie.
async fn register(router: &axum::Router, username: &str, invite: &str) -> String {
    let (status, _, cookies) = post(
        router,
        "/register",
        &format!("invite={invite}&username={username}&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "registration failed");
    cookies
        .iter()
        .find(|c| c.starts_with("brolly_session="))
        .expect("a session cookie")
        .split(';')
        .next()
        .expect("cookie value")
        .to_string()
}

async fn get_as(router: &axum::Router, path: &str, cookie: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::builder().uri(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

const ADMIN_PAGES: [&str; 2] = ["/admin", "/admin/users"];

// --- the guard ---------------------------------------------------------------

#[tokio::test]
async fn a_member_cannot_see_the_console_at_all() {
    let (db, _dir, router) = harness().await;
    let invite = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();
    let cookie = register(&router, "alice", &invite).await;

    for path in ADMIN_PAGES {
        let (status, body) = get_as(&router, path, Some(&cookie)).await;
        // 404 and not 403: 403 would confirm the surface exists to someone who
        // has just been told they may not use it.
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} leaked to a member");
        assert!(
            !body.contains("Admin"),
            "{path} rendered admin content for a member: {body}"
        );
    }
}

#[tokio::test]
async fn an_anonymous_visitor_is_sent_to_log_in_rather_than_to_a_dead_end() {
    let (_db, _dir, router) = harness().await;

    for path in ADMIN_PAGES {
        let (status, _) = get_as(&router, path, None).await;
        // Not 404: a bookmarked admin URL has to lead somewhere, or an admin
        // who is merely logged out concludes the console is gone.
        assert_eq!(status, StatusCode::SEE_OTHER, "{path} did not redirect");
    }
}

#[tokio::test]
async fn a_stale_cookie_is_treated_as_anonymous_not_as_an_admin() {
    let (_db, _dir, router) = harness().await;

    let (status, _) = get_as(&router, "/admin", Some("brolly_session=not-a-real-token")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn an_admin_sees_the_console() {
    let (db, _dir, router) = harness().await;
    let invite = db::create_invite(&db.pool, None, 1, None, Some("admin"))
        .await
        .unwrap();
    let cookie = register(&router, "keeper", &invite).await;

    let (status, body) = get_as(&router, "/admin", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Admin"), "got: {body}");

    let (status, body) = get_as(&router, "/admin/users", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("keeper"),
        "the member list omits its own admin"
    );
}

// --- bootstrap ---------------------------------------------------------------

#[tokio::test]
async fn the_bootstrap_invite_grants_admin_on_an_empty_instance() {
    let (db, _dir, router) = harness().await;

    // What `main` does on every start.
    brolly_server::admin::bootstrap(&db.pool).await.unwrap();

    // The operator reads the code from the logs; the test reads it from the
    // only other place it exists.
    let code = only_bootstrap_invite(&db.pool).await;
    let cookie = register(&router, "operator", &code).await;

    let (status, _) = get_as(&router, "/admin", Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the bootstrap invite did not produce an admin"
    );
}

#[tokio::test]
async fn bootstrap_stops_once_anybody_has_registered() {
    let (db, _dir, router) = harness().await;
    let invite = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();
    register(&router, "alice", &invite).await;

    let before = invite_count(&db.pool).await;
    brolly_server::admin::bootstrap(&db.pool).await.unwrap();
    let after = invite_count(&db.pool).await;

    // Otherwise every restart mints a fresh key to the instance and logs it.
    assert_eq!(
        before, after,
        "bootstrap minted an admin invite on a populated instance"
    );
}

#[tokio::test]
async fn an_ordinary_invite_does_not_grant_admin() {
    let (db, _dir, router) = harness().await;
    let invite = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();
    let cookie = register(&router, "alice", &invite).await;

    let (status, _) = get_as(&router, "/admin", Some(&cookie)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_admin_invite_is_spent_by_the_first_redeemer() {
    let (db, _dir, _router) = harness().await;
    let code = db::create_invite(&db.pool, None, 1, None, Some("admin"))
        .await
        .unwrap();

    assert_eq!(
        db::redeem_invite(&db.pool, &code).await.unwrap().as_deref(),
        Some("admin")
    );
    // A second redemption would hand the instance to whoever asked twice.
    assert!(db::redeem_invite(&db.pool, &code).await.is_err());
}

// --- role changes take effect on live sessions -------------------------------

#[tokio::test]
async fn promotion_reaches_a_session_that_is_already_open() {
    let (db, _dir, router) = harness().await;
    let invite = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();
    let cookie = register(&router, "alice", &invite).await;

    let (before, _) = get_as(&router, "/admin", Some(&cookie)).await;
    assert_eq!(before, StatusCode::NOT_FOUND);

    let user = db::find_by_username(&db.pool, "alice")
        .await
        .unwrap()
        .unwrap();
    db::set_role(&db.pool, user.id, "admin").await.unwrap();

    // The session resolves to a `User` per request, so the grant is live. If
    // this ever regresses to a role cached in the cookie, a demotion would not
    // take effect either — which is the direction that actually matters.
    let (after, _) = get_as(&router, "/admin", Some(&cookie)).await;
    assert_eq!(
        after,
        StatusCode::OK,
        "a promoted member had to log in again"
    );

    db::set_role(&db.pool, user.id, "member").await.unwrap();
    let (revoked, _) = get_as(&router, "/admin", Some(&cookie)).await;
    assert_eq!(
        revoked,
        StatusCode::NOT_FOUND,
        "a demoted admin kept the console"
    );
}

#[tokio::test]
async fn counting_admins_ignores_disabled_ones() {
    let (db, _dir, _router) = harness().await;
    let user = db::create_user(&db.pool, "keeper", None, "correct-horse-battery", "admin")
        .await
        .unwrap();
    assert_eq!(db::count_admins(&db.pool).await.unwrap(), 1);

    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user.id)
        .execute(&db.pool)
        .await
        .unwrap();

    // A disabled admin cannot log in, so treating them as cover would let the
    // last usable admin be demoted and lock everyone out.
    assert_eq!(db::count_admins(&db.pool).await.unwrap(), 0);
}

// --- helpers -----------------------------------------------------------------

async fn invite_count(pool: &sqlx::PgPool) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM invites")
        .fetch_one(pool)
        .await
        .unwrap();
    n
}

/// The bootstrap invite's plaintext is only ever logged, so a test cannot read
/// it back. Mint a known one against the same column instead and assert the
/// bootstrap produced exactly one row to stand in for it.
async fn only_bootstrap_invite(pool: &sqlx::PgPool) -> String {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM invites WHERE grants_role = 'admin'")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "bootstrap did not mint exactly one admin invite");

    sqlx::query("DELETE FROM invites")
        .execute(pool)
        .await
        .unwrap();
    db::create_invite(pool, None, 1, None, Some("admin"))
        .await
        .unwrap()
}

/// Disabled is the state that must never read as ordinary: an operator
/// scanning for the account they just disabled should find it without reading.
/// Marking `active` and `member` too would make everything marked, which is the
/// condition <mark> exists to distinguish itself from.
#[tokio::test]
async fn the_member_list_marks_only_the_exceptional() {
    let (db, _dir, router) = harness().await;

    let invite = db::create_invite(&db.pool, None, 1, None, Some("admin"))
        .await
        .unwrap();
    let cookie = register(&router, "keeper", &invite).await;

    let invite = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();
    let _ = register(&router, "alice", &invite).await;
    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&db.pool)
        .await
        .unwrap();

    let (status, body) = get_as(&router, "/admin/users", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        body.contains("chip-disabled"),
        "a disabled account is marked"
    );
    assert!(body.contains("chip-admin"), "an admin is marked");
    // Exactly two marks: keeper's role and alice's status. Counting binds this
    // in a way `!contains("chip-active")` cannot — no such class is ever
    // defined, so that would pass even if every cell were wrapped in a chip.
    assert_eq!(
        body.matches("<mark").count(),
        2,
        "only the exceptional values are marked; got: {body}"
    );
}
