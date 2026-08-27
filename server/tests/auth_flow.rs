//! The front door, end to end, against a real database.
//!
//! §4.1 calls the anonymous visitor "first contact — determines whether anyone
//! joins at all". These assert it actually works, not just that it renders.
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

async fn get(router: &axum::Router, path: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body)
}

#[tokio::test]
async fn the_login_page_renders_a_real_form() {
    let (_db, _dir, router) = harness().await;
    let (status, body) = get(&router, "/login").await;

    assert_eq!(status, StatusCode::OK);
    // Progressive enhancement (§4.2): a real form with a real action, so the
    // page works with JavaScript disabled.
    assert!(body.contains(r#"<form method="post" action="/login""#));
    assert!(body.contains(r#"name="username""#));
    assert!(body.contains(r#"type="password""#));
    // Accessibility is a gate, not a polish pass (§4.3).
    assert!(body.contains(r#"<label for="username">"#));
    assert!(body.contains(r#"<label for="password">"#));
    assert!(
        !body.contains("<script"),
        "the front door needs no JavaScript"
    );
}

#[tokio::test]
async fn registration_requires_a_valid_invite() {
    let (_db, _dir, router) = harness().await;

    let (status, body, cookies) = post(
        &router,
        "/register",
        "invite=nonsense&username=alice&email=&password=correct-horse-battery",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("not valid"), "got: {body}");
    assert!(
        cookies.is_empty(),
        "a failed registration must not create a session"
    );
}

#[tokio::test]
async fn a_valid_invite_registers_and_logs_in() {
    let (db, _dir, router) = harness().await;
    let code = db::create_invite(&db.pool, None, 1, None).await.unwrap();

    let (status, _, cookies) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "registration redirects on success"
    );
    let session = cookies.iter().find(|c| c.starts_with("brolly_session="));
    let session = session.expect("a session cookie is set");
    assert!(
        session.contains("HttpOnly"),
        "session must be unreadable from JS"
    );
    assert!(session.contains("Secure"));
    assert!(session.contains("SameSite=Lax"));

    assert!(
        db::find_by_username(&db.pool, "alice")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_invite_cannot_be_used_twice() {
    let (db, _dir, router) = harness().await;
    let code = db::create_invite(&db.pool, None, 1, None).await.unwrap();

    let (first, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(first, StatusCode::SEE_OTHER);

    let (second, body, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=bob&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(second, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("used up") || body.contains("not valid"),
        "got: {body}"
    );
    assert!(
        db::find_by_username(&db.pool, "bob")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_rejected_username_does_not_consume_the_invite() {
    let (db, _dir, router) = harness().await;
    let code = db::create_invite(&db.pool, None, 1, None).await.unwrap();

    // "Alice" is invalid: usernames become subdomains.
    let (status, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=Alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The invite must still work — validation happens before redemption.
    let (retry, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(
        retry,
        StatusCode::SEE_OTHER,
        "a rejected form must not burn the invite"
    );
}

#[tokio::test]
async fn login_succeeds_and_sets_a_session() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let (status, _, cookies) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let token = cookies
        .iter()
        .find_map(|c| c.strip_prefix("brolly_session="))
        .and_then(|c| c.split(';').next())
        .expect("session token");
    let user = db::user_for_session(&db.pool, token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.username, "alice");
}

#[tokio::test]
async fn a_wrong_password_reveals_nothing_about_the_account() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let (existing_status, existing_body, cookies) =
        post(&router, "/login", "username=alice&password=wrong").await;
    let (missing_status, missing_body, _) =
        post(&router, "/login", "username=mallory&password=wrong").await;

    assert_eq!(existing_status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);
    assert!(cookies.is_empty());

    // Identical wording, so the page cannot be used to enumerate accounts.
    let extract = |b: &str| b.contains("Incorrect username or password.");
    assert!(extract(&existing_body) && extract(&missing_body));
}

#[tokio::test]
async fn a_short_password_is_refused_before_the_invite_is_spent() {
    let (db, _dir, router) = harness().await;
    let code = db::create_invite(&db.pool, None, 1, None).await.unwrap();

    let (status, body, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=short"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("12 characters"), "got: {body}");

    let (retry, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(retry, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn logout_revokes_the_session_server_side() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let (_, _, cookies) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    let token = cookies
        .iter()
        .find_map(|c| c.strip_prefix("brolly_session="))
        .and_then(|c| c.split(';').next())
        .unwrap()
        .to_string();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .header(header::COOKIE, format!("brolly_session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    assert!(
        db::user_for_session(&db.pool, &token)
            .await
            .unwrap()
            .is_none(),
        "logout must revoke server-side, not merely clear the cookie"
    );
}

#[tokio::test]
async fn logout_is_not_reachable_by_get() {
    let (_db, _dir, router) = harness().await;
    let (status, _) = get(&router, "/logout").await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "a prefetch or cross-site <img> must not be able to log someone out"
    );
}

#[tokio::test]
async fn registering_provisions_a_pod_the_member_can_write_to() {
    // WAC grants nothing by default — a missing ACL meaning "allow" is how
    // authorization bugs become data leaks — so the owner's grant has to be
    // created, and account creation is the only moment that is certainly
    // right. Without it the first write any new member attempts is refused,
    // while the pod looks perfectly fine from the outside.
    let (db, _dir, router) = harness().await;
    let invite = db::create_invite(&db.pool, None, 1, None)
        .await
        .expect("invite");

    let (status, _, cookies) = post(
        &router,
        "/register",
        &format!("invite={invite}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "registration should succeed");
    let cookie = cookies
        .first()
        .expect("a session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Asserted over HTTP rather than against the store directly: this is the
    // path a member actually takes, and it evaluates the ACL that was written.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/~/notes/first")
                .header(header::HOST, "alice.brolly.test")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "text/turtle")
                .body(Body::from(
                    "<https://alice.brolly.test/~/notes/first> <https://brolly.id/ns#note> \"hi\" .",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "a newly registered member cannot write to their own pod"
    );
}
