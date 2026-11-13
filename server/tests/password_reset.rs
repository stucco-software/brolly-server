//! Setting a password from a reset link (`/reset`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, FrontEnd, app};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn harness(
    account_home: Option<&str>,
) -> (brolly_test_support::TestDb, tempfile::TempDir, axum::Router) {
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
        theme_css: false,
        public_registration: false,
        front_end: FrontEnd {
            account_home: account_home.map(str::to_string),
            ..FrontEnd::default()
        },
        limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
        www_redirect: None,
        max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
        pod_quota_bytes: brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
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

/// Status, `Location`, body.
async fn send(
    router: &axum::Router,
    request: Request<Body>,
) -> (StatusCode, Option<String>, String) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, location, body)
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().uri(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::empty()).unwrap()
}

fn post_form(path: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

const HOUR: time::Duration = time::Duration::hours(1);

/// Alice, signed in, with a live reset link.
async fn alice_with_a_link(db: &brolly_test_support::TestDb) -> (String, String) {
    let user = db::create_user(
        &db.pool,
        "alice",
        Some("alice@example.org"),
        "old-password-1234",
        "member",
    )
    .await
    .unwrap();
    let session = db::create_session(&db.pool, user.id, time::Duration::days(1), None)
        .await
        .unwrap();
    let (token, _) = db::issue_password_reset(&db.pool, user.id, HOUR, time::Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    (
        format!("{}={session}", brolly_identity::extract::SESSION_COOKIE),
        token,
    )
}

fn reset(token: &str, new: &str, confirm: &str) -> Request<Body> {
    post_form(
        &format!("/reset?token={token}"),
        &format!("new_password={new}&confirm_password={confirm}"),
        None,
    )
}

#[tokio::test]
async fn a_live_link_shows_the_form() {
    let (db, _dir, router) = harness(None).await;
    let (_, token) = alice_with_a_link(&db).await;

    let (status, _, body) = send(&router, get(&format!("/reset?token={token}"), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("name=\"new_password\""), "{body}");
    assert!(
        body.contains(&format!("action=\"/reset?token={token}\"")),
        "{body}"
    );
    assert!(body.contains("alice"), "names whose password it is: {body}");
}

#[tokio::test]
async fn a_dead_link_says_so_and_shows_no_form() {
    let (_db, _dir, router) = harness(None).await;
    for path in ["/reset?token=not-a-token", "/reset"] {
        let (status, _, body) = send(&router, get(path, None)).await;
        assert_eq!(status, StatusCode::GONE, "{path}");
        assert!(
            !body.contains("<form method=\"post\" action=\"/reset"),
            "{path}: {body}"
        );
    }
    let (status, _, _) = send(
        &router,
        reset("not-a-token", "new-password-5678", "new-password-5678"),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn the_new_password_works_and_every_session_ends() {
    let (db, _dir, router) = harness(Some("https://front.example/profile")).await;
    let (cookie, token) = alice_with_a_link(&db).await;

    let (status, location, _) = send(
        &router,
        reset(&token, "new-password-5678", "new-password-5678"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("https://front.example/profile"));

    db::authenticate(&db.pool, "alice", "new-password-5678")
        .await
        .unwrap();
    // The session from before the reset is gone.
    let (status, location, _) = send(&router, get("/account", Some(&cookie))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location:?}");
    assert!(location.unwrap_or_default().starts_with("/login"));

    // Once only.
    let (status, _, _) = send(
        &router,
        reset(&token, "third-password-90", "third-password-90"),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn without_an_account_home_it_lands_on_login() {
    let (db, _dir, router) = harness(None).await;
    let (_, token) = alice_with_a_link(&db).await;
    let (status, location, _) = send(
        &router,
        reset(&token, "new-password-5678", "new-password-5678"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/login"));
}

#[tokio::test]
async fn a_short_or_mismatched_password_keeps_the_link() {
    let (db, _dir, router) = harness(None).await;
    let (_, token) = alice_with_a_link(&db).await;

    for (new, confirm) in [
        ("short", "short"),
        ("new-password-5678", "new-password-9999"),
    ] {
        let (status, _, body) = send(&router, reset(&token, new, confirm)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{new}/{confirm}");
        assert!(
            body.contains("name=\"new_password\""),
            "the form again: {body}"
        );
    }
    // Nothing was spent.
    assert!(
        db::password_reset_user(&db.pool, &token)
            .await
            .unwrap()
            .is_some()
    );
    db::authenticate(&db.pool, "alice", "old-password-1234")
        .await
        .unwrap();
}
