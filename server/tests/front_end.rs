//! An app in front of the instance (`FrontEnd`): the pages it takes over
//! redirect to it, and with nothing configured every page is brolly's own.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, FrontEnd, app};
use http_body_util::BodyExt;
use tower::ServiceExt;

const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;
const HOME: &str = "https://stuccoid.example.org/";
const SIGNUP: &str = "https://stuccoid.example.org/account/create";
const ACCOUNT_HOME: &str = "https://stuccoid.example.org/profile";

fn fronted() -> FrontEnd {
    FrontEnd {
        home: Some(HOME.into()),
        signup: Some(SIGNUP.into()),
        account_home: Some(ACCOUNT_HOME.into()),
        ..FrontEnd::default()
    }
}

async fn harness(
    public_registration: bool,
    front_end: FrontEnd,
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
        public_registration,
        front_end,
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

fn post_json(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A member with a live session, made directly: these tests are about where
/// the pages send people, not about the door.
async fn signed_in(db: &brolly_test_support::TestDb, username: &str) -> String {
    let user = db::create_user(
        &db.pool,
        username,
        Some(&format!("{username}@example.org")),
        "correct-horse-battery",
        "member",
    )
    .await
    .unwrap();
    let token = db::create_session(&db.pool, user.id, time::Duration::days(1), None)
        .await
        .unwrap();
    format!("{SESSION_COOKIE}={token}")
}

#[tokio::test]
async fn with_no_front_end_every_page_is_brollys_own() {
    let (_db, _dir, router) = harness(true, FrontEnd::default()).await;

    let (status, _, body) = send(&router, get("/", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("name=\"password\""), "the login form: {body}");

    let (status, _, _) = send(&router, get("/register", None)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = send(
        &router,
        post_json(
            "/api/accounts",
            r#"{"username":"alice","password":"correct-horse-battery"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "got: {body}");
}

#[tokio::test]
async fn the_homepage_hands_off_and_login_stays() {
    let (_db, _dir, router) = harness(false, fronted()).await;

    let (status, location, _) = send(&router, get("/", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some(HOME));

    // Every OAuth flow sends an anonymous visitor to /login; it must render.
    let (status, _, body) = send(&router, get("/login", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("name=\"password\""), "got: {body}");
}

#[tokio::test]
async fn the_register_page_hands_off_and_creates_nobody() {
    let (db, _dir, router) = harness(true, fronted()).await;

    let (status, location, _) = send(&router, get("/register", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some(SIGNUP));

    let (status, location, _) = send(
        &router,
        post_form(
            "/register",
            "username=alice&email=&password=correct-horse-battery",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some(SIGNUP));
    assert!(
        db::find_by_username(&db.pool, "alice")
            .await
            .unwrap()
            .is_none(),
        "a delegated door creates nobody"
    );
}

/// Delegated signup closes the public API even on a public instance: the
/// front end is the only way in, so its records see every account.
#[tokio::test]
async fn delegated_signup_closes_the_public_api() {
    let (db, _dir, router) = harness(true, fronted()).await;

    let (status, _, body) = send(
        &router,
        post_json(
            "/api/accounts",
            r#"{"username":"alice","password":"correct-horse-battery"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "got: {body}");
    assert!(
        db::find_by_username(&db.pool, "alice")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_profile_and_delete_pages_hand_off() {
    let (db, _dir, router) = harness(false, fronted()).await;
    let cookie = signed_in(&db, "alice").await;

    for request in [
        get("/account/profile", Some(&cookie)),
        post_form("/account/profile", "display_name=Alice&bio=", Some(&cookie)),
        get("/account/delete", Some(&cookie)),
        post_form("/account/delete", "confirm=alice", Some(&cookie)),
    ] {
        let path = request.uri().to_string();
        let (status, location, _) = send(&router, request).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(location.as_deref(), Some(ACCOUNT_HOME), "{path}");
    }

    assert!(
        db::find_by_username(&db.pool, "alice")
            .await
            .unwrap()
            .is_some(),
        "the handed-off delete deleted nothing"
    );

    // The rest of the dashboard is still brolly's.
    let (status, _, _) = send(&router, get("/account/security", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn without_an_account_home_the_profile_page_is_brollys() {
    let (db, _dir, router) = harness(false, FrontEnd::default()).await;
    let cookie = signed_in(&db, "alice").await;

    let (status, _, _) = send(&router, get("/account/profile", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
}
