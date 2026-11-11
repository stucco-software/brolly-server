//! The service API (`/internal/v1/`): what an app in front of the instance
//! runs the account lifecycle through.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, FrontEnd, app};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn harness(
    token: Option<&str>,
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
        // Invite-only on purpose: the service must not need an open door.
        public_registration: false,
        front_end: FrontEnd {
            service_token_hash: token.map(db::hash_secret),
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

const TOKEN: &str = "0123456789abcdef0123456789abcdef-service";

fn call(method: &str, path: &str, body: Option<&str>) -> Request<Body> {
    call_as(method, path, body, Some(TOKEN), None, None)
}

fn call_as(
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
    host: Option<&str>,
    forwarded_for: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(host) = host {
        request = request.header(header::HOST, host);
    }
    if let Some(ip) = forwarded_for {
        request = request.header("x-forwarded-for", ip);
    }
    match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    }
}

fn alice() -> &'static str {
    r#"{"username":"alice","email":"alice@example.org","password":"correct-horse-battery"}"#
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

#[tokio::test]
async fn without_a_token_configured_the_api_does_not_exist() {
    let (_db, _dir, router) = harness(None).await;
    let (status, _, _) = send(
        &router,
        call("POST", "/internal/v1/accounts", Some(alice())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_missing_or_wrong_token_is_refused() {
    let (db, _dir, router) = harness(Some(TOKEN)).await;
    for token in [None, Some("not-the-token"), Some("")] {
        let (status, _, body) = send(
            &router,
            call_as(
                "POST",
                "/internal/v1/accounts",
                Some(alice()),
                token,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
        assert_eq!(json(&body)["error"], "unauthorized");
    }
    assert!(
        db::find_by_username(&db.pool, "alice")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_members_subdomain_has_no_service_api() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    let (status, _, _) = send(
        &router,
        call_as(
            "GET",
            "/internal/v1/usernames/bob",
            None,
            Some(TOKEN),
            Some("alice.brolly.test"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_service_creates_a_member_on_an_invite_only_instance() {
    let (db, _dir, router) = harness(Some(TOKEN)).await;

    let (status, _, body) = send(
        &router,
        call("POST", "/internal/v1/accounts", Some(alice())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "got: {body}");
    let body = json(&body);
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.org");
    assert_eq!(body["webId"], "https://alice.brolly.test/profile#me");
    assert_eq!(body["storage"], "https://alice.brolly.test/~/");

    let alice = db::find_by_username(&db.pool, "alice")
        .await
        .unwrap()
        .expect("created");
    assert_eq!(alice.role, "member");
    // The whole member: the login works.
    db::authenticate(&db.pool, "alice", "correct-horse-battery")
        .await
        .unwrap();
}

#[tokio::test]
async fn creation_names_what_is_wrong() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    let (status, _, _) = send(
        &router,
        call("POST", "/internal/v1/accounts", Some(alice())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    for (request, status, expected) in [
        (
            r#"{"username":"alice","email":"other@example.org","password":"correct-horse-battery"}"#,
            StatusCode::CONFLICT,
            serde_json::json!({"error": "username_taken"}),
        ),
        (
            r#"{"username":"alice2","email":"ALICE@example.org","password":"correct-horse-battery"}"#,
            StatusCode::CONFLICT,
            serde_json::json!({"error": "email_taken"}),
        ),
    ] {
        let (got, _, body) = send(
            &router,
            call("POST", "/internal/v1/accounts", Some(request)),
        )
        .await;
        assert_eq!(got, status, "{request}");
        assert_eq!(json(&body), expected, "{request}");
    }

    for (request, field) in [
        (
            r#"{"username":"bob","email":"bob@example.org","password":"short"}"#,
            "password",
        ),
        (
            r#"{"username":"-bob","email":"bob@example.org","password":"correct-horse-battery"}"#,
            "username",
        ),
        (
            r#"{"username":"admin","email":"bob@example.org","password":"correct-horse-battery"}"#,
            "username",
        ),
        (
            r#"{"username":"bob","email":"  ","password":"correct-horse-battery"}"#,
            "email",
        ),
        (r#"{"username":"bob"}"#, "body"),
    ] {
        let (got, _, body) = send(
            &router,
            call("POST", "/internal/v1/accounts", Some(request)),
        )
        .await;
        assert_eq!(got, StatusCode::UNPROCESSABLE_ENTITY, "{request}");
        let body = json(&body);
        assert_eq!(body["error"], "validation", "{request}");
        assert_eq!(body["field"], field, "{request}");
        assert!(
            body["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "{request}"
        );
    }
}

/// Every StuccoID signup comes from the same few addresses. The door's
/// per-address gate (5 per 10 minutes) would stop the sixth person.
#[tokio::test]
async fn the_service_is_not_held_by_the_signup_gate() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    for i in 0..8 {
        let request = format!(
            r#"{{"username":"member{i}","email":"member{i}@example.org","password":"correct-horse-battery"}}"#
        );
        let (status, _, body) = send(
            &router,
            call_as(
                "POST",
                "/internal/v1/accounts",
                Some(&request),
                Some(TOKEN),
                None,
                Some("203.0.113.7"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "signup {i}: {body}");
    }
}

#[tokio::test]
async fn usernames_are_available_taken_reserved_or_invalid() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    send(
        &router,
        call("POST", "/internal/v1/accounts", Some(alice())),
    )
    .await;

    for (username, expected) in [
        ("bob", serde_json::json!({"available": true})),
        (
            "alice",
            serde_json::json!({"available": false, "reason": "taken"}),
        ),
        (
            "admin",
            serde_json::json!({"available": false, "reason": "reserved"}),
        ),
        (
            "-bob",
            serde_json::json!({"available": false, "reason": "invalid"}),
        ),
        (
            "Bob",
            serde_json::json!({"available": false, "reason": "invalid"}),
        ),
    ] {
        let (status, _, body) = send(
            &router,
            call("GET", &format!("/internal/v1/usernames/{username}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{username}");
        assert_eq!(json(&body), expected, "{username}");
    }
}

#[tokio::test]
async fn an_account_is_found_by_its_webid_and_nothing_else() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    send(
        &router,
        call("POST", "/internal/v1/accounts", Some(alice())),
    )
    .await;

    let (status, _, body) = send(
        &router,
        call(
            "GET",
            "/internal/v1/accounts?webId=https%3A%2F%2Falice.brolly.test%2Fprofile%23me",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    let body = json(&body);
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.org");

    for web_id in [
        "https%3A%2F%2Fbob.brolly.test%2Fprofile%23me", // nobody
        "https%3A%2F%2Falice.elsewhere.test%2Fprofile%23me", // another instance
        "https%3A%2F%2Falice.brolly.test%2Fprofile%2Fcard%23me", // not a brolly WebID
        "https%3A%2F%2Fevil.alice.brolly.test%2Fprofile%23me", // nested subdomain
    ] {
        let (status, _, _) = send(
            &router,
            call(
                "GET",
                &format!("/internal/v1/accounts?webId={web_id}"),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{web_id}");
    }
}

#[tokio::test]
async fn a_password_is_checked_and_guessing_is_limited() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    send(
        &router,
        call("POST", "/internal/v1/accounts", Some(alice())),
    )
    .await;
    let check = |password: &str| {
        call(
            "POST",
            "/internal/v1/accounts/alice/verify-password",
            Some(&format!(r#"{{"password":"{password}"}}"#)),
        )
    };

    let (status, _, _) = send(&router, check("correct-horse-battery")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(&router, check("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Unknown members answer like wrong passwords.
    let (status, _, _) = send(
        &router,
        call(
            "POST",
            "/internal/v1/accounts/nobody/verify-password",
            Some(r#"{"password":"x"}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Ten attempts per username per fifteen minutes; two are spent above.
    for _ in 0..8 {
        send(&router, check("wrong")).await;
    }
    let (status, _, _) = send(&router, check("correct-horse-battery")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_deleted_account_is_gone() {
    let (db, _dir, router) = harness(Some(TOKEN)).await;
    send(
        &router,
        call("POST", "/internal/v1/accounts", Some(alice())),
    )
    .await;

    let (status, _, _) = send(&router, call("DELETE", "/internal/v1/accounts/alice", None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        db::find_by_username(&db.pool, "alice")
            .await
            .unwrap()
            .is_none()
    );

    let (status, _, _) = send(&router, call("DELETE", "/internal/v1/accounts/alice", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The name is free again.
    let (_, _, body) = send(&router, call("GET", "/internal/v1/usernames/alice", None)).await;
    assert_eq!(json(&body), serde_json::json!({"available": true}));
}
