//! The front door, end to end, against a real database.
//!
//! §4.1 calls the anonymous visitor "first contact — determines whether anyone
//! joins at all". These assert it actually works, not just that it renders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_store::resources::{Kind, PodRead};
use http_body_util::BodyExt;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

/// The session cookie's name, from the one place that defines it.
const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;

async fn harness() -> (brolly_test_support::TestDb, tempfile::TempDir, axum::Router) {
    harness_with(false).await
}

/// The door's policy is the deployment's: every test here runs against one of
/// the two, so the harness takes it rather than the env var.
async fn harness_with(
    public_registration: bool,
) -> (brolly_test_support::TestDb, tempfile::TempDir, axum::Router) {
    harness_as(public_registration, None).await
}

/// And the `www` host is the deployment's too: the redirect tests pass a
/// target, everything else runs with the host unclaimed.
async fn harness_as(
    public_registration: bool,
    www_redirect: Option<&str>,
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
        public_registration,
        limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
        www_redirect: www_redirect.map(str::to_string),
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

/// `post`, as seen from `ip` — the address the proxy in front of a deployment
/// reports in `X-Forwarded-For`.
async fn post_from(
    router: &axum::Router,
    path: &str,
    body: &str,
    ip: &str,
) -> (StatusCode, String, Vec<String>, Option<String>) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-for", ip)
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
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    // `Retry-After` rides in the location slot's neighbour so the tuple shape
    // stays the one every other test destructures.
    (status, body, cookies, location.or(retry_after))
}

/// Returns `Location` too: several flows assert where a successful POST lands.
async fn post(
    router: &axum::Router,
    path: &str,
    body: &str,
) -> (StatusCode, String, Vec<String>, Option<String>) {
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
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body, cookies, location)
}

async fn get(router: &axum::Router, path: &str) -> (StatusCode, String) {
    let (status, body, _) = get_as(router, path, None).await;
    (status, body)
}

/// Returns `Location` as well as status and body, because the door's whole
/// behaviour for a signed-in visitor is a redirect.
async fn get_as(
    router: &axum::Router,
    path: &str,
    cookie: Option<&str>,
) -> (StatusCode, String, Option<String>) {
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
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body, location)
}

/// Register `alice` and return her session cookie, `name=value` only.
async fn register_alice(db: &brolly_test_support::TestDb, router: &axum::Router) -> String {
    let code = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();
    let (_, _, cookies, _) = post(
        router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;
    cookies
        .iter()
        .find(|c| c.starts_with(&format!("{SESSION_COOKIE}=")))
        .expect("a session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// Every `error` event emitted on this thread while it's installed, as text.
///
/// `#[tokio::test]` runs the test and the handlers it drives on one thread, so
/// a thread-local subscriber sees everything registration logs.
struct ErrorLog {
    events: Arc<Mutex<Vec<String>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl ErrorLog {
    fn install() -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Collect(Arc::clone(&events)));
        Self {
            events,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

struct Collect(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collect {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() == tracing::Level::ERROR {
            let mut text = event.metadata().target().to_string();
            event.record(&mut Fields(&mut text));
            self.0.lock().unwrap().push(text);
        }
    }
}

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
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

    let (status, body, cookies, _) = post(
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
    let code = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();

    let (status, _, cookies, _) = post(
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
    let session = cookies
        .iter()
        .find(|c| c.starts_with(&format!("{SESSION_COOKIE}=")));
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
    let code = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();

    let (first, _, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(first, StatusCode::SEE_OTHER);

    let (second, body, _, _) = post(
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
    let code = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();

    // "Alice" is invalid: usernames become subdomains.
    let (status, _, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=Alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The invite must still work — validation happens before redemption.
    let (retry, _, _, _) = post(
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

/// `next` is the open-redirect surface of the door, and a browser's idea of
/// where `Location: /<TAB>/evil.example/` points is `//evil.example/` — it
/// strips the tab before parsing (WHATWG URL §4.4) — so what the server
/// thinks is "a path starting with a slash" lands a freshly signed-in
/// member on another host. Such a `next` is dropped, not sanitised: the
/// member lands where they would have with no `next` at all.
#[tokio::test]
async fn a_next_a_browser_would_read_as_another_host_is_dropped() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    for next in [
        "%2F%09%2Fevil.example%2F",
        "%2F%0A%2Fevil.example%2F",
        "%2Fa%5Cevil.example%2F",
    ] {
        let (status, _, _, location) = post(
            &router,
            &format!("/login?next={next}"),
            "username=alice&password=correct-horse-battery",
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "next={next}");
        assert_eq!(location.as_deref(), Some("/account"), "next={next}");
    }
}

/// Guessing a known member's password is the attack the door exists to
/// resist, and argon2's cost alone is a brake, not a wall. The gate here is
/// per *username*, so an attacker rotating addresses gains nothing: ten
/// wrong answers for alice, from ten different places, and the eleventh is
/// refused with a `Retry-After` — whoever sends it, including alice.
#[tokio::test]
async fn login_attempts_on_one_account_are_limited_whatever_the_address() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    for i in 0..10 {
        let (status, _, _, _) = post_from(
            &router,
            "/login",
            "username=alice&password=wrong",
            &format!("203.0.113.{i}"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    let (status, _, _, retry_after) = post_from(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
        "203.0.113.200",
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let seconds: u64 = retry_after.expect("Retry-After").parse().unwrap();
    assert!(seconds >= 1, "a wait, not a free retry");

    // Bob's door is bob's: another account is untouched.
    let (status, _, _, _) = post_from(
        &router,
        "/login",
        "username=bob&password=wrong",
        "203.0.113.200",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// And per *address*: one place spraying guesses across many usernames is
/// the other shape of the same attack.
#[tokio::test]
async fn login_attempts_from_one_address_are_limited_whatever_the_account() {
    let (_db, _dir, router) = harness().await;
    for i in 0..10 {
        let (status, _, _, _) = post_from(
            &router,
            "/login",
            &format!("username=user{i}&password=wrong"),
            "203.0.113.7",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    let (status, _, _, _) = post_from(
        &router,
        "/login",
        "username=user99&password=wrong",
        "203.0.113.7",
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// Registration mints a pod, keypairs and an identity per account — the most
/// expensive thing an anonymous caller can make the instance do. On a public
/// instance that is a disk-and-CPU faucet without a gate; on a private one
/// it is invite guessing (infeasible at 256 bits, but free is still wrong).
/// Both surfaces, the form and the API, share one gate per address.
#[tokio::test]
async fn account_creation_from_one_address_is_limited_across_both_surfaces() {
    let (_db, _dir, router) = harness_with(true).await;
    let mut created = 0;
    for i in 0..5 {
        let (status, _, _, _) = post_from(
            &router,
            "/register",
            &format!("username=member{i}&email=&password=correct-horse-battery"),
            "203.0.113.7",
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "registration {i}");
        created += 1;
    }
    assert_eq!(created, 5);

    // The sixth, through the other surface, is the same gate.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/accounts")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "203.0.113.7")
                .body(Body::from(
                    r#"{"username":"member6","password":"correct-horse-battery"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(header::RETRY_AFTER));

    // Somebody else, somewhere else, is not held up by it.
    let (status, _, _, _) = post_from(
        &router,
        "/register",
        "username=elsewhere&email=&password=correct-horse-battery",
        "198.51.100.1",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

/// A browser names where a POST came from, and a form post from any origin
/// but ours is refused before the handler runs — whatever the cookie says.
/// `SameSite=Lax` keeps the session cookie off a cross-*site* post, but a
/// member's own subdomain is same-site with the apex, so the day a member
/// can serve a document is the day Lax stops being a defence. This is the
/// defence that does not depend on that day never coming.
#[tokio::test]
async fn a_form_post_from_another_origin_is_refused() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let login = |origin: &'static str| {
        Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, origin)
            .body(Body::from("username=alice&password=correct-horse-battery"))
            .unwrap()
    };

    let response = router
        .clone()
        .oneshot(login("https://evil.example"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "no session for a cross-origin post"
    );

    // Our own origin, as every browser sends it on a same-origin post.
    let response = router
        .clone()
        .oneshot(login("https://brolly.test"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

/// The door, the dashboard and the admin console are the instance's, and a
/// member's subdomain is their pod (ADR 0009): none of it answers there. A
/// login form on alice.<apex> is a place to type a password that the
/// instance never named, and a session minted there is a host-only cookie on
/// a member host — the one place a session cookie must never exist, since
/// that host is the one a member's own documents would be served from.
#[tokio::test]
async fn the_door_the_dashboard_and_the_console_are_apex_only() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    // Each with the method it accepts and a body it would take, so a 404 is
    // the host rule and not the router's own 405 or 415.
    // `/` too: ADR 0010 reserves a member's root for a profile page that
    // does not exist yet, and until it does the root answers what the
    // fallback answers for `SubdomainRoute::Root` — a 404 — rather than the
    // login form the route order let through.
    for (method, path) in [
        ("GET", "/"),
        ("GET", "/login"),
        ("POST", "/login"),
        ("GET", "/register"),
        ("POST", "/register"),
        ("POST", "/logout"),
        ("GET", "/account"),
        ("GET", "/account/profile"),
        ("POST", "/account/profile"),
        ("GET", "/account/security"),
        ("POST", "/account/security"),
        ("GET", "/account/apps"),
        ("POST", "/account/apps"),
        ("GET", "/account/export"),
        ("GET", "/account/delete"),
        ("POST", "/account/delete"),
        ("GET", "/admin"),
        ("GET", "/admin/users"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::HOST, "alice.brolly.test")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("username=alice&password=correct-horse-battery"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{method} {path} answered on a member subdomain"
        );
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "{method} {path}: a cookie was set on a member host"
        );
    }
}

#[tokio::test]
async fn login_succeeds_and_sets_a_session() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let (status, _, cookies, _) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let token = cookies
        .iter()
        .find_map(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")))
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

    let (existing_status, existing_body, cookies, _) =
        post(&router, "/login", "username=alice&password=wrong").await;
    let (missing_status, missing_body, _, _) =
        post(&router, "/login", "username=mallory&password=wrong").await;

    assert_eq!(existing_status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);
    assert!(cookies.is_empty());

    // Identical wording, so the page cannot be used to enumerate accounts.
    let extract = |b: &str| b.contains("Incorrect username or password.");
    assert!(extract(&existing_body) && extract(&missing_body));
}

/// A taken username is the one rejection that happened *after* the invite
/// was redeemed, so the invitee who typed a name somebody already has was
/// locked out and needed a new invite — while the comment on create_member
/// promised the opposite. Availability is checked first now.
#[tokio::test]
async fn a_taken_username_does_not_consume_the_invite() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let code = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();

    let (status, _, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (retry, _, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice2&email=&password=correct-horse-battery"),
    )
    .await;
    assert_eq!(
        retry,
        StatusCode::SEE_OTHER,
        "a taken username must not burn the invite"
    );
}

/// Email is unique because createSession accepts it as an identifier, and a
/// second account on the same address was reported as a *username* clash —
/// the one unique violation mapped to the one error. The member retyping a
/// free username got the same answer forever. Named for what it is now.
#[tokio::test]
async fn the_api_names_a_taken_email_as_such() {
    let (_db, _dir, router) = harness_with(true).await;
    let first = post_json(
        &router,
        "/api/accounts",
        r#"{"username":"alice","email":"alice@example.org","password":"correct-horse-battery"}"#,
    )
    .await;
    assert_eq!(first.0, StatusCode::CREATED, "{}", first.1);

    let (status, body) = post_json(
        &router,
        "/api/accounts",
        r#"{"username":"alice2","email":"alice@example.org","password":"correct-horse-battery"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("\"email_taken\""), "got: {body}");
    assert!(!body.contains("username_taken"), "got: {body}");
}

#[tokio::test]
async fn a_short_password_is_refused_before_the_invite_is_spent() {
    let (db, _dir, router) = harness().await;
    let code = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .unwrap();

    let (status, body, _, _) = post(
        &router,
        "/register",
        &format!("invite={code}&username=alice&email=&password=short"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("12 characters"), "got: {body}");

    let (retry, _, _, _) = post(
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
    let (_, _, cookies, _) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    let token = cookies
        .iter()
        .find_map(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .and_then(|c| c.split(';').next())
        .unwrap()
        .to_string();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .header(header::COOKIE, format!("{SESSION_COOKIE}={token}"))
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

/// A `__Host-` cookie can only be cleared by a `Set-Cookie` that carries the
/// prefix's attributes (ADR 0018, control 6). `CookieJar::remove` on a bare
/// name would emit a removal without `Secure` or `Path`, which the browser
/// drops — the session would be revoked server-side and the cookie would
/// stay in the browser, inert but present. The removal has to be built from
/// the same cookie the login set.
#[tokio::test]
async fn logout_clears_a_host_prefixed_cookie_the_browser_will_honour() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let (_, _, cookies, _) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    let session = cookies
        .iter()
        .find(|c| c.starts_with("__Host-brolly_session="))
        .expect("a __Host- session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let removal = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("__Host-brolly_session="))
        .expect("a removal Set-Cookie")
        .to_string();
    assert!(removal.starts_with("__Host-brolly_session=;"), "{removal}");
    assert!(removal.contains("Max-Age=0"), "{removal}");
    assert!(removal.contains("Secure"), "{removal}");
    assert!(removal.contains("Path=/"), "{removal}");
    assert!(!removal.contains("Domain="), "{removal}");
}

/// The old name authenticates nothing: a cookie minted on a member host
/// before `0a465e0`, or one tossed by a member page, is inert (ADR 0018).
#[tokio::test]
async fn the_old_cookie_name_is_not_a_session() {
    let (db, _dir, router) = harness().await;
    let user = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let token = db::create_session(&db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();

    let (status, _, location) = get_on_host(&router, "/account", "brolly.test").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "no cookie: to login");
    assert!(location.unwrap().starts_with("/login"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account")
                .header(header::HOST, "brolly.test")
                .header(header::COOKIE, format!("brolly_session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a valid token under the old name is not a session"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account")
                .header(header::HOST, "brolly.test")
                .header(header::COOKIE, format!("__Host-brolly_session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the same token under the new name is"
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
    let invite = db::create_invite(&db.pool, None, 1, None, None)
        .await
        .expect("invite");

    let (status, _, cookies, _) = post(
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

    // 201: the note didn't exist, and a PUT that creates says so (5b, H11).
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "a newly registered member cannot write to their own pod"
    );
}

/// Stage 5a: registration opens a brand-new pod, which the upgrade marks
/// current on the spot, and provisioning records its root and root ACL in the
/// pod's metadata. None of that is an error.
///
/// Reopening the pod is what shows it's at layout 2. An unmarked pod would be
/// upgraded again, find no old-layout root (provisioning never writes one), and
/// log at `error`.
#[tokio::test]
async fn a_new_registrations_pod_starts_on_the_current_layout() {
    let errors = ErrorLog::install();
    let (db, dir, router) = harness().await;
    register_alice(&db, &router).await;
    let alice = db::find_by_username(&db.pool, "alice")
        .await
        .unwrap()
        .expect("registration created alice");

    // Close every store the server holds, so the pod is opened afresh.
    drop(router);
    let stores = brolly_store::StoreManager::open(dir.path(), 4, 60).expect("reopen the stores");
    let pod = stores.pod(alice.id).expect("reopen alice's pod");

    let root = pod
        .read(|r| r.meta("https://alice.brolly.test/~/"))
        .unwrap()
        .expect("provisioning recorded the storage root");
    assert!(
        matches!(root.kind, Kind::Container),
        "the root is a container"
    );
    let acl = pod
        .read(|r| r.meta("https://alice.brolly.test/~/.acl"))
        .unwrap()
        .expect("the root ACL is a resource");
    assert!(
        matches!(acl.kind, Kind::Auxiliary),
        "the root ACL is auxiliary"
    );

    assert_eq!(
        errors.take(),
        Vec::<String>::new(),
        "registering or reopening the pod logged an error"
    );
}

// --- the front door -------------------------------------------------------

/// `/` and `/login` are one template on two routes, so they cannot drift.
#[tokio::test]
async fn the_front_door_and_the_login_page_are_the_same_page() {
    let (_db, _dir, router) = harness().await;

    let (_, root, _) = get_as(&router, "/", None).await;
    let (_, login, _) = get_as(&router, "/login", None).await;

    assert_eq!(root, login);
}

/// Replaces `the_landing_page_knows_you_are_signed_in`, which asserted 200 on a
/// page that named who you were. A login form is not an answer to a request
/// from somebody already logged in.
#[tokio::test]
async fn the_front_door_sends_a_signed_in_member_to_their_account() {
    let (db, _dir, router) = harness().await;
    let cookie = register_alice(&db, &router).await;

    let (status, _, location) = get_as(&router, "/", Some(&cookie)).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/account"));
}

/// Replaces `the_landing_page_still_invites_anonymous_visitors_in`. The door
/// names the instance and lets you in; it no longer sells anything.
#[tokio::test]
async fn the_front_door_names_the_instance_and_lets_you_in() {
    let (_db, _dir, router) = harness().await;

    let (status, body, _) = get_as(&router, "/", None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<h1>brolly.test</h1>"), "got: {body}");
    assert!(body.contains("name=\"password\""), "got: {body}");
    assert!(body.contains(r#"href="/register""#), "got: {body}");
}

/// Kept, retargeted: a stale cookie still reaches the door rather than
/// bouncing into a loop.
#[tokio::test]
async fn a_stale_session_cookie_falls_back_to_the_anonymous_front_door() {
    let (_db, _dir, router) = harness().await;

    let (status, body, _) = get_as(
        &router,
        "/",
        Some(&format!("{SESSION_COOKIE}=not-a-real-token")),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "a bad cookie must not 500");
    assert!(body.contains("name=\"password\""), "got: {body}");
}

/// The source link is not optional: AGPL-3.0 §13 means an operator running a
/// modified copy owes their users the source, and a link from a page every user
/// reaches is the cheapest discharge. Terms and privacy are optional.
#[tokio::test]
async fn the_fine_print_is_configuration() {
    let (_db, _dir, router) = harness().await;
    let (status, body) = get(&router, "/login").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(brolly_server::SOURCE_URL_DEFAULT),
        "the source link always renders"
    );
    assert!(!body.contains(">Terms<"), "unset terms renders no link");
    assert!(!body.contains(">Privacy<"), "unset privacy renders no link");
}

// --- the door bounces people who are already in ------------------------------

/// A login form is not an answer to a request from somebody already logged in.
#[tokio::test]
async fn a_signed_in_visitor_is_sent_to_their_account() {
    let (db, _dir, router) = harness().await;
    let cookie = register_alice(&db, &router).await;

    for path in ["/login", "/register"] {
        let (status, _, location) = get_as(&router, path, Some(&cookie)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path} should redirect");
        assert_eq!(location.as_deref(), Some("/account"), "{path}");
    }
}

/// ...but an anonymous one still gets the form, and a stale cookie counts as
/// anonymous rather than bouncing into a loop.
#[tokio::test]
async fn an_anonymous_visitor_still_gets_the_form() {
    let (_db, _dir, router) = harness().await;

    let (status, body, _) = get_as(&router, "/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("name=\"password\""));

    let (status, _, _) = get_as(
        &router,
        "/login",
        Some(&format!("{SESSION_COOKIE}=nonsense")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a stale cookie is not a redirect loop"
    );
}

/// Logging in lands on the dashboard, not on a door that would immediately
/// bounce them to the dashboard.
#[tokio::test]
async fn a_successful_login_lands_on_the_account() {
    let (db, _dir, router) = harness().await;
    let _ = register_alice(&db, &router).await;

    let (status, _, _, location) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/account"));
}

// --- the door ----------------------------------------------------------------

/// The door is chromeless: the name panel IS the brand, so a header repeating
/// the instance name would be the same words twice.
#[tokio::test]
async fn the_door_has_no_chrome() {
    let (_db, _dir, router) = harness().await;
    let (_, body, _) = get_as(&router, "/login", None).await;

    assert!(
        !body.contains("shell-header"),
        "the door suppresses the header"
    );
    assert!(!body.contains("shell-footer"), "and the footer");
    assert!(body.contains("skip-link"), "but keeps the skip link");
    assert!(body.contains("<main"), "and the main landmark");
}

/// The page is *this instance*; logging in is what you do on it. The invariant
/// counts h1s but does not say which one wins — this does.
#[tokio::test]
async fn the_instance_name_is_the_heading() {
    let (_db, _dir, router) = harness().await;
    let (_, body, _) = get_as(&router, "/login", None).await;

    assert!(body.contains("<h1>brolly.test</h1>"), "got: {body}");
    assert!(body.contains("<h2>Log in</h2>"), "got: {body}");
}

/// The description has never reached a human before now — it was read only by
/// mastodon_api, for /api/v1/instance.
#[tokio::test]
async fn the_door_shows_the_instance_description() {
    let (_db, _dir, router) = harness().await;
    let (_, body, _) = get_as(&router, "/login", None).await;
    assert!(body.contains("A private community server."), "got: {body}");
}

/// Register shares the door. This is the seam the whole design exists to close,
/// so it gets its own assertion rather than being assumed from /login.
#[tokio::test]
async fn register_renders_the_door_too() {
    let (_db, _dir, router) = harness().await;
    let (status, body, _) = get_as(&router, "/register", None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("shell-header"));
    assert!(body.contains("<h1>brolly.test</h1>"));
    assert!(body.contains("name=\"invite\""));
}

// --- the registration policy (public vs invite-only) --------------------------

/// A JSON POST helper for the account-creation API. The API's callers are
/// scripts on other origins, so the tests are too.
async fn post_json(router: &axum::Router, path: &str, body: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body)
}

/// On an invite-only instance the register form asks for an invite, and says
/// so — a visitor should learn the door's policy from the page, not from a
/// failed submission.
#[tokio::test]
async fn a_private_instance_form_asks_for_an_invite() {
    let (_db, _dir, router) = harness().await;
    let (_, body, _) = get_as(&router, "/register", None).await;

    assert!(body.contains("name=\"invite\""), "got: {body}");
    assert!(body.contains("invite-only"), "got: {body}");
}

/// On a public instance the form asks for no invite: the field is dropped, not
/// marked optional, so a signup page never suggests an invite exists to
/// present.
#[tokio::test]
async fn a_public_instance_form_asks_for_no_invite() {
    let (_db, _dir, router) = harness_with(true).await;
    let (_, body, _) = get_as(&router, "/register", None).await;

    assert!(!body.contains("name=\"invite\""), "got: {body}");
    assert!(!body.contains("invite-only"), "got: {body}");
}

/// The default is the conservative door: no invite, no account — on the API
/// exactly as on the form, so the API is not a way around an invite-only
/// instance.
#[tokio::test]
async fn a_private_instance_api_requires_an_invite() {
    let (_db, _dir, router) = harness().await;

    let (status, body) = post_json(
        &router,
        "/api/accounts",
        r#"{"username":"alice","password":"correct-horse-battery"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("\"invite_invalid\""), "got: {body}");
}

/// A public instance's API creates the account with no invite, and answers
/// with the two facts a signup surface needs: the handle and the WebID.
#[tokio::test]
async fn a_public_instance_api_creates_an_account() {
    let (db, _dir, router) = harness_with(true).await;

    let (status, body) = post_json(
        &router,
        "/api/accounts",
        r#"{"username":"alice","email":"alice@example.org","password":"correct-horse-battery"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "got: {body}");
    assert!(body.contains("\"username\":\"alice\""), "got: {body}");
    assert!(
        body.contains("\"webid\":\"https://alice.brolly.test/profile#me\""),
        "got: {body}"
    );

    // The API creates the member — the full member, pod and ATProto identity
    // included — not a row that half-works. `find_by_username` answering is
    // the row; the login working is the password.
    db::find_by_username(&db.pool, "alice")
        .await
        .unwrap()
        .expect("the API created the member");
    let (_, _, cookies, _) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    assert!(!cookies.is_empty(), "the created member can log in");
}

/// The API answers a signup surface on another origin, and CORS is what lets
/// that surface's script read the answer — including the error, which is how
/// it learns a handle is taken.
#[tokio::test]
async fn the_api_answers_a_cross_origin_caller() {
    let (_db, _dir, router) = harness_with(true).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/accounts")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://signup.example.org")
                .body(Body::from(
                    r#"{"username":"alice","password":"correct-horse-battery"}"#.to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("https://signup.example.org"),
        "the origin is echoed, so the calling script can read the answer"
    );
}

/// A taken username is a conflict, with a code a signup surface can switch on
/// rather than a message it has to parse — the predecessor's app had to
/// regex-match CSS's prose to learn this, which is the trap the codes exist
/// to close.
#[tokio::test]
async fn the_api_names_a_taken_username() {
    let (_db, _dir, router) = harness_with(true).await;
    let first = post_json(
        &router,
        "/api/accounts",
        r#"{"username":"alice","password":"correct-horse-battery"}"#,
    )
    .await;
    assert_eq!(first.0, StatusCode::CREATED);

    let (status, body) = post_json(
        &router,
        "/api/accounts",
        r#"{"username":"alice","password":"correct-horse-battery"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("\"username_taken\""), "got: {body}");
}

/// A public instance still redeems an invite that is presented — optional,
/// never ignored. The bootstrap admin invite is how an empty instance gets its
/// first admin on either policy, and treating a presented admin invite as no
/// invite would register the operator as a plain member.
#[tokio::test]
async fn a_public_instance_still_redeems_a_presented_invite() {
    let (db, _dir, router) = harness_with(true).await;
    let code = db::create_invite(&db.pool, None, 1, None, Some("admin"))
        .await
        .unwrap();

    let (status, _) = post_json(
        &router,
        "/api/accounts",
        &format!(r#"{{"username":"alice","password":"correct-horse-battery","invite":"{code}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let alice = db::find_by_username(&db.pool, "alice")
        .await
        .unwrap()
        .expect("created");
    assert_eq!(
        alice.role, "admin",
        "the invite's grant survived the policy"
    );
}

/// A presented-but-invalid invite is refused on a public instance too. Serving
/// it as a plain member registration would silently downgrade an admin
/// bootstrap attempt, and telling the caller which invites exist would make
/// the endpoint an oracle.
#[tokio::test]
async fn a_public_instance_refuses_an_invalid_presented_invite() {
    let (_db, _dir, router) = harness_with(true).await;

    let (status, body) = post_json(
        &router,
        "/api/accounts",
        r#"{"username":"alice","password":"correct-horse-battery","invite":"nonsense"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("\"invite_invalid\""), "got: {body}");
}

/// The form on a public instance takes the same path: no invite needed — and
/// the browser posts no `invite` key at all, because the field is not
/// rendered, so this posts exactly what that form submits.
#[tokio::test]
async fn a_public_instance_form_registers_without_an_invite() {
    let (_db, _dir, router) = harness_with(true).await;

    let (status, _, cookies, location) = post(
        &router,
        "/register",
        "username=alice&email=&password=correct-horse-battery",
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/account"));
    assert!(!cookies.is_empty(), "the member is logged in");
}

/// A member's subdomain is their pod, and an instance-level endpoint does not
/// answer there (ADR 0009) — the same 404 the OAuth surface gives, not a 201
/// from someone else's pod host.
#[tokio::test]
async fn the_api_does_not_answer_on_a_member_subdomain() {
    let (_db, _dir, router) = harness_with(true).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/accounts")
                .header(header::HOST, "alice.brolly.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"alice","password":"correct-horse-battery"}"#.to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- the www host (BROLLY_WWW_REDIRECT) ---------------------------------------

/// A `GET` with an explicit host, for the host-routed surfaces.
async fn get_on_host(
    router: &axum::Router,
    path: &str,
    host: &str,
) -> (StatusCode, String, Option<String>) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::HOST, host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body, location)
}

/// Configured, the `www` host sends everything to the configured base, with
/// the path and query intact — a deep link to `www/pricing` lands on the
/// target's `/pricing`, not its front page.
#[tokio::test]
async fn a_configured_www_host_redirects_with_path_and_query() {
    let (_db, _dir, router) = harness_as(false, Some("https://stucco.software/stuccoid")).await;

    let (status, _, location) =
        get_on_host(&router, "/pricing?section=member", "www.brolly.test").await;

    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        location.as_deref(),
        Some("https://stucco.software/stuccoid/pricing?section=member"),
        "the base's path is a prefix, and the request's query rides along"
    );
}

/// Every host the caller might write reaches the redirect: ports in
/// development, capitals in address bars — the same normalization
/// `subdomain_user` applies everywhere else.
#[tokio::test]
async fn the_www_redirect_normalizes_the_host() {
    let (_db, _dir, router) = harness_as(false, Some("https://example.org")).await;

    for host in ["www.brolly.test:3000", "WWW.BROLLY.TEST"] {
        let (status, _, location) = get_on_host(&router, "/", host).await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT, "host was {host}");
        assert_eq!(
            location.as_deref(),
            Some("https://example.org/"),
            "host was {host}"
        );
    }
}

/// The redirect is the whole host, not a surface: the apex's own routes do
/// not answer on `www` — a login POST aimed there is sent to the target,
/// method and body intact, which is what a 308 promises (RFC 9110 §15.4.9).
#[tokio::test]
async fn the_www_host_redirects_every_method_and_path() {
    let (_db, _dir, router) = harness_as(false, Some("https://example.org")).await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::HOST, "www.brolly.test")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=secret-secret"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("https://example.org/login"),
        "the apex's login route must not answer on www"
    );
}

/// Unconfigured, the `www` host is nobody's: `www` is a reserved username, so
/// it is never a member's pod, and the instance's own pages are apex-only, so
/// it is not the door either. It answers 404 for everything — a dead host,
/// not the half-apex it used to be — until the variable claims it.
#[tokio::test]
async fn an_unconfigured_www_host_is_nobodys() {
    let (_db, _dir, router) = harness_as(false, None).await;

    let (status, _, location) = get_on_host(&router, "/", "www.brolly.test").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(location, None);
}

/// Only the `www` host redirects. The apex and a member's subdomain keep
/// their own surfaces, and a foreign host — DNS pointed at us by someone
/// else's name — is not the deployment's to send anywhere.
#[tokio::test]
async fn the_redirect_claims_only_the_www_host() {
    let (_db, _dir, router) = harness_as(false, Some("https://example.org")).await;

    // The apex still serves its own front door.
    let (status, _, _) = get_on_host(&router, "/", "brolly.test").await;
    assert_eq!(status, StatusCode::OK);

    // A member's subdomain still serves its pod, not the marketing site.
    let (status, _, location) = get_on_host(&router, "/", "alice.brolly.test").await;
    assert_ne!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(location, None);

    // A foreign host is nobody's to redirect.
    let (status, _, location) = get_on_host(&router, "/", "example.net").await;
    assert_ne!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(location, None);
}

/// The redirect base is validated where a typo is a startup error with the
/// value in the log, not a 500 on every request to the host.
#[test]
fn the_redirect_base_is_validated() {
    use brolly_server::parse_www_redirect;

    // A bare origin, an origin with a path prefix, and a trailing slash that
    // must not double up against a request path.
    assert_eq!(
        parse_www_redirect("https://example.org").as_deref(),
        Ok("https://example.org")
    );
    assert_eq!(
        parse_www_redirect("https://example.org/stuccoid/").as_deref(),
        Ok("https://example.org/stuccoid")
    );
    // http stays legal: a local surface during a migration is a real case.
    assert_eq!(
        parse_www_redirect("http://localhost:3000").as_deref(),
        Ok("http://localhost:3000")
    );

    // Not a URL, a scheme nobody can serve, a query with nowhere to go, a
    // fragment that never reaches a server.
    assert!(parse_www_redirect("example.org").is_err());
    assert!(parse_www_redirect("ftp://example.org").is_err());
    assert!(parse_www_redirect("https://example.org?a=b").is_err());
    assert!(parse_www_redirect("https://example.org/#section").is_err());
}
