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
    };
    let router = app(state, "server/static");
    (db, dir, router)
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
        .find(|c| c.starts_with("brolly_session="))
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

    let (status, body, _) = get_as(&router, "/", Some("brolly_session=not-a-real-token")).await;

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

    let (status, _, _) = get_as(&router, "/login", Some("brolly_session=nonsense")).await;
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
