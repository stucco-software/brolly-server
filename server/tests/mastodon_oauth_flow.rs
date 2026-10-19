//! The Mastodon OAuth flow over HTTP.
//!
//! This is what standing between a member and Phanpy looks like: register the
//! app, log in, consent, exchange the code, then use the bearer token. If any
//! step is wrong the client shows a login loop with no explanation, so the
//! whole path is asserted rather than its pieces.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use http_body_util::BodyExt;
use tower::ServiceExt;

const BASE: &str = "brolly.test";
const REDIRECT: &str = "https://app.example/cb";

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let router = app(
        AppState {
            pool: db.pool.clone(),
            base_domain: BASE.into(),
            instance_name: BASE.to_string(),
            instance_description: "A private community server.".to_string(),
            source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
            terms_url: None,
            privacy_url: None,
            public_registration: false,
            max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
            stores: std::sync::Arc::new(
                brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap(),
            ),
            provider_key: std::sync::Arc::new(
                brolly_solid::oidc::store::load_or_create_key(&db.pool)
                    .await
                    .expect("provider key"),
            ),
            instance_actor: std::sync::Arc::new(
                brolly_identity::instance::load_or_create(
                    &db.pool,
                    brolly_activitypub::keys::generate,
                )
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
            issuer_jwks: std::sync::Arc::new(
                brolly_server::client_metadata::StaticDocuments::default(),
            ),
            webid_documents: std::sync::Arc::new(
                brolly_server::client_metadata::StaticDocuments::default(),
            ),
        },
        "server/static",
    );
    Harness {
        db,
        _dir: dir,
        router,
    }
}

struct Reply {
    status: StatusCode,
    body: String,
    location: Option<String>,
    cookies: Vec<String>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("expected JSON, got {}: {}", self.body, e))
    }
    fn redirect_params(&self) -> std::collections::HashMap<String, String> {
        let location = self.location.as_deref().expect("a Location header");
        let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
        form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }
}

async fn send(h: &Harness, request: Request<Body>) -> Reply {
    let response = h.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    Reply {
        status,
        body,
        location,
        cookies,
    }
}

fn builder(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, BASE)
}

async fn post_form(h: &Harness, uri: &str, body: &str, cookie: Option<&str>) -> Reply {
    let mut request =
        builder("POST", uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(h, request.body(Body::from(body.to_string())).unwrap()).await
}

async fn get(h: &Harness, uri: &str, cookie: Option<&str>) -> Reply {
    let mut request = builder("GET", uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(h, request.body(Body::empty()).unwrap()).await
}

fn urlencode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// --- flow helpers -------------------------------------------------------------

struct App {
    client_id: String,
    client_secret: String,
}

async fn register(h: &Harness) -> App {
    let reply = post_form(
        h,
        "/api/v1/apps",
        &format!(
            "client_name=Phanpy&redirect_uris={}&scopes={}",
            urlencode(REDIRECT),
            urlencode("read write follow")
        ),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "apps: {}", reply.body);
    let json = reply.json();
    App {
        client_id: json["client_id"].as_str().unwrap().to_string(),
        client_secret: json["client_secret"].as_str().unwrap().to_string(),
    }
}

async fn a_logged_in_member(h: &Harness) -> String {
    db::create_user(
        &h.db.pool,
        "alice",
        None,
        "correct-horse-battery-staple",
        "member",
    )
    .await
    .expect("create user");
    let reply = post_form(
        h,
        "/login",
        "username=alice&password=correct-horse-battery-staple",
        None,
    )
    .await;
    reply.cookies[0].split(';').next().unwrap().to_string()
}

fn request_token(html: &str) -> String {
    let marker = r#"name="request" value=""#;
    let start = html
        .find(marker)
        .unwrap_or_else(|| panic!("no request token in consent page: {html}"))
        + marker.len();
    html[start..].split('"').next().unwrap().to_string()
}

async fn a_bearer_token(h: &Harness) -> String {
    let app = register(h).await;
    let cookie = a_logged_in_member(h).await;

    let authorize = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}",
        urlencode(&app.client_id),
        urlencode(REDIRECT),
        urlencode("read write")
    );
    let consent = get(h, &authorize, Some(&cookie)).await;
    assert_eq!(consent.status, StatusCode::OK, "consent: {}", consent.body);

    let decision = post_form(
        h,
        "/oauth/authorize",
        &format!(
            "request={}&decision=allow",
            urlencode(&request_token(&consent.body))
        ),
        Some(&cookie),
    )
    .await;
    let code = decision.redirect_params()["code"].clone();

    let token = post_form(
        h,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}",
            urlencode(&code),
            urlencode(&app.client_id),
            urlencode(&app.client_secret),
            urlencode(REDIRECT)
        ),
        None,
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "token: {}", token.body);
    token.json()["access_token"].as_str().unwrap().to_string()
}

// --- registration -------------------------------------------------------------

#[tokio::test]
async fn an_app_registers_and_gets_credentials_once() {
    let h = harness().await;
    let reply = post_form(
        &h,
        "/api/v1/apps",
        &format!("client_name=Phanpy&redirect_uris={}", urlencode(REDIRECT)),
        None,
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    let json = reply.json();
    assert_eq!(json["name"], "Phanpy");
    assert!(json["client_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        json["client_secret"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    // Clients read this back to confirm what they registered.
    assert_eq!(json["redirect_uri"], REDIRECT);
}

#[tokio::test]
async fn app_registration_accepts_json_as_well_as_a_form() {
    // Clients send both, and Mastodon accepts both.
    let h = harness().await;
    let reply = send(
        &h,
        builder("POST", "/api/v1/apps")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "client_name": "Ivory",
                    "redirect_uris": REDIRECT,
                    "scopes": "read",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    assert_eq!(reply.json()["name"], "Ivory");
}

#[tokio::test]
async fn an_app_without_a_name_is_refused_in_mastodons_error_shape() {
    let h = harness().await;
    let reply = post_form(
        &h,
        "/api/v1/apps",
        "redirect_uris=urn:ietf:wg:oauth:2.0:oob",
        None,
    )
    .await;

    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        reply.json()["error"].as_str().is_some(),
        "clients parse `error`; anything else shows as an unexplained failure"
    );
}

// --- the whole flow ------------------------------------------------------------

#[tokio::test]
async fn a_client_gets_a_working_bearer_token() {
    let h = harness().await;
    let token = a_bearer_token(&h).await;

    let grant = brolly_mastodon::oauth::verify_token(&h.db.pool, &token)
        .await
        .expect("verify")
        .expect("the issued token must verify");
    assert_eq!(grant.scopes, "read write");
}

#[tokio::test]
async fn the_token_response_has_the_shape_clients_parse() {
    let h = harness().await;
    let app = register(&h).await;
    let cookie = a_logged_in_member(&h).await;

    let consent = get(
        &h,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=read",
            urlencode(&app.client_id),
            urlencode(REDIRECT)
        ),
        Some(&cookie),
    )
    .await;
    let decision = post_form(
        &h,
        "/oauth/authorize",
        &format!(
            "request={}&decision=allow",
            urlencode(&request_token(&consent.body))
        ),
        Some(&cookie),
    )
    .await;
    let code = decision.redirect_params()["code"].clone();

    let reply = post_form(
        &h,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code={}&client_id={}&client_secret={}",
            urlencode(&code),
            urlencode(&app.client_id),
            urlencode(&app.client_secret)
        ),
        None,
    )
    .await;

    let json = reply.json();
    assert_eq!(
        json["token_type"], "Bearer",
        "Mastodon clients send `Authorization: Bearer`"
    );
    assert_eq!(json["scope"], "read");
    assert!(json["created_at"].is_number());
}

#[tokio::test]
async fn authorizing_without_a_session_sends_you_to_log_in_and_back() {
    let h = harness().await;
    let app = register(&h).await;

    let target = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=read",
        urlencode(&app.client_id),
        urlencode(REDIRECT)
    );
    let reply = get(&h, &target, None).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let location = reply.location.expect("a login redirect");
    let next = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "next")
        .map(|(_, v)| v.into_owned())
        .expect("a next parameter");
    assert!(
        next.starts_with("/oauth/authorize?"),
        "the member must land back on the request that sent them: {next}"
    );
}

#[tokio::test]
async fn the_consent_screen_names_the_app_and_its_scopes() {
    let h = harness().await;
    let app = register(&h).await;
    let cookie = a_logged_in_member(&h).await;

    let consent = get(
        &h,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}",
            urlencode(&app.client_id),
            urlencode(REDIRECT),
            urlencode("read write")
        ),
        Some(&cookie),
    )
    .await;

    assert_eq!(consent.status, StatusCode::OK);
    assert!(consent.body.contains("Phanpy"));
    assert!(consent.body.contains("alice"));
    assert!(
        consent.body.contains(r#"<form method="post""#),
        "consent must work without JavaScript"
    );
}

#[tokio::test]
async fn declining_tells_the_client_rather_than_leaving_it_hanging() {
    let h = harness().await;
    let app = register(&h).await;
    let cookie = a_logged_in_member(&h).await;

    let consent = get(
        &h,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=read&state=xyz",
            urlencode(&app.client_id),
            urlencode(REDIRECT)
        ),
        Some(&cookie),
    )
    .await;
    let reply = post_form(
        &h,
        "/oauth/authorize",
        &format!(
            "request={}&decision=deny",
            urlencode(&request_token(&consent.body))
        ),
        Some(&cookie),
    )
    .await;

    let params = reply.redirect_params();
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["state"], "xyz", "state must survive a refusal");
    assert!(!params.contains_key("code"));
}

// --- the things that go wrong ---------------------------------------------------

#[tokio::test]
async fn an_unregistered_redirect_uri_is_refused() {
    // The open-redirect case: knowing a client_id must not let an attacker
    // have the code delivered somewhere else.
    let h = harness().await;
    let app = register(&h).await;
    let cookie = a_logged_in_member(&h).await;

    let reply = get(
        &h,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=read",
            urlencode(&app.client_id),
            urlencode("https://attacker.example/collect")
        ),
        Some(&cookie),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.location.is_none(), "must not redirect anywhere");
}

#[tokio::test]
async fn a_code_cannot_be_exchanged_twice() {
    let h = harness().await;
    let app = register(&h).await;
    let cookie = a_logged_in_member(&h).await;

    let consent = get(
        &h,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=read",
            urlencode(&app.client_id),
            urlencode(REDIRECT)
        ),
        Some(&cookie),
    )
    .await;
    let decision = post_form(
        &h,
        "/oauth/authorize",
        &format!(
            "request={}&decision=allow",
            urlencode(&request_token(&consent.body))
        ),
        Some(&cookie),
    )
    .await;
    let code = decision.redirect_params()["code"].clone();

    let exchange = || {
        format!(
            "grant_type=authorization_code&code={}&client_id={}&client_secret={}",
            urlencode(&code),
            urlencode(&app.client_id),
            urlencode(&app.client_secret)
        )
    };

    assert_eq!(
        post_form(&h, "/oauth/token", &exchange(), None)
            .await
            .status,
        StatusCode::OK
    );
    let second = post_form(&h, "/oauth/token", &exchange(), None).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert_eq!(second.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn a_wrong_client_secret_gets_no_token() {
    let h = harness().await;
    let app = register(&h).await;

    let reply = post_form(
        &h,
        "/oauth/token",
        &format!(
            "grant_type=authorization_code&code=whatever&client_id={}&client_secret=wrong",
            urlencode(&app.client_id)
        ),
        None,
    )
    .await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"], "invalid_client");
}

#[tokio::test]
async fn a_revoked_token_stops_working() {
    let h = harness().await;
    let token = a_bearer_token(&h).await;

    let reply = post_form(
        &h,
        "/oauth/revoke",
        &format!("token={}", urlencode(&token)),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);

    assert!(
        brolly_mastodon::oauth::verify_token(&h.db.pool, &token)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn revoking_an_unknown_token_still_answers_ok() {
    // RFC 7009. Anything else lets a caller probe which tokens exist.
    let h = harness().await;
    let reply = post_form(&h, "/oauth/revoke", "token=never-issued", None).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn a_solid_client_at_the_mastodon_path_is_told_where_to_go() {
    // ADR 0008's defensive detection: diagnosis, never routing. The
    // predecessor's visible failure was a Mastodon client receiving
    // "missing field `request_uri`" from the ATProtocol handler.
    let h = harness().await;
    let reply = send(
        &h,
        builder(
            "GET",
            "/oauth/authorize?response_type=code&client_id=https://app.example/id",
        )
        .header("DPoP", "a-proof")
        .body(Body::empty())
        .unwrap(),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let description = reply.json()["error_description"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        description.contains("/oauth/"),
        "the error must name the correct endpoint, got {description}"
    );
}

#[tokio::test]
async fn the_oauth_surface_is_apex_only() {
    let h = harness().await;
    for (method, path) in [
        ("GET", "/oauth/authorize"),
        ("POST", "/oauth/token"),
        ("POST", "/api/v1/apps"),
    ] {
        let reply = send(
            &h,
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, format!("alice.{BASE}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{path} answered on a member subdomain"
        );
    }
}
