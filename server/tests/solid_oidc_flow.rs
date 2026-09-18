//! The Solid-OIDC provider, end to end over HTTP.
//!
//! The whole flow, not its pieces: register a client, log in, consent, redeem a
//! code, present a DPoP-bound token. The unit tests next door prove the JWT and
//! proof mechanics; these prove they are actually wired to a socket, which is
//! the part that was missing when the provider had four modules and no routes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db;
use brolly_server::{AppState, app};
use http_body_util::BodyExt;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const BASE: &str = "brolly.test";
const REDIRECT: &str = "https://app.example/cb";

struct Harness {
    _db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().expect("tempdir");
    let key = brolly_solid::oidc::store::load_or_create_key(&db.pool)
        .await
        .expect("provider key");
    let state = AppState {
        pool: db.pool.clone(),
        base_domain: BASE.into(),
        instance_name: BASE.to_string(),
        instance_description: "A private community server.".to_string(),
        source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
        terms_url: None,
        privacy_url: None,
        stores: std::sync::Arc::new(
            brolly_store::StoreManager::open(dir.path(), 4, 60).expect("stores"),
        ),
        provider_key: std::sync::Arc::new(key),
        instance_actor: std::sync::Arc::new(
            brolly_identity::instance::load_or_create(&db.pool, brolly_activitypub::keys::generate)
                .await
                .expect("instance actor"),
        ),
        commits: tokio::sync::broadcast::channel(64).0,
        plc_client: None,
    };
    let router = app(state, "server/static");
    Harness {
        _db: db,
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
    /// The query parameters of the redirect target.
    fn redirect_params(&self) -> std::collections::HashMap<String, String> {
        let location = self.location.as_deref().expect("a Location header");
        let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
        form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }
}

async fn send(harness: &Harness, request: Request<Body>) -> Reply {
    let response = harness.router.clone().oneshot(request).await.unwrap();
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

async fn get(harness: &Harness, uri: &str, cookie: Option<&str>) -> Reply {
    let mut request = builder("GET", uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(harness, request.body(Body::empty()).unwrap()).await
}

async fn post_form(harness: &Harness, uri: &str, body: &str, cookie: Option<&str>) -> Reply {
    let mut request =
        builder("POST", uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(harness, request.body(Body::from(body.to_string())).unwrap()).await
}

// --- client-side crypto, as a real browser app would do it ------------------

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn pkce() -> (String, String) {
    let verifier = "a-high-entropy-cryptographic-random-string-of-length-64ish".to_string();
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// A DPoP proof for `method url`, signed by the client's key.
fn dpop_proof(key: &SigningKey, method: &str, url: &str, ath: Option<&str>) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(&sec1[1..33]),
            "y": B64.encode(&sec1[33..65]),
        },
    });
    let mut claims = serde_json::json!({
        "htm": method,
        "htu": url,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": now(),
    });
    if let Some(ath) = ath {
        claims["ath"] = serde_json::Value::String(ath.to_string());
    }
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

fn client_key() -> SigningKey {
    SigningKey::from_slice(&[7u8; 32]).expect("client key")
}

/// The `jkt` a token issued to `key` must be bound to.
fn thumbprint(key: &SigningKey) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        B64.encode(&sec1[1..33]),
        B64.encode(&sec1[33..65])
    );
    B64.encode(Sha256::digest(canonical.as_bytes()))
}

// --- flow helpers -----------------------------------------------------------

async fn register(harness: &Harness) -> String {
    let reply = send(
        harness,
        builder("POST", "/oauth/solid/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "client_name": "Test App",
                    "redirect_uris": [REDIRECT],
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::CREATED,
        "register: {}",
        reply.body
    );
    reply.json()["client_id"].as_str().unwrap().to_string()
}

async fn a_logged_in_member(harness: &Harness) -> String {
    db::create_user(
        &harness._db.pool,
        "alice",
        None,
        "correct-horse-battery-staple",
        "member",
    )
    .await
    .expect("create user");

    let reply = post_form(
        harness,
        "/login",
        "username=alice&password=correct-horse-battery-staple",
        None,
    )
    .await;
    reply
        .cookies
        .first()
        .expect("a session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn authorize_url(client_id: &str, challenge: &str) -> String {
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("scope", "openid webid offline_access")
        .append_pair("state", "opaque-client-state")
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    format!("/oauth/solid/authorize?{query}")
}

/// Pull the signed request token out of the rendered consent form.
fn request_token(html: &str) -> String {
    let marker = r#"name="request" value=""#;
    let start = html
        .find(marker)
        .unwrap_or_else(|| panic!("no request token in consent page: {html}"))
        + marker.len();
    html[start..].split('"').next().unwrap().to_string()
}

/// Register, log in, consent, and return the authorization code.
async fn a_code(harness: &Harness, client_id: &str, challenge: &str, cookie: &str) -> String {
    let consent = get(harness, &authorize_url(client_id, challenge), Some(cookie)).await;
    assert_eq!(
        consent.status,
        StatusCode::OK,
        "authorize: {}",
        consent.body
    );
    let token = request_token(&consent.body);

    let decision = post_form(
        harness,
        "/oauth/solid/authorize",
        &format!("request={}&decision=allow", urlencode(&token)),
        Some(cookie),
    )
    .await;
    assert_eq!(
        decision.status,
        StatusCode::SEE_OTHER,
        "decision: {}",
        decision.body
    );
    decision
        .redirect_params()
        .get("code")
        .expect("a code in the redirect")
        .clone()
}

fn urlencode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// --- discovery --------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_only_endpoints_that_are_actually_mounted() {
    // ADR 0008's consequence: "if oauth-authorization-server advertises the
    // wrong path, clients break — so a test asserts the advertised paths match
    // the mounted routes." A discovery document is a promise.
    let harness = harness().await;

    let reply = get(&harness, "/.well-known/openid-configuration", None).await;
    assert_eq!(reply.status, StatusCode::OK);
    let doc = reply.json();

    assert_eq!(doc["issuer"], format!("https://{BASE}"));

    let advertised: Vec<String> = [
        "authorization_endpoint",
        "token_endpoint",
        "registration_endpoint",
        "jwks_uri",
    ]
    .iter()
    .map(|k| {
        doc[k]
            .as_str()
            .unwrap_or_else(|| panic!("{k} missing from discovery: {doc}"))
            .to_string()
    })
    .collect();

    for url in advertised {
        let path = url
            .strip_prefix(&format!("https://{BASE}"))
            .unwrap_or_else(|| panic!("{url} is not on this issuer"));
        let reply = get(&harness, path, None).await;
        assert_ne!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{path} is advertised in discovery but not mounted"
        );
    }
}

#[tokio::test]
async fn the_jwks_publishes_the_key_that_signs_tokens() {
    let harness = harness().await;
    let reply = get(&harness, "/oauth/solid/jwks", None).await;

    assert_eq!(reply.status, StatusCode::OK);
    let jwk = &reply.json()["keys"][0];
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["alg"], "ES256");
    assert!(jwk["kid"].as_str().is_some_and(|k| !k.is_empty()));
    assert!(
        jwk.get("d").is_none(),
        "the private scalar must never be published"
    );
}

#[tokio::test]
async fn the_oauth_surface_is_apex_only() {
    // ADR 0008: these are not served on user subdomains. A token endpoint that
    // answers on alice.brolly.id is a place to send a client's credentials that
    // the issuer never promised.
    let harness = harness().await;

    // Each endpoint with the method it actually accepts: a GET to a POST-only
    // route is a 405 from the router before any handler runs, which tests
    // axum's method matching rather than the host rule.
    for (method, path) in [
        ("GET", "/.well-known/openid-configuration"),
        ("GET", "/oauth/solid/jwks"),
        ("GET", "/oauth/solid/authorize"),
        ("POST", "/oauth/solid/authorize"),
        ("POST", "/oauth/solid/token"),
        ("POST", "/oauth/solid/register"),
    ] {
        let reply = send(
            &harness,
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, format!("alice.{BASE}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{method} {path} answered on a user subdomain"
        );
    }
}

// --- registration -----------------------------------------------------------

#[tokio::test]
async fn a_browser_app_registers_itself_and_gets_an_identifier() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    assert!(
        client_id.starts_with("urn:uuid:"),
        "expected a urn:uuid: client id, got {client_id}"
    );
}

#[tokio::test]
async fn registration_requires_at_least_one_redirect_uri() {
    let harness = harness().await;
    let reply = send(
        &harness,
        builder("POST", "/oauth/solid/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"client_name":"No Redirect"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_redirect_uri");
}

// --- authorization ----------------------------------------------------------

#[tokio::test]
async fn authorizing_without_a_session_sends_you_to_log_in_and_back_again() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let (_, challenge) = pkce();

    let target = authorize_url(&client_id, &challenge);
    let reply = get(&harness, &target, None).await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let location = reply.location.expect("a redirect to login");
    assert!(
        location.starts_with("/login?"),
        "expected a login redirect, got {location}"
    );
    // Without this the member logs in and lands on the homepage, and the app
    // that sent them is left waiting forever.
    let next = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "next")
        .map(|(_, v)| v.into_owned())
        .expect("a next parameter");
    assert_eq!(next, target);
}

#[tokio::test]
async fn an_unknown_client_is_refused_before_anything_is_rendered() {
    let harness = harness().await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let reply = get(
        &harness,
        &authorize_url("urn:uuid:00000000-0000-0000-0000-000000000000", &challenge),
        Some(&cookie),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        reply.location.is_none(),
        "an unregistered client's redirect_uri is not trustworthy enough to redirect to"
    );
}

#[tokio::test]
async fn an_unregistered_redirect_uri_is_refused() {
    // The open-redirect case: an attacker who knows a client id must not be
    // able to have the code delivered somewhere else.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", "https://attacker.example/collect")
        .append_pair("scope", "openid webid")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    let reply = get(
        &harness,
        &format!("/oauth/solid/authorize?{query}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.location.is_none());
}

#[tokio::test]
async fn pkce_is_mandatory_and_plain_is_refused() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;

    let without = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("scope", "openid webid")
        .finish();
    let reply = get(
        &harness,
        &format!("/oauth/solid/authorize?{without}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "a request with no code_challenge must not proceed"
    );

    let plain = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("scope", "openid webid")
        .append_pair("code_challenge", "whatever")
        .append_pair("code_challenge_method", "plain")
        .finish();
    let reply = get(
        &harness,
        &format!("/oauth/solid/authorize?{plain}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "S256 is the only method discovery advertises"
    );
}

#[tokio::test]
async fn consent_names_the_app_and_the_member() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let reply = get(
        &harness,
        &authorize_url(&client_id, &challenge),
        Some(&cookie),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Test App"), "the app must be named");
    assert!(reply.body.contains("alice"), "the member must be named");
    assert!(
        reply.body.contains(r#"<form method="post""#),
        "consent must work without JavaScript (§4.2)"
    );
}

#[tokio::test]
async fn declining_consent_tells_the_app_rather_than_leaving_it_hanging() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let consent = get(
        &harness,
        &authorize_url(&client_id, &challenge),
        Some(&cookie),
    )
    .await;
    let token = request_token(&consent.body);

    let reply = post_form(
        &harness,
        "/oauth/solid/authorize",
        &format!("request={}&decision=deny", urlencode(&token)),
        Some(&cookie),
    )
    .await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let params = reply.redirect_params();
    assert_eq!(params["error"], "access_denied");
    assert_eq!(
        params["state"], "opaque-client-state",
        "state must survive a denial too, or the client cannot correlate it"
    );
    assert!(!params.contains_key("code"));
}

#[tokio::test]
async fn one_members_consent_token_cannot_be_spent_by_another() {
    // The request token is signed, so it cannot be edited — but a signature
    // alone would let anyone who obtains one replay it. It is bound to the
    // session that was shown the screen.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let alice = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let consent = get(
        &harness,
        &authorize_url(&client_id, &challenge),
        Some(&alice),
    )
    .await;
    let token = request_token(&consent.body);

    db::create_user(
        &harness._db.pool,
        "mallory",
        None,
        "another-long-password",
        "member",
    )
    .await
    .expect("create mallory");
    let login = post_form(
        &harness,
        "/login",
        "username=mallory&password=another-long-password",
        None,
    )
    .await;
    let mallory = login.cookies[0].split(';').next().unwrap().to_string();

    let reply = post_form(
        &harness,
        "/oauth/solid/authorize",
        &format!("request={}&decision=allow", urlencode(&token)),
        Some(&mallory),
    )
    .await;

    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "a consent token must only be spendable by the member it was issued to"
    );
}

// --- the token endpoint -----------------------------------------------------

#[tokio::test]
async fn the_full_flow_yields_a_token_bound_to_the_clients_key() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", &verifier)
        .finish();

    let reply = send(
        &harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "token: {}", reply.body);
    let tokens = reply.json();

    assert_eq!(
        tokens["token_type"], "DPoP",
        "a bearer token_type would invite clients to drop the proof"
    );
    assert!(tokens["access_token"].as_str().is_some());
    assert!(
        tokens["id_token"].as_str().is_some(),
        "openid was requested"
    );
    assert!(
        tokens["refresh_token"].as_str().is_some(),
        "offline_access was requested"
    );

    // The binding is the point: the access token must name this client's key.
    let access = tokens["access_token"].as_str().unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&B64.decode(access.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(claims["cnf"]["jkt"], thumbprint(&key));
    assert_eq!(claims["webid"], format!("https://alice.{BASE}/profile#me"));
    assert_eq!(claims["iss"], format!("https://{BASE}"));
}

#[tokio::test]
async fn the_token_endpoint_requires_a_proof() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", &verifier)
        .finish();

    let reply = post_form(&harness, "/oauth/solid/token", &body, None).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.json()["error"],
        "invalid_dpop_proof",
        "issuing an unbound token here is what makes DPoP decorative"
    );
}

#[tokio::test]
async fn a_wrong_pkce_verifier_is_refused() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", "not-the-verifier-that-made-the-challenge")
        .finish();

    let reply = send(
        &harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn an_intercepted_code_is_inert_once_it_has_been_used() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let redeem = || {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", REDIRECT)
            .append_pair("client_id", &client_id)
            .append_pair("code_verifier", &verifier)
            .finish();
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap()
    };

    assert_eq!(send(&harness, redeem()).await.status, StatusCode::OK);
    let second = send(&harness, redeem()).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert_eq!(second.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn a_refresh_token_rotates_and_the_old_one_dies() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");

    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", &verifier)
        .finish();
    let first = send(
        &harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    let refresh = first.json()["refresh_token"].as_str().unwrap().to_string();

    let refresh_request = |token: &str| {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", token)
            .append_pair("client_id", &client_id)
            .finish();
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap()
    };

    let rotated = send(&harness, refresh_request(&refresh)).await;
    assert_eq!(rotated.status, StatusCode::OK, "refresh: {}", rotated.body);
    let new_refresh = rotated.json()["refresh_token"]
        .as_str()
        .expect("rotation issues a replacement")
        .to_string();
    assert_ne!(new_refresh, refresh, "the token must actually rotate");

    let replayed = send(&harness, refresh_request(&refresh)).await;
    assert_eq!(
        replayed.status,
        StatusCode::BAD_REQUEST,
        "the spent refresh token must not still work"
    );
}

#[tokio::test]
async fn a_refresh_token_cannot_be_used_by_a_different_key() {
    // Theft of the refresh token alone must not be enough.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", &verifier)
        .finish();
    let first = send(
        &harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    let refresh = first.json()["refresh_token"].as_str().unwrap().to_string();

    let thief = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", &refresh)
        .append_pair("client_id", &client_id)
        .finish();
    let reply = send(
        &harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&thief, "POST", &url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn a_token_endpoint_proof_is_good_for_one_request() {
    // RFC 9449: a proof's jti is used once. Otherwise a proof captured in
    // transit works for its whole freshness window, at any endpoint where the
    // attacker holds something else worth presenting — here, a refresh token.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, &client_id, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let token_request = |body: String, proof: &str| {
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", proof)
            .body(Body::from(body))
            .unwrap()
    };

    let proof = dpop_proof(&key, "POST", &url, None);
    let exchange = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", &verifier)
        .finish();
    let first = send(&harness, token_request(exchange, &proof)).await;
    assert_eq!(first.status, StatusCode::OK, "token: {}", first.body);
    let refresh = first.json()["refresh_token"]
        .as_str()
        .expect("offline_access was requested")
        .to_string();

    let refresh_body = || {
        form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", &refresh)
            .append_pair("client_id", &client_id)
            .finish()
    };

    // A valid refresh, carrying the proof the exchange already spent.
    let replayed = send(&harness, token_request(refresh_body(), &proof)).await;
    assert_eq!(
        replayed.status,
        StatusCode::BAD_REQUEST,
        "{}",
        replayed.body
    );
    assert_eq!(replayed.json()["error"], "invalid_dpop_proof");

    // Refused before the grant was touched, so the refresh token still
    // rotates once the client signs a new proof.
    let fresh = dpop_proof(&key, "POST", &url, None);
    let rotated = send(&harness, token_request(refresh_body(), &fresh)).await;
    assert_eq!(rotated.status, StatusCode::OK, "refresh: {}", rotated.body);
}
