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

async fn harness_with(
    solid_clients: std::sync::Arc<
        dyn brolly_server::client_metadata::ClientLookup<
                Document = brolly_solid::client_documents::ClientIdDocument,
                Invalid = brolly_solid::client_documents::InvalidDocument,
            >,
    >,
) -> Harness {
    harness_with_webids(
        solid_clients,
        std::sync::Arc::new(brolly_server::client_metadata::StaticDocuments::default()),
    )
    .await
}

/// [`harness_with`], with the WebID document lookup the console's link action
/// dereferences — the stand-in for the production fetcher.
async fn harness_with_webids(
    solid_clients: std::sync::Arc<
        dyn brolly_server::client_metadata::ClientLookup<
                Document = brolly_solid::client_documents::ClientIdDocument,
                Invalid = brolly_solid::client_documents::InvalidDocument,
            >,
    >,
    webid_documents: std::sync::Arc<
        dyn brolly_server::client_metadata::ClientLookup<
                Document = brolly_solid::webid_documents::WebIdDocument,
                Invalid = brolly_solid::webid_documents::InvalidWebIdDocument,
            >,
    >,
) -> Harness {
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
        theme_css: false,
        public_registration: false,
        front_end: brolly_server::FrontEnd::default(),
        limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
        www_redirect: None,
        max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
        pod_quota_bytes: brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
        stores: std::sync::Arc::new(
            brolly_store::StoreManager::open(dir.path(), 4, 60).expect("stores"),
        ),
        provider_key: std::sync::Arc::new(key),
        instance_actor: std::sync::Arc::new(
            brolly_identity::instance::load_or_create(&db.pool, brolly_activitypub::keys::generate)
                .await
                .expect("instance actor"),
        ),
        dpop_nonce_secret: [0x42; 64],
        commits: tokio::sync::broadcast::channel(64).0,
        plc_client: None,
        appview: None,
        clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),
        client_jwks: std::sync::Arc::new(brolly_server::client_metadata::StaticDocuments::default()),
        // Where Client ID Documents come from (spec 6, H3): a fixed,
        // validated set here, as the ATProto side's `StaticClients` does.
        solid_clients,
        // The remote path's lookups (spec 6, H5): empty, as a fetch that
        // finds nothing would be — this suite's requests never take the
        // remote path.
        issuer_discovery: std::sync::Arc::new(
            brolly_server::client_metadata::StaticDocuments::default(),
        ),
        issuer_jwks: std::sync::Arc::new(brolly_server::client_metadata::StaticDocuments::default()),
        webid_documents,
    };
    let router = app(state, "server/static");
    Harness {
        _db: db,
        _dir: dir,
        router,
    }
}

async fn harness() -> Harness {
    harness_with(std::sync::Arc::new(
        brolly_server::client_metadata::StaticClientDocuments::default(),
    ))
    .await
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
    authorize_query(
        client_id,
        REDIRECT,
        "openid webid offline_access",
        challenge,
        None,
    )
}

/// An authorize URL with the parts the `prompt` tests vary (spec 6, H4).
fn authorize_query(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    challenge: &str,
    prompt: Option<&str>,
) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("response_type", "code");
    query.append_pair("client_id", client_id);
    query.append_pair("redirect_uri", redirect_uri);
    query.append_pair("scope", scope);
    query.append_pair("state", "opaque-client-state");
    query.append_pair("code_challenge", challenge);
    query.append_pair("code_challenge_method", "S256");
    if let Some(prompt) = prompt {
        query.append_pair("prompt", prompt);
    }
    format!("/oauth/solid/authorize?{}", query.finish())
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

/// Walk the interactive consent screen to an allow, and return the decision's
/// answer — the walk that remembers the consent (spec 6, H4).
async fn allow(harness: &Harness, url: &str, cookie: &str) -> Reply {
    let consent = get(harness, url, Some(cookie)).await;
    assert_eq!(
        consent.status,
        StatusCode::OK,
        "authorize: {}",
        consent.body
    );
    let token = request_token(&consent.body);
    post_form(
        harness,
        "/oauth/solid/authorize",
        &format!("request={}&decision=allow", urlencode(&token)),
        Some(cookie),
    )
    .await
}

/// Redeem a code at the token endpoint, as the client would.
async fn redeem(harness: &Harness, client_id: &str, code: &str, verifier: &str) -> Reply {
    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", client_id)
        .append_pair("code_verifier", verifier)
        .finish();
    send(
        harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(&key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
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

/// The consent decision is a form post from our own page and nowhere else:
/// an Allow posted from another origin with the member's session is refused.
/// The token endpoint, two routes over, is posted to by apps on other
/// origins by design, and must not be caught by the same rule.
#[tokio::test]
async fn a_consent_decision_from_another_origin_is_refused_but_the_token_endpoint_is_not() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_verifier, challenge) = pkce();

    let consent = get(
        &harness,
        &authorize_url(&client_id, &challenge),
        Some(&cookie),
    )
    .await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
    let token = request_token(&consent.body);

    let decision = send(
        &harness,
        builder("POST", "/oauth/solid/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "https://evil.example")
            .body(Body::from(format!(
                "request={}&decision=allow",
                urlencode(&token)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(decision.status, StatusCode::FORBIDDEN, "{}", decision.body);
    assert!(decision.location.is_none(), "no code was issued");

    // The token endpoint answers a cross-origin caller on the merits of the
    // request — here, a bad one — not with a refusal to look.
    let redeem = send(
        &harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, "https://app.example")
            .body(Body::from("grant_type=authorization_code&code=nope"))
            .unwrap(),
    )
    .await;
    assert_ne!(redeem.status, StatusCode::FORBIDDEN, "{}", redeem.body);
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

// --- Client ID Documents (spec 6, H3) ---------------------------------------

/// The `https://` client_id of the tests below, and the Turtle document it
/// names — registered in the harness's `StaticClientDocuments`, which
/// validates it exactly as the fetch path would.
const DOCUMENT_ID: &str = "https://penny.example/id";

fn a_client_id_document() -> brolly_server::client_metadata::StaticClientDocuments {
    brolly_server::client_metadata::StaticClientDocuments::default()
        .with(
            DOCUMENT_ID,
            &format!(
                "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>.\n\
                 <> oidc:redirect_uris <{REDIRECT}> ; \
                 oidc:client_name \"Penny\" ."
            ),
        )
        .expect("the test document validates")
}

#[tokio::test]
async fn a_client_id_document_authorizes_and_reaches_the_token_endpoint() {
    // The real flow, end to end, for the third kind of client (spec 6, H3):
    // fetched (here, from the validated stub), validated, consented, redeemed
    // — with the grant remembering the `https://` client_id string, so the
    // token endpoint's comparison is the unchanged one.
    let harness = harness_with(std::sync::Arc::new(a_client_id_document())).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(&harness, DOCUMENT_ID, &challenge, &cookie).await;

    let key = client_key();
    let url = format!("https://{BASE}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", DOCUMENT_ID)
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
    assert!(reply.json().get("access_token").is_some());
}

#[tokio::test]
async fn the_consent_screen_names_a_document_client_by_its_client_name() {
    // The document's `client_name`, in place of the raw IRI — the same part
    // of the screen a registered client's name fills (spec 6, H3). The IRI is
    // still shown as the requester; the name is what the member reads.
    let harness = harness_with(std::sync::Arc::new(a_client_id_document())).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let reply = get(
        &harness,
        &authorize_url(DOCUMENT_ID, &challenge),
        Some(&cookie),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.body.contains("Penny"),
        "the document's name must be shown"
    );
    assert!(
        reply.body.contains(DOCUMENT_ID),
        "and the client_id it was fetched from"
    );
}

#[tokio::test]
async fn a_document_clients_unlisted_redirect_uri_is_refused() {
    // The open-redirect case for the third kind of client: the document
    // lists one URI, the request names another.
    let harness = harness_with(std::sync::Arc::new(a_client_id_document())).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", DOCUMENT_ID)
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

/// Serves one canned answer per client_id — the refusals the validating
/// `StaticClientDocuments` cannot hold, which is the point (spec 6, H3).
struct BrokenDocuments {
    answers: std::collections::HashMap<
        String,
        Result<
            brolly_solid::client_documents::ClientIdDocument,
            brolly_server::client_metadata::LookupError<
                brolly_solid::client_documents::InvalidDocument,
            >,
        >,
    >,
}

impl brolly_server::client_metadata::ClientLookup for BrokenDocuments {
    type Document = brolly_solid::client_documents::ClientIdDocument;
    type Invalid = brolly_solid::client_documents::InvalidDocument;

    fn fetch<'a>(
        &'a self,
        url: &'a url::Url,
    ) -> brolly_server::client_metadata::Lookup<'a, Self::Document, Self::Invalid> {
        let answer = self.answers.get(url.as_str()).cloned().unwrap_or(Err(
            brolly_server::client_metadata::LookupError::Unreachable,
        ));
        Box::pin(std::future::ready(answer))
    }
}

#[tokio::test]
async fn every_unusable_client_answer_is_identical() {
    // The load-bearing property (spec 6, H3): an unknown `urn:uuid:`, a
    // client_id that is neither kind, a document that could not be fetched,
    // one that would not parse, one that is not a client at all, and one that
    // does not list the redirect_uri — byte-for-byte the same 400, before
    // any redirect, so the endpoint is not an oracle for which client
    // documents exist on the open web.
    use brolly_server::client_metadata::LookupError;
    use brolly_solid::client_documents::InvalidDocument;

    let mut answers = BrokenDocuments {
        answers: std::collections::HashMap::new(),
    };
    // A fetched-but-broken document, for every way a document can be broken.
    answers.answers.insert(
        "https://unparseable.example/id".to_string(),
        Err(LookupError::Invalid(InvalidDocument::Unparseable(
            "parse error".to_string(),
        ))),
    );
    answers.answers.insert(
        "https://mistyped.example/id".to_string(),
        Err(LookupError::Invalid(InvalidDocument::NotAClientDocument)),
    );
    answers.answers.insert(
        "https://wrong-content-type.example/id".to_string(),
        Err(LookupError::Invalid(InvalidDocument::NotRdf(
            "text/html".to_string(),
        ))),
    );
    let harness = harness_with(std::sync::Arc::new(answers)).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let mut refusals: Vec<(String, Reply)> = Vec::new();
    for client_id in [
        "urn:uuid:00000000-0000-0000-0000-000000000000", // unknown in the table
        "did:key:z6Mk",                                  // neither kind
        "http://app.example/id",                         // not https: no fetch
        "https://unfetched.example/id",                  // the stub has nothing
        "https://unparseable.example/id",
        "https://mistyped.example/id",
        "https://wrong-content-type.example/id",
    ] {
        let reply = get(
            &harness,
            &authorize_url(client_id, &challenge),
            Some(&cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{client_id}");
        assert!(reply.location.is_none(), "{client_id}: no redirect, ever");
        refusals.push((client_id.to_string(), reply));
    }

    // And a document that does not list the redirect_uri: the same answer
    // again, from the same constant.
    let unlisting = brolly_server::client_metadata::StaticClientDocuments::default()
        .with(
            "https://unlisting.example/id",
            "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>. \
             <> oidc:redirect_uris <https://unlisting.example/other> .",
        )
        .unwrap();
    let harness = harness_with(std::sync::Arc::new(unlisting)).await;
    let cookie = a_logged_in_member(&harness).await;
    let reply = get(
        &harness,
        &authorize_url("https://unlisting.example/id", &challenge),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.location.is_none());
    refusals.push(("https://unlisting.example/id".to_string(), reply));

    let (_, first) = &refusals[0];
    for (client_id, reply) in &refusals[1..] {
        assert_eq!(
            reply.body, first.body,
            "{client_id} must be indistinguishable from an unknown client"
        );
    }
}

/// Serve the router on a real port, as `xrpc.rs` does for its websocket
/// tests: the fetcher is real HTTP, and `oneshot` is not.
async fn serve(router: axum::Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

#[tokio::test]
async fn our_own_profile_is_not_a_client_id_document() {
    // The trap, against our own server (spec 6, H3): `/profile` serves HTML
    // to anything that sounds like a browser and RDF to a caller that asks
    // for it. The fetch must ask for RDF — and get it — and the profile that
    // comes back must still be refused as a document: not a content-type
    // refusal, not a transport failure, but a profile not being a client.
    //
    // The base domain and the username are chosen so that the member's
    // subdomain *is* the loopback IP the router is served on — `127.0.0.1`
    // reads back as user `127` of a server based at `0.0.1` — because a real
    // fetch cannot set its own Host header.
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().expect("tempdir");
    let key = brolly_solid::oidc::store::load_or_create_key(&db.pool)
        .await
        .expect("provider key");
    let state = AppState {
        pool: db.pool.clone(),
        base_domain: "0.0.1".to_string(),
        instance_name: "0.0.1".to_string(),
        instance_description: "A private community server.".to_string(),
        source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
        terms_url: None,
        privacy_url: None,
        theme_css: false,
        public_registration: false,
        front_end: brolly_server::FrontEnd::default(),
        limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
        www_redirect: None,
        max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
        pod_quota_bytes: brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
        stores: std::sync::Arc::new(
            brolly_store::StoreManager::open(dir.path(), 4, 60).expect("stores"),
        ),
        provider_key: std::sync::Arc::new(key),
        instance_actor: std::sync::Arc::new(
            brolly_identity::instance::load_or_create(&db.pool, brolly_activitypub::keys::generate)
                .await
                .expect("instance actor"),
        ),
        dpop_nonce_secret: [0x42; 64],
        commits: tokio::sync::broadcast::channel(64).0,
        plc_client: None,
        appview: None,
        clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),
        client_jwks: std::sync::Arc::new(brolly_server::client_metadata::StaticDocuments::default()),
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
    db::create_user(&db.pool, "127", None, "a-long-password", "member")
        .await
        .expect("the 127.0.0.1 member");
    let router = app(state, "server/static");
    let addr = serve(router).await;

    use brolly_server::client_metadata::{ClientLookup, LookupError};
    use brolly_solid::client_documents::InvalidDocument;
    let fetcher = brolly_server::client_metadata::Fetcher::<
        brolly_solid::client_documents::ClientIdDocument,
    >::for_tests(
        true,
        true,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
    )
    .expect("the test fetcher builds");
    let profile = url::Url::parse(&format!("http://{addr}/profile")).unwrap();
    assert_eq!(
        fetcher.fetch(&profile).await,
        Err(LookupError::Invalid(InvalidDocument::NotAClientDocument))
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

// --- prompt, and remembered consents (spec 6, H4) --------------------------

#[tokio::test]
async fn prompt_none_without_a_session_is_an_error_redirect_not_a_login_page() {
    // The client asked not to be interacted with; the only correct answer is
    // an error it can handle (spec 6, H4). The login page would strand a
    // client that is waiting on a redirect that never comes.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let (_, challenge) = pkce();

    let reply = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid",
            &challenge,
            Some("none"),
        ),
        None,
    )
    .await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let location = reply.location.clone().expect("a redirect, not a page");
    assert!(
        location.starts_with(&format!("{REDIRECT}?")),
        "the error goes to the client's redirect_uri, got {location}"
    );
    let params = reply.redirect_params();
    assert_eq!(params["error"], "login_required");
    assert_eq!(
        params["state"], "opaque-client-state",
        "state must return with the error, or the client cannot correlate it"
    );
    assert!(!params.contains_key("code"));
}

#[tokio::test]
async fn prompt_none_with_only_the_old_cookie_name_is_login_required() {
    // ADR 0018: a live token under `brolly_session` is no session, so the
    // silent path answers as it does for nobody at all.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let (_, challenge) = pkce();
    let session = a_logged_in_member(&harness).await;
    let (_, token) = session.split_once('=').expect("name=value");
    let query = authorize_query(
        &client_id,
        REDIRECT,
        "openid webid",
        &challenge,
        Some("none"),
    );

    let reply = get(&harness, &query, Some(&format!("brolly_session={token}"))).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.redirect_params()["error"], "login_required");

    // The control: the same token under the real name is a session, so the
    // answer above is the name's doing, not the token's. With no consent
    // remembered, the silent path says so.
    let reply = get(
        &harness,
        &query,
        Some(&format!(
            "{}={token}",
            brolly_identity::extract::SESSION_COOKIE
        )),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let params = reply.redirect_params();
    assert_ne!(params["error"], "login_required", "{params:?}");
    assert_eq!(params["error"], "consent_required", "{params:?}");
}

#[tokio::test]
async fn prompt_none_with_a_session_but_no_remembered_consent_is_consent_required() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let reply = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid",
            &challenge,
            Some("none"),
        ),
        Some(&cookie),
    )
    .await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let params = reply.redirect_params();
    assert_eq!(params["error"], "consent_required");
    assert_eq!(params["state"], "opaque-client-state");
    assert!(!params.contains_key("code"));
}

#[tokio::test]
async fn prompt_none_with_a_covering_consent_issues_silently_exactly_as_an_allow_would() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();

    // The interactive allow — the walk that also remembers the consent.
    let allowed = allow(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid offline_access",
            &challenge,
            None,
        ),
        &cookie,
    )
    .await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);

    // The silent request: same member, same client, the same scope — a
    // subset of what was remembered, trivially.
    let silent = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid offline_access",
            &challenge,
            Some("none"),
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(silent.status, StatusCode::SEE_OTHER, "{}", silent.body);

    // Byte-for-byte what the allow produced: the same target, the same
    // parameters in the same order — a code, then the state, then the issuer
    // (RFC 9207). Only the code's value differs, because every code is
    // freshly random.
    let iss = urlencode(&format!("https://{BASE}"));
    for reply in [&allowed, &silent] {
        let location = reply.location.as_deref().expect("a redirect");
        assert!(
            location.starts_with(&format!("{REDIRECT}?code="))
                && location.ends_with(&format!("&state=opaque-client-state&iss={iss}")),
            "an issuance redirect is a code, the state, then the issuer, got {location}"
        );
    }

    // And the code is a real one: it redeems at the token endpoint exactly
    // as the interactive flow's code does.
    let code = silent
        .redirect_params()
        .get("code")
        .cloned()
        .expect("a code in the silent redirect");
    let reply = redeem(&harness, &client_id, &code, &verifier).await;
    assert_eq!(reply.status, StatusCode::OK, "token: {}", reply.body);
    let tokens = reply.json();
    assert_eq!(tokens["token_type"], "DPoP");
    assert!(
        tokens["refresh_token"].as_str().is_some(),
        "offline_access was requested"
    );
    let access = tokens["access_token"].as_str().unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&B64.decode(access.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(claims["cnf"]["jkt"], thumbprint(&client_key()));
    assert_eq!(claims["webid"], format!("https://alice.{BASE}/profile#me"));
}

#[tokio::test]
async fn prompt_none_combined_with_another_value_is_refused_before_any_redirect() {
    // OIDC Core §3.1.2.1 forbids the combination, and honouring the
    // interactive half would quietly break the no-interaction contract the
    // `none` half asked for (spec 6, H4). The 400 comes before any redirect
    // — here, before the login redirect a sessionless request would
    // otherwise get, and before the silent path a session would run.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    for prompt in ["none login", "login none", "none consent"] {
        let reply = get(
            &harness,
            &authorize_query(
                &client_id,
                REDIRECT,
                "openid webid",
                &challenge,
                Some(prompt),
            ),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{prompt}");
        assert!(reply.location.is_none(), "{prompt}: no redirect, ever");

        let reply = get(
            &harness,
            &authorize_query(
                &client_id,
                REDIRECT,
                "openid webid",
                &challenge,
                Some(prompt),
            ),
            Some(&cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{prompt}");
        assert!(reply.location.is_none(), "{prompt}: no redirect, ever");
    }
}

#[tokio::test]
async fn prompt_login_forces_the_login_page_even_with_a_session() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let reply = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid",
            &challenge,
            Some("login"),
        ),
        Some(&cookie),
    )
    .await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let location = reply.location.expect("a redirect to login");
    assert!(location.starts_with("/login?"), "got {location}");
    let next = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "next")
        .map(|(_, v)| v.into_owned())
        .expect("a next parameter");
    // `next` must not carry `prompt=login` back into the request: that
    // would loop the member through the login page forever (spec 6, H4).
    assert!(!next.contains("prompt="), "got {next}");
    // Everything else survives, so the member lands on a plain interactive
    // authorization.
    assert!(next.contains("client_id="), "got {next}");
    assert!(next.contains("code_challenge_method=S256"), "got {next}");
}

#[tokio::test]
async fn any_other_prompt_value_is_todays_behaviour() {
    let harness = harness().await;
    let client_id = register(&harness).await;
    let (_, challenge) = pkce();

    // No session: the login page, with `next`, exactly as without `prompt`.
    let reply = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid",
            &challenge,
            Some("consent"),
        ),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert!(
        reply.location.as_deref().unwrap().starts_with("/login?"),
        "got {:?}",
        reply.location
    );

    // With a session: the consent screen, as always.
    let cookie = a_logged_in_member(&harness).await;
    let reply = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid",
            &challenge,
            Some("consent"),
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.body.contains(r#"<form method="post""#),
        "the consent screen, not an error"
    );
}

#[tokio::test]
async fn an_interactive_request_still_shows_the_consent_screen_after_a_remembered_consent() {
    // The remembered-consent table is consulted only by `prompt=none`
    // (spec 6, H4): skipping the consent screen for interactive
    // re-authorizations is a product decision recorded as revisitable, not
    // one this stage makes.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();
    a_code(&harness, &client_id, &challenge, &cookie).await;

    let reply = get(
        &harness,
        &authorize_url(&client_id, &challenge),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.body.contains(r#"<form method="post""#),
        "an interactive request always shows the consent screen"
    );
}

#[tokio::test]
async fn a_remembered_consent_covers_a_subset_scope_request() {
    // The spec's own example (spec 6, H4): exact-match scope would refuse a
    // remembered `openid webid` consent for a bare `webid` request;
    // coverage is subset matching, both ways.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();

    // Remember the wide scope: `authorize_url` asks for all three.
    a_code(&harness, &client_id, &challenge, &cookie).await;

    let reply = get(
        &harness,
        &authorize_query(&client_id, REDIRECT, "webid", &challenge, Some("none")),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let code = reply
        .redirect_params()
        .get("code")
        .cloned()
        .expect("a covering consent issues silently");
    let tokens = redeem(&harness, &client_id, &code, &verifier).await;
    assert_eq!(tokens.status, StatusCode::OK, "token: {}", tokens.body);
}

#[tokio::test]
async fn a_request_for_more_than_was_remembered_is_not_covered() {
    // The other direction of subset matching (spec 6, H4): a superset
    // request must not be silently granted what was never approved.
    let harness = harness().await;
    let client_id = register(&harness).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    let allowed = allow(
        &harness,
        &authorize_query(&client_id, REDIRECT, "webid", &challenge, None),
        &cookie,
    )
    .await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);

    let reply = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid",
            &challenge,
            Some("none"),
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let params = reply.redirect_params();
    assert_eq!(params["error"], "consent_required");
    assert!(!params.contains_key("code"));
}

#[tokio::test]
async fn an_unremembered_redirect_uri_falls_back_to_the_consent_screen_under_prompt_none() {
    // The `redirect_uris` column is load-bearing security (spec 6, H4): a
    // request is covered only when its redirect_uri is among the remembered
    // URIs. Here the client is valid and the URI registered — but the member
    // allowed a different one, so the silent request is refused with
    // `consent_required` rather than carrying a code to a URI the member
    // never saw. The screen the member then sees is the interactive retry's
    // — the interactive path's exposure, once, not more.
    let harness = harness().await;
    let reply = send(
        &harness,
        builder("POST", "/oauth/solid/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "client_name": "Test App",
                    "redirect_uris": [REDIRECT, "https://app.example/other"],
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let client_id = reply.json()["client_id"].as_str().unwrap().to_string();

    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    // Allow at the first URI: that is what the consent remembers.
    let allowed = allow(
        &harness,
        &authorize_query(&client_id, REDIRECT, "openid webid", &challenge, None),
        &cookie,
    )
    .await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);

    // The silent request at the second: the client is valid, the scope is a
    // subset, but the member never allowed this URI.
    let silent = get(
        &harness,
        &authorize_query(
            &client_id,
            "https://app.example/other",
            "openid webid",
            &challenge,
            Some("none"),
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(silent.status, StatusCode::SEE_OTHER, "{}", silent.body);
    let params = silent.redirect_params();
    assert_eq!(params["error"], "consent_required");
    assert!(!params.contains_key("code"));

    // And the client's interactive retry is what shows the screen — once.
    let retry = get(
        &harness,
        &authorize_query(
            &client_id,
            "https://app.example/other",
            "openid webid",
            &challenge,
            None,
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.body);
    assert!(
        retry.body.contains(r#"<form method="post""#),
        "the interactive retry shows the consent screen"
    );
}

/// Serves whatever document it currently holds for a client_id, so a test
/// can change the document between requests — the reused-or-taken-over
/// client_id URL, the case the remembered `redirect_uris` column exists for
/// (spec 6, H4).
#[derive(Default)]
struct ChangingDocuments {
    answers: std::sync::Mutex<
        std::collections::HashMap<String, brolly_solid::client_documents::ClientIdDocument>,
    >,
}

impl ChangingDocuments {
    fn serve(&self, client_id: &str, turtle: &str) {
        let document = brolly_solid::client_documents::parse(
            &url::Url::parse(client_id).unwrap(),
            "text/turtle",
            turtle.as_bytes(),
        )
        .expect("the test document validates");
        self.answers
            .lock()
            .unwrap()
            .insert(client_id.to_string(), document);
    }
}

impl brolly_server::client_metadata::ClientLookup for ChangingDocuments {
    type Document = brolly_solid::client_documents::ClientIdDocument;
    type Invalid = brolly_solid::client_documents::InvalidDocument;

    fn fetch<'a>(
        &'a self,
        url: &'a url::Url,
    ) -> brolly_server::client_metadata::Lookup<'a, Self::Document, Self::Invalid> {
        let found = self
            .answers
            .lock()
            .unwrap()
            .get(url.as_str())
            .cloned()
            .ok_or(brolly_server::client_metadata::LookupError::Unreachable);
        Box::pin(std::future::ready(found))
    }
}

#[tokio::test]
async fn a_changed_document_cannot_carry_a_remembered_consent_elsewhere() {
    // The reason `redirect_uris` is a column (spec 6, H4): a Client ID
    // Document at a reused or taken-over client_id URL can change its listed
    // redirect URIs, and without the column a `prompt=none` request would
    // carry a code silently to a URI the member never saw. With it, the
    // silent request is refused with `consent_required`, and the changed
    // document falls back to the consent screen — on the interactive retry,
    // once: the interactive path's exposure, not more.
    let documents = std::sync::Arc::new(ChangingDocuments::default());
    documents.serve(
        DOCUMENT_ID,
        &format!(
            "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>.\n\
             <> oidc:redirect_uris <{REDIRECT}> ; \
             oidc:client_name \"Penny\" ."
        ),
    );
    let harness = harness_with(documents.clone()).await;
    let cookie = a_logged_in_member(&harness).await;
    let (_, challenge) = pkce();

    // The member allows Penny — at the URI the document then listed.
    let allowed = allow(
        &harness,
        &authorize_query(DOCUMENT_ID, REDIRECT, "openid webid", &challenge, None),
        &cookie,
    )
    .await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);

    // The document changes — the takeover.
    documents.serve(
        DOCUMENT_ID,
        "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>. \
         <> oidc:redirect_uris <https://attacker.example/collect> ; \
         oidc:client_name \"Penny\" .",
    );

    // The silent request at the new URI: the document now lists it, the
    // scope is a subset, the member has a session — but the consent
    // remembers only the URI they actually allowed.
    let silent = get(
        &harness,
        &authorize_query(
            DOCUMENT_ID,
            "https://attacker.example/collect",
            "openid webid",
            &challenge,
            Some("none"),
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(silent.status, StatusCode::SEE_OTHER, "{}", silent.body);
    let params = silent.redirect_params();
    assert_eq!(params["error"], "consent_required");
    assert!(!params.contains_key("code"));

    // And the interactive retry is what shows the screen — the member sees
    // the request at the new URI before any code is issued.
    let retry = get(
        &harness,
        &authorize_query(
            DOCUMENT_ID,
            "https://attacker.example/collect",
            "openid webid",
            &challenge,
            None,
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.body);
    assert!(
        retry.body.contains(r#"<form method="post""#),
        "the interactive retry shows the consent screen"
    );
}

#[tokio::test]
async fn prompt_none_issues_silently_for_a_document_client_too() {
    // Silent issuance is per client_id string, not per client kind (spec 6,
    // H4): the consent remembers the `https://` client_id the document was
    // fetched from, and the grant the code carries is the same string the
    // token endpoint compares against.
    let harness = harness_with(std::sync::Arc::new(a_client_id_document())).await;
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();

    let allowed = allow(&harness, &authorize_url(DOCUMENT_ID, &challenge), &cookie).await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);

    let reply = get(
        &harness,
        &authorize_query(
            DOCUMENT_ID,
            REDIRECT,
            "openid webid offline_access",
            &challenge,
            Some("none"),
        ),
        Some(&cookie),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let params = reply.redirect_params();
    assert_eq!(
        params["state"], "opaque-client-state",
        "state returns with a silent issuance too"
    );
    let code = params.get("code").cloned().expect("a silent code");

    let tokens = redeem(&harness, DOCUMENT_ID, &code, &verifier).await;
    assert_eq!(tokens.status, StatusCode::OK, "token: {}", tokens.body);
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

/// A client through the whole code flow: its id, its key, and the refresh
/// token it was issued.
async fn a_refreshing_client(harness: &Harness) -> (String, SigningKey, String) {
    let client_id = register(harness).await;
    let cookie = a_logged_in_member(harness).await;
    let (verifier, challenge) = pkce();
    let code = a_code(harness, &client_id, &challenge, &cookie).await;
    let first = redeem(harness, &client_id, &code, &verifier).await;
    assert_eq!(first.status, StatusCode::OK, "token: {}", first.body);
    let refresh = first.json()["refresh_token"]
        .as_str()
        .expect("offline_access was requested")
        .to_string();
    (client_id, client_key(), refresh)
}

/// Present `token` at the token endpoint as `client_id`, proven with `key`.
async fn refresh_as(harness: &Harness, token: &str, client_id: &str, key: &SigningKey) -> Reply {
    let url = format!("https://{BASE}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", token)
        .append_pair("client_id", client_id)
        .finish();
    send(
        harness,
        builder("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(key, "POST", &url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// A thief with the token but not the key is refused — and the owner is not
/// logged out by the attempt. Spending the token before checking the key
/// turned every stolen token into a logout button: the legitimate client's
/// next refresh found its token already revoked.
#[tokio::test]
async fn a_stolen_refresh_token_presented_with_the_wrong_key_does_not_log_the_owner_out() {
    let harness = harness().await;
    let (client_id, key, refresh) = a_refreshing_client(&harness).await;

    let thief = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let theft = refresh_as(&harness, &refresh, &client_id, &thief).await;
    assert_eq!(theft.status, StatusCode::BAD_REQUEST);
    assert_eq!(theft.json()["error"], "invalid_grant");

    let owner = refresh_as(&harness, &refresh, &client_id, &key).await;
    assert_eq!(
        owner.status,
        StatusCode::OK,
        "the owner's token must survive a thief's attempt: {}",
        owner.body
    );
}

/// A spent refresh token presented again is theft made visible — one of the
/// two holders is not the client — and the answer is to end the grant, not
/// just refuse the replay: every token in the family is revoked, the live
/// one included, so whichever holder was the thief has nothing left.
#[tokio::test]
async fn a_replayed_refresh_token_revokes_the_whole_grant() {
    let harness = harness().await;
    let (client_id, key, first) = a_refreshing_client(&harness).await;

    let rotated = refresh_as(&harness, &first, &client_id, &key).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let second = rotated.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    let replay = refresh_as(&harness, &first, &client_id, &key).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.json()["error"], "invalid_grant");

    let after = refresh_as(&harness, &second, &client_id, &key).await;
    assert_eq!(
        after.status,
        StatusCode::BAD_REQUEST,
        "the live token must die with the family: {}",
        after.body
    );
    assert_eq!(after.json()["error"], "invalid_grant");
}

/// The code grant checks that the presenting client is the one the code was
/// issued to; the refresh grant must too. The key binding makes this hard to
/// exploit on its own, but a grant is a grant to one client, and a token
/// endpoint that lets another client's id ride it is wrong on its face.
#[tokio::test]
async fn a_refresh_token_is_bound_to_the_client_it_was_issued_to() {
    let harness = harness().await;
    let (client_id, key, refresh) = a_refreshing_client(&harness).await;
    let other_client = register(&harness).await;
    assert_ne!(other_client, client_id);

    let wrong = refresh_as(&harness, &refresh, &other_client, &key).await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{}", wrong.body);
    assert_eq!(wrong.json()["error"], "invalid_grant");

    // And the attempt did not cost the real client its token.
    let right = refresh_as(&harness, &refresh, &client_id, &key).await;
    assert_eq!(right.status, StatusCode::OK, "{}", right.body);
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

// --- client_credentials: the agent grant (ADR 0020) -------------------------

/// The agent the collector authenticates as — a WebID this instance does
/// not host, whose own document names this issuer.
const AGENT_WEBID: &str = "https://pushbroom.co/agent#it";

/// A member with a linked WebID, and a credential pair minted for it.
/// Linking's own proof — the dereference of the WebID's `solid:oidcIssuer`
/// — is `link_webid`'s to gather and the link tests' to cover; this is the
/// write it licenses.
async fn a_linked_credential(harness: &Harness, webid: &str) -> (uuid::Uuid, String, String) {
    let user = db::create_user(
        &harness._db.pool,
        "pushbroom",
        None,
        "correct-horse-battery-staple",
        "member",
    )
    .await
    .expect("agent account");
    brolly_solid::oidc::store::link_webid(&harness._db.pool, user.id, webid)
        .await
        .expect("link");
    let (id, secret) =
        brolly_solid::oidc::store::issue_client_credentials(&harness._db.pool, webid)
            .await
            .expect("credentials");
    (user.id, id, secret)
}

/// The collector's exact wire shape (ADR 0020): discovery for the endpoint,
/// then `Authorization: Basic base64(urlencode(id):urlencode(secret))`, a
/// DPoP proof over POST/htu, and `grant_type=client_credentials&scope=webid`.
async fn client_credentials_request(
    harness: &Harness,
    id: &str,
    secret: &str,
    scope: Option<&str>,
    dpop: bool,
) -> Reply {
    // What the collector does first, and what any client does: read the
    // token endpoint out of the discovery document rather than guessing it.
    let discovery = get(harness, "/.well-known/openid-configuration", None).await;
    assert_eq!(discovery.status, StatusCode::OK);
    let token_endpoint = discovery.json()["token_endpoint"]
        .as_str()
        .expect("token_endpoint")
        .to_string();
    assert_eq!(token_endpoint, format!("https://{BASE}/oauth/solid/token"));

    let key = client_key();
    let basic = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            urlencode(id),
            urlencode(secret)
        ))
    };
    let mut body = form_urlencoded::Serializer::new(String::new());
    body.append_pair("grant_type", "client_credentials");
    if let Some(scope) = scope {
        body.append_pair("scope", scope);
    }
    let mut request = builder("POST", "/oauth/solid/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {basic}"));
    if dpop {
        request = request.header("DPoP", dpop_proof(&key, "POST", &token_endpoint, None));
    }
    send(harness, request.body(Body::from(body.finish())).unwrap()).await
}

#[tokio::test]
async fn the_collectors_request_yields_a_token_naming_the_linked_webid() {
    let harness = harness().await;
    let (_, id, secret) = a_linked_credential(&harness, AGENT_WEBID).await;

    let reply = client_credentials_request(&harness, &id, &secret, Some("webid"), true).await;
    assert_eq!(reply.status, StatusCode::OK, "token: {}", reply.body);
    let tokens = reply.json();

    let access = tokens["access_token"].as_str().expect("an access token");
    assert_eq!(tokens["token_type"], "DPoP");
    let expires_in = tokens["expires_in"].as_i64().expect("expires_in");
    assert!(expires_in >= 300, "a short-lived token, not a standing one");
    assert_eq!(tokens["scope"], "webid");
    // RFC 6749 §4.4.3: no refresh token on this grant — the credential is
    // the renewal. And no ID token: there is no session behind it.
    assert!(tokens.get("refresh_token").is_none());
    assert!(tokens.get("id_token").is_none());

    // The claims the collector checks and the pods verify. The payload is
    // decoded without verification here — that is the collector's posture —
    // but the signature is checked below against the published key.
    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(access.split('.').nth(1).expect("three segments"))
            .expect("payload"),
    )
    .expect("claims");
    assert_eq!(
        claims["webid"], AGENT_WEBID,
        "the token names the linked WebID"
    );
    assert_eq!(claims["sub"], AGENT_WEBID);
    assert_eq!(claims["iss"], format!("https://{BASE}"));
    assert_eq!(claims["aud"], "solid");
    let key = client_key();
    assert_eq!(
        claims["cnf"]["jkt"],
        thumbprint(&key),
        "bound to the proof's key"
    );
    assert!(
        claims["exp"]
            .as_i64()
            .is_some_and(|exp| exp > claims["iat"].as_i64().unwrap_or(0))
    );

    // The signature, against the key the JWKS endpoint publishes — the
    // check a customer pod runs on every request carrying this token.
    let jwks = get(&harness, "/oauth/solid/jwks", None).await;
    let jwk = &jwks.json()["keys"][0];
    let x = B64.decode(jwk["x"].as_str().expect("x")).expect("x bytes");
    let y = B64.decode(jwk["y"].as_str().expect("y")).expect("y bytes");
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let verify = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).expect("the published key");
    let signed = access.rsplit_once('.').expect("signature").0;
    let signature_bytes = B64
        .decode(access.rsplit_once('.').expect("signature").1)
        .expect("signature bytes");
    let signature = p256::ecdsa::Signature::from_slice(&signature_bytes).expect("signature");
    use p256::ecdsa::signature::Verifier;
    verify
        .verify(signed.as_bytes(), &signature)
        .expect("signed by the published key");
}

#[tokio::test]
async fn an_absent_scope_still_names_the_webid() {
    // CSS clients send `scope=webid`; a client that sends nothing gets the
    // same token, because there is nothing else this grant is for.
    let harness = harness().await;
    let (_, id, secret) = a_linked_credential(&harness, AGENT_WEBID).await;

    let reply = client_credentials_request(&harness, &id, &secret, None, true).await;
    assert_eq!(reply.status, StatusCode::OK, "token: {}", reply.body);
    assert_eq!(reply.json()["scope"], "webid");
}

#[tokio::test]
async fn a_scope_beyond_webid_is_refused() {
    // `openid` would promise an ID token and `offline_access` a refresh
    // token, and this grant delivers neither (RFC 6749 §4.4.3) — so neither
    // is accepted.
    let harness = harness().await;
    let (_, id, secret) = a_linked_credential(&harness, AGENT_WEBID).await;

    for scope in ["openid", "offline_access", "webid profile"] {
        let reply = client_credentials_request(&harness, &id, &secret, Some(scope), true).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "scope={scope} should be refused: {}",
            reply.body
        );
        assert_eq!(reply.json()["error"], "invalid_scope");
    }
}

#[tokio::test]
async fn an_unknown_credential_is_refused() {
    let harness = harness().await;
    a_linked_credential(&harness, AGENT_WEBID).await;

    let reply = client_credentials_request(
        &harness,
        "an-id-nobody-minted",
        "and-a-secret-nobody-holds",
        Some("webid"),
        true,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_client");
    // The scheme it attempted owes it a challenge (RFC 7617 §2).
    assert!(reply.location.is_none());
}

#[tokio::test]
async fn a_wrong_secret_is_refused() {
    // The id is real and the secret is wrong: the same 401, byte for byte,
    // as an unknown id — the endpoint is not an oracle for which ids exist.
    let harness = harness().await;
    let (_, id, _) = a_linked_credential(&harness, AGENT_WEBID).await;

    let reply =
        client_credentials_request(&harness, &id, "the-wrong-secret", Some("webid"), true).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_client");
}

#[tokio::test]
async fn client_credentials_without_a_dpop_proof_is_refused() {
    let harness = harness().await;
    let (_, id, secret) = a_linked_credential(&harness, AGENT_WEBID).await;

    let reply = client_credentials_request(&harness, &id, &secret, Some("webid"), false).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn an_unlinked_webid_is_refused() {
    // The kill switch, from the outside: unlink the WebID and the pair —
    // right id, right secret — stops working, because the credential went
    // with the link.
    let harness = harness().await;
    let (user_id, id, secret) = a_linked_credential(&harness, AGENT_WEBID).await;
    brolly_solid::oidc::store::unlink_webid(&harness._db.pool, user_id, AGENT_WEBID)
        .await
        .expect("unlink");

    let reply = client_credentials_request(&harness, &id, &secret, Some("webid"), true).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_client");
}

#[tokio::test]
async fn discovery_advertises_the_agent_grant() {
    let harness = harness().await;
    let doc = get(&harness, "/.well-known/openid-configuration", None)
        .await
        .json();

    let grants = doc["grant_types_supported"].as_array().expect("grants");
    assert!(
        grants.iter().any(|g| g == "client_credentials"),
        "the agent grant must be advertised: {grants:?}"
    );
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods");
    assert!(
        methods.iter().any(|m| m == "client_secret_basic"),
        "Basic must be advertised for the minted pairs: {methods:?}"
    );
    assert!(
        methods.iter().any(|m| m == "none"),
        "the public clients keep their method: {methods:?}"
    );
}

// --- linking (ADR 0020) ------------------------------------------------------

/// A fixed set of WebID documents, keyed by WebID — the stand-in for the
/// production fetcher, so the checks around the dereference are tested
/// without the network.
fn documents_of(
    answers: &[(&str, &str)],
) -> brolly_server::client_metadata::StaticDocuments<brolly_solid::webid_documents::WebIdDocument> {
    let mut documents = brolly_server::client_metadata::StaticDocuments::default();
    for (webid, issuer) in answers {
        let url = url::Url::parse(webid).expect("a WebID");
        let turtle = format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
             <{webid}> solid:oidcIssuer <{issuer}> ."
        );
        let document = brolly_solid::webid_documents::parse(&url, "text/turtle", turtle.as_bytes())
            .expect("a document");
        documents = documents.with(webid, document);
    }
    documents
}

async fn an_account(harness: &Harness, handle: &str) -> db::User {
    db::create_user(
        &harness._db.pool,
        handle,
        None,
        "correct-horse-battery-staple",
        "member",
    )
    .await
    .expect("account")
}

#[tokio::test]
async fn linking_requires_the_webids_own_document_to_name_this_issuer() {
    let harness = harness().await;
    let user = an_account(&harness, "keeper").await;

    // The slash is the spelling convention of hand-written WebID documents;
    // we mint the bare origin. Both name this issuer.
    let naming = documents_of(&[(AGENT_WEBID, &format!("https://{BASE}/"))]);
    let linked =
        brolly_server::solid_oidc::link_webid(&naming, &harness._db.pool, BASE, &user, AGENT_WEBID)
            .await;
    assert_eq!(
        linked.expect("linked"),
        brolly_solid::oidc::store::Linked::Now
    );

    // A document that names another issuer does not link.
    let elsewhere = documents_of(&[("https://elsewhere.co/agent#it", "https://idp.example")]);
    let refused = brolly_server::solid_oidc::link_webid(
        &elsewhere,
        &harness._db.pool,
        BASE,
        &user,
        "https://elsewhere.co/agent#it",
    )
    .await;
    assert!(matches!(
        refused,
        Err(brolly_server::solid_oidc::LinkError::NotOurIssuer)
    ));

    // A WebID whose document cannot be dereferenced does not link.
    let nothing = documents_of(&[]);
    let unreachable = brolly_server::solid_oidc::link_webid(
        &nothing,
        &harness._db.pool,
        BASE,
        &user,
        "https://gone.co/agent#it",
    )
    .await;
    assert!(matches!(
        unreachable,
        Err(brolly_server::solid_oidc::LinkError::Dereference(_))
    ));
}

#[tokio::test]
async fn a_webid_this_instance_hosts_cannot_be_linked() {
    // The escalation the local check exists for: a hosted WebID's issuer
    // triple is written by this instance, so the dereference would always
    // pass — linking one would let an account mint tokens naming another's
    // identity. The instance's own WebID is nobody's to link either.
    let harness = harness().await;
    let user = an_account(&harness, "keeper").await;
    let everything_passes = documents_of(&[]);

    for webid in [
        format!("https://alice.{BASE}/profile#me"),
        format!("https://{BASE}/profile#me"),
    ] {
        let refused = brolly_server::solid_oidc::link_webid(
            &everything_passes,
            &harness._db.pool,
            BASE,
            &user,
            &webid,
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(brolly_server::solid_oidc::LinkError::LocalWebid)
            ),
            "{webid} is hosted here; it cannot be linked"
        );
    }
}

#[tokio::test]
async fn a_webid_that_is_not_https_cannot_be_linked() {
    let harness = harness().await;
    let user = an_account(&harness, "keeper").await;
    let everything_passes = documents_of(&[]);

    let refused = brolly_server::solid_oidc::link_webid(
        &everything_passes,
        &harness._db.pool,
        BASE,
        &user,
        "http://pushbroom.co/agent#it",
    )
    .await;
    assert!(matches!(
        refused,
        Err(brolly_server::solid_oidc::LinkError::NotAnHttpsUrl)
    ));
}

#[tokio::test]
async fn a_webid_linked_to_one_account_cannot_be_linked_to_another() {
    let harness = harness().await;
    let keeper = an_account(&harness, "keeper").await;
    let rival = an_account(&harness, "rival").await;
    let naming = documents_of(&[(AGENT_WEBID, &format!("https://{BASE}"))]);

    let linked = brolly_server::solid_oidc::link_webid(
        &naming,
        &harness._db.pool,
        BASE,
        &keeper,
        AGENT_WEBID,
    )
    .await
    .expect("linked");
    assert_eq!(linked, brolly_solid::oidc::store::Linked::Now);

    let refused = brolly_server::solid_oidc::link_webid(
        &naming,
        &harness._db.pool,
        BASE,
        &rival,
        AGENT_WEBID,
    )
    .await
    .expect("no error — a refusal");
    assert_eq!(refused, brolly_solid::oidc::store::Linked::AnotherAccount);

    // And the same account re-linking is a no-op, not an error: operators
    // re-run commands.
    let again = brolly_server::solid_oidc::link_webid(
        &naming,
        &harness._db.pool,
        BASE,
        &keeper,
        AGENT_WEBID,
    )
    .await
    .expect("linked again");
    assert_eq!(again, brolly_solid::oidc::store::Linked::Already);
}

// --- the console path (ADR 0021) --------------------------------------------

/// An admin's session cookie, through the real login form.
async fn an_admin_session(harness: &Harness) -> String {
    db::create_user(
        &harness._db.pool,
        "keeper",
        None,
        "correct-horse-battery-staple",
        "admin",
    )
    .await
    .expect("admin");
    post_form(
        harness,
        "/login",
        "username=keeper&password=correct-horse-battery-staple",
        None,
    )
    .await
    .cookies
    .first()
    .expect("a session cookie")
    .split(';')
    .next()
    .unwrap()
    .to_string()
}

#[tokio::test]
async fn the_console_provisions_a_working_credential_while_the_server_runs() {
    // The panel answer to "do we have to stop the server?" — no. The server
    // holds the stores' locks and the dereference and the mint all happen
    // in-process: an admin with a browser runs the whole path, and the pair
    // it mints works at the token endpoint.
    let naming = documents_of(&[(AGENT_WEBID, &format!("https://{BASE}/"))]);
    let harness = harness_with_webids(
        std::sync::Arc::new(brolly_server::client_metadata::StaticClientDocuments::default()),
        std::sync::Arc::new(naming),
    )
    .await;
    let admin = an_admin_session(&harness).await;

    // 1. The account, through the reserved-handle door the panel is. The
    //    password rides the response once.
    let reply = post_form(
        &harness,
        "/admin/agents/account",
        "handle=pushbroom&email=pushbroom%40stucco.software",
        Some(&admin),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "account: {}", reply.body);
    assert!(reply.body.contains("shown once"), "the warning is the UI");
    let user = db::find_by_username(&harness._db.pool, "pushbroom")
        .await
        .expect("lookup")
        .expect("the account exists");
    assert_eq!(user.email.as_deref(), Some("pushbroom@stucco.software"));

    // A reload shows nothing: the page is a plain GET, and the password
    // lives in no store.
    let reloaded = get(&harness, "/admin/agents", Some(&admin)).await;
    assert_eq!(reloaded.status, StatusCode::OK);
    assert!(
        !reloaded.body.contains("shown once"),
        "no secret on a plain load"
    );

    // 2. The link — the server's own dereference of the WebID document.
    let reply = post_form(
        &harness,
        "/admin/agents/link",
        &format!("handle=pushbroom&webid={}", urlencode(AGENT_WEBID)),
        Some(&admin),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "link: {}", reply.body);
    assert!(
        reply
            .location
            .as_deref()
            .is_some_and(|l| l.contains("/admin/agents"))
    );

    // The listing names it.
    let page = get(&harness, "/admin/agents", Some(&admin)).await;
    assert!(
        page.body.contains(AGENT_WEBID),
        "the listing shows the link"
    );

    // 3. The pair, shown once on the response.
    let reply = post_form(
        &harness,
        "/admin/agents/credentials",
        &format!("webid={}", urlencode(AGENT_WEBID)),
        Some(&admin),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "mint: {}", reply.body);
    let (id, secret) = the_pair(&reply.body);
    assert!(
        !id.is_empty() && !secret.is_empty(),
        "the pair is the page: {}",
        reply.body
    );

    // 4. The exchange — the collector's request, with the panel-minted pair.
    let reply = client_credentials_request(&harness, &id, &secret, Some("webid"), true).await;
    assert_eq!(reply.status, StatusCode::OK, "token: {}", reply.body);
    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(
            reply.json()["access_token"]
                .as_str()
                .expect("an access token")
                .split('.')
                .nth(1)
                .expect("payload"),
        )
        .expect("decoded"),
    )
    .expect("claims");
    assert_eq!(claims["webid"], AGENT_WEBID);
}

/// The id and the secret off the minted-pair page: the two
/// `<span class="mono">` values of the minted notice, in order. The prose
/// around them says "secret" before the secret does, so the pair is read as
/// a pair, not by label.
fn the_pair(page: &str) -> (String, String) {
    let notice = &page[page.find("Credentials minted.").expect("the notice")..];
    let value = |from: &str| {
        let opened = &from[from.find("mono").expect("the class")..];
        let opened = &opened[opened.find('>').expect("the opening tag") + 1..];
        opened
            .split("</span>")
            .next()
            .unwrap_or_default()
            .to_string()
    };
    let id = value(notice);
    let after_id = &notice[notice.find(&id).expect("the id") + id.len()..];
    (id.clone(), value(after_id))
}

#[tokio::test]
async fn the_console_refuses_a_link_the_webid_does_not_vouch_for() {
    // The panel cannot be talked into skipping the dereference: a WebID
    // whose document names another issuer is refused with the reason
    // against the form, and no link is written.
    let elsewhere = documents_of(&[(AGENT_WEBID, "https://idp.example")]);
    let harness = harness_with_webids(
        std::sync::Arc::new(brolly_server::client_metadata::StaticClientDocuments::default()),
        std::sync::Arc::new(elsewhere),
    )
    .await;
    let admin = an_admin_session(&harness).await;
    db::create_user(
        &harness._db.pool,
        "pushbroom",
        None,
        "correct-horse-battery-staple",
        "member",
    )
    .await
    .expect("account");

    let reply = post_form(
        &harness,
        "/admin/agents/link",
        &format!("handle=pushbroom&webid={}", urlencode(AGENT_WEBID)),
        Some(&admin),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "link: {}",
        reply.body
    );
    assert!(reply.body.contains("does not name this issuer"));
    // The submitted WebID is kept against the form, the quota form's shape.
    assert!(reply.body.contains(AGENT_WEBID));
    assert!(
        brolly_solid::oidc::store::webid_link_owner(&harness._db.pool, AGENT_WEBID)
            .await
            .expect("lookup")
            .is_none(),
        "no link was written"
    );
}

#[tokio::test]
async fn the_console_is_not_a_member_surface() {
    // The guard is the feature: a member gets the console's 404 on every
    // agent path, GET and POST alike, and an anonymous visitor the login
    // redirect.
    let harness = harness().await;
    db::create_user(
        &harness._db.pool,
        "alice",
        None,
        "correct-horse-battery-staple",
        "member",
    )
    .await
    .expect("member");
    let member = post_form(
        &harness,
        "/login",
        "username=alice&password=correct-horse-battery-staple",
        None,
    )
    .await
    .cookies
    .first()
    .expect("a session cookie")
    .split(';')
    .next()
    .unwrap()
    .to_string();

    let page = get(&harness, "/admin/agents", Some(&member)).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    for path in [
        "/admin/agents/account",
        "/admin/agents/link",
        "/admin/agents/unlink",
        "/admin/agents/credentials",
    ] {
        let reply = post_form(&harness, path, "handle=x&webid=y&email=", Some(&member)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "POST {path}");
    }
    let anonymous = get(&harness, "/admin/agents", None).await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert!(anonymous.location.is_some_and(|l| l.contains("/login")));
}

#[tokio::test]
async fn a_cross_origin_agent_post_is_refused() {
    // The same-origin guard covers the console's new writes (lib.rs's
    // `SAME_ORIGIN_FORMS`), exactly as it covers the quota form.
    let harness = harness().await;
    let admin = an_admin_session(&harness).await;

    let reply = send(
        &harness,
        builder("POST", "/admin/agents/link")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, "https://elsewhere.example")
            .header(header::COOKIE, &admin)
            .body(Body::from(format!(
                "handle=pushbroom&webid={}",
                urlencode(AGENT_WEBID)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
}

// --- the operator path (ADR 0020) -------------------------------------------

/// Run `brolly-admin` against the harness's own database and stores, and
/// return (exit success, stdout, stderr) — the operator's terminal, from a
/// test. `CARGO_BIN_EXE_` is set for every binary the package builds, so
/// this runs the real CLI, not a reconstruction of it.
async fn run_admin(
    harness: &Harness,
    dir: &std::path::Path,
    args: &[&str],
) -> (bool, String, String) {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_brolly-admin"))
        .env("DATABASE_URL", &harness._db.url)
        .env("BROLLY_BASE_DOMAIN", BASE)
        .env("BROLLY_DATA_DIR", dir)
        .args(args)
        .output()
        .await
        .expect("run brolly-admin");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[tokio::test]
async fn the_operator_path_provisions_a_working_credential() {
    // Definition of the whole feature, as the operator runs it: create the
    // reserved-handle account, link the WebID, mint the pair, exchange it.
    // The link step runs the same `link_webid` the CLI's `link-webid` calls
    // — its production fetcher is the transport the fetch tests cover —
    // because the fetch itself refuses loopback, and a test is loopback.
    let harness = harness().await;
    let dir = tempfile::tempdir().expect("stores");

    // 1. The account, with the handle the front end's reserved list keeps
    //    out of signup and the service API. The password is generated and
    //    printed once, alone on stdout.
    let (ok, stdout, stderr) = run_admin(
        &harness,
        dir.path(),
        &[
            "agent-account",
            "pushbroom",
            "--email",
            "pushbroom@stucco.software",
        ],
    )
    .await;
    assert!(ok, "agent-account failed: {stderr}");
    let password = stdout.trim();
    assert!(
        password.len() >= 12,
        "a generated password, not a token gesture"
    );
    let user = db::find_by_username(&harness._db.pool, "pushbroom")
        .await
        .expect("lookup")
        .expect("the account exists");
    assert_eq!(user.email.as_deref(), Some("pushbroom@stucco.software"));

    // 2. The link. The WebID's document names this issuer — the slash
    //    spelling, as the live one does.
    let naming = documents_of(&[(AGENT_WEBID, &format!("https://{BASE}/"))]);
    let linked =
        brolly_server::solid_oidc::link_webid(&naming, &harness._db.pool, BASE, &user, AGENT_WEBID)
            .await
            .expect("linked");
    assert_eq!(linked, brolly_solid::oidc::store::Linked::Now);

    // And the CLI lists it.
    let (ok, stdout, stderr) = run_admin(&harness, dir.path(), &["webids", "pushbroom"]).await;
    assert!(ok, "webids failed: {stderr}");
    assert_eq!(stdout.trim(), AGENT_WEBID);

    // 3. The pair: id on the first line, secret on the second, nothing else
    //    on stdout, so the operator can pipe the two apart.
    let (ok, stdout, stderr) =
        run_admin(&harness, dir.path(), &["agent-credentials", AGENT_WEBID]).await;
    assert!(ok, "agent-credentials failed: {stderr}");
    let mut lines = stdout.lines();
    let id = lines.next().expect("the id").trim().to_string();
    let secret = lines.next().expect("the secret").trim().to_string();
    assert!(
        lines.next().is_none(),
        "stdout is the pair and nothing else"
    );
    assert!(!id.is_empty() && !secret.is_empty());
    assert!(
        !stderr.contains(&secret),
        "the secret never rides a log line"
    );

    // 4. The exchange — the collector's exact request, over the real router.
    let reply = client_credentials_request(&harness, &id, &secret, Some("webid"), true).await;
    assert_eq!(reply.status, StatusCode::OK, "token: {}", reply.body);
    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(
            reply.json()["access_token"]
                .as_str()
                .expect("an access token")
                .split('.')
                .nth(1)
                .expect("payload"),
        )
        .expect("decoded"),
    )
    .expect("claims");
    assert_eq!(claims["webid"], AGENT_WEBID);

    // And the kill switch, also as the operator runs it.
    let (ok, _, stderr) = run_admin(
        &harness,
        dir.path(),
        &["unlink-webid", "pushbroom", AGENT_WEBID],
    )
    .await;
    assert!(ok, "unlink-webid failed: {stderr}");
    let reply = client_credentials_request(&harness, &id, &secret, Some("webid"), true).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
}

// --- RFC 9207, and the clients that insist on it ----------------------------

#[tokio::test]
async fn every_authorization_response_names_the_issuer() {
    // RFC 9207 §2: `iss` on every authorization response, error or code, so a
    // client talking to several issuers can refuse an answer from the wrong
    // one. It is exactly the discovery document's `issuer`, because that is
    // the string clients compare it with.
    let harness = harness().await;
    let doc = get(&harness, "/.well-known/openid-configuration", None)
        .await
        .json();
    assert_eq!(doc["authorization_response_iss_parameter_supported"], true);
    let issuer = doc["issuer"].as_str().unwrap().to_string();

    let client_id = register(&harness).await;
    let (_, challenge) = pkce();

    // prompt=none with no session: an error redirect.
    let login_required = get(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid webid",
            &challenge,
            Some("none"),
        ),
        None,
    )
    .await;

    // A consent screen answered both ways.
    let cookie = a_logged_in_member(&harness).await;
    let allowed = allow(&harness, &authorize_url(&client_id, &challenge), &cookie).await;
    let consent = get(
        &harness,
        &authorize_url(&client_id, &challenge),
        Some(&cookie),
    )
    .await;
    let denied = post_form(
        &harness,
        "/oauth/solid/authorize",
        &format!(
            "request={}&decision=deny",
            urlencode(&request_token(&consent.body))
        ),
        Some(&cookie),
    )
    .await;

    for (what, reply) in [
        ("a prompt=none error", &login_required),
        ("an allow", &allowed),
        ("a deny", &denied),
    ] {
        assert_eq!(
            reply.status,
            StatusCode::SEE_OTHER,
            "{what}: {}",
            reply.body
        );
        assert_eq!(
            reply.redirect_params().get("iss"),
            Some(&issuer),
            "{what} must name the issuer"
        );
    }
}

/// A token-endpoint proof as `@uvdsl/solid-oidc-client-browser` writes it:
/// jose's `exportJWK`, plus an `alg` member it adds itself. Its resource
/// proofs leave `alg` out, so the thumbprint has to ignore the extra member
/// (RFC 7638 §3.2) or the token is bound to a key no later proof matches.
fn dpop_proof_with_jwk_alg(key: &SigningKey, method: &str, url: &str) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(&sec1[1..33]),
            "y": B64.encode(&sec1[33..65]),
            "alg": "ES256",
        },
    });
    let claims = serde_json::json!({
        "htu": url,
        "htm": method,
        "iat": now(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// Everything uvdsl checks before it calls a session active: jose's
/// `jwtVerify` against the JWKS (signature, `iss`, `aud: "solid"`, `exp`),
/// then `cnf.jkt` against its own key, `client_id`, and a `webid` claim.
async fn assert_uvdsl_accepts(
    harness: &Harness,
    issuer: &str,
    client_id: &str,
    key: &SigningKey,
    access: &str,
) {
    let mut parts = access.split('.');
    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(parts.next().unwrap()).unwrap()).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&B64.decode(parts.next().unwrap()).unwrap()).unwrap();

    // jose picks the JWKS key by `kid` and `alg`.
    let jwks = get(harness, "/oauth/solid/jwks", None).await.json();
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == header["kid"])
        .unwrap_or_else(|| panic!("no JWKS key for kid {}", header["kid"]));
    assert_eq!(header["alg"], "ES256");
    let mut sec1 = vec![0x04];
    sec1.extend(B64.decode(jwk["x"].as_str().unwrap()).unwrap());
    sec1.extend(B64.decode(jwk["y"].as_str().unwrap()).unwrap());
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let (signed, signature) = access.rsplit_once('.').unwrap();
    let signature = p256::ecdsa::Signature::from_slice(&B64.decode(signature).unwrap()).unwrap();
    use p256::ecdsa::signature::Verifier;
    verifying
        .verify(signed.as_bytes(), &signature)
        .expect("the access token verifies against the JWKS");

    assert_eq!(claims["iss"], issuer, "iss must equal discovery's issuer");
    assert_eq!(claims["aud"], "solid");
    assert!(claims["exp"].as_i64().unwrap() > now());
    assert_eq!(claims["cnf"]["jkt"], thumbprint(key));
    assert_eq!(claims["client_id"], client_id);
    assert_eq!(claims["webid"], format!("https://alice.{BASE}/profile#me"));
}

#[tokio::test]
async fn the_uvdsl_browser_client_logs_in_and_refreshes() {
    // `@uvdsl/solid-oidc-client-browser` (v0.2.3) is the client SolidOS is
    // moving to. This walks its sequence request for request, and checks
    // each answer the way it does — it is stricter than most: it requires
    // `iss` on the callback and verifies the access token itself.
    let harness = harness().await;

    // Discovery at the origin the member typed. It refuses to go on unless
    // `issuer` matches that origin, ignoring a trailing slash.
    let doc = get(&harness, "/.well-known/openid-configuration", None)
        .await
        .json();
    let issuer = doc["issuer"].as_str().unwrap().to_string();
    assert_eq!(issuer.trim_end_matches('/'), format!("https://{BASE}"));
    let token_endpoint = doc["token_endpoint"].as_str().unwrap().to_string();
    let token_path = token_endpoint.strip_prefix(&issuer).unwrap().to_string();

    // A browser app on another origin: the preflights for registration and
    // for the token endpoint (`dpop` is not a safelisted header).
    for (path, headers) in [
        ("/oauth/solid/register", "content-type"),
        (token_path.as_str(), "content-type,dpop"),
    ] {
        let preflight = send(
            &harness,
            builder("OPTIONS", path)
                .header(header::ORIGIN, "https://app.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, headers)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert!(preflight.status.is_success(), "preflight {path}");
    }

    // Dynamic registration, with the members it always sends.
    let registered = send(
        &harness,
        builder("POST", "/oauth/solid/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "redirect_uris": [REDIRECT],
                    "client_name": "A uvdsl app",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "none",
                    "application_type": "web",
                    "subject_type": "public",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{}",
        registered.body
    );
    let client_id = registered.json()["client_id"].as_str().unwrap().to_string();

    // Authorize, always with `prompt=consent` (CSS needs it for a refresh
    // token), and allow.
    let cookie = a_logged_in_member(&harness).await;
    let (verifier, challenge) = pkce();
    let callback = allow(
        &harness,
        &authorize_query(
            &client_id,
            REDIRECT,
            "openid offline_access webid",
            &challenge,
            Some("consent"),
        ),
        &cookie,
    )
    .await;
    assert_eq!(callback.status, StatusCode::SEE_OTHER, "{}", callback.body);
    let params = callback.redirect_params();
    // The check that kept it from logging in at all: `iss` must be present
    // and equal to the issuer it discovered.
    assert_eq!(
        params.get("iss"),
        Some(&issuer),
        "RFC 9207 iss on the callback"
    );
    assert_eq!(params["state"], "opaque-client-state");

    // The code exchange. Its redirect_uri is the callback URL with `code`,
    // `state` and `iss` deleted again — the registered one.
    let key = client_key();
    let token_request = |body: String| {
        builder("POST", &token_path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                dpop_proof_with_jwk_alg(&key, "POST", &token_endpoint),
            )
            .body(Body::from(body))
            .unwrap()
    };
    let exchanged = send(
        &harness,
        token_request(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", &params["code"])
                .append_pair("code_verifier", &verifier)
                .append_pair("redirect_uri", REDIRECT)
                .append_pair("client_id", &client_id)
                .finish(),
        ),
    )
    .await;
    assert_eq!(exchanged.status, StatusCode::OK, "{}", exchanged.body);
    let tokens = exchanged.json();
    assert_uvdsl_accepts(
        &harness,
        &issuer,
        &client_id,
        &key,
        tokens["access_token"].as_str().unwrap(),
    )
    .await;
    let first_refresh = tokens["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_string();

    // Restoring after a reload: the refresh grant. It stores whatever
    // `refresh_token` comes back, so one must come back.
    let refreshed = send(
        &harness,
        token_request(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "refresh_token")
                .append_pair("refresh_token", &first_refresh)
                .append_pair("client_id", &client_id)
                .finish(),
        ),
    )
    .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.body);
    let tokens = refreshed.json();
    let second_refresh = tokens["refresh_token"]
        .as_str()
        .expect("a rotated refresh token");
    assert_ne!(second_refresh, first_refresh);
    let access = tokens["access_token"].as_str().unwrap().to_string();
    assert_uvdsl_accepts(&harness, &issuer, &client_id, &key, &access).await;

    // Its `authFetch` proofs — jwk without `alg`, `ath` always, htu origin
    // plus path — are the shape `solid_token_access.rs` already presents to
    // the pod, so the pod half is proven there.
}
