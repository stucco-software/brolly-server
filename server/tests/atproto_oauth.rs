//! ATProtocol OAuth, end to end.
//!
//! Three protocol requirements shape every assertion here, and they are the
//! reasons this is not just the Solid or Mastodon flow with different paths:
//!
//! * **PAR is mandatory** — the request is pushed and referenced by an opaque
//!   handle, so nothing meaningful travels through the browser.
//! * **DPoP is mandatory**, with the key pledged at push time, so the token is
//!   bound to a key the client committed to before consent was shown.
//! * **`client_id` is a URL** serving client metadata; there is no
//!   registration and no secret to leak.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db;
use brolly_server::client_metadata::{
    ClientLookup, Lookup, StaticClientDocuments, StaticClients, StaticDocuments,
};
use brolly_server::{AppState, app};
use http_body_util::BodyExt;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

const BASE: &str = "brolly.test";
const CLIENT: &str = "https://app.example/client-metadata.json";
const REDIRECT: &str = "https://app.example/cb";

/// The client every test here pushes as, registered the way production would
/// accept it: through `validate`, so it can't be a client production refuses.
fn app_example() -> StaticClients {
    brolly_server::client_metadata::StaticClients::default()
        .with(
            CLIENT,
            &serde_json::json!({
                "client_id": CLIENT,
                "client_name": "Example App",
                "redirect_uris": [REDIRECT],
                "scope": "atproto transition:generic",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "application_type": "web",
                "dpop_bound_access_tokens": true,
            })
            .to_string(),
        )
        .expect("app.example's metadata validates")
}

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
}

async fn harness() -> Harness {
    harness_with(Arc::new(app_example())).await
}

async fn harness_with(
    clients: Arc<
        dyn ClientLookup<
                Document = brolly_atproto::client_metadata::ClientMetadata,
                Invalid = brolly_atproto::client_metadata::ClientError,
            >,
    >,
) -> Harness {
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
            limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
            www_redirect: None,
            max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
            pod_quota_bytes: brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
            stores: std::sync::Arc::new(
                brolly_store::StoreManager::open(dir.path(), 8, 60).unwrap(),
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
            clients,
            solid_clients: std::sync::Arc::new(StaticClientDocuments::default()),
            // The remote path's lookups (spec 6, H5): empty here, as a fetch
            // that finds nothing would be — these tests never leave the
            // instance.
            issuer_discovery: std::sync::Arc::new(StaticDocuments::default()),
            issuer_jwks: std::sync::Arc::new(StaticDocuments::default()),
            webid_documents: std::sync::Arc::new(StaticDocuments::default()),
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
            .unwrap_or_else(|e| panic!("expected JSON, got {}: {e}", self.body))
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

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A DPoP proof, as a real client produces one.
fn proof(key: &SigningKey, method: &str, url: &str, ath: Option<&str>) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "dpop+jwt",
        "jwk": {"kty": "EC", "crv": "P-256",
                "x": B64.encode(&sec1[1..33]), "y": B64.encode(&sec1[33..65])},
    });
    let mut claims = serde_json::json!({
        "htm": method, "htu": url,
        "jti": uuid::Uuid::new_v4().to_string(), "iat": now(),
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
    SigningKey::from_slice(&[11u8; 32]).unwrap()
}

fn pkce() -> (String, String) {
    let verifier = "a-high-entropy-value-for-the-atproto-oauth-flow-tests".to_string();
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn urlencode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn push(h: &Harness, key: &SigningKey, challenge: &str) -> Reply {
    let dpop = proof(
        key,
        "POST",
        &format!("https://{BASE}/oauth/atproto/par"),
        None,
    );
    push_with_proof(h, &dpop, challenge).await
}

/// PAR with a proof the caller supplies, so a test can present one twice.
async fn push_with_proof(h: &Harness, dpop: &str, challenge: &str) -> Reply {
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", CLIENT)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", "atproto transition:generic")
        .append_pair("state", "client-state")
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// PAR with exactly these form fields, signed by the test client's key.
async fn par_with(h: &Harness, fields: &[(&str, &str)]) -> Reply {
    let mut form = form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        form.append_pair(name, value);
    }
    send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                proof(
                    &client_key(),
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/par"),
                    None,
                ),
            )
            .body(Body::from(form.finish()))
            .unwrap(),
    )
    .await
}

/// The consent screen for a pushed request, as a logged-in member sees it.
async fn consent_page(h: &Harness, client_id: &str, request_uri: &str, cookie: &str) -> Reply {
    send(
        h,
        Request::builder()
            .uri(format!(
                "/oauth/atproto/authorize?client_id={}&request_uri={}",
                urlencode(client_id),
                urlencode(request_uri)
            ))
            .header(header::HOST, BASE)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// Counts lookups. Defined here so the production types carry no counters.
struct CountingClients {
    inner: StaticClients,
    lookups: Arc<AtomicUsize>,
}

impl ClientLookup for CountingClients {
    type Document = brolly_atproto::client_metadata::ClientMetadata;
    type Invalid = brolly_atproto::client_metadata::ClientError;

    fn fetch<'a>(&'a self, url: &'a url::Url) -> Lookup<'a, Self::Document, Self::Invalid> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch(url)
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
    .unwrap();
    let reply = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "username=alice&password=correct-horse-battery-staple",
            ))
            .unwrap(),
    )
    .await;
    reply.cookies[0].split(';').next().unwrap().to_string()
}

fn request_token(html: &str) -> String {
    let marker = r#"name="request" value=""#;
    let start = html
        .find(marker)
        .unwrap_or_else(|| panic!("no token in {html}"))
        + marker.len();
    html[start..].split('"').next().unwrap().to_string()
}

/// The whole flow, returning the token response.
async fn full_flow(h: &Harness, key: &SigningKey) -> serde_json::Value {
    let (verifier, challenge) = pkce();
    let pushed = push(h, key, &challenge).await;
    assert_eq!(pushed.status, StatusCode::CREATED, "par: {}", pushed.body);
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();

    let cookie = a_logged_in_member(h).await;
    let consent = send(
        h,
        Request::builder()
            .uri(format!(
                "/oauth/atproto/authorize?client_id={}&request_uri={}",
                urlencode(CLIENT),
                urlencode(&request_uri)
            ))
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        consent.status,
        StatusCode::OK,
        "authorize: {}",
        consent.body
    );

    let decision = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/authorize")
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "request={}&decision=allow",
                urlencode(&request_token(&consent.body))
            )))
            .unwrap(),
    )
    .await;
    let code = decision.redirect_params()["code"].clone();

    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", CLIENT)
        .append_pair("code_verifier", &verifier)
        .finish();
    let token = send(
        h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/token")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                proof(
                    key,
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/token"),
                    None,
                ),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "token: {}", token.body);
    token.json()
}

// --- discovery ---------------------------------------------------------------------

#[tokio::test]
async fn the_metadata_advertises_mounted_endpoints_and_mandatory_par() {
    let h = harness().await;
    let reply = send(
        &h,
        Request::builder()
            .uri("/.well-known/oauth-authorization-server")
            .header(header::HOST, BASE)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let doc = reply.json();

    assert_eq!(doc["require_pushed_authorization_requests"], true);
    assert_eq!(doc["dpop_signing_alg_values_supported"][0], "ES256");
    assert_eq!(doc["code_challenge_methods_supported"][0], "S256");

    // Every advertised endpoint must actually answer (ADR 0008).
    for key in [
        "authorization_endpoint",
        "token_endpoint",
        "pushed_authorization_request_endpoint",
    ] {
        let url = doc[key].as_str().unwrap_or_else(|| panic!("{key} missing"));
        let path = url.strip_prefix(&format!("https://{BASE}")).unwrap();
        let reply = send(
            &h,
            Request::builder()
                .uri(path)
                .header(header::HOST, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_ne!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{path} is advertised but not mounted"
        );
    }
}

// --- PAR ---------------------------------------------------------------------------

#[tokio::test]
async fn a_pushed_request_yields_an_opaque_handle() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = push(&h, &client_key(), &challenge).await;

    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let uri = reply.json()["request_uri"].as_str().unwrap().to_string();
    assert!(
        uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "expected an RFC 9126 URN, got {uri}"
    );
    // The point of PAR: nothing meaningful is in the handle itself.
    assert!(!uri.contains(REDIRECT));
    assert!(!uri.contains(&challenge));
}

#[tokio::test]
async fn a_pushed_request_requires_a_dpop_proof() {
    // The key is pledged here, so the token can be bound to it later.
    let h = harness().await;
    let (_, challenge) = pkce();
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", CLIENT)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn a_client_id_that_is_not_a_fetchable_url_is_refused() {
    // Without a fetchable metadata document there is nothing to hold the
    // client to its declared redirect URIs.
    let h = harness().await;
    let (_, challenge) = pkce();
    let key = client_key();
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "urn:uuid:not-a-url")
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/par")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                proof(
                    &key,
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/par"),
                    None,
                ),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_client");
}

#[tokio::test]
async fn an_unknown_client_is_refused_without_saying_why_it_could_not_be_reached() {
    // Every unreachable client gets the same words, so PAR can't be used to
    // find out which internal hosts exist or answer.
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", "https://unknown.example/client-metadata.json"),
            ("redirect_uri", "https://unknown.example/cb"),
            ("response_type", "code"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_client");
    assert_eq!(
        reply.json()["error_description"],
        "client metadata could not be retrieved"
    );
}

#[tokio::test]
async fn an_undeclared_redirect_uri_is_refused_without_redirecting() {
    // Hole 3: this is where the code used to go.
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", "https://evil.example/cb"),
            ("response_type", "code"),
            ("scope", "atproto"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_request");
    assert!(reply.location.is_none(), "a refusal never redirects");
}

#[tokio::test]
async fn a_scope_without_atproto_is_refused() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "transition:generic"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_scope");
}

#[tokio::test]
async fn a_scope_the_client_did_not_declare_is_refused() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "atproto transition:chat.bsky"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_scope");
}

#[tokio::test]
async fn a_loopback_client_id_naming_an_external_redirect_is_refused() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            (
                "client_id",
                "http://localhost?redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
            ),
            ("redirect_uri", "https://evil.example/cb"),
            ("response_type", "code"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_client");
    assert!(reply.location.is_none());
}

#[tokio::test]
async fn a_request_missing_pkce_is_refused_before_any_lookup() {
    // The request's own checks cost nothing; a fetch costs up to five seconds
    // and a request to someone else's server.
    let lookups = Arc::new(AtomicUsize::new(0));
    let h = harness_with(Arc::new(CountingClients {
        inner: app_example(),
        lookups: lookups.clone(),
    }))
    .await;

    let reply = par_with(
        &h,
        &[
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_request");
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        0,
        "refused before the lookup"
    );

    // And the counter isn't vacuous: a complete request does look the client up.
    let (_, challenge) = pkce();
    let pushed = push(&h, &client_key(), &challenge).await;
    assert_eq!(pushed.status, StatusCode::CREATED, "{}", pushed.body);
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_consent_screen_names_the_client_by_its_host() {
    // Not its self-asserted client_name: brolly has no list of vetted clients
    // (S5). The full client_id is still shown as the requester.
    let h = harness().await;
    let (_, challenge) = pkce();
    let pushed = push(&h, &client_key(), &challenge).await;
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();
    let cookie = a_logged_in_member(&h).await;

    let consent = consent_page(&h, CLIENT, &request_uri, &cookie).await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
    assert!(
        consent.body.contains("Authorise app.example"),
        "{}",
        consent.body
    );
    assert!(!consent.body.contains("Authorise https://"));
    assert!(
        !consent.body.contains("Example App"),
        "client_name is not shown"
    );
    assert!(
        consent.body.contains("client-metadata.json"),
        "the full client_id still appears"
    );
}

#[tokio::test]
async fn a_loopback_client_needs_no_metadata_and_is_named_as_development() {
    let h = harness().await;
    let (_, challenge) = pkce();
    let client = "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto";
    let pushed = par_with(
        &h,
        &[
            ("client_id", client),
            ("redirect_uri", "http://127.0.0.1:52431/callback"),
            ("response_type", "code"),
            ("scope", "atproto"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(pushed.status, StatusCode::CREATED, "{}", pushed.body);
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();
    let cookie = a_logged_in_member(&h).await;

    let consent = consent_page(&h, client, &request_uri, &cookie).await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
    assert!(
        consent.body.contains("Authorise localhost (development)"),
        "{}",
        consent.body
    );
}

#[tokio::test]
async fn a_loopback_redirect_uri_not_in_canonical_form_is_refused() {
    // A loopback redirect matches after URL parsing, which strips tabs and
    // newlines. The string stored, put in Location and compared at the token
    // endpoint must be the one that was checked, so only the canonical form
    // is accepted.
    let h = harness().await;
    let (_, challenge) = pkce();
    let reply = par_with(
        &h,
        &[
            (
                "client_id",
                "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback",
            ),
            ("redirect_uri", "http://127.0.0.1:52431/call\nback"),
            ("response_type", "code"),
            ("scope", "atproto"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(reply.json()["error"], "invalid_request");
    assert!(reply.location.is_none());
}

#[tokio::test]
async fn a_par_proof_is_good_for_one_request() {
    // PAR is where the key is pledged. A replayed proof would let anyone who
    // saw one push requests pledged to a key they don't hold.
    let h = harness().await;
    let key = client_key();
    let (_, challenge) = pkce();
    let dpop = proof(
        &key,
        "POST",
        &format!("https://{BASE}/oauth/atproto/par"),
        None,
    );

    let first = push_with_proof(&h, &dpop, &challenge).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);

    let replayed = push_with_proof(&h, &dpop, &challenge).await;
    assert_eq!(
        replayed.status,
        StatusCode::BAD_REQUEST,
        "{}",
        replayed.body
    );
    assert_eq!(replayed.json()["error"], "invalid_dpop_proof");

    let fresh = push(&h, &key, &challenge).await;
    assert_eq!(fresh.status, StatusCode::CREATED, "{}", fresh.body);
}

#[tokio::test]
async fn authorize_without_par_is_refused() {
    // PAR is not optional here, and the error says which requirement was missed.
    let h = harness().await;
    let cookie = a_logged_in_member(&h).await;
    let reply = send(
        &h,
        Request::builder()
            .uri(format!(
                "/oauth/atproto/authorize?client_id={}&redirect_uri={}&response_type=code",
                urlencode(CLIENT),
                urlencode(REDIRECT)
            ))
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        reply.json()["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("PAR")
    );
}

// --- the full flow -------------------------------------------------------------------

#[tokio::test]
async fn a_client_gets_a_dpop_bound_token_pair() {
    let h = harness().await;
    let tokens = full_flow(&h, &client_key()).await;

    assert_eq!(
        tokens["token_type"], "DPoP",
        "a Bearer token_type would invite clients to drop the proof"
    );
    assert!(tokens["access_token"].as_str().is_some());
    assert!(tokens["refresh_token"].as_str().is_some());
    assert!(
        tokens["sub"]
            .as_str()
            .is_some_and(|s| s.starts_with("did:")),
        "clients read the subject DID straight off the token response"
    );
}

#[tokio::test]
async fn the_token_is_bound_to_the_key_that_pushed_the_request() {
    // Otherwise PAR's key pledge would be decorative: someone who intercepted
    // the code could redeem it with a key of their own.
    let h = harness().await;
    let key = client_key();
    let (verifier, challenge) = pkce();

    let pushed = push(&h, &key, &challenge).await;
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();
    let cookie = a_logged_in_member(&h).await;

    let consent = send(
        &h,
        Request::builder()
            .uri(format!(
                "/oauth/atproto/authorize?client_id={}&request_uri={}",
                urlencode(CLIENT),
                urlencode(&request_uri)
            ))
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let decision = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/authorize")
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "request={}&decision=allow",
                urlencode(&request_token(&consent.body))
            )))
            .unwrap(),
    )
    .await;
    let code = decision.redirect_params()["code"].clone();

    // A different key redeems the code.
    let thief = SigningKey::from_slice(&[99u8; 32]).unwrap();
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("client_id", CLIENT)
        .append_pair("code_verifier", &verifier)
        .finish();
    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/token")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                proof(
                    &thief,
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/token"),
                    None,
                ),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn a_pushed_request_is_answerable_only_once() {
    let h = harness().await;
    let key = client_key();
    let (_, challenge) = pkce();
    let pushed = push(&h, &key, &challenge).await;
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();
    let cookie = a_logged_in_member(&h).await;

    let authorize_url = format!(
        "/oauth/atproto/authorize?client_id={}&request_uri={}",
        urlencode(CLIENT),
        urlencode(&request_uri)
    );
    let consent = send(
        &h,
        Request::builder()
            .uri(&authorize_url)
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let token = request_token(&consent.body);

    let answer = |token: String, cookie: String| {
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/authorize")
            .header(header::HOST, BASE)
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "request={}&decision=allow",
                urlencode(&token)
            )))
            .unwrap()
    };

    let first = send(&h, answer(token.clone(), cookie.clone())).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER);

    let second = send(&h, answer(token, cookie)).await;
    assert_eq!(
        second.status,
        StatusCode::BAD_REQUEST,
        "one authorization per pushed request"
    );
}

#[tokio::test]
async fn declining_tells_the_client_and_preserves_state() {
    let h = harness().await;
    let key = client_key();
    let (_, challenge) = pkce();
    let pushed = push(&h, &key, &challenge).await;
    let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_string();
    let cookie = a_logged_in_member(&h).await;

    let consent = send(
        &h,
        Request::builder()
            .uri(format!(
                "/oauth/atproto/authorize?client_id={}&request_uri={}",
                urlencode(CLIENT),
                urlencode(&request_uri)
            ))
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let reply = send(
        &h,
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/authorize")
            .header(header::HOST, BASE)
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "request={}&decision=deny",
                urlencode(&request_token(&consent.body))
            )))
            .unwrap(),
    )
    .await;

    let params = reply.redirect_params();
    assert_eq!(params["error"], "access_denied");
    assert_eq!(params["state"], "client-state");
    assert!(!params.contains_key("code"));
}

#[tokio::test]
async fn a_refresh_rotates_and_the_old_token_dies() {
    let h = harness().await;
    let key = client_key();
    let tokens = full_flow(&h, &key).await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();

    let request = |token: &str| {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", token)
            .append_pair("client_id", CLIENT)
            .finish();
        Request::builder()
            .method("POST")
            .uri("/oauth/atproto/token")
            .header(header::HOST, BASE)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "DPoP",
                proof(
                    &key,
                    "POST",
                    &format!("https://{BASE}/oauth/atproto/token"),
                    None,
                ),
            )
            .body(Body::from(body))
            .unwrap()
    };

    let rotated = send(&h, request(&refresh)).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    assert_ne!(rotated.json()["refresh_token"].as_str().unwrap(), refresh);

    let replayed = send(&h, request(&refresh)).await;
    assert_eq!(
        replayed.status,
        StatusCode::BAD_REQUEST,
        "a spent refresh token must not work twice"
    );
}

#[tokio::test]
async fn the_atproto_oauth_surface_is_apex_only() {
    let h = harness().await;
    for (method, path) in [
        ("GET", "/.well-known/oauth-authorization-server"),
        ("POST", "/oauth/atproto/par"),
        ("GET", "/oauth/atproto/authorize"),
        ("POST", "/oauth/atproto/token"),
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
