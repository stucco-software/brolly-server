//! A Solid app reaching the pod with the token it was issued.
//!
//! This is the join between the provider and the store: the provider mints a
//! DPoP-bound token, and the pod has to turn that token back into the `Subject`
//! WAC evaluates. Until it did, `subject_for` mapped every Bearer and DPoP
//! credential to anonymous and an app with a perfectly good token got a 404.
//! Since 5b, a credential that doesn't verify is a 401 naming what was wrong
//! with it (H2), not a quiet downgrade.
//!
//! The negative cases matter more than the positive one. A token is only worth
//! its binding if presenting it without the key fails.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db;
use brolly_server::client_metadata::{ClientLookup, LookupError, StaticDocuments};
use brolly_server::{AppState, app};
use brolly_solid::oidc::dpop;
use brolly_solid::oidc::tokens::{RemoteDiscovery, RemoteJwks};
use brolly_solid::webid_documents::{self, WebIdDocument};
use brolly_store::StoreManager;
use brolly_store::resources::Content;
use http_body_util::BodyExt;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;
use url::Url;

const BASE_DOMAIN: &str = "brolly.test";
const POD_HOST: &str = "alice.brolly.test";
const POD: &str = "https://alice.brolly.test";
const ROOT: &str = "https://alice.brolly.test/~/";
const NOTE: &str = "https://alice.brolly.test/~/note";
/// A resource whose path a client must percent-encode. `+` is a sub-delimiter,
/// so an encoding client sends `%2B` and a decoding server sees `+`; the two
/// spellings are both legal IRIs and they are not equal, which is what makes
/// this a test rather than a coincidence.
const DRAFT: &str = "https://alice.brolly.test/~/note+draft";
const DRAFT_PATH: &str = "/~/note%2Bdraft";
const DRAFT_URL: &str = "https://alice.brolly.test/~/note%2Bdraft";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const REDIRECT: &str = "https://app.example/cb";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn t(g: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(n(s)),
        n(p),
        Term::NamedNode(n(o)),
        GraphName::NamedNode(n(g)),
    )
}

struct Harness {
    _db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    /// The member's pod, for tests that write the grant a scenario needs.
    pod: std::sync::Arc<brolly_store::resources::Pod>,
}

/// The lookups the remote path consults (spec 6, H5), as the harness holds
/// them.
type RemoteLookups = (
    std::sync::Arc<
        dyn brolly_server::client_metadata::ClientLookup<
                Document = brolly_solid::oidc::tokens::RemoteDiscovery,
                Invalid = brolly_solid::oidc::tokens::InvalidDiscovery,
            >,
    >,
    std::sync::Arc<
        dyn brolly_server::client_metadata::ClientLookup<
                Document = brolly_solid::oidc::tokens::RemoteJwks,
                Invalid = brolly_solid::oidc::tokens::InvalidJwks,
            >,
    >,
    std::sync::Arc<
        dyn brolly_server::client_metadata::ClientLookup<
                Document = brolly_solid::webid_documents::WebIdDocument,
                Invalid = brolly_solid::webid_documents::InvalidWebIdDocument,
            >,
    >,
);

/// Empty remote lookups, as a fetch that finds nothing would be (spec 6,
/// H5): the tests that take the remote path supply their own.
fn no_remote_documents() -> RemoteLookups {
    use brolly_server::client_metadata::StaticDocuments;
    (
        std::sync::Arc::new(StaticDocuments::default()),
        std::sync::Arc::new(StaticDocuments::default()),
        std::sync::Arc::new(StaticDocuments::default()),
    )
}

async fn harness_with((issuer_discovery, issuer_jwks, webid_documents): RemoteLookups) -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 4, 60).unwrap());

    let user = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let pod = stores.pod(user.id).unwrap();
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    let grant = [
        t(&g, &a, &format!("{ACL}default"), ROOT),
        t(&g, &a, &format!("{ACL}accessTo"), ROOT),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(&g, &a, &format!("{ACL}agent"), &format!("{POD}/profile#me")),
    ];
    // Something to read.
    let note = [t(
        NOTE,
        NOTE,
        "https://example.org/title",
        "https://example.org/a",
    )];
    pod.write(|w| {
        w.create_root(ROOT)?;
        w.put(&g, Content::Auxiliary(&grant))?;
        w.put(NOTE, Content::Rdf(&note))?;
        let draft = [t(
            DRAFT,
            DRAFT,
            "https://example.org/title",
            "https://example.org/b",
        )];
        w.put(DRAFT, Content::Rdf(&draft))?;
        Ok(())
    })
    .unwrap();

    let router = app(
        AppState {
            pool: db.pool.clone(),
            base_domain: BASE_DOMAIN.into(),
            instance_name: BASE_DOMAIN.to_string(),
            instance_description: "A private community server.".to_string(),
            source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
            terms_url: None,
            privacy_url: None,
            stores,
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
            issuer_discovery,
            issuer_jwks,
            webid_documents,
        },
        "server/static",
    );

    Harness {
        _db: db,
        _dir: dir,
        router,
        pod,
    }
}

async fn harness() -> Harness {
    harness_with(no_remote_documents()).await
}

async fn send(harness: &Harness, request: Request<Body>) -> (StatusCode, String) {
    let response = harness.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body)
}

/// A request's status and its `WWW-Authenticate`, for H3's assertions. The
/// header is the only thing a refused client can act on, so asserting the
/// status alone would let the two error codes collapse into one unnoticed.
async fn challenged(harness: &Harness, request: Request<Body>) -> (StatusCode, String) {
    let response = harness.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, challenge)
}

const INVALID_TOKEN: &str = r#"error="invalid_token""#;
const INVALID_PROOF: &str = r#"error="invalid_dpop_proof""#;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

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

/// Drive the whole provider flow and return the access token issued to `key`.
async fn access_token(harness: &Harness, key: &SigningKey) -> String {
    let apex = |method: &str, uri: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, BASE_DOMAIN)
    };

    let (_, body) = send(
        harness,
        apex("POST", "/oauth/solid/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({"client_name": "Notes", "redirect_uris": [REDIRECT]})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    let client_id: String = serde_json::from_str::<serde_json::Value>(&body).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = harness
        .router
        .clone()
        .oneshot(
            apex("POST", "/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=correct-horse-battery"))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let verifier = "a-high-entropy-cryptographic-random-string-of-length-64ish";
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("scope", "openid webid")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let (_, consent) = send(
        harness,
        apex("GET", &format!("/oauth/solid/authorize?{query}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let marker = r#"name="request" value=""#;
    let start = consent.find(marker).expect("consent form") + marker.len();
    let request_token = consent[start..].split('"').next().unwrap().to_string();

    let response = harness
        .router
        .clone()
        .oneshot(
            apex("POST", "/oauth/solid/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(format!(
                    "request={}&decision=allow",
                    form_urlencoded::byte_serialize(request_token.as_bytes()).collect::<String>()
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("a code");

    let token_url = format!("https://{BASE_DOMAIN}/oauth/solid/token");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("client_id", &client_id)
        .append_pair("code_verifier", verifier)
        .finish();
    let (status, body) = send(
        harness,
        apex("POST", "/oauth/solid/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", dpop_proof(key, "POST", &token_url, None))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token endpoint: {body}");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn client_key() -> SigningKey {
    SigningKey::from_slice(&[7u8; 32]).unwrap()
}

/// `GET /~/note` carrying whatever credentials the caller supplies.
fn read_note(authorization: Option<&str>, proof: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("GET")
        .uri("/~/note")
        .header(header::HOST, POD_HOST);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    if let Some(proof) = proof {
        request = request.header("DPoP", proof);
    }
    request.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn an_app_reads_the_pod_with_the_token_it_was_issued() {
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let proof = dpop_proof(
        &key,
        "GET",
        NOTE,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let (status, body) = send(
        &harness,
        read_note(Some(&format!("DPoP {token}")), Some(&proof)),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.contains("example.org/title"),
        "expected the note's triples, got {body}"
    );
}

#[tokio::test]
async fn a_token_without_its_proof_is_not_accepted() {
    // The whole point of binding: a token lifted from a log or a compromised
    // store is inert on its own.
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let (status, challenge) =
        challenged(&harness, read_note(Some(&format!("DPoP {token}")), None)).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unproven token must not read the pod"
    );
    // The token is fine; the proof is missing. `invalid_token` would send the
    // client to refresh a good token and present the same absent proof again.
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");
}

#[tokio::test]
async fn a_stolen_token_proven_with_the_wrong_key_is_not_accepted() {
    let harness = harness().await;
    let token = access_token(&harness, &client_key()).await;

    let thief = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let proof = dpop_proof(
        &thief,
        "GET",
        NOTE,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let (status, challenge) = challenged(
        &harness,
        read_note(Some(&format!("DPoP {token}")), Some(&proof)),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a proof from another key must not satisfy this token's binding"
    );
    // The token is the victim's and it is fine; the proof is the thief's.
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");
}

#[tokio::test]
async fn a_proof_for_another_request_is_not_accepted() {
    // Replaying a proof captured from one request onto another is what `htm`
    // and `htu` exist to stop.
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let elsewhere = dpop_proof(
        &key,
        "GET",
        "https://alice.brolly.test/~/somewhere-else",
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let (status, challenge) = challenged(
        &harness,
        read_note(Some(&format!("DPoP {token}")), Some(&elsewhere)),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // An `htu` mismatch is the proof's fault, not the token's.
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");
}

#[tokio::test]
async fn a_proof_without_the_token_hash_is_not_accepted() {
    // `ath` is what stops a proof minted for the token endpoint being replayed
    // against a resource.
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let no_ath = dpop_proof(&key, "GET", NOTE, None);
    let (status, challenge) = challenged(
        &harness,
        read_note(Some(&format!("DPoP {token}")), Some(&no_ath)),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A missing `ath` is the proof's fault, not the token's.
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");
}

#[tokio::test]
async fn a_solid_token_presented_as_a_bearer_is_not_accepted() {
    // Downgrading to bearer semantics is the mistake that makes DPoP
    // decorative, so the scheme itself is refused rather than tolerated.
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let proof = dpop_proof(
        &key,
        "GET",
        NOTE,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let (status, challenge) = challenged(
        &harness,
        read_note(Some(&format!("Bearer {token}")), Some(&proof)),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A bare bearer gets a `Bearer` challenge: whatever sent it has no key to
    // sign a proof with, and a `DPoP` challenge would loop.
    assert_eq!(
        challenge, r#"Bearer error="invalid_token""#,
        "got: {challenge}"
    );
}

#[tokio::test]
async fn a_forged_token_is_not_accepted() {
    let harness = harness().await;
    let key = client_key();

    // Well-formed, signed by a key that is not the provider's.
    let claims = serde_json::json!({
        "iss": format!("https://{BASE_DOMAIN}"),
        "webid": format!("{POD}/profile#me"),
        "sub": format!("{POD}/profile#me"),
        "scope": "webid",
        "exp": now() + 900,
        "cnf": {"jkt": "irrelevant"},
    });
    let forger = SigningKey::from_slice(&[11u8; 32]).unwrap();
    let header = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": "made-up"});
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = forger.sign(signed.as_bytes());
    let forged = format!("{signed}.{}", B64.encode(signature.to_bytes()));

    let proof = dpop_proof(
        &key,
        "GET",
        NOTE,
        Some(&B64.encode(Sha256::digest(forged.as_bytes()))),
    );
    let (status, challenge) = challenged(
        &harness,
        read_note(Some(&format!("DPoP {forged}")), Some(&proof)),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The signature is the token's, not the proof's.
    assert!(challenge.contains(INVALID_TOKEN), "got: {challenge}");
}

/// Without a credential, a resource that isn't public gets a challenge. The
/// member's note is still not disclosed: the challenge is identical for a note
/// that doesn't exist (`pod_http.rs`,
/// `an_anonymous_refusal_is_the_same_for_a_real_and_a_fictive_resource`).
#[tokio::test]
async fn an_anonymous_request_still_gets_the_default_deny() {
    let harness = harness().await;
    let (status, challenge) = challenged(&harness, read_note(None, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge,
        format!(r#"DPoP algs="ES256", as_uri="https://{BASE_DOMAIN}""#)
    );
}

/// Refused with `invalid_dpop_proof`, so the client signs a fresh proof rather
/// than refreshing a token that never expired.
#[tokio::test]
async fn a_resource_proof_is_good_for_one_request() {
    // `ath` binds a proof to the token and `htu` to the resource, but neither
    // stops the identical request being sent again. Only the jti does.
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;
    let ath = B64.encode(Sha256::digest(token.as_bytes()));
    let authorization = format!("DPoP {token}");

    let proof = dpop_proof(&key, "GET", NOTE, Some(&ath));
    let (status, body) = send(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, challenge) =
        challenged(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a replayed proof must be refused, not silently downgraded"
    );
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");

    let fresh = dpop_proof(&key, "GET", NOTE, Some(&ath));
    let (status, _) = send(&harness, read_note(Some(&authorization), Some(&fresh))).await;
    assert_eq!(status, StatusCode::OK, "the token itself is still good");
}

/// A correct client signs `htm: HEAD` on a HEAD. Handing the verifier the
/// literal `"GET"` made that proof fail, the caller was downgraded to
/// anonymous, and the member's own resource answered as if it did not exist —
/// so `HEAD` was unusable for exactly the cache revalidation it exists for.
/// CTS signs HEAD proofs (`read-method-allow.feature`).
#[tokio::test]
async fn a_head_is_authenticated_as_a_head() {
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let proof = dpop_proof(
        &key,
        "HEAD",
        NOTE,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let request = Request::builder()
        .method("HEAD")
        .uri("/~/note")
        .header(header::HOST, POD_HOST)
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&harness, request).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.is_empty(), "HEAD sent a body: {body}");
}

/// `htu_matches` is exact string equality after stripping query and fragment
/// (`identity/src/dpop.rs:397`), so the URL the proof is checked against has to
/// be the one the client signed. Building it from the decoded `Path` made
/// every escaped character in a path a silent authentication failure.
#[tokio::test]
async fn a_proof_is_checked_against_the_undecoded_path() {
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let proof = dpop_proof(
        &key,
        "GET",
        DRAFT_URL,
        Some(&B64.encode(Sha256::digest(token.as_bytes()))),
    );
    let request = Request::builder()
        .method("GET")
        .uri(DRAFT_PATH)
        .header(header::HOST, POD_HOST)
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&harness, request).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("example.org/b"), "got: {body}");
}

// --- the remote path (spec 6, H5) ---------------------------------------------
//
// A token another Solid-OIDC issuer signed: verified against that issuer's
// own key set, bound to its WebID by the WebID's own `solid:oidcIssuer`, and
// a caller with no account here reading what a member granted its WebID.
// The lookups are stubbed the way the client-document tests stub theirs —
// answers parsed by the production `parse`, keyed by URL — with the fetches
// counted where a test pins what the path consults.

/// A foreign Solid-OIDC issuer, standing in for any other deployment.
const ISSUER: &str = "https://idp.example";
const JWKS_URI: &str = "https://idp.example/jwks";
const ISSUER_KID: &str = "idp-2026-1";
/// A WebID this instance does not host: `bob.example.org`, not a subdomain
/// of the base domain.
const BOB: &str = "https://bob.example.org/profile#me";

fn issuer_key() -> SigningKey {
    SigningKey::from_slice(&[13u8; 32]).unwrap()
}

/// The issuer's discovery document, pointing at its key set.
fn discovery_document(issuer: &str, jwks_uri: &str) -> RemoteDiscovery {
    RemoteDiscovery::parse(
        "application/json",
        serde_json::json!({"issuer": issuer, "jwks_uri": jwks_uri})
            .to_string()
            .as_bytes(),
    )
    .unwrap()
}

/// A key set carrying one ES256 key, `kid` naming it — built from the key
/// itself so the signature below is really its.
fn key_set(key: &SigningKey, kid: &str) -> RemoteJwks {
    let sec1 = key.verifying_key().to_sec1_bytes();
    RemoteJwks::parse(
        "application/json",
        serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid,
                "x": B64.encode(&sec1[1..33]),
                "y": B64.encode(&sec1[33..65]),
            }]
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap()
}

/// A WebID profile naming one issuer, as the binding reads it.
fn profile_naming(webid: &str, issuer: &str) -> WebIdDocument {
    let turtle = format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
         <{webid}> solid:oidcIssuer <{issuer}> ."
    );
    webid_documents::parse(
        &Url::parse(webid).unwrap(),
        "text/turtle",
        turtle.as_bytes(),
    )
    .unwrap()
}

/// Mint the access token a foreign issuer would (spec 6, H5): ES256 with
/// the issuer's key, `kid` naming it, and `claims` as the issuer writes them.
fn signed_by(key: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
    let header = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid});
    let signed = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", B64.encode(signature.to_bytes()))
}

/// The claims a Solid-OIDC issuer puts in an access token (spec 6, H5),
/// complete and valid: `aud: solid`, the WebID in both `sub` and `webid`,
/// DPoP-bound to `jkt`.
fn remote_claims(iss: &str, webid: &str, jkt: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": iss,
        "sub": webid,
        "webid": webid,
        "aud": "solid",
        "client_id": "https://penny.example/id",
        "scope": "webid",
        "iat": now(),
        "exp": now() + 900,
        "cnf": {"jkt": jkt},
    })
}

fn jkt_of(key: &SigningKey) -> String {
    let sec1 = key.verifying_key().to_sec1_bytes();
    dpop::thumbprint(&dpop::PublicJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: B64.encode(&sec1[1..33]),
        y: B64.encode(&sec1[33..65]),
    })
}

/// One of the remote lookups as a counting stub (spec 6, H5): answers by
/// URL, every fetch counted, so a test can pin what the remote path
/// consults — once per issuer, once more for a rotation.
struct Counting<D> {
    answers: std::collections::HashMap<String, D>,
    fetches: Arc<AtomicUsize>,
}

// Manual, because the derive would demand `D: Default`.
impl<D> Default for Counting<D> {
    fn default() -> Self {
        Self {
            answers: std::collections::HashMap::new(),
            fetches: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<D: brolly_server::client_metadata::Document> ClientLookup for Counting<D> {
    type Document = D;
    type Invalid = D::Invalid;

    fn fetch<'a>(
        &'a self,
        url: &'a Url,
    ) -> brolly_server::client_metadata::Lookup<'a, D, D::Invalid> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let found = self
            .answers
            .get(url.as_str())
            .cloned()
            .ok_or(LookupError::Unreachable);
        Box::pin(std::future::ready(found))
    }
}

/// The remote path's lookups for a working issuer: the discovery document
/// and key set counted, Bob's profile held. Returns the counters alongside,
/// for the once-each assertion.
async fn a_foreign_issuer() -> (Harness, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let mut discovery = Counting::<RemoteDiscovery>::default();
    discovery.answers.insert(
        format!("{ISSUER}/.well-known/openid-configuration"),
        discovery_document(ISSUER, JWKS_URI),
    );
    let discovery_fetches = discovery.fetches.clone();
    let mut jwks = Counting::<RemoteJwks>::default();
    jwks.answers
        .insert(JWKS_URI.to_string(), key_set(&issuer_key(), ISSUER_KID));
    let jwks_fetches = jwks.fetches.clone();
    let webids = StaticDocuments::default().with(BOB, profile_naming(BOB, ISSUER));

    let harness = harness_with((Arc::new(discovery), Arc::new(jwks), Arc::new(webids))).await;
    (harness, discovery_fetches, jwks_fetches)
}

/// The member grants a WebID Read on the root by default (spec 6, H5): the
/// ACL a member can already write, because WAC's `acl:agent` matching is
/// IRI-based and needs no changes for a foreign WebID.
async fn grant_read_on_the_root(harness: &Harness, webid: &str) {
    let g = format!("{ROOT}.acl");
    let guest = format!("{g}#guest");
    let grant = [
        t(&g, &format!("{g}#owner"), &format!("{ACL}default"), ROOT),
        t(&g, &format!("{g}#owner"), &format!("{ACL}accessTo"), ROOT),
        t(
            &g,
            &format!("{g}#owner"),
            &format!("{ACL}mode"),
            &format!("{ACL}Read"),
        ),
        t(
            &g,
            &format!("{g}#owner"),
            &format!("{ACL}mode"),
            &format!("{ACL}Write"),
        ),
        t(
            &g,
            &format!("{g}#owner"),
            &format!("{ACL}agent"),
            &format!("{POD}/profile#me"),
        ),
        t(&g, &guest, &format!("{ACL}default"), ROOT),
        t(&g, &guest, &format!("{ACL}accessTo"), ROOT),
        t(&g, &guest, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &guest, &format!("{ACL}agent"), webid),
    ];
    harness
        .pod
        .write(|w| w.put(&g, Content::Auxiliary(&grant)))
        .unwrap();
}

/// A `GET` of `path` — proof signed for `htu`, which for a percent-encoded
/// path is the undecoded form the client signs (`a_proof_is_checked_against_
/// the_undecoded_path`).
async fn a_remote_read(
    harness: &Harness,
    token: &str,
    client: &SigningKey,
    path: &str,
    htu: &str,
) -> (StatusCode, String) {
    let ath = B64.encode(Sha256::digest(token.as_bytes()));
    let proof = dpop_proof(client, "GET", htu, Some(&ath));
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, POD_HOST)
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();
    send(harness, request).await
}

#[tokio::test]
async fn a_remote_webid_reads_what_the_member_granted_it() {
    // The finish-line mechanism (spec 6, H5): a token another Solid-OIDC
    // issuer signed, for a WebID that issuer is bound to by the WebID's own
    // `solid:oidcIssuer`, reads a resource the member granted that WebID —
    // and nothing the member did not.
    let (harness, discovery_fetches, jwks_fetches) = a_foreign_issuer().await;
    grant_read_on_the_root(&harness, BOB).await;

    let client = client_key();
    let token = signed_by(
        &issuer_key(),
        ISSUER_KID,
        remote_claims(ISSUER, BOB, &jkt_of(&client)),
    );

    let (status, body) = a_remote_read(&harness, &token, &client, "/~/note", NOTE).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.contains("example.org/title"),
        "expected the note's triples, got {body}"
    );

    // Once each (H5): one discovery fetch and one key-set fetch per issuer.
    assert_eq!(discovery_fetches.load(Ordering::SeqCst), 1);
    assert_eq!(jwks_fetches.load(Ordering::SeqCst), 1);

    // Not granted, not read: the draft has its own ACL, the member's only,
    // and the closest ACL governs to the exclusion of every ancestor — so a
    // remote caller with the root's default Read still cannot read it.
    let draft_acl = format!("{DRAFT}.acl");
    let owner = format!("{draft_acl}#owner");
    let draft_grant = [
        t(&draft_acl, &owner, &format!("{ACL}accessTo"), DRAFT),
        t(
            &draft_acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Read"),
        ),
        t(
            &draft_acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Write"),
        ),
        t(
            &draft_acl,
            &owner,
            &format!("{ACL}agent"),
            &format!("{POD}/profile#me"),
        ),
    ];
    harness
        .pod
        .write(|w| w.put(&draft_acl, Content::Auxiliary(&draft_grant)))
        .unwrap();
    let (status, body) = a_remote_read(&harness, &token, &client, DRAFT_PATH, DRAFT_URL).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a remote caller reads only what its WebID was granted: {body}"
    );
}

#[tokio::test]
async fn every_remote_refusal_is_identical() {
    // The load-bearing property (spec 6, H5): a path-bearing `iss`, a
    // discovery document naming another issuer, a `kid` still unknown after
    // the one re-fetch, a wrong signature, a missing `cnf.jkt`, an `aud` that
    // isn't `solid`, an expired token, a WebID that does not dereference, one
    // that names no such issuer, and a local WebID a foreign issuer claims —
    // byte-for-byte the same 401, because the resource server is not an
    // oracle for which foreign issuers are up or which WebIDs exist.
    let issuer = issuer_key();
    let forger = SigningKey::from_slice(&[15u8; 32]).unwrap();
    let client = client_key();
    let jkt = jkt_of(&client);

    // A mismatching issuer, whose discovery document names another; a stale
    // one, whose key set does not carry the token's kid.
    let discovery = StaticDocuments::<RemoteDiscovery>::default()
        .with(
            &format!("{ISSUER}/.well-known/openid-configuration"),
            discovery_document(ISSUER, JWKS_URI),
        )
        .with(
            "https://mismatch.example/.well-known/openid-configuration",
            discovery_document("https://elsewhere.example", "https://mismatch.example/jwks"),
        )
        .with(
            "https://stale.example/.well-known/openid-configuration",
            discovery_document("https://stale.example", "https://stale.example/jwks"),
        );
    let jwks = StaticDocuments::<RemoteJwks>::default()
        .with(JWKS_URI, key_set(&issuer, ISSUER_KID))
        .with("https://stale.example/jwks", key_set(&issuer, "an-old-kid"));
    // A profile that names no such issuer; a local WebID's profile, which —
    // as every profile this instance serves — names this instance's apex
    // and no one else, so the binding refuses a foreign issuer's claim.
    let webids = StaticDocuments::<WebIdDocument>::default()
        .with(BOB, profile_naming(BOB, ISSUER))
        .with(
            "https://unbound.example/profile#me",
            profile_naming(
                "https://unbound.example/profile#me",
                "https://other-idp.example",
            ),
        )
        .with(
            &format!("{POD}/profile#me"),
            profile_naming(
                &format!("{POD}/profile#me"),
                &format!("https://{BASE_DOMAIN}"),
            ),
        );
    let harness = harness_with((Arc::new(discovery), Arc::new(jwks), Arc::new(webids))).await;
    grant_read_on_the_root(&harness, BOB).await;

    let claims = |iss: &str, webid: &str| remote_claims(iss, webid, &jkt);
    let without_binding = {
        let mut claims = remote_claims(ISSUER, BOB, &jkt);
        claims.as_object_mut().unwrap().remove("cnf");
        claims
    };
    let mut other_audience = remote_claims(ISSUER, BOB, &jkt);
    other_audience["aud"] = serde_json::json!("some-other-resource-server");
    let mut expired = remote_claims(ISSUER, BOB, &jkt);
    expired["exp"] = serde_json::json!(now() - 1);

    let tokens = [
        (
            "a path-bearing iss",
            signed_by(
                &issuer,
                ISSUER_KID,
                claims("https://idp.example/issuer", BOB),
            ),
        ),
        (
            "a discovery document naming another issuer",
            signed_by(&issuer, ISSUER_KID, claims("https://mismatch.example", BOB)),
        ),
        (
            "a kid still unknown after the one re-fetch",
            signed_by(&issuer, ISSUER_KID, claims("https://stale.example", BOB)),
        ),
        (
            "a wrong signature",
            signed_by(&forger, ISSUER_KID, claims(ISSUER, BOB)),
        ),
        (
            "a missing cnf.jkt",
            signed_by(&issuer, ISSUER_KID, without_binding),
        ),
        (
            "an aud that is not solid",
            signed_by(&issuer, ISSUER_KID, other_audience),
        ),
        ("an expired token", signed_by(&issuer, ISSUER_KID, expired)),
        (
            "a webid that does not dereference",
            signed_by(
                &issuer,
                ISSUER_KID,
                claims(ISSUER, "https://gone.example/profile#me"),
            ),
        ),
        (
            "a webid naming no such issuer",
            signed_by(
                &issuer,
                ISSUER_KID,
                claims(ISSUER, "https://unbound.example/profile#me"),
            ),
        ),
        (
            "a local webid a foreign issuer claims",
            signed_by(
                &issuer,
                ISSUER_KID,
                claims(ISSUER, &format!("{POD}/profile#me")),
            ),
        ),
    ];

    let mut answers = Vec::new();
    for (_, token) in tokens {
        let ath = B64.encode(Sha256::digest(token.as_bytes()));
        let proof = dpop_proof(&client, "GET", NOTE, Some(&ath));
        let answer = challenged(
            &harness,
            read_note(Some(&format!("DPoP {token}")), Some(&proof)),
        )
        .await;
        answers.push(answer);
    }
    for answer in &answers {
        assert_eq!(answer.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            answer.1,
            format!(r#"DPoP algs="ES256", as_uri="https://{BASE_DOMAIN}", error="invalid_token""#),
            "the challenge is the one answer every cause gets"
        );
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "every refusal is byte-for-byte the same"
    );
}

/// The key-set lookup a rotation looks like from the outside (spec 6, H5):
/// the first fetch answers with the stale set, every one after it with the
/// rotated one — so what a request could read tells a re-fetch happened, and
/// the count tells how many.
struct Rotating {
    stale: RemoteJwks,
    rotated: RemoteJwks,
    fetches: Arc<AtomicUsize>,
}

impl ClientLookup for Rotating {
    type Document = RemoteJwks;
    type Invalid = brolly_solid::oidc::tokens::InvalidJwks;

    fn fetch<'a>(
        &'a self,
        _url: &'a Url,
    ) -> brolly_server::client_metadata::Lookup<'a, Self::Document, Self::Invalid> {
        let fetches = self.fetches.fetch_add(1, Ordering::SeqCst);
        let answer = if fetches == 0 {
            self.stale.clone()
        } else {
            self.rotated.clone()
        };
        Box::pin(std::future::ready(Ok(answer)))
    }
}

#[tokio::test]
async fn a_rotation_is_answered_by_exactly_one_re_fetch() {
    // The rotation contract (spec 6, H5): the token names a `kid` the first
    // set does not carry; the one re-fetch brings the set that does, and the
    // read succeeds through it. A `kid` neither set carries is refused after
    // the same one re-fetch — not a loop, not a wait for the cache.
    let issuer = issuer_key();
    let rotated_key = SigningKey::from_slice(&[17u8; 32]).unwrap();
    let client = client_key();
    let jkt = jkt_of(&client);

    let jwks = Rotating {
        stale: key_set(&issuer, "idp-2025-9"),
        rotated: key_set(&rotated_key, ISSUER_KID),
        fetches: Arc::new(AtomicUsize::new(0)),
    };
    let jwks_fetches = jwks.fetches.clone();
    let mut discovery = Counting::<RemoteDiscovery>::default();
    discovery.answers.insert(
        format!("{ISSUER}/.well-known/openid-configuration"),
        discovery_document(ISSUER, JWKS_URI),
    );
    let discovery_fetches = discovery.fetches.clone();
    let webids = StaticDocuments::default().with(BOB, profile_naming(BOB, ISSUER));

    let harness = harness_with((Arc::new(discovery), Arc::new(jwks), Arc::new(webids))).await;
    grant_read_on_the_root(&harness, BOB).await;

    // The token is the rotated key's, naming the rotated kid.
    let token = signed_by(&rotated_key, ISSUER_KID, remote_claims(ISSUER, BOB, &jkt));
    let (status, body) = a_remote_read(&harness, &token, &client, "/~/note", NOTE).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the one re-fetch answered the rotation: {body}"
    );
    assert_eq!(
        jwks_fetches.load(Ordering::SeqCst),
        2,
        "the initial fetch and exactly one re-fetch"
    );
    assert_eq!(
        discovery_fetches.load(Ordering::SeqCst),
        1,
        "the retry re-fetches the key set only, never the discovery document"
    );

    // A kid neither set carries: the same one re-fetch, then a refusal.
    let unknown = signed_by(
        &rotated_key,
        "a-kid-nobody-has",
        remote_claims(ISSUER, BOB, &jkt),
    );
    let (status, challenge) = {
        let ath = B64.encode(Sha256::digest(unknown.as_bytes()));
        let proof = dpop_proof(&client, "GET", NOTE, Some(&ath));
        challenged(
            &harness,
            read_note(Some(&format!("DPoP {unknown}")), Some(&proof)),
        )
        .await
    };
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(challenge.contains(INVALID_TOKEN), "got: {challenge}");
    assert_eq!(
        jwks_fetches.load(Ordering::SeqCst),
        4,
        "one more fetch and one more re-fetch, then refused — not a loop"
    );
}

#[tokio::test]
async fn a_remote_proof_is_good_for_one_request() {
    // DPoP runs exactly as today on the remote path (spec 6, H5): the jti
    // spend is the remote path's too, so the identical request cannot be
    // sent twice.
    let (harness, _, _) = a_foreign_issuer().await;
    grant_read_on_the_root(&harness, BOB).await;

    let client = client_key();
    let token = signed_by(
        &issuer_key(),
        ISSUER_KID,
        remote_claims(ISSUER, BOB, &jkt_of(&client)),
    );
    let authorization = format!("DPoP {token}");
    let ath = B64.encode(Sha256::digest(token.as_bytes()));

    let proof = dpop_proof(&client, "GET", NOTE, Some(&ath));
    let (status, body) = send(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, challenge) =
        challenged(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a replayed proof must be refused, not silently downgraded"
    );
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");

    let fresh = dpop_proof(&client, "GET", NOTE, Some(&ath));
    let (status, _) = send(&harness, read_note(Some(&authorization), Some(&fresh))).await;
    assert_eq!(status, StatusCode::OK, "the token itself is still good");
}

#[tokio::test]
async fn a_remote_token_bound_to_another_key_is_refused() {
    // The cnf.jkt/proof binding on the remote path (spec 6, H5): a proof
    // from the thief's key does not satisfy a token bound to the holder's.
    let (harness, _, _) = a_foreign_issuer().await;
    grant_read_on_the_root(&harness, BOB).await;

    let holder = client_key();
    let thief = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let token = signed_by(
        &issuer_key(),
        ISSUER_KID,
        remote_claims(ISSUER, BOB, &jkt_of(&holder)),
    );

    let (status, challenge) = a_remote_read_challenged(&harness, &token, &thief).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a proof from another key must not satisfy this token's binding"
    );
    assert!(challenge.contains(INVALID_PROOF), "got: {challenge}");
}

/// [`a_remote_read`], with the `WWW-Authenticate` instead of the body.
async fn a_remote_read_challenged(
    harness: &Harness,
    token: &str,
    client: &SigningKey,
) -> (StatusCode, String) {
    let ath = B64.encode(Sha256::digest(token.as_bytes()));
    let proof = dpop_proof(client, "GET", NOTE, Some(&ath));
    challenged(
        harness,
        read_note(Some(&format!("DPoP {token}")), Some(&proof)),
    )
    .await
}
