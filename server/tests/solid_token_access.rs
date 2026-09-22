//! A Solid app reaching the pod with the token it was issued.
//!
//! This is the join between the provider and the store: the provider mints a
//! DPoP-bound token, and the pod has to turn that token back into the `Subject`
//! WAC evaluates. Until it did, `subject_for` mapped every Bearer and DPoP
//! credential to anonymous and an app with a perfectly good token got a 404.
//!
//! The negative cases matter more than the positive one. A token is only worth
//! its binding if presenting it without the key fails.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_solid::storage;
use brolly_store::StoreManager;
use brolly_store::resources::Pod;
use http_body_util::BodyExt;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const BASE_DOMAIN: &str = "brolly.test";
const POD_HOST: &str = "alice.brolly.test";
const POD: &str = "https://alice.brolly.test";
const ROOT: &str = "https://alice.brolly.test/~/";
const NOTE: &str = "https://alice.brolly.test/~/note";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const REDIRECT: &str = "https://app.example/cb";

/// Setup straight into the store, bypassing `Pod::write` (`test-fixtures`),
/// so it doesn't depend on the code under test.
fn seed(target: &Pod, quads: &[Quad]) {
    let store = target.raw_store();
    for quad in quads {
        store.insert(quad).unwrap();
    }
}

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
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 4, 60).unwrap());

    let user = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let pod = stores.pod(user.id).unwrap();
    pod.write(|w| storage::init_storage_root(w, ROOT)).unwrap();
    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    seed(
        &pod,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}agent"), &format!("{POD}/profile#me")),
            // Something to read.
            t(
                NOTE,
                NOTE,
                "https://example.org/title",
                "https://example.org/a",
            ),
        ],
    );

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
        },
        "server/static",
    );

    Harness {
        _db: db,
        _dir: dir,
        router,
    }
}

async fn send(harness: &Harness, request: Request<Body>) -> (StatusCode, String) {
    let response = harness.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, body)
}

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

    let (status, _) = send(&harness, read_note(Some(&format!("DPoP {token}")), None)).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unproven token must not read the pod"
    );
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
    let (status, _) = send(
        &harness,
        read_note(Some(&format!("DPoP {token}")), Some(&proof)),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a proof from another key must not satisfy this token's binding"
    );
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
    let (status, _) = send(
        &harness,
        read_note(Some(&format!("DPoP {token}")), Some(&elsewhere)),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_proof_without_the_token_hash_is_not_accepted() {
    // `ath` is what stops a proof minted for the token endpoint being replayed
    // against a resource.
    let harness = harness().await;
    let key = client_key();
    let token = access_token(&harness, &key).await;

    let no_ath = dpop_proof(&key, "GET", NOTE, None);
    let (status, _) = send(
        &harness,
        read_note(Some(&format!("DPoP {token}")), Some(&no_ath)),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
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
    let (status, _) = send(
        &harness,
        read_note(Some(&format!("Bearer {token}")), Some(&proof)),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
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
    let (status, _) = send(
        &harness,
        read_note(Some(&format!("DPoP {forged}")), Some(&proof)),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_anonymous_request_still_gets_the_default_deny() {
    let harness = harness().await;
    let (status, _) = send(&harness, read_note(None, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

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

    let (status, _) = send(&harness, read_note(Some(&authorization), Some(&proof))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a replayed proof must leave the caller anonymous"
    );

    let fresh = dpop_proof(&key, "GET", NOTE, Some(&ath));
    let (status, _) = send(&harness, read_note(Some(&authorization), Some(&fresh))).await;
    assert_eq!(status, StatusCode::OK, "the token itself is still good");
}
