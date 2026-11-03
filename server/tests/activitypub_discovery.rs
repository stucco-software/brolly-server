//! Actor documents, WebFinger and NodeInfo — how the fediverse finds us.
//!
//! Everything downstream depends on these being right. An actor document with
//! the wrong `inbox` sends private delivery to the shared inbox; a WebFinger
//! that answers for a host we do not serve lets someone else's handle resolve
//! to our actor. Both fail quietly and both are load-bearing, so they are
//! asserted rather than eyeballed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, app};
use brolly_store::StoreManager;
use http_body_util::BodyExt;
use tower::ServiceExt;

const BASE: &str = "brolly.test";
const ALICE_HOST: &str = "alice.brolly.test";
const ALICE_ROOT: &str = "https://alice.brolly.test/~/";

/// What a fediverse client actually sends.
const AS2: &str = "application/activity+json";

struct Harness {
    db: brolly_test_support::TestDb,
    _dir: tempfile::TempDir,
    router: axum::Router,
    stores: std::sync::Arc<StoreManager>,
    alice: uuid::Uuid,
}

async fn harness() -> Harness {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = std::sync::Arc::new(StoreManager::open(dir.path(), 4, 60).unwrap());

    let alice = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let pod = stores.pod(alice.id).unwrap();
    pod.write(|w| w.create_root(ALICE_ROOT)).unwrap();

    let router = app(
        AppState {
            pool: db.pool.clone(),
            base_domain: BASE.into(),
            instance_name: BASE.to_string(),
            instance_description: "A private community server.".to_string(),
            source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
            terms_url: None,
            privacy_url: None,
            theme_css: false,
            public_registration: false,
            limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
            www_redirect: None,
            max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
            pod_quota_bytes: brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
            stores: std::sync::Arc::clone(&stores),
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
        stores,
        alice: alice.id,
    }
}

struct Reply {
    status: StatusCode,
    body: String,
    content_type: Option<String>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("expected JSON, got {}: {}", self.body, e))
    }
}

async fn get(harness: &Harness, host: &str, path: &str, accept: Option<&str>) -> Reply {
    let mut request = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, host);
    if let Some(accept) = accept {
        request = request.header(header::ACCEPT, accept);
    }
    let response = harness
        .router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    Reply {
        status,
        body,
        content_type,
    }
}

// --- member actor -----------------------------------------------------------

#[tokio::test]
async fn a_member_has_an_actor_document() {
    let h = harness().await;
    let reply = get(&h, ALICE_HOST, "/actor", Some(AS2)).await;

    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    let actor = reply.json();

    assert_eq!(actor["type"], "Person");
    assert_eq!(actor["id"], "https://alice.brolly.test/actor");
    assert_eq!(actor["preferredUsername"], "alice");

    // Every collection must be on alice's own host. An `inbox` on the apex
    // would route her private delivery to the shared inbox.
    assert_eq!(actor["inbox"], "https://alice.brolly.test/inbox");
    assert_eq!(actor["outbox"], "https://alice.brolly.test/outbox");
    assert_eq!(actor["followers"], "https://alice.brolly.test/followers");
    assert_eq!(actor["following"], "https://alice.brolly.test/following");
}

#[tokio::test]
async fn the_actor_document_carries_a_verifiable_public_key() {
    // Without this a remote instance cannot verify anything we sign, so every
    // delivery we make is rejected.
    let h = harness().await;
    let actor = get(&h, ALICE_HOST, "/actor", Some(AS2)).await.json();

    let key = &actor["publicKey"];
    assert_eq!(
        key["id"], "https://alice.brolly.test/actor#main-key",
        "the key id is what a verifier dereferences from the Signature header"
    );
    assert_eq!(key["owner"], "https://alice.brolly.test/actor");
    assert!(
        key["publicKeyPem"]
            .as_str()
            .is_some_and(|p| p.starts_with("-----BEGIN PUBLIC KEY-----")),
        "expected PEM, got {:?}",
        key["publicKeyPem"]
    );
}

#[tokio::test]
async fn the_actor_document_is_served_as_activity_json() {
    // A fediverse client that gets `application/json` back will often refuse
    // to treat the document as an actor at all.
    let h = harness().await;
    let reply = get(&h, ALICE_HOST, "/actor", Some(AS2)).await;
    assert_eq!(reply.content_type.as_deref(), Some(AS2));

    // The AS2 context is what makes the bare property names mean anything.
    let actor = reply.json();
    let context = actor["@context"].to_string();
    assert!(
        context.contains("https://www.w3.org/ns/activitystreams"),
        "missing AS2 context: {context}"
    );
    assert!(
        context.contains("w3id.org/security"),
        "publicKey comes from the security vocabulary: {context}"
    );
}

#[tokio::test]
async fn the_actor_name_comes_from_the_pod() {
    // D8: profile triples are asserted onto the WebID and every protocol reads
    // that one node. The actor document is a projection, not a second copy.
    let h = harness().await;
    let pod = h.stores.pod(h.alice).unwrap();
    pod.write(|w| {
        brolly_solid::profile::write(
            w,
            "https://alice.brolly.test/profile#me",
            "https://alice.brolly.test/profile",
            &brolly_solid::profile::Profile {
                display_name: "Alice Example".into(),
                bio: "Testing in production".into(),
                ..brolly_solid::profile::Profile::blank()
            },
        )
    })
    .unwrap();

    let actor = get(&h, ALICE_HOST, "/actor", Some(AS2)).await.json();
    assert_eq!(actor["name"], "Alice Example");
    assert_eq!(actor["summary"], "Testing in production");
}

#[tokio::test]
async fn the_actor_icon_comes_from_the_pod() {
    // H6 (spec 4): the depiction triple on the WebID is the one avatar
    // mechanism, and the actor document is one of the surfaces that renders
    // it — the same projection as the name, one field over. The IRI is
    // emitted with no access check: a pointer, not bytes, and public read on
    // the target is the member's `.acl` call, not the actor's.
    let h = harness().await;
    let bare = get(&h, ALICE_HOST, "/actor", Some(AS2)).await.json();
    assert!(bare.get("icon").is_none(), "no triple, no icon");

    let pod = h.stores.pod(h.alice).unwrap();
    let target = "https://alice.brolly.test/~/media/01J5ZP7WQC5V1TQ3M8BRFNV8HA";
    pod.write(|w| {
        w.insert(&[oxigraph::model::Quad::new(
            oxigraph::model::NamedOrBlankNode::NamedNode(
                oxigraph::model::NamedNode::new_unchecked("https://alice.brolly.test/profile#me"),
            ),
            oxigraph::model::NamedNode::new_unchecked(brolly_domain::vocab::FOAF_DEPICTION),
            oxigraph::model::Term::NamedNode(oxigraph::model::NamedNode::new_unchecked(target)),
            oxigraph::model::GraphName::NamedNode(oxigraph::model::NamedNode::new_unchecked(
                "https://alice.brolly.test/profile",
            )),
        )])
    })
    .unwrap();

    let actor = get(&h, ALICE_HOST, "/actor", Some(AS2)).await.json();
    assert_eq!(actor["icon"]["type"], "Image");
    assert_eq!(actor["icon"]["url"], target);
}

#[tokio::test]
async fn an_unknown_member_has_no_actor() {
    let h = harness().await;
    let reply = get(&h, "nobody.brolly.test", "/actor", Some(AS2)).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

// --- instance actor ---------------------------------------------------------

#[tokio::test]
async fn the_instance_has_an_actor_of_its_own_on_the_apex() {
    // D4. It receives the same deliveries a member does, which is what lets the
    // server index be populated by push instead of by crawling.
    let h = harness().await;
    let reply = get(&h, BASE, "/actor", Some(AS2)).await;

    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    let actor = reply.json();

    assert_eq!(
        actor["type"], "Application",
        "an instance actor is a service, not a person — clients render it differently"
    );
    assert_eq!(actor["id"], "https://brolly.test/actor");
    assert_eq!(actor["inbox"], "https://brolly.test/inbox");
    assert!(actor["publicKey"]["publicKeyPem"].as_str().is_some());
}

#[tokio::test]
async fn the_instance_actor_signs_with_a_different_key_from_a_member() {
    let h = harness().await;
    let instance = get(&h, BASE, "/actor", Some(AS2)).await.json();
    let member = get(&h, ALICE_HOST, "/actor", Some(AS2)).await.json();

    assert_ne!(
        instance["publicKey"]["publicKeyPem"], member["publicKey"]["publicKeyPem"],
        "the instance must not sign with a member's key"
    );
}

// --- WebFinger --------------------------------------------------------------

#[tokio::test]
async fn webfinger_resolves_a_handle_to_an_actor() {
    // ADR 0005 R9. This is the lookup that happens before any user context
    // exists, and it is how every remote instance first finds a member.
    let h = harness().await;
    let reply = get(
        &h,
        BASE,
        "/.well-known/webfinger?resource=acct:alice@brolly.test",
        None,
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK, "body: {}", reply.body);
    assert_eq!(
        reply.content_type.as_deref(),
        Some("application/jrd+json"),
        "WebFinger has its own media type and Mastodon checks it"
    );

    let jrd = reply.json();
    assert_eq!(jrd["subject"], "acct:alice@brolly.test");

    let self_link = jrd["links"]
        .as_array()
        .expect("links")
        .iter()
        .find(|l| l["rel"] == "self")
        .expect("a self link");
    assert_eq!(self_link["type"], AS2);
    assert_eq!(self_link["href"], "https://alice.brolly.test/actor");
}

#[tokio::test]
async fn webfinger_accepts_the_handle_with_and_without_a_leading_at() {
    let h = harness().await;
    // These are post-decode forms — what the handler actually receives. A
    // client that percent-encodes the `@` sends `%40`, and query decoding has
    // already turned it back into `@` by the time we see it.
    for resource in [
        "acct:alice@brolly.test",
        "@alice@brolly.test",
        "acct:@alice@brolly.test",
        "alice@brolly.test",
    ] {
        let reply = get(
            &h,
            BASE,
            &format!(
                "/.well-known/webfinger?resource={}",
                form_urlencoded::byte_serialize(resource.as_bytes()).collect::<String>()
            ),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{resource} was refused");
    }
}

#[tokio::test]
async fn webfinger_refuses_an_account_on_a_host_we_do_not_serve() {
    // Answering for `alice@mastodon.social` would let our instance vouch for a
    // handle that is not ours — a remote resolver that trusted it would send
    // someone else's delivery here.
    let h = harness().await;
    let reply = get(
        &h,
        BASE,
        "/.well-known/webfinger?resource=acct:alice@mastodon.social",
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn webfinger_refuses_an_unknown_member() {
    let h = harness().await;
    let reply = get(
        &h,
        BASE,
        "/.well-known/webfinger?resource=acct:nobody@brolly.test",
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn webfinger_needs_a_resource() {
    let h = harness().await;
    let reply = get(&h, BASE, "/.well-known/webfinger", None).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_disabled_member_does_not_resolve() {
    let h = harness().await;
    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&h.db.pool)
        .await
        .unwrap();

    assert_eq!(
        get(
            &h,
            BASE,
            "/.well-known/webfinger?resource=acct:alice@brolly.test",
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&h, ALICE_HOST, "/actor", Some(AS2)).await.status,
        StatusCode::NOT_FOUND,
        "a suspended account must not keep federating"
    );
}

// --- NodeInfo ---------------------------------------------------------------

#[tokio::test]
async fn nodeinfo_is_discoverable_and_describes_the_software() {
    let h = harness().await;

    let discovery = get(&h, BASE, "/.well-known/nodeinfo", None).await;
    assert_eq!(discovery.status, StatusCode::OK);
    let link = discovery.json()["links"]
        .as_array()
        .expect("links")
        .iter()
        .find(|l| {
            l["rel"]
                .as_str()
                .is_some_and(|r| r.ends_with("/schema/2.1"))
        })
        .expect("a 2.1 link")
        .clone();

    let href = link["href"].as_str().expect("href").to_string();
    let path = href
        .strip_prefix("https://brolly.test")
        .unwrap_or_else(|| panic!("{href} is not on this instance"));

    let document = get(&h, BASE, path, None).await;
    assert_eq!(
        document.status,
        StatusCode::OK,
        "the advertised NodeInfo document must exist"
    );
    let node = document.json();
    assert_eq!(node["version"], "2.1");
    assert_eq!(node["software"]["name"], "brolly");
    assert_eq!(
        node["openRegistrations"], false,
        "registration is invite-only"
    );
}

#[tokio::test]
async fn nodeinfo_counts_local_members() {
    let h = harness().await;
    let node = get(&h, BASE, "/nodeinfo/2.1", None).await.json();
    assert_eq!(node["usage"]["users"]["total"], 1);
}

// --- host scoping -----------------------------------------------------------

#[tokio::test]
async fn discovery_endpoints_are_apex_only() {
    // WebFinger and NodeInfo describe the instance, not a member. Serving them
    // on a subdomain would offer two answers to the same question.
    let h = harness().await;
    for path in [
        "/.well-known/webfinger?resource=acct:alice@brolly.test",
        "/.well-known/nodeinfo",
        "/nodeinfo/2.1",
    ] {
        assert_eq!(
            get(&h, ALICE_HOST, path, None).await.status,
            StatusCode::NOT_FOUND,
            "{path} answered on a member subdomain"
        );
    }
}
