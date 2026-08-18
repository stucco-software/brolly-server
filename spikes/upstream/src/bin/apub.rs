//! Spike probe — ActivityPub via `activitypub_federation`.
//!
//! Open decision O1, ActivityPub half. ADR 0003 settled the licence; this proves
//! the framework actually drives **our** domain types rather than requiring us
//! to adopt its data model — the constraint the old research called AP2 and
//! marked PASS without exercising.
//!
//! Run: `cargo run -p spike-upstream --bin apub`

use activitypub_federation::config::{Data, FederationConfig};
use activitypub_federation::http_signatures::generate_actor_keypair;
use activitypub_federation::protocol::context::WithContext;
use activitypub_federation::traits::{Actor, Object};
use url::Url;

/// Stands in for whatever `brolly-server` passes around. The framework is
/// generic over it, which is the property under test.
#[derive(Clone)]
struct OurAppState {
    instance_domain: String,
}

/// Our own actor type — deliberately not the framework's.
#[derive(Debug, Clone)]
struct OurActor {
    id: Url,
    inbox: Url,
    public_key_pem: String,
    private_key_pem: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersonJson {
    #[serde(rename = "type")]
    kind: String,
    id: Url,
    inbox: Url,
    #[serde(rename = "publicKey")]
    public_key: activitypub_federation::protocol::public_key::PublicKey,
}

#[async_trait::async_trait]
impl Object for OurActor {
    type DataType = OurAppState;
    type Kind = PersonJson;
    type Error = anyhow::Error;

    fn id(&self) -> &Url {
        &self.id
    }

    async fn read_from_id(
        _object_id: Url,
        _data: &Data<Self::DataType>,
    ) -> Result<Option<Self>, Self::Error> {
        Ok(None)
    }

    async fn into_json(self, _data: &Data<Self::DataType>) -> Result<Self::Kind, Self::Error> {
        Ok(PersonJson {
            kind: "Person".to_string(),
            id: self.id.clone(),
            inbox: self.inbox.clone(),
            public_key: self.public_key(),
        })
    }

    async fn verify(
        _json: &Self::Kind,
        _expected_domain: &Url,
        _data: &Data<Self::DataType>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn from_json(
        json: Self::Kind,
        _data: &Data<Self::DataType>,
    ) -> Result<Self, Self::Error> {
        Ok(OurActor {
            id: json.id,
            inbox: json.inbox,
            public_key_pem: json.public_key.public_key_pem,
            private_key_pem: None,
        })
    }
}

#[async_trait::async_trait]
impl Actor for OurActor {
    fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }
    fn private_key_pem(&self) -> Option<String> {
        self.private_key_pem.clone()
    }
    fn inbox(&self) -> Url {
        self.inbox.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut check = |name: &str, ok: bool, detail: String| {
        if ok {
            pass += 1;
            println!("  PASS  {name:<38} {detail}");
        } else {
            fail += 1;
            println!("  FAIL  {name:<38} {detail}");
        }
    };

    println!("\nactivitypub_federation probe (open decision O1, ADR 0003)\n");

    // --- keypair via the public API --------------------------------------
    let keypair = generate_actor_keypair()?;
    check(
        "actor keypair generated",
        keypair.public_key.contains("BEGIN PUBLIC KEY")
            && keypair.private_key.contains("PRIVATE KEY"),
        format!("{} byte public PEM", keypair.public_key.len()),
    );

    // --- BYO application state -------------------------------------------
    let config = FederationConfig::builder()
        .domain("brolly.test")
        .app_data(OurAppState {
            instance_domain: "brolly.test".to_string(),
        })
        .debug(true)
        .build()
        .await?;
    check(
        "FederationConfig carries our own state",
        true,
        "app_data = OurAppState".to_string(),
    );

    // --- BYO actor type ---------------------------------------------------
    let actor = OurActor {
        id: Url::parse("https://alice.brolly.test/actor")?,
        inbox: Url::parse("https://alice.brolly.test/inbox")?,
        public_key_pem: keypair.public_key.clone(),
        private_key_pem: Some(keypair.private_key.clone()),
    };

    let data: Data<OurAppState> = config.to_request_data();
    check(
        "request data reaches our state",
        data.instance_domain == "brolly.test",
        data.instance_domain.clone(),
    );

    let json = actor.clone().into_json(&data).await?;
    check(
        "our actor serializes to AS2",
        json.kind == "Person" && json.public_key.owner == actor.id,
        format!("owner {}", json.public_key.owner),
    );

    let with_ctx = WithContext::new_default(json.clone());
    let wire = serde_json::to_value(&with_ctx)?;
    check(
        "AS2 @context is attached",
        wire.get("@context").is_some(),
        match &wire["@context"] {
            serde_json::Value::Array(a) => format!("{} entries, first = {}", a.len(), a[0]),
            other => other.to_string(),
        },
    );

    // --- round-trip back into our type ------------------------------------
    let restored = OurActor::from_json(json, &data).await?;
    check(
        "AS2 round-trips back to our type",
        restored.id == actor.id && restored.public_key_pem == actor.public_key_pem,
        restored.id.to_string(),
    );

    check(
        "public_key() derives from our PEM",
        actor.public_key().public_key_pem == keypair.public_key,
        "no framework-owned key storage".to_string(),
    );

    println!("\n  {pass} passed, {fail} failed\n");
    if fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}
