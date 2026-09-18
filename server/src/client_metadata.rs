//! Looking up ATProto OAuth client metadata.
//!
//! The rules live in [`brolly_atproto::client_metadata`]. This module decides
//! where the metadata comes from: the network in production (`Fetcher`), a
//! fixed map in integration tests ([`StaticClients`]).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use brolly_atproto::client_metadata::{
    ClientError, ClientId, ClientMetadata, loopback_metadata, parse_client_id, validate,
};
use url::Url;

/// Why a client's metadata couldn't be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// The document was retrieved and broke a rule. Safe to describe.
    Invalid(ClientError),
    /// DNS refusal, connection failure, timeout, TLS failure, a non-200 status
    /// or an oversized body. All of them get one description, so PAR can't be
    /// used to map which internal hosts exist or answer (S4).
    Unreachable,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupError::Invalid(e) => e.fmt(f),
            LookupError::Unreachable => f.write_str("client metadata could not be retrieved"),
        }
    }
}

impl std::error::Error for LookupError {}

/// What [`ClientLookup::fetch`] returns: a boxed future, because an `async fn`
/// in a trait can't be called through `dyn`.
pub type Lookup<'a> =
    Pin<Box<dyn Future<Output = Result<ClientMetadata, LookupError>> + Send + 'a>>;

/// Where client metadata comes from.
///
/// `Send + Sync` so it can live in axum state as `Arc<dyn ClientLookup>`.
pub trait ClientLookup: Send + Sync {
    /// Retrieve and validate the metadata document at `url`.
    ///
    /// Only ever called for discoverable clients: PAR goes through
    /// [`lookup_client`], which answers loopback clients itself.
    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a>;
}

/// The metadata for a parsed `client_id`.
///
/// A free function rather than a default method on [`ClientLookup`], so no
/// implementation can override the loopback branch and send a `localhost`
/// client to the network.
pub async fn lookup_client(
    clients: &dyn ClientLookup,
    id: &ClientId,
) -> Result<ClientMetadata, LookupError> {
    match id {
        ClientId::Loopback(_) => Ok(loopback_metadata(id)),
        ClientId::Discoverable(url) => clients.fetch(url).await,
    }
}

/// A fixed set of clients, for integration tests.
///
/// It skips fetching, not validation: [`StaticClients::with`] runs the
/// document through `validate`, so a test can't register a client production
/// would refuse (S8). An id that isn't registered is `Unreachable`, as a 404
/// would be.
#[derive(Debug, Clone, Default)]
pub struct StaticClients {
    clients: HashMap<String, ClientMetadata>,
}

impl StaticClients {
    /// Register `client_id`, serving `document` as `application/json`.
    pub fn with(mut self, client_id: &str, document: &str) -> Result<Self, ClientError> {
        let id = parse_client_id(client_id)?;
        let metadata = validate(&id, "application/json", document.as_bytes())?;
        self.clients
            .insert(metadata.client_id().to_owned(), metadata);
        Ok(self)
    }
}

impl ClientLookup for StaticClients {
    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a> {
        let found = self
            .clients
            .get(url.as_str())
            .cloned()
            .ok_or(LookupError::Unreachable);
        Box::pin(std::future::ready(found))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const APP: &str = "https://app.example/client-metadata.json";

    fn document(client_id: &str) -> String {
        serde_json::json!({
            "client_id": client_id,
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "dpop_bound_access_tokens": true,
        })
        .to_string()
    }

    /// Counts calls to `fetch`. Here rather than on `StaticClients`, so the
    /// production types carry no counters.
    struct Counting {
        inner: StaticClients,
        lookups: Arc<AtomicUsize>,
    }

    impl ClientLookup for Counting {
        fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.inner.fetch(url)
        }
    }

    #[test]
    fn static_clients_hold_only_what_validate_accepts() {
        let no_dpop = serde_json::json!({
            "client_id": APP,
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        })
        .to_string();
        assert!(matches!(
            StaticClients::default().with(APP, &no_dpop),
            Err(ClientError::InvalidMetadata(_))
        ));
        assert!(matches!(
            StaticClients::default().with("http://localhost", &document("http://localhost")),
            Err(ClientError::InvalidClientId(_))
        ));
        assert!(StaticClients::default().with(APP, &document(APP)).is_ok());
    }

    #[tokio::test]
    async fn a_registered_client_is_found_and_an_unknown_one_is_unreachable() {
        let clients = StaticClients::default().with(APP, &document(APP)).unwrap();

        let found = clients.fetch(&Url::parse(APP).unwrap()).await.unwrap();
        assert_eq!(found.client_id(), APP);

        let unknown = Url::parse("https://unknown.example/client-metadata.json").unwrap();
        assert_eq!(clients.fetch(&unknown).await, Err(LookupError::Unreachable));
    }

    #[tokio::test]
    async fn a_loopback_client_never_reaches_fetch() {
        let lookups = Arc::new(AtomicUsize::new(0));
        let clients = Counting {
            inner: StaticClients::default().with(APP, &document(APP)).unwrap(),
            lookups: lookups.clone(),
        };

        let loopback = parse_client_id("http://localhost").unwrap();
        let meta = lookup_client(&clients, &loopback).await.unwrap();
        assert_eq!(meta.scope(), "atproto");
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            0,
            "loopback ids never hit the network"
        );

        let discoverable = parse_client_id(APP).unwrap();
        lookup_client(&clients, &discoverable).await.unwrap();
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn every_unreachable_client_is_described_the_same_way() {
        assert_eq!(
            LookupError::Unreachable.to_string(),
            "client metadata could not be retrieved"
        );
    }
}
