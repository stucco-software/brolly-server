//! Inviting a relay to crawl (stage 3, E): `com.atproto.sync.requestCrawl`,
//! sent once per boot to a configured relay.
//!
//! A relay learns a PDS exists by being told. The request carries only the
//! instance's hostname and no credentials: the relay authorises the crawl by
//! the PDS it then discovers there (`describeServer`, `listRepos`, the
//! firehose), so a service token from a DID it has never seen would prove
//! nothing.
//!
//! A relay that is briefly down at boot must not cost the instance its place
//! in the crawl queue until someone restarts it, so a failure retries with
//! doubling backoff, capped at once a minute, for as long as the process
//! runs. The first success ends the loop; a new boot starts it again.
//!
//! Configuration-gated and off by default (`BROLLY_RELAY_URL`): unset,
//! nothing is sent — the wire is unchanged for every existing deployment, and
//! only a deployment on its real domain should announce itself.

use std::time::Duration;

use serde_json::json;
use url::Url;

/// How long one attempt may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The backoff: doubling from `first`, never longer than `cap`.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub first: Duration,
    pub cap: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            first: Duration::from_secs(1),
            cap: Duration::from_secs(60),
        }
    }
}

/// A configured relay and the hardened client that reaches it.
pub struct Relay {
    origin: Url,
    http: reqwest::Client,
}

impl Relay {
    /// Production: an `https` origin with no path, on public addresses only.
    pub fn new(origin: &str) -> Result<Self, String> {
        Self::build(origin, false)
    }

    /// For tests that stand a relay up on `http://127.0.0.1:PORT`.
    pub fn for_tests(origin: &str) -> Result<Self, String> {
        Self::build(origin, true)
    }

    fn build(origin: &str, local: bool) -> Result<Self, String> {
        let origin = Url::parse(origin).map_err(|e| format!("BROLLY_RELAY_URL: {e}"))?;
        if !(origin.scheme() == "https" || local && origin.scheme() == "http") {
            return Err("BROLLY_RELAY_URL must be https".into());
        }
        if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
            return Err("BROLLY_RELAY_URL must be an origin, with no path".into());
        }
        let http = crate::client_metadata::hardened_http(local, local, TIMEOUT)
            .map_err(|e| format!("building the relay client: {e}"))?;
        Ok(Self { origin, http })
    }

    /// From the environment; `None` when `BROLLY_RELAY_URL` is unset.
    pub fn from_env() -> Result<Option<Self>, String> {
        match std::env::var("BROLLY_RELAY_URL") {
            Ok(url) if !url.is_empty() => Self::new(&url).map(Some),
            _ => Ok(None),
        }
    }

    /// One `requestCrawl`. `Err` describes why it did not land.
    pub async fn request_crawl(&self, hostname: &str) -> Result<(), String> {
        let url = self
            .origin
            .join("/xrpc/com.atproto.sync.requestCrawl")
            .map_err(|e| e.to_string())?;
        let response = self
            .http
            .post(url)
            .json(&json!({ "hostname": hostname }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("the relay answered {}", response.status()))
        }
    }

    /// Ask until the relay accepts, backing off between failures. Returns how
    /// many attempts it took; spawned once at boot, it never returns otherwise.
    pub async fn announce(&self, hostname: &str, backoff: Backoff) -> u32 {
        let mut wait = backoff.first;
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.request_crawl(hostname).await {
                Ok(()) => {
                    tracing::info!(relay = %self.origin, attempts, "relay invited to crawl");
                    return attempts;
                }
                Err(e) => {
                    tracing::warn!(relay = %self.origin, error = %e, retry_in = ?wait, "requestCrawl failed");
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(backoff.cap);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_an_https_origin() {
        crate::tls::install_crypto_provider();
        assert!(Relay::new("https://bsky.network").is_ok());
        for url in ["http://bsky.network", "https://bsky.network/xrpc", "nope"] {
            assert!(Relay::new(url).is_err(), "{url}");
        }
    }
}
