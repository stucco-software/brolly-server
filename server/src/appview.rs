//! The AppView proxy (stage 3, D): `app.bsky.*` methods this server does not
//! implement, forwarded to a configured AppView on the member's behalf.
//!
//! A PDS is not an AppView: timelines, threads, profiles-with-counts and
//! search are the network's aggregate view, and the reference world answers
//! them at a separate service the PDS delegates to. This is that delegation:
//!
//! * **What forwards** is an unmounted method in the AppView's namespace,
//!   `app.bsky.*`, and nothing else. `com.atproto.*` is ours or nobody's — a
//!   PDS that forwarded its own namespace would split its identity — and other
//!   namespaces are not the AppView's to answer.
//! * **Protected methods never forward**: account state the PDS owns. Both are
//!   mounted locally today; the list is the guard that keeps them from ever
//!   leaking upstream if a route were lost.
//! * **Credentials never forward.** The client's `Authorization` and `DPoP`
//!   are credentials for *this* server; replayed at the AppView they would be
//!   a token leaked to a third party. In their place goes a service-auth token
//!   the member's key signs, `aud` the AppView, `lxm` the method — the
//!   AppView's own delegation model. Anonymous callers forward anonymously:
//!   AppView reads are public.
//! * **The answer is the AppView's.** Status, type and body stream back as
//!   they came; a proxy that rewrote them would be lying about whose answer it
//!   is. An AppView that cannot be reached is the reference's
//!   `UpstreamFailure`, a 502 — "configured but down" is not "not
//!   implemented", and the difference is whether a client retries.
//!
//! Configuration-gated and off by default (`BROLLY_APPVIEW_URL` and
//! `BROLLY_APPVIEW_DID`, both or neither): unset, every unimplemented method
//! answers 501 exactly as before.

use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use url::Url;

/// `app.bsky.*` methods that are the PDS's own and never forwarded: the
/// reference PDS answers preferences from its own storage, and so do we
/// (stage 3, C).
pub const PROTECTED: &[&str] = &[
    "app.bsky.actor.getPreferences",
    "app.bsky.actor.putPreferences",
];

/// A feed page can be large and an AppView slow under load; this bounds the
/// whole exchange, not the first byte.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Request headers a client sends that the AppView reads. Everything else —
/// credentials, cookies, hop-by-hop headers, the client's own `atproto-proxy`
/// — stays here.
const FORWARDED_REQUEST: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "content-encoding",
    "atproto-accept-labelers",
    "x-bsky-topics",
];

/// Response headers the AppView sets that the client reads. A `set-cookie`
/// from a third party has no business on our origin.
const FORWARDED_RESPONSE: &[&str] = &[
    "content-type",
    "content-language",
    "content-encoding",
    "atproto-content-labelers",
    "atproto-repo-rev",
];

/// Is this method one the proxy forwards?
pub fn forwardable(nsid: &str) -> bool {
    nsid.starts_with("app.bsky.") && !PROTECTED.contains(&nsid)
}

/// The configured AppView: where it is, who it is, and the hardened client
/// that reaches it.
pub struct AppView {
    origin: Url,
    did: String,
    http: reqwest::Client,
}

impl AppView {
    /// Production: an `https` origin with no path, on public addresses only.
    pub fn new(origin: &str, did: &str) -> Result<Self, String> {
        Self::build(origin, did, false)
    }

    /// For tests that stand an AppView up on `http://127.0.0.1:PORT`. The one
    /// place loopback and plain HTTP are allowed, and only by a caller that
    /// asks — a deployment configures `new`.
    pub fn for_tests(origin: &str, did: &str) -> Result<Self, String> {
        Self::build(origin, did, true)
    }

    fn build(origin: &str, did: &str, local: bool) -> Result<Self, String> {
        let origin = Url::parse(origin).map_err(|e| format!("BROLLY_APPVIEW_URL: {e}"))?;
        if !(origin.scheme() == "https" || local && origin.scheme() == "http") {
            return Err("BROLLY_APPVIEW_URL must be https".into());
        }
        if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
            return Err("BROLLY_APPVIEW_URL must be an origin, with no path".into());
        }
        let well_formed = (did.starts_with("did:plc:") || did.starts_with("did:web:"))
            && !did.contains('#')
            && did.len() > 8;
        if !well_formed {
            return Err("BROLLY_APPVIEW_DID must be a did:plc or did:web, with no fragment".into());
        }
        let http = crate::client_metadata::hardened_http(local, local, TIMEOUT)
            .map_err(|e| format!("building the AppView client: {e}"))?;
        Ok(Self {
            origin,
            did: did.to_owned(),
            http,
        })
    }

    /// From the environment: both variables or neither. One without the other
    /// is a misconfiguration, refused at boot rather than half-applied.
    pub fn from_env() -> Result<Option<Self>, String> {
        let url = std::env::var("BROLLY_APPVIEW_URL")
            .ok()
            .filter(|v| !v.is_empty());
        let did = std::env::var("BROLLY_APPVIEW_DID")
            .ok()
            .filter(|v| !v.is_empty());
        match (url, did) {
            (None, None) => Ok(None),
            (Some(url), Some(did)) => Self::new(&url, &did).map(Some),
            _ => Err(
                "BROLLY_APPVIEW_URL and BROLLY_APPVIEW_DID are set together or not at all".into(),
            ),
        }
    }

    /// The AppView's DID: the `aud` of every service token minted for it.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Forward one request and stream the answer back.
    ///
    /// `path_and_query` is the request's own (`/xrpc/{nsid}?…`), joined onto
    /// the AppView's origin unchanged; `service_token` is the member's
    /// delegation, `None` for an anonymous caller.
    pub async fn forward(
        &self,
        method: Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Body,
        service_token: Option<String>,
    ) -> Response {
        let Ok(url) = self.origin.join(path_and_query) else {
            return upstream_failure();
        };
        let mut request = self
            .http
            .request(method, url)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()));
        for name in FORWARDED_REQUEST {
            for value in headers.get_all(*name) {
                request = request.header(*name, value);
            }
        }
        if let Some(token) = service_token {
            request = request.bearer_auth(token);
        }

        let upstream = match request.send().await {
            Ok(upstream) => upstream,
            Err(e) => {
                tracing::warn!(error = %e, appview = %self.origin, "the AppView is unreachable");
                return upstream_failure();
            }
        };

        let mut response = Response::builder().status(upstream.status().as_u16());
        for name in FORWARDED_RESPONSE {
            for value in upstream.headers().get_all(*name) {
                response = response.header(HeaderName::from_static(name), value.as_bytes());
            }
        }
        response
            // The answer is per caller whenever a token went up.
            .header(header::VARY, "Authorization")
            .body(Body::from_stream(upstream.bytes_stream()))
            .unwrap_or_else(|_| upstream_failure())
    }
}

/// The reference's name for "the service behind me failed".
fn upstream_failure() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        axum::Json(json!({
            "error": "UpstreamFailure",
            "message": "the AppView could not be reached",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unprotected_app_bsky_methods_forward() {
        assert!(forwardable("app.bsky.feed.getTimeline"));
        assert!(forwardable("app.bsky.notification.listNotifications"));
        assert!(!forwardable("app.bsky.actor.getPreferences"));
        assert!(!forwardable("app.bsky.actor.putPreferences"));
        assert!(!forwardable("com.atproto.server.getSession"));
        assert!(!forwardable("chat.bsky.convo.listConvos"));
        assert!(!forwardable("app.bskyx.feed.getTimeline"));
    }

    #[test]
    fn configuration_is_an_https_origin_and_a_bare_did() {
        crate::tls::install_crypto_provider();
        assert!(AppView::new("https://api.bsky.app", "did:web:api.bsky.app").is_ok());
        for (url, did) in [
            ("http://api.bsky.app", "did:web:api.bsky.app"),
            ("https://api.bsky.app/xrpc", "did:web:api.bsky.app"),
            ("https://api.bsky.app?x=1", "did:web:api.bsky.app"),
            ("https://api.bsky.app", "did:web:api.bsky.app#bsky_appview"),
            ("https://api.bsky.app", "api.bsky.app"),
            ("not a url", "did:web:api.bsky.app"),
        ] {
            assert!(AppView::new(url, did).is_err(), "{url} {did}");
        }
    }
}
