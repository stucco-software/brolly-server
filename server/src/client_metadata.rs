//! Looking up OAuth client metadata and Client ID Documents over the network.
//!
//! The rules live in [`brolly_atproto::client_metadata`] and
//! [`brolly_solid::client_documents`]. This module decides where the document
//! comes from: the network in production ([`Fetcher`]), a fixed map in
//! integration tests ([`StaticClients`], [`StaticClientDocuments`]).
//!
//! The transport — 5 s timeout, 64 KiB cap, no redirects, HTTPS-only, DNS
//! filtered to public addresses, a cache with distinct ok/error TTLs — is
//! protocol-agnostic and shared: one [`Fetcher`] per protocol, parameterized
//! by what the protocol does with the bytes ([`Document`]). ATProto fetches
//! `application/json`; Solid-OIDC fetches RDF, because our own `/profile`
//! serves HTML to anything that sounds like a browser (spec 6, H3). The
//! remote path's three documents (spec 6, H5) ride the same transport: a
//! foreign issuer's discovery document and key set as JSON, a remote WebID's
//! profile document as RDF.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use brolly_atproto::client_metadata::{
    ClientError, ClientId, ClientMetadata, loopback_metadata, parse_client_id, validate,
};
use brolly_solid::client_documents::{self, ClientIdDocument, InvalidDocument};
use brolly_solid::oidc::tokens::{InvalidDiscovery, InvalidJwks, RemoteDiscovery, RemoteJwks};
use brolly_solid::webid_documents::{self, InvalidWebIdDocument, WebIdDocument};
use moka::Expiry;
use moka::future::Cache;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};

/// Why a client's document couldn't be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError<I> {
    /// The document was retrieved and broke a rule. Safe to describe.
    Invalid(I),
    /// DNS refusal, connection failure, timeout, TLS failure, a non-200 status
    /// or an oversized body. All of them get one description, so PAR can't be
    /// used to map which internal hosts exist or answer (S4).
    Unreachable,
}

impl<I: std::fmt::Display> std::fmt::Display for LookupError<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupError::Invalid(e) => e.fmt(f),
            LookupError::Unreachable => f.write_str("client metadata could not be retrieved"),
        }
    }
}

impl<I: std::fmt::Display + std::fmt::Debug> std::error::Error for LookupError<I> {}

/// What [`ClientLookup::fetch`] returns: a boxed future, because an `async fn`
/// in a trait can't be called through `dyn`.
pub type Lookup<'a, D, I> = Pin<Box<dyn Future<Output = Result<D, LookupError<I>>> + Send + 'a>>;

/// Where a protocol's client documents come from.
///
/// `Send + Sync` so it can live in axum state as `Arc<dyn ClientLookup<..>>`.
pub trait ClientLookup: Send + Sync {
    type Document: Clone + Send + Sync;
    type Invalid: std::error::Error + Clone + Send + Sync + 'static;

    /// Retrieve and validate the document at `url`.
    ///
    /// Only ever called for discoverable clients: PAR goes through
    /// [`lookup_client`], which answers loopback clients itself, and the
    /// Solid-OIDC authorize branch only consults it for `https://` client ids.
    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, Self::Document, Self::Invalid>;

    /// A fetch that must not be answered from a cache (spec 6, H5).
    ///
    /// Key rotation: a foreign issuer can rotate a new key into its set
    /// between our cached copy and a token that names it, and an unknown
    /// `kid` re-fetches the set exactly once before refusing — so a rotation
    /// must not wait out the cache's lifetime. The default is [`fetch`]
    /// itself, so a stub that counts fetches counts a re-fetch too; the
    /// production [`Fetcher`] drops its cached answer first.
    fn refetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, Self::Document, Self::Invalid> {
        self.fetch(url)
    }
}

/// The metadata for a parsed `client_id`.
///
/// A free function rather than a default method on [`ClientLookup`], so no
/// implementation can override the loopback branch and send a `localhost`
/// client to the network.
pub async fn lookup_client(
    clients: &dyn ClientLookup<Document = ClientMetadata, Invalid = ClientError>,
    id: &ClientId,
) -> Result<ClientMetadata, LookupError<ClientError>> {
    match id {
        ClientId::Loopback(_) => Ok(loopback_metadata(id)),
        ClientId::Discoverable(url) => clients.fetch(url).await,
    }
}

/// What one protocol's fetch does with the bytes it gets back: the `Accept`
/// header, the content-type check, and the parse (spec 6, H3). Everything
/// downstream of the bytes — the ATProto fetcher's `application/json` and
/// JSON parse, the Solid-OIDC fetcher's RDF ask and RDF parse — so that one
/// hardened transport can serve both.
pub trait Document: Sized + Clone + Send + Sync + 'static {
    /// Why a retrieved document broke a rule. Safe to show the caller: it
    /// names the rule, never anything fetched.
    type Invalid: std::error::Error + Clone + Send + Sync + 'static;

    /// The `Accept` header: what the protocol's documents are served as. A
    /// fetch that does not ask for what it wants gets whatever the server
    /// hands browsers — for our own `/profile`, an HTML page.
    fn accept() -> &'static str;

    /// The content-type check and the parse, as one: a document served with
    /// the wrong content type is not that protocol's document, whatever its
    /// bytes say.
    fn parse(url: &Url, content_type: &str, body: &[u8]) -> Result<Self, Self::Invalid>;
}

/// ATProto's half of a fetch: `application/json` metadata, as the ATProto
/// OAuth spec's `client_id_metadata_document_supported` serves it.
impl Document for ClientMetadata {
    type Invalid = ClientError;

    fn accept() -> &'static str {
        "application/json"
    }

    fn parse(url: &Url, content_type: &str, body: &[u8]) -> Result<Self, ClientError> {
        validate(&ClientId::Discoverable(url.clone()), content_type, body)
    }
}

/// The Solid-OIDC half of a fetch (spec 6, H3): a Client ID Document is RDF,
/// asked for as RDF and parsed as RDF.
impl Document for ClientIdDocument {
    type Invalid = InvalidDocument;

    fn accept() -> &'static str {
        client_documents::ACCEPT
    }

    fn parse(url: &Url, content_type: &str, body: &[u8]) -> Result<Self, InvalidDocument> {
        client_documents::parse(url, content_type, body)
    }
}

// --- the remote path's documents (spec 6, H5) -----------------------------------
//
// Three more protocols over the one transport: a foreign issuer's discovery
// document and key set, asked for as JSON like the ATProto side's client
// metadata, and a remote WebID's profile document, asked for as RDF like a
// Client ID Document.

/// A foreign issuer's discovery document (spec 6, H5).
impl Document for RemoteDiscovery {
    type Invalid = InvalidDiscovery;

    fn accept() -> &'static str {
        "application/json"
    }

    fn parse(_url: &Url, content_type: &str, body: &[u8]) -> Result<Self, InvalidDiscovery> {
        RemoteDiscovery::parse(content_type, body)
    }
}

/// A foreign issuer's key set (spec 6, H5).
impl Document for RemoteJwks {
    type Invalid = InvalidJwks;

    fn accept() -> &'static str {
        "application/json"
    }

    fn parse(_url: &Url, content_type: &str, body: &[u8]) -> Result<Self, InvalidJwks> {
        RemoteJwks::parse(content_type, body)
    }
}

/// A remote WebID's profile document (spec 6, H5): RDF again, so the ask a
/// Client ID Document makes is the ask this one makes.
impl Document for WebIdDocument {
    type Invalid = InvalidWebIdDocument;

    fn accept() -> &'static str {
        client_documents::ACCEPT
    }

    fn parse(url: &Url, content_type: &str, body: &[u8]) -> Result<Self, InvalidWebIdDocument> {
        webid_documents::parse(url, content_type, body)
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
    type Document = ClientMetadata;
    type Invalid = ClientError;

    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, ClientMetadata, ClientError> {
        let found = self
            .clients
            .get(url.as_str())
            .cloned()
            .ok_or(LookupError::Unreachable);
        Box::pin(std::future::ready(found))
    }
}

/// A fixed set of Client ID Documents, for integration tests (spec 6, H3).
///
/// The same deal as [`StaticClients`]: it skips fetching, not validation, so
/// a test can't register a document production would refuse. Documents are
/// Turtle — the form a hand-written one takes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticClientDocuments {
    documents: HashMap<String, ClientIdDocument>,
}

impl StaticClientDocuments {
    /// Register `client_id`, holding `document`.
    ///
    /// Only `https://` ids, the only kind the authorize branch fetches (H3):
    /// a test can't register an id the branch would refuse before looking.
    pub fn with(mut self, client_id: &str, document: &str) -> Result<Self, InvalidDocument> {
        if !client_id.starts_with("https://") {
            return Err(InvalidDocument::NotRdf(client_id.to_string()));
        }
        let url =
            Url::parse(client_id).map_err(|_| InvalidDocument::NotRdf(client_id.to_string()))?;
        let parsed = client_documents::parse(&url, "text/turtle", document.as_bytes())?;
        self.documents.insert(client_id.to_owned(), parsed);
        Ok(self)
    }
}

impl ClientLookup for StaticClientDocuments {
    type Document = ClientIdDocument;
    type Invalid = InvalidDocument;

    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, ClientIdDocument, InvalidDocument> {
        let found = self
            .documents
            .get(url.as_str())
            .cloned()
            .ok_or(LookupError::Unreachable);
        Box::pin(std::future::ready(found))
    }
}

/// A fixed set of one of the remote path's documents, for integration tests
/// (spec 6, H5).
///
/// The same deal as [`StaticClients`] and [`StaticClientDocuments`]: it skips
/// fetching, not validation — the documents it holds were parsed by the
/// production `parse` when the test built them. A URL it doesn't hold is
/// `Unreachable`, as a fetch that finds nothing would be. The remote-path
/// tests that count fetches or change an answer mid-rotation write their own
/// stubs, as the client-document tests do.
#[derive(Debug)]
pub struct StaticDocuments<D: Document> {
    documents: HashMap<String, D>,
}

// Manual, because the derive would demand `D: Default` — an empty map is
// default whatever the documents are.
impl<D: Document> Default for StaticDocuments<D> {
    fn default() -> Self {
        Self {
            documents: HashMap::new(),
        }
    }
}

impl<D: Document> StaticDocuments<D> {
    /// Hold `document`, answered for `url`.
    pub fn with(mut self, url: &str, document: D) -> Self {
        self.documents.insert(url.to_owned(), document);
        self
    }
}

impl<D: Document> ClientLookup for StaticDocuments<D> {
    type Document = D;
    type Invalid = D::Invalid;

    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, D, D::Invalid> {
        let found = self
            .documents
            .get(url.as_str())
            .cloned()
            .ok_or(LookupError::Unreachable);
        Box::pin(std::future::ready(found))
    }
}

// --- fetching --------------------------------------------------------------------

/// Total time for one fetch: connect, TLS, headers and body.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Client metadata is a few hundred bytes. Anything this big isn't metadata.
const MAX_BODY: usize = 64 * 1024;
const OK_TTL: Duration = Duration::from_secs(10 * 60);
/// Failures are cached too, so a bad or slow client can't make every PAR
/// fetch again.
const ERR_TTL: Duration = Duration::from_secs(60);
const CAPACITY: u64 = 1_000;
/// Static, not per instance: `Fetcher::new` takes no arguments, and the software
/// and version are what a client operator needs to recognise the fetch in their
/// logs. Which instance asked is the one their user just signed in to.
const FETCH_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

type Cached<D> = Result<D, LookupError<<D as Document>::Invalid>>;

/// Why one retrieval failed, in the detail the operator's log needs and the
/// caller must never see.
enum Failure<I> {
    /// Refused without reading a response, or while reading it.
    Refused(&'static str),
    /// Any status other than 200.
    Status(reqwest::StatusCode),
    /// reqwest's own: https-only, DNS refusal by [`PublicOnly`], connection,
    /// TLS, timeout, a broken body.
    Http(reqwest::Error),
    /// The document was read and broke a rule.
    Invalid(I),
}

impl<I: std::fmt::Display> std::fmt::Display for Failure<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Refused(why) => f.write_str(why),
            Failure::Status(status) => write!(f, "answered {status}"),
            Failure::Http(e) => e.fmt(f),
            Failure::Invalid(e) => e.fmt(f),
        }
    }
}

/// Fetches a protocol's client documents over the network, from public
/// addresses only, and caches the answer (spec 6, H3).
///
/// What `main.rs` builds, once per protocol: `Fetcher::<ClientMetadata>` for
/// ATProto, `Fetcher::<ClientIdDocument>` for Solid-OIDC. The transport is
/// shared and identical for both; only [`Document`] — the `Accept` header,
/// the content-type check, the parse — varies. Every bypass of the address
/// filter is closed where it happens (S3):
/// - redirects aren't followed, so a public host can't bounce the fetch inward;
/// - proxies are off, so an environment proxy can't resolve names the filter
///   never sees;
/// - names resolve through [`PublicOnly`], which filters at resolution, leaving
///   no window between checking an address and connecting to it;
/// - IP-literal hosts never reach a resolver, so they're refused here (and
///   `parse_client_id` refuses them before that).
///
/// It never calls `ClientBuilder::resolve` or `resolve_to_addrs`: reqwest
/// applies those overrides on top of the custom resolver.
pub struct Fetcher<D: Document> {
    http: reqwest::Client,
    cache: Cache<String, Cached<D>>,
    allow_loopback: bool,
    _document: std::marker::PhantomData<D>,
}

impl<D: Document> Fetcher<D> {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::build(false, false, OK_TTL, ERR_TTL)
    }

    /// For tests that fetch from `http://127.0.0.1:PORT` — this module's unit
    /// tests, and the integration tests that fetch from a server served on a
    /// real loopback port — which also need cache lifetimes in milliseconds.
    ///
    /// `allow_loopback` lets loopback IP literals through and stops
    /// [`PublicOnly`] dropping loopback addresses. `allow_http` lifts
    /// https-only. Production builds `new`, which allows neither. Like `new`,
    /// building the client can fail, so the caller — a test — expects.
    pub fn for_tests(
        allow_loopback: bool,
        allow_http: bool,
        ok_ttl: Duration,
        err_ttl: Duration,
    ) -> Result<Self, reqwest::Error> {
        Self::build(allow_loopback, allow_http, ok_ttl, err_ttl)
    }

    fn build(
        allow_loopback: bool,
        allow_http: bool,
        ok_ttl: Duration,
        err_ttl: Duration,
    ) -> Result<Self, reqwest::Error> {
        // Idempotent. Here as well as in main so no constructor can reach
        // reqwest's panic for a missing crypto provider.
        crate::tls::install_crypto_provider();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(TIMEOUT)
            .user_agent(FETCH_USER_AGENT)
            .https_only(!allow_http)
            .dns_resolver(PublicOnly { allow_loopback })
            .build()?;
        let cache = Cache::builder()
            .max_capacity(CAPACITY)
            .expire_after(Lifetimes {
                ok: ok_ttl,
                err: err_ttl,
            })
            .build();
        Ok(Self {
            http,
            cache,
            allow_loopback,
            _document: std::marker::PhantomData,
        })
    }

    /// Would connecting to this URL's host skip the resolver filter?
    fn host_allowed(&self, url: &Url) -> bool {
        match url.host() {
            Some(Host::Domain(_)) => true,
            Some(Host::Ipv4(ip)) => self.allow_loopback && ip.is_loopback(),
            Some(Host::Ipv6(ip)) => self.allow_loopback && ip.is_loopback(),
            None => false,
        }
    }

    /// One retrieval, as the cache stores it. The only place a failure is
    /// logged, so each is logged once, and a cached failure not again.
    async fn retrieve(&self, url: &Url) -> Cached<D> {
        self.request(url).await.map_err(|failure| {
            // The caller gets one description; the operator gets the detail.
            tracing::info!(client_id = %url, error = %failure, "client document lookup failed");
            match failure {
                Failure::Invalid(e) => LookupError::Invalid(e),
                Failure::Refused(_) | Failure::Status(_) | Failure::Http(_) => {
                    LookupError::Unreachable
                }
            }
        })
    }

    async fn request(&self, url: &Url) -> Result<D, Failure<D::Invalid>> {
        if !self.host_allowed(url) {
            return Err(Failure::Refused("the host is an IP address"));
        }
        let mut response = self
            .http
            .get(url.as_str())
            // What varies with the protocol, and everything else is shared:
            // the Accept is why an RDF fetch gets RDF and an ATProto fetch
            // gets JSON from the same server (spec 6, H3).
            .header(reqwest::header::ACCEPT, D::accept())
            .send()
            .await
            .map_err(Failure::Http)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Failure::Status(response.status()));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(Failure::Http)? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(Failure::Refused("the body is over 64 KiB"));
            }
            body.extend_from_slice(&chunk);
        }

        D::parse(url, &content_type, &body).map_err(Failure::Invalid)
    }
}

impl<D: Document> ClientLookup for Fetcher<D> {
    type Document = D;
    type Invalid = D::Invalid;

    fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, D, D::Invalid> {
        // get_with also collapses concurrent lookups of one client into a
        // single fetch.
        Box::pin(async move {
            self.cache
                .get_with(url.as_str().to_owned(), self.retrieve(url))
                .await
        })
    }

    fn refetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, D, D::Invalid> {
        // Rotation (spec 6, H5): the cached answer is dropped first, so the
        // one re-fetch an unknown `kid` forces reads the wire and not the
        // cache — and what it finds is cached, so the next request does not
        // repeat the round trip.
        Box::pin(async move {
            self.cache.invalidate(url.as_str()).await;
            self.cache
                .get_with(url.as_str().to_owned(), self.retrieve(url))
                .await
        })
    }
}

/// Successes are kept longer than failures.
struct Lifetimes {
    ok: Duration,
    err: Duration,
}

impl<D: Document> Expiry<String, Cached<D>> for Lifetimes {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Cached<D>,
        _at: Instant,
    ) -> Option<Duration> {
        Some(if value.is_ok() { self.ok } else { self.err })
    }
}

// --- address filtering ------------------------------------------------------------

/// A DNS resolver that only returns public addresses.
///
/// Resolves with tokio's resolver, then drops every address [`is_public`]
/// refuses. If none survive, resolution fails, so the connection is never
/// attempted.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicOnly {
    allow_loopback: bool,
}

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(resolve_public(
            name.as_str().to_owned(),
            self.allow_loopback,
        ))
    }
}

async fn resolve_public(
    host: String,
    allow_loopback: bool,
) -> Result<Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let allowed: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
        .await?
        .filter(|addr| {
            is_public(addr.ip()) || (allow_loopback && addr.ip().to_canonical().is_loopback())
        })
        .collect();
    if allowed.is_empty() {
        return Err(std::io::Error::other("the host has no public address").into());
    }
    Ok(Box::new(allowed.into_iter()))
}

/// May a client metadata fetch connect to this address?
///
/// Refuses loopback, private (RFC 1918 / RFC 4193), link-local, unspecified,
/// multicast, broadcast, CGNAT, documentation and benchmarking ranges, and
/// IPv6 forms that can carry an IPv4 address. IPv4-mapped, SIIT-translated
/// and NAT64 are judged by the IPv4 address inside them. IPv4-compatible,
/// local-use NAT64, 6to4 and Teredo are refused outright.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let refused = a == 0                                  // 0.0.0.0/8, unspecified and "this network"
        || ip.is_loopback()                               // 127.0.0.0/8
        || ip.is_private()                                // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                             // 169.254.0.0/16
        || (a == 100 && (b & 0b1100_0000) == 64)          // 100.64.0.0/10, CGNAT
        || (a == 192 && b == 0 && c == 0)                 // 192.0.0.0/24, IETF protocol assignments
        || (a == 192 && b == 88 && c == 99)               // 192.88.99.0/24, 6to4 relay anycast (deprecated)
        || ip.is_documentation()                          // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || (a == 198 && (b & 0b1111_1110) == 18)          // 198.18.0.0/15, benchmarking
        || ip.is_multicast()                              // 224.0.0.0/4
        || a >= 240; // 240.0.0.0/4 reserved, including 255.255.255.255 broadcast
    !refused
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // IPv4-compatible (::/96, deprecated), which also covers :: and ::1.
    if s[..6] == [0; 6] {
        return false;
    }
    // Forms that reach exactly the IPv4 address in their last 32 bits: judge
    // that address. (IPv4-mapped, ::ffff:0:0/96, is unwrapped in `is_public`.)
    let embedded = || {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        Ipv4Addr::new(a, b, c, d)
    };
    // NAT64 well-known prefix, 64:ff9b::/96 (RFC 6052).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return is_public_v4(embedded());
    }
    // SIIT IPv4-translated, ::ffff:0:0:0/96 (RFC 7915).
    if s[..6] == [0, 0, 0, 0, 0xffff, 0] {
        return is_public_v4(embedded());
    }
    // Forms whose destination depends on a translator or relay we can't see,
    // or that embed IPv4 somewhere other than the last 32 bits: refused
    // whatever they carry.
    let refused = (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // 64:ff9b:1::/48, local-use NAT64 (RFC 8215)
        || s[0] == 0x2002                               // 2002::/16, 6to4
        || (s[0] == 0x2001 && s[1] == 0x0000)           // 2001::/32, Teredo
        || (s[0] == 0x0100 && s[1..4] == [0; 3])        // 100::/64, discard-only (RFC 6666)
        || (s[0] & 0xfe00) == 0xfc00                    // fc00::/7, unique local (RFC 4193)
        || (s[0] & 0xffc0) == 0xfe80                    // fe80::/10, link-local
        || (s[0] & 0xffc0) == 0xfec0                    // fec0::/10, site-local (deprecated)
        || (s[0] & 0xff00) == 0xff00                    // ff00::/8, multicast
        || (s[0] == 0x2001 && s[1] == 0x0db8)           // 2001:db8::/32, documentation
        || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0); // 2001:2::/48, benchmarking
    !refused
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
        type Document = ClientMetadata;
        type Invalid = ClientError;

        fn fetch<'a>(&'a self, url: &'a Url) -> Lookup<'a, ClientMetadata, ClientError> {
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
            LookupError::<ClientError>::Unreachable.to_string(),
            "client metadata could not be retrieved"
        );
    }

    #[test]
    fn static_client_documents_hold_only_what_parse_accepts() {
        // The stub validates, so it cannot hold what production would refuse:
        // not a non-https id, not a non-document, not unparseable Turtle.
        let valid = "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>. \
                     <https://app.example/id> oidc:redirect_uris <https://app.example/cb> .";
        assert!(
            StaticClientDocuments::default()
                .with("https://app.example/id", valid)
                .is_ok()
        );
        assert!(matches!(
            StaticClientDocuments::default().with("http://app.example/id", valid),
            Err(InvalidDocument::NotRdf(_))
        ));
        assert!(matches!(
            StaticClientDocuments::default().with("https://app.example/id", "not turtle"),
            Err(InvalidDocument::Unparseable(_))
        ));
        // Parses, but the triples are about some other node: not the
        // client's own document.
        assert_eq!(
            StaticClientDocuments::default().with(
                "https://app.example/id",
                "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>. \
                 <https://elsewhere/> oidc:redirect_uris <https://app.example/cb> .",
            ),
            Err(InvalidDocument::NotAClientDocument)
        );
    }

    #[tokio::test]
    async fn a_registered_document_is_found_and_an_unknown_one_is_unreachable() {
        let documents = StaticClientDocuments::default()
            .with(
                "https://app.example/id",
                "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>. \
                 <> oidc:redirect_uris <https://app.example/cb> .",
            )
            .unwrap();

        let found = documents
            .fetch(&Url::parse("https://app.example/id").unwrap())
            .await
            .unwrap();
        assert_eq!(found.client_id(), "https://app.example/id");

        let unknown = Url::parse("https://unknown.example/id").unwrap();
        assert_eq!(
            documents.fetch(&unknown).await,
            Err(LookupError::Unreachable)
        );
    }
}

#[cfg(test)]
mod fetch_tests {
    use super::*;
    use axum::Router;
    use axum::http::{StatusCode, header};
    use axum::routing::get;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MINUTE: Duration = Duration::from_secs(60);

    fn document(client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "redirect_uris": ["https://app.example/cb"],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "dpop_bound_access_tokens": true,
        })
    }

    /// Serve `app(url)` on an ephemeral loopback port. `url` is the address of
    /// `/client-metadata.json` on it, which a valid document must repeat.
    async fn serve(app: impl FnOnce(String) -> Router) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/client-metadata.json",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let router = app(url.to_string());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        url
    }

    /// `/client-metadata.json`, always answering with these, counting hits.
    fn answering(
        status: StatusCode,
        content_type: &'static str,
        body: String,
        hits: &Arc<AtomicUsize>,
    ) -> Router {
        let hits = hits.clone();
        Router::new().route(
            "/client-metadata.json",
            get(move || {
                let hits = hits.clone();
                let body = body.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (status, [(header::CONTENT_TYPE, content_type)], body)
                }
            }),
        )
    }

    fn local_fetcher() -> Fetcher<ClientMetadata> {
        Fetcher::for_tests(true, true, MINUTE, MINUTE).unwrap()
    }

    /// A Client ID Document in Turtle, about the client at `url`.
    fn solid_document(url: &str) -> String {
        format!(
            "@prefix oidc: <http://www.w3.org/ns/solid/oidc#>.\n<{url}> \
             oidc:redirect_uris <https://app.example/cb> ; \
             oidc:client_name \"Penny\" ."
        )
    }

    #[tokio::test]
    async fn a_valid_document_is_fetched_and_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(
                StatusCode::OK,
                "application/json",
                document(&url).to_string(),
                &hits,
            )
        })
        .await;
        let fetcher = local_fetcher();

        let first = fetcher.fetch(&url).await.unwrap();
        assert_eq!(first.client_id(), url.as_str());
        let second = fetcher.fetch(&url).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the second lookup is a cache hit"
        );
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(
                StatusCode::OK,
                "application/json",
                document(&url).to_string(),
                &hits,
            )
            .route(
                "/moved.json",
                get(|| async {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, "/client-metadata.json")],
                    )
                }),
            )
        })
        .await;
        let moved = url.join("/moved.json").unwrap();

        assert_eq!(
            local_fetcher().fetch(&moved).await,
            Err(LookupError::Unreachable)
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the redirect target was never fetched"
        );
    }

    #[tokio::test]
    async fn only_200_is_accepted() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(
                StatusCode::CREATED,
                "application/json",
                document(&url).to_string(),
                &hits,
            )
        })
        .await;
        assert_eq!(
            local_fetcher().fetch(&url).await,
            Err(LookupError::Unreachable)
        );
    }

    #[tokio::test]
    async fn a_body_over_64_kib_is_refused() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            let mut padded = document(&url);
            padded["padding"] = serde_json::Value::String("x".repeat(70 * 1024));
            answering(
                StatusCode::OK,
                "application/json",
                padded.to_string(),
                &hits,
            )
        })
        .await;
        assert_eq!(
            local_fetcher().fetch(&url).await,
            Err(LookupError::Unreachable)
        );
    }

    #[tokio::test]
    async fn a_slow_server_hits_the_timeout() {
        let url = serve(|url| {
            let body = document(&url).to_string();
            Router::new().route(
                "/client-metadata.json",
                get(move || {
                    let body = body.clone();
                    async move {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        ([(header::CONTENT_TYPE, "application/json")], body)
                    }
                }),
            )
        })
        .await;

        let started = std::time::Instant::now();
        assert_eq!(
            local_fetcher().fetch(&url).await,
            Err(LookupError::Unreachable)
        );
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(4) && waited < Duration::from_secs(10),
            "gave up after {waited:?}, expected the 5 s timeout"
        );
    }

    #[tokio::test]
    async fn text_html_is_refused() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(
                StatusCode::OK,
                "text/html",
                document(&url).to_string(),
                &hits,
            )
        })
        .await;
        assert!(matches!(
            local_fetcher().fetch(&url).await,
            Err(LookupError::Invalid(ClientError::InvalidMetadata(_)))
        ));
    }

    #[tokio::test]
    async fn a_failure_is_cached_for_its_lifetime_then_retried() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|_| {
            answering(
                StatusCode::NOT_FOUND,
                "text/plain",
                "gone".to_string(),
                &hits,
            )
        })
        .await;
        let fetcher =
            Fetcher::<ClientMetadata>::for_tests(true, true, MINUTE, Duration::from_millis(50))
                .unwrap();

        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a failure is cached too");

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "and retried once it expires"
        );
    }

    #[tokio::test]
    async fn an_ip_literal_is_refused_unless_loopback_is_allowed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(
                StatusCode::OK,
                "application/json",
                document(&url).to_string(),
                &hits,
            )
        })
        .await;
        let fetcher = Fetcher::<ClientMetadata>::for_tests(false, true, MINUTE, MINUTE).unwrap();
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 0, "refused before connecting");
    }

    #[tokio::test]
    async fn a_name_that_resolves_only_to_loopback_is_refused() {
        let hits = Arc::new(AtomicUsize::new(0));
        let ip_url = serve(|url| {
            answering(
                StatusCode::OK,
                "application/json",
                document(&url).to_string(),
                &hits,
            )
        })
        .await;
        let mut by_name = ip_url.clone();
        by_name.set_host(Some("localhost")).unwrap();

        let fetcher = Fetcher::<ClientMetadata>::for_tests(false, true, MINUTE, MINUTE).unwrap();
        assert_eq!(fetcher.fetch(&by_name).await, Err(LookupError::Unreachable));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "PublicOnly dropped every address"
        );
    }

    #[tokio::test]
    async fn plain_http_is_refused_unless_allowed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(
                StatusCode::OK,
                "application/json",
                document(&url).to_string(),
                &hits,
            )
        })
        .await;
        let fetcher = Fetcher::<ClientMetadata>::for_tests(true, false, MINUTE, MINUTE).unwrap();
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn production_refuses_ip_literals_and_plain_http() {
        // Pins Fetcher::new, what main.rs builds, to allow_loopback = false and
        // allow_http = false. `request` rather than `fetch`, so each refusal is
        // seen to come from its own flag and not from something further on.
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(
                StatusCode::OK,
                "application/json",
                document(&url).to_string(),
                &hits,
            )
        })
        .await;
        let fetcher = Fetcher::<ClientMetadata>::new().unwrap();

        // http://127.0.0.1:PORT: refused as an IP literal, before connecting.
        assert!(matches!(
            fetcher.request(&url).await,
            Err(Failure::Refused(_))
        ));
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));

        // An https IP literal, loopback or public, is refused the same way.
        let mut https_loopback = url.clone();
        https_loopback.set_scheme("https").unwrap();
        assert!(matches!(
            fetcher.request(&https_loopback).await,
            Err(Failure::Refused(_))
        ));
        let https_public = Url::parse("https://1.1.1.1/client-metadata.json").unwrap();
        assert!(matches!(
            fetcher.request(&https_public).await,
            Err(Failure::Refused(_))
        ));

        // http by name gets past the literal check and is refused by
        // https_only, which reqwest reports as a builder error, before any
        // resolution or connection.
        let mut http_by_name = url.clone();
        http_by_name.set_host(Some("localhost")).unwrap();
        assert!(matches!(
            fetcher.request(&http_by_name).await,
            Err(Failure::Http(e)) if e.is_builder()
        ));

        assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reached the server");
    }

    #[tokio::test]
    async fn the_fetch_names_its_software() {
        let seen = Arc::new(std::sync::Mutex::new(None::<String>));
        let url = serve(|url| {
            let body = document(&url).to_string();
            let seen = seen.clone();
            Router::new().route(
                "/client-metadata.json",
                get(move |headers: axum::http::HeaderMap| {
                    let body = body.clone();
                    let seen = seen.clone();
                    async move {
                        *seen.lock().unwrap() = headers
                            .get(header::USER_AGENT)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        ([(header::CONTENT_TYPE, "application/json")], body)
                    }
                }),
            )
        })
        .await;

        local_fetcher().fetch(&url).await.unwrap();
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.as_deref(), Some(FETCH_USER_AGENT));
        assert!(FETCH_USER_AGENT.starts_with("brolly-server/"));
    }

    // --- Solid-OIDC Client ID Documents (spec 6, H3) ------------------------------
    //
    // The transport above is shared with the ATProto fetcher and tested once:
    // what these pin is the half that varies — the RDF ask, the content-type
    // check, the RDF parse — and that the shared rules really are shared.

    /// A local fetcher of Client ID Documents.
    fn solid_fetcher() -> Fetcher<ClientIdDocument> {
        Fetcher::for_tests(true, true, MINUTE, MINUTE).unwrap()
    }

    #[tokio::test]
    async fn a_client_id_document_is_asked_for_as_rdf_and_parsed_as_rdf() {
        // The trap the RDF ask exists for: this server, like our own
        // `/profile`, serves HTML to anything that sounds like a browser and
        // Turtle to a caller that asks for it. A fetcher that does not ask
        // for RDF gets the page and must be refused by the content-type
        // check; a fetcher that asks gets the document.
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            let hits = hits.clone();
            let body = solid_document(&url);
            Router::new().route(
                "/client-metadata.json",
                get(move |headers: axum::http::HeaderMap| {
                    let hits = hits.clone();
                    let body = body.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let accept = headers
                            .get(header::ACCEPT)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default();
                        let browser = accept
                            .split(',')
                            .map(|part| part.split(';').next().unwrap_or("").trim())
                            .any(|media| media == "text/html");
                        if browser {
                            (
                                [(header::CONTENT_TYPE, "text/html")],
                                "<html>A page, not a document</html>".to_string(),
                            )
                        } else {
                            ([(header::CONTENT_TYPE, "text/turtle")], body.clone())
                        }
                    }
                }),
            )
        })
        .await;

        let document = solid_fetcher().fetch(&url).await.unwrap();
        assert_eq!(document.client_id(), url.as_str());
        assert_eq!(document.client_name(), Some("Penny"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_page_served_to_browsers_is_not_a_client_id_document() {
        // The second half of the trap: even if HTML arrives — a server that
        // serves it whatever the ask — the content-type check refuses it
        // before any parse. The page's contents are irrelevant; a real page
        // is what a browser-sounding Accept on our own `/profile` gets.
        let url = serve(|_| {
            answering(
                StatusCode::OK,
                "text/html",
                "<html>A page, not a document</html>".to_string(),
                &Arc::new(AtomicUsize::new(0)),
            )
        })
        .await;
        assert!(matches!(
            solid_fetcher().fetch(&url).await,
            Err(LookupError::Invalid(InvalidDocument::NotRdf(_)))
        ));
    }

    #[tokio::test]
    async fn a_client_id_document_redirect_is_not_followed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|url| {
            answering(StatusCode::OK, "text/turtle", solid_document(&url), &hits).route(
                "/moved.json",
                get(|| async {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, "/client-metadata.json")],
                    )
                }),
            )
        })
        .await;
        let moved = url.join("/moved.json").unwrap();

        assert_eq!(
            solid_fetcher().fetch(&moved).await,
            Err(LookupError::Unreachable)
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the redirect target was never fetched"
        );
    }

    #[tokio::test]
    async fn a_client_id_document_fetch_is_https_only_from_public_addresses() {
        // `Fetcher::<ClientIdDocument>::new` is what main.rs builds: the
        // parameterization changed nothing about the transport rules.
        let hits = Arc::new(AtomicUsize::new(0));
        let url =
            serve(|url| answering(StatusCode::OK, "text/turtle", solid_document(&url), &hits))
                .await;
        let fetcher = Fetcher::<ClientIdDocument>::new().unwrap();

        // Plain http: refused by https_only, before any connection.
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        // An IP-literal host: refused before the resolver, https or not.
        let mut https_loopback = url.clone();
        https_loopback.set_scheme("https").unwrap();
        assert_eq!(
            fetcher.fetch(&https_loopback).await,
            Err(LookupError::Unreachable)
        );
        // A name with no public address: refused by the resolver filter.
        let mut by_name = url.clone();
        by_name.set_host(Some("localhost")).unwrap();
        assert_eq!(fetcher.fetch(&by_name).await, Err(LookupError::Unreachable));
        assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reached the server");
    }

    #[tokio::test]
    async fn a_client_id_document_is_fetched_and_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url =
            serve(|url| answering(StatusCode::OK, "text/turtle", solid_document(&url), &hits))
                .await;
        let fetcher = solid_fetcher();

        let first = fetcher.fetch(&url).await.unwrap();
        let second = fetcher.fetch(&url).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a fetched document is reused, not re-fetched"
        );
    }

    #[tokio::test]
    async fn a_failed_client_id_document_fetch_is_not_re_hammered() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|_| {
            answering(
                StatusCode::NOT_FOUND,
                "text/plain",
                "gone".to_string(),
                &hits,
            )
        })
        .await;
        let fetcher =
            Fetcher::<ClientIdDocument>::for_tests(true, true, MINUTE, Duration::from_millis(50))
                .unwrap();

        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(fetcher.fetch(&url).await, Err(LookupError::Unreachable));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a failure is cached for its shorter lifetime, not re-hammered"
        );
    }

    // --- the remote path's documents (spec 6, H5) ------------------------------
    //
    // The transport above is shared and tested once, per protocol; what these
    // pin is the half that varies — the JSON ask for the issuer's two
    // documents, the RDF ask for the WebID's — and the one rule that is new
    // to the remote path: `refetch` drops the cached answer, because a key
    // rotation must not wait out a cache lifetime.

    /// A discovery document for an issuer at `issuer`.
    fn discovery_body(issuer: &str) -> String {
        serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
        })
        .to_string()
    }

    /// A key set carrying one ES256 key, `kid` naming it.
    fn jwks_body(kid: &str) -> String {
        let key = p256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let sec1 = key.verifying_key().to_sec1_bytes();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid,
                "x": b64.encode(&sec1[1..33]),
                "y": b64.encode(&sec1[33..65]),
            }]
        })
        .to_string()
    }

    #[tokio::test]
    async fn a_discovery_document_is_fetched_as_json_and_cached() {
        // Once per issuer (H5): the second lookup is a cache hit.
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|_| {
            answering(
                StatusCode::OK,
                "application/json",
                discovery_body("https://idp.example"),
                &hits,
            )
        })
        .await;
        let fetcher = Fetcher::<RemoteDiscovery>::for_tests(true, true, MINUTE, MINUTE).unwrap();

        let first = fetcher.fetch(&url).await.unwrap();
        assert_eq!(first.issuer, "https://idp.example");
        assert_eq!(first.jwks_uri, "https://idp.example/jwks");
        let second = fetcher.fetch(&url).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "cached per issuer");
    }

    #[tokio::test]
    async fn a_discovery_document_is_json_only() {
        let url = serve(|_| {
            answering(
                StatusCode::OK,
                "text/html",
                "<html>A page, not a discovery document</html>".to_string(),
                &Arc::new(AtomicUsize::new(0)),
            )
        })
        .await;
        assert!(matches!(
            Fetcher::<RemoteDiscovery>::for_tests(true, true, MINUTE, MINUTE)
                .unwrap()
                .fetch(&url)
                .await,
            Err(LookupError::Invalid(InvalidDiscovery::NotJson(_)))
        ));
    }

    #[tokio::test]
    async fn a_key_set_is_fetched_parsed_and_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|_| {
            answering(
                StatusCode::OK,
                "application/json",
                jwks_body("idp-1"),
                &hits,
            )
        })
        .await;
        let fetcher = Fetcher::<RemoteJwks>::for_tests(true, true, MINUTE, MINUTE).unwrap();

        let first = fetcher.fetch(&url).await.unwrap();
        assert!(first.key_for("idp-1").is_some(), "the parse kept the key");
        assert!(
            fetcher
                .fetch(&url)
                .await
                .unwrap()
                .key_for("idp-1")
                .is_some()
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1, "cached per issuer");
    }

    #[tokio::test]
    async fn a_refetch_drops_the_cached_answer() {
        // The rotation plumbing (H5): `refetch` reads the wire, not the cache
        // — and what it finds replaces the cached answer.
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|_| {
            answering(
                StatusCode::OK,
                "application/json",
                jwks_body("idp-1"),
                &hits,
            )
        })
        .await;
        let fetcher = Fetcher::<RemoteJwks>::for_tests(true, true, MINUTE, MINUTE).unwrap();

        let cached = fetcher.fetch(&url).await.unwrap();
        let fresh = fetcher.refetch(&url).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2, "the re-fetch read the wire");
        let after = fetcher.fetch(&url).await.unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "and what it found was cached"
        );
        assert!(fresh.key_for("idp-1").is_some());
        assert!(cached.key_for("idp-1").is_some());
        assert!(after.key_for("idp-1").is_some());
    }

    #[tokio::test]
    async fn a_webid_document_is_asked_for_as_rdf_parsed_and_cached() {
        // The trap the RDF ask exists for, again: this server, like our own
        // `/profile`, serves HTML to anything that sounds like a browser and
        // Turtle to a caller that asks for it. The WebID's fragment is in the
        // fetch URL and never reaches the wire — the request that arrives is
        // for `/profile` — which is what lets the parse anchor the
        // `solid:oidcIssuer` triples on the WebID's exact IRI.
        let hits = Arc::new(AtomicUsize::new(0));
        let url = serve(|_| {
            let hits = hits.clone();
            Router::new().route(
                "/profile",
                get(move |headers: axum::http::HeaderMap| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let accept = headers
                            .get(header::ACCEPT)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default();
                        let browser = accept
                            .split(',')
                            .map(|part| part.split(';').next().unwrap_or("").trim())
                            .any(|media| media == "text/html");
                        if browser {
                            (
                                [(header::CONTENT_TYPE, "text/html")],
                                "<html>A page, not a profile</html>".to_string(),
                            )
                        } else {
                            (
                                [(header::CONTENT_TYPE, "text/turtle")],
                                "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
                                 <#me> solid:oidcIssuer <https://idp.example> ."
                                    .to_string(),
                            )
                        }
                    }
                }),
            )
        })
        .await;
        // The WebID, fragment and all: the cache key is per WebID, and the
        // wire sees only the path.
        let webid = url.join("/profile#me").unwrap();
        let fetcher = Fetcher::<WebIdDocument>::for_tests(true, true, MINUTE, MINUTE).unwrap();

        let first = fetcher.fetch(&webid).await.unwrap();
        assert!(first.names("https://idp.example"));
        let second = fetcher.fetch(&webid).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the fragment never hit the wire, and the document is cached per WebID"
        );
    }

    #[tokio::test]
    async fn a_page_served_to_browsers_is_not_a_webid_document() {
        let url = serve(|_| {
            answering(
                StatusCode::OK,
                "text/html",
                "<html>A page, not a profile</html>".to_string(),
                &Arc::new(AtomicUsize::new(0)),
            )
        })
        .await;
        assert!(matches!(
            Fetcher::<WebIdDocument>::for_tests(true, true, MINUTE, MINUTE)
                .unwrap()
                .fetch(&url)
                .await,
            Err(LookupError::Invalid(InvalidWebIdDocument::NotRdf(_)))
        ));
    }

    // --- PublicOnly -----------------------------------------------------------------

    #[test]
    fn every_refused_range_is_refused() {
        for ip in [
            // IPv4
            "0.0.0.0",         // unspecified
            "0.1.2.3",         // "this network"
            "127.0.0.1",       // loopback
            "127.255.255.254", // loopback
            "10.0.0.1",        // RFC 1918
            "172.16.0.1",      // RFC 1918
            "172.31.255.255",  // RFC 1918
            "192.168.1.1",     // RFC 1918
            "169.254.169.254", // link-local, and the cloud metadata service
            "100.64.0.1",      // CGNAT
            "100.127.255.254", // CGNAT
            "224.0.0.1",       // multicast
            "239.255.255.255", // multicast
            "255.255.255.255", // broadcast
            "240.0.0.1",       // reserved
            "192.0.2.1",       // documentation
            "198.51.100.7",    // documentation
            "203.0.113.9",     // documentation
            "198.18.0.1",      // benchmarking
            "198.19.255.254",  // benchmarking
            "192.0.0.8",       // IETF protocol assignments
            "192.88.99.1",     // 6to4 relay anycast (deprecated)
            // IPv6
            "::",             // unspecified
            "::1",            // loopback
            "fc00::1",        // unique local (RFC 4193)
            "fd12:3456::1",   // unique local (RFC 4193)
            "fe80::1",        // link-local
            "fec0::1",        // site-local (deprecated)
            "ff02::1",        // multicast
            "2001:db8::1",    // documentation
            "2001:2::1",      // benchmarking
            "::127.0.0.1",    // IPv4-compatible (deprecated)
            "64:ff9b::a00:1", // NAT64 of 10.0.0.1
            "100::1",         // discard-only (RFC 6666)
            // local-use NAT64 (RFC 8215), refused whatever it embeds
            "64:ff9b:1::a00:1",
            "64:ff9b:1::808:808",
            // SIIT IPv4-translated (::ffff:0:0:0/96) of refused IPv4 addresses
            "::ffff:0:0.0.0.0",
            "::ffff:0:127.0.0.1",
            "::ffff:0:10.0.0.1",
            "::ffff:0:169.254.169.254",
            "::ffff:0:100.64.0.1",
            // 6to4 (2002::/16), refused whatever it embeds
            "2002:a00:1::1",
            "2002:808:808::1",
            // Teredo (2001::/32), refused whatever it embeds
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001::1",
            // IPv4-mapped IPv6 forms
            "::ffff:0.0.0.0",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:172.16.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.169.254",
            "::ffff:100.64.0.1",
            "::ffff:224.0.0.1",
            "::ffff:255.255.255.255",
            "::ffff:192.0.2.1",
            "::ffff:198.18.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip} should be refused");
        }
    }

    #[test]
    fn a_public_address_is_allowed() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.215.14",
            "100.63.255.255", // just below CGNAT
            "100.128.0.1",    // just above CGNAT
            "172.15.255.255", // just below RFC 1918
            "172.32.0.1",     // just above RFC 1918
            "198.17.255.255", // just below benchmarking
            "198.20.0.1",     // just above benchmarking
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
            "::ffff:1.1.1.1",
            "64:ff9b::808:808",     // NAT64 of 8.8.8.8
            "::ffff:0:8.8.8.8",     // SIIT of 8.8.8.8
            "2001:4860:4860::8888", // Google DNS, in 2001::/16 but not Teredo
            "2003::1",              // just above 6to4
            "100:0:0:1::1",         // just outside the discard 100::/64
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    #[tokio::test]
    async fn the_resolver_drops_loopback_unless_told_otherwise() {
        let refused = PublicOnly::default()
            .resolve("localhost".parse().unwrap())
            .await;
        assert!(refused.is_err(), "localhost has no public address");

        let allowed = PublicOnly {
            allow_loopback: true,
        }
        .resolve("localhost".parse().unwrap())
        .await;
        assert!(allowed.is_ok_and(|mut addrs| addrs.next().is_some()));
    }
}
