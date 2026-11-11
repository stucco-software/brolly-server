//! Composes the adapters, owns [`app`], and spawns workers.
//!
//! **This is the only crate that may depend on more than one adapter, and the
//! only crate that may define `app()`.** Both rules are enforced by
//! `tests/architecture.rs`; together they are what keeps the dependency graph
//! acyclic. See `docs/greenfield-implementation-plan.md` §2.1.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use axum::Router;
use axum::extract::State;
use axum::http::{Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use brolly_identity::extract;
use sqlx::PgPool;
use tower_http::services::ServeDir;

pub mod account;
pub mod activitypub;
pub mod admin;
pub mod atproto_oauth;
pub mod auth;
pub mod client_metadata;
pub mod consent;
pub mod internal_api;
pub mod mastodon_api;
pub mod mastodon_oauth;
pub mod outbox;
pub mod pod;
pub mod profile;
pub mod provision;
pub mod ratelimit;
pub mod solid_oidc;
pub mod tls;
pub mod xrpc;

/// Everything a handler needs. Composed here because `server` is the only crate
/// permitted to depend on more than one adapter.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub base_domain: String,
    /// What this instance calls itself, in page titles and headings.
    ///
    /// One image serves many deployments — brolly.id, a Solid provider on
    /// someone else's domain, a community on a subdomain — and each of them is
    /// a different thing to the people using it. Hardcoding "Brolly" made every
    /// instance claim to be the flagship. Defaults to `base_domain`, which is
    /// never wrong even when nobody sets it.
    pub instance_name: String,
    /// One line describing this instance, shown by Mastodon clients.
    ///
    /// Configurable for the same reason as the name: every deployment is
    /// somebody else's community.
    pub instance_description: String,
    pub source_url: String,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    /// Whether this deployment ships a theme override: `theme.css` in the
    /// static dir, `COPY`ed in by a derived image.
    ///
    /// A bool rather than a path because nothing is decided per request —
    /// `ServeDir` already serves whatever is in the static dir — so the pages
    /// only need to know whether to link it. Detected once at startup, and
    /// loudly: a `theme.css` that exists but is not a regular file (a botched
    /// bind mount creates a *directory* at the target) is a startup failure
    /// with the path in the log, not a silently unthemed deployment.
    pub theme_css: bool,
    /// Whether this instance lets anyone register, or only invite-holders.
    ///
    /// `BROLLY_PUBLIC_REGISTRATION`, read once at startup. The default is the
    /// conservative one — **invite-only** — because an open registration form
    /// is an abuse surface a small private community never asked for, while a
    /// public deployment (a pod provider with a signup page) sets one variable
    /// to open the door. The policy governs both registration surfaces, the
    /// The policy governs both registration surfaces, the
    /// `/register` form and the `POST /api/accounts` API: on a private
    /// instance the API requires an invite exactly as the form does, so the
    /// API is not a way around the door.
    pub public_registration: bool,
    /// The door's rate limits: one bucket per gate and key, in memory. See
    /// [`ratelimit`].
    pub limiter: std::sync::Arc<ratelimit::Limiter>,
    /// Where `www.{base_domain}` redirects to, when it redirects.
    ///
    /// `BROLLY_WWW_REDIRECT`, read once at startup: an absolute URL — a
    /// marketing site, a landing page, another deployment's public surface —
    /// that every request to the `www` host is sent to with its path and
    /// query intact. `www` is a reserved username, so no member can ever own
    /// the host and the redirect can never shadow a pod.
    ///
    /// Unset, the `www` host keeps its incidental behaviour: it matches the
    /// apex's routes (login, register) because routing is by path, while the
    /// host-checked surfaces (OAuth, pods) 404 it — a broken half-apex that
    /// exists only because nothing claimed the name. Setting the variable
    /// claims it.
    pub www_redirect: Option<String>,
    /// The app in front of this instance, if there is one. See [`FrontEnd`].
    pub front_end: FrontEnd,
    /// The one upload limit (spec 4, H3): the `DefaultBodyLimit` on the pod
    /// and media routes. Instance state rather than a constant at the route,
    /// because `BROLLY_MAX_UPLOAD_BYTES` overrides it — read once in `main`,
    /// before the state is built, and threaded here. Defaults to the same
    /// constant the Mastodon instance configuration advertises.
    pub max_upload_bytes: usize,
    /// How much a member's pod may hold, in bytes on disk, before a write is
    /// refused with 507. `BROLLY_POD_QUOTA_BYTES`, read once in `main`;
    /// defaults to `media::DEFAULT_POD_QUOTA_BYTES`.
    pub pod_quota_bytes: u64,
    pub stores: std::sync::Arc<brolly_store::StoreManager>,
    /// The Solid-OIDC provider's signing key, loaded once at startup.
    ///
    /// Instance state rather than a per-request lookup: it signs and verifies
    /// on every token operation, and re-reading it from Postgres each time
    /// would put a round trip in the middle of every authenticated request.
    pub provider_key: std::sync::Arc<brolly_solid::oidc::keys::ProviderKey>,
    /// The instance's own actor identity (D4).
    ///
    /// Signs outbound delivery on the instance's behalf and backs the shared
    /// inbox. Loaded once at startup for the same reason as `provider_key`.
    pub instance_actor: std::sync::Arc<brolly_identity::instance::ActorKeys>,
    /// Live firehose events, for consumers already attached (1, E).
    ///
    /// A broadcast channel and *not* the durable record — the log in Postgres
    /// is what lets a consumer that drops resume. This only saves attached
    /// consumers a poll, and carries every kind the log does: a relay that
    /// never hears an `#account` event while connected is exactly the consumer
    /// the log exists to protect. A lagging receiver is dropped by the channel
    /// rather than allowed to grow unbounded; the stream names the outcome —
    /// the lexicon's `ConsumerTooSlow` — and closes, and the consumer
    /// reconnects with its cursor and backfills, which is the path that
    /// already exists (1, F).
    ///
    /// Fed by two senders (1, G): the writers' fast-path sends, and the shared
    /// `LISTEN` task (spawned in `main`) whose rebroadcasts are what make
    /// delivery correct rather than merely fast — an event written by another
    /// process reaches a live subscriber through it.
    pub commits: tokio::sync::broadcast::Sender<brolly_atproto::firehose::Event>,
    /// Used to register `did:plc` operations with the directory.
    ///
    /// `None` disables submission without disabling identity: keys, DID and
    /// repo are still created, and the operation waits in
    /// `identity::unsubmitted`. That is the right shape for local development
    /// and for a first boot behind a firewall — a member who cannot be
    /// published yet is very different from a member who was never given an
    /// identity at all (ADR 0016).
    pub plc_client: Option<reqwest::Client>,
    /// Where ATProto OAuth client metadata comes from.
    ///
    /// The network in production (`client_metadata::Fetcher`), a fixed,
    /// validated set in tests (`client_metadata::StaticClients`). A trait
    /// object so tests never need a TLS server to register a client.
    pub clients: std::sync::Arc<
        dyn client_metadata::ClientLookup<
                Document = brolly_atproto::client_metadata::ClientMetadata,
                Invalid = brolly_atproto::client_metadata::ClientError,
            >,
    >,
    /// Where Solid-OIDC Client ID Documents come from (spec 6, H3).
    ///
    /// The same transport as `clients`, parameterized for RDF: an `https://`
    /// client_id at `authorize` is fetched and validated here rather than
    /// looked up in a table. A trait object for the same reason.
    pub solid_clients: std::sync::Arc<
        dyn client_metadata::ClientLookup<
                Document = brolly_solid::client_documents::ClientIdDocument,
                Invalid = brolly_solid::client_documents::InvalidDocument,
            >,
    >,
    /// Where a foreign Solid-OIDC issuer's discovery document comes from
    /// (spec 6, H5).
    ///
    /// The same transport again, parameterized for JSON: a token whose `iss`
    /// names another issuer takes the remote path, which fetches that
    /// issuer's discovery document here, cached per issuer. A trait object
    /// for the same reason as `clients`.
    pub issuer_discovery: std::sync::Arc<
        dyn client_metadata::ClientLookup<
                Document = brolly_solid::oidc::tokens::RemoteDiscovery,
                Invalid = brolly_solid::oidc::tokens::InvalidDiscovery,
            >,
    >,
    /// Where a foreign issuer's key set comes from (spec 6, H5) — fetched
    /// from the `jwks_uri` its discovery document names, with the one
    /// cache-bypassing re-fetch a key rotation forces.
    pub issuer_jwks: std::sync::Arc<
        dyn client_metadata::ClientLookup<
                Document = brolly_solid::oidc::tokens::RemoteJwks,
                Invalid = brolly_solid::oidc::tokens::InvalidJwks,
            >,
    >,
    /// Where a remote WebID's profile document comes from (spec 6, H5) —
    /// the dereference the issuer binding reads, cached per WebID.
    pub webid_documents: std::sync::Arc<
        dyn client_metadata::ClientLookup<
                Document = brolly_solid::webid_documents::WebIdDocument,
                Invalid = brolly_solid::webid_documents::InvalidWebIdDocument,
            >,
    >,
}

/// The upstream repository, and the default value of `BROLLY_SOURCE_URL`.
///
/// AGPL-3.0 §13 (ADR 0003) obliges an operator running a modified copy to offer
/// their users the source. This is that offer, so it has no unset state — an
/// operator running a fork points the variable at theirs.
///
/// The default is **provisional**: `www.brolly.id` is the flagship instance's
/// front page, not a source repository, so it does not yet discharge §13.
/// Point this at the repository once there is a public one.
pub const SOURCE_URL_DEFAULT: &str = "https://www.brolly.id";

/// What every page's chrome renders, regardless of which page it is.
///
/// One field on every page struct rather than six, because `base.html`'s
/// footer renders the fine print and Askama type-checks an `{% include %}`
/// against the *including* struct. The upside of the indirection is that a new
/// page cannot compile without it.
pub struct Chrome<'a> {
    pub instance_name: &'a str,
    pub instance_description: &'a str,
    pub source_url: &'a str,
    pub terms_url: Option<&'a str>,
    pub privacy_url: Option<&'a str>,
    /// Whether to link the deployment's `theme.css` override. See
    /// [`AppState::theme_css`].
    pub theme_css: bool,
}

impl AppState {
    pub fn chrome(&self) -> Chrome<'_> {
        Chrome {
            instance_name: &self.instance_name,
            instance_description: &self.instance_description,
            source_url: &self.source_url,
            terms_url: self.terms_url.as_deref(),
            privacy_url: self.privacy_url.as_deref(),
            theme_css: self.theme_css,
        }
    }
}

/// The CORS posture for the whole server.
///
/// Solid is a browser protocol. An app at another origin dereferences a
/// member's WebID, reads the discovery document, registers itself, exchanges a
/// token and then reads the pod — every one of those is a cross-origin fetch,
/// and without these headers the browser refuses to hand the response to the
/// script. There was no CORS here at all, which made the server unusable from
/// any browser-based Solid client however correct its endpoints were.
///
/// **Hand-rolled rather than `tower_http::cors`, for one specific reason.**
/// That layer short-circuits *every* `OPTIONS` request as a preflight
/// (`cors/mod.rs:715`, no check for `Access-Control-Request-Method`). LDP uses
/// `OPTIONS` for capability discovery — it is how a client learns which PATCH
/// syntaxes a resource accepts — so using that layer silently replaced those
/// answers with an empty preflight. A preflight is `OPTIONS` **with**
/// `Access-Control-Request-Method`; a bare `OPTIONS` is a real request and has
/// to reach the handler.
///
/// **The origin is echoed, with no `Allow-Credentials`, and the omission is
/// the security-critical half.** Echoing the origin *with* credentials would
/// let any site on the web make cookie-authenticated requests to the dashboard
/// and read the answers. Solid authenticates with a `DPoP` or `Authorization`
/// header the calling script must already hold, never with our cookie, so the
/// echo costs nothing and grants nothing: a cross-origin script with no token
/// is anonymous, and WAC treats it accordingly. With credentials disallowed,
/// echoing and `*` grant a browser identical permission; the echo is for
/// caches, which can key on it, and for CTS, which checks for it. A request
/// with no `Origin` keeps the wildcard.
///
/// **A preflight is answered with the headers it asked for**, rather than from
/// a fixed list that can never admit one it doesn't already name (Solid §8.1).
/// The echoed value is a `HeaderValue` the `http` crate already parsed out of
/// the request, so it cannot carry a newline into the response.
///
/// The session cookie is `SameSite=Lax` besides, so it is not sent on a
/// cross-site subresource request in the first place. These headers change only
/// which responses a script may *read*, never which requests reach the server,
/// so they add no CSRF surface.
async fn cors(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    // Read what the answer depends on before the request is consumed.
    let origin = request.headers().get(header::ORIGIN).cloned();
    let requested = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned();

    let mut response = if preflight {
        axum::http::StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };

    // The fallback for a response that isn't answering a preflight, where the
    // field means nothing to a browser but has always been sent. `dpop` and
    // `slug` are not on the CORS safelist, so any request carrying one is
    // preflighted and fails unless named.
    const ALLOW_HEADERS: &str =
        "authorization, dpop, content-type, accept, slug, link, if-match, if-none-match";
    // A script sees only safelisted response headers unless they are exposed.
    // `location` after a POST and `link` for the ACL are load-bearing in LDP;
    // `www-authenticate` is how a client learns to re-authenticate (H3) and
    // `vary` is how it learns what the answer depended on (H10). `updates-via`
    // is gone: nothing sends it until stage 7, and an expose list is a promise.
    const EXPOSE_HEADERS: &str = "location, link, etag, allow, accept-patch, \
         accept-post, accept-put, wac-allow, www-authenticate, vary";

    let headers = response.headers_mut();
    for (name, value) in [
        (
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
        ),
        (header::ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE_HEADERS),
        (header::ACCESS_CONTROL_MAX_AGE, "86400"),
    ] {
        headers.insert(name, axum::http::HeaderValue::from_static(value));
    }
    // Echoed when there is one to echo; a request with no `Origin` — curl, a
    // `file://` page — still needs the wildcard to read anything.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        origin.unwrap_or(axum::http::HeaderValue::from_static("*")),
    );
    // A preflight is answered with what it asked for: CTS also checks we don't
    // name headers the preflight didn't ask for.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        requested.unwrap_or(axum::http::HeaderValue::from_static(ALLOW_HEADERS)),
    );
    // Appended, never inserted: the handler sets `Vary: Accept` on a
    // negotiated read (H10) and this layer is outermost, so an `insert` here
    // would drop it. On every response, binaries and refusals included —
    // `Allow-Origin` depends on `Origin` whatever the status.
    headers.append(header::VARY, axum::http::HeaderValue::from_static("Origin"));
    response
}

/// `X-Content-Type-Options: nosniff` on every response (spec 4, H4).
///
/// A browser that follows the header will not second-guess a response's
/// `Content-Type`, so a binary served with the type the server recorded — the
/// allow-list's decision, not the uploader's — is the type it is rendered as.
/// The header is harmless where it is redundant and load-bearing where a type
/// could be second-guessed, and one layer at composition is how it stays on
/// every response: per-route application is how it ends up missing on the one
/// route that matters.
///
/// Two more ride the same layer, for the same reason:
///
/// * `Content-Security-Policy: frame-ancestors …`, and `X-Frame-Options` to
///   match for the browsers that predate CSP 2 — **decided per host** (ADR
///   0018). On the apex, `'none'`/`DENY`: the consent screen is there,
///   rendered inside somebody else's OAuth flow, and `SameSite=Lax` is not
///   its defence — `alice.<apex>` is same-site with the apex, so a document
///   on a member host could frame it with the member's own session and dress
///   the Authorise button as something else. This header is what keeps the
///   frame out, and ADR 0018 lists it among the controls a pod serving
///   documents rests on. On a member host, `'self'`/`SAMEORIGIN`: a pod page
///   carries no authority a foreign frame could abuse, SolidOS served from
///   the pod frames the pod's own documents for previews, and `'self'` is
///   what protects a pod-hosted *app* — which does hold the member's tokens
///   in that origin — from being framed by anyone else. The host test is
///   `subdomain_user`'s, so every subdomain-shaped host gets `'self'`,
///   `www` and unregistered names included; nothing is served there, so
///   nothing is lost.
/// * `Referrer-Policy: strict-origin-when-cross-origin`. A pod URL, an OAuth
///   `state`, a consent request token in a query — none of it belongs in
///   another site's access log.
///
/// No further CSP directives: a member's origin holds no credential the
/// instance issues to a browser, and a pod-hosted app's own tokens would not
/// be protected by a policy permissive enough to run the app (ADR 0018,
/// "What stays as it was").
async fn security_headers(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let member_host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|host| extract::subdomain_user(host, &state.base_domain).is_some());
    let mut response = next.run(request).await;
    // Inserted, not appended: nothing else writes these headers, so there is
    // no value to preserve, and a duplicate would be a spec violation either
    // way.
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    let (frame_ancestors, frame_options) = if member_host {
        ("frame-ancestors 'self'", "SAMEORIGIN")
    } else {
        ("frame-ancestors 'none'", "DENY")
    };
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(frame_ancestors),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static(frame_options),
    );
    headers.insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response
}

/// The paths a browser posts the instance's own forms to. Every one of them
/// is a page the instance renders, acted on with the session cookie, and a
/// post to any of them from another origin is refused by [`same_origin`]
/// before the handler runs. An entry ending in `/` is a prefix.
/// `server/tests/ui_invariants.rs` checks that every `<form method="post">` in
/// the templates lands here.
///
/// Not on the list, deliberately: the OAuth token, PAR and registration
/// endpoints, `/api/accounts`, the Mastodon client API, XRPC, and the pod —
/// all posted to from other origins by design, and none acted on with a
/// cookie.
pub const SAME_ORIGIN_FORMS: &[&str] = &[
    "/login",
    "/register",
    "/logout",
    "/account/profile",
    "/account/security",
    "/account/apps",
    "/account/delete",
    // The three consent decisions (ADR 0011): one screen, three callers.
    "/oauth/solid/authorize",
    "/oauth/authorize",
    "/oauth/atproto/authorize",
    // An entry ending in `/` is a prefix: the console's per-member actions
    // carry the username in the path.
    "/admin/users/",
];

/// Is `path` one the same-origin rule guards? An entry ending in `/` is a
/// prefix, anything else an exact path.
fn form_post_is_guarded(path: &str) -> bool {
    SAME_ORIGIN_FORMS.iter().any(|entry| {
        if let Some(prefix) = entry.strip_suffix('/') {
            path.strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
        } else {
            *entry == path
        }
    })
}

/// A form post from any origin but ours is refused.
///
/// `SameSite=Lax` keeps the session cookie off a cross-*site* post, and that
/// is the defence the forms have leaned on. It leans on a fact about the
/// deployment, not the request: `alice.<apex>` is same-site with the apex, so
/// the day a member can serve a document that submits a form — one
/// allow-list change — is the day Lax stops being a defence for the delete
/// button and the consent screen. This is the defence that does not depend
/// on that day never coming.
///
/// A browser names where a post came from in `Origin`, and every browser
/// sends it on a cross-origin post. When it is present it must be our apex
/// origin — `null`, which a sandboxed frame or a privacy mode sends, is not
/// ours. Absent, `Referer` is read the same way. Absent both, the post is let
/// through: no browser omits both on a cross-origin post, so what is left is
/// a same-origin post from an old browser, or a client that is not one.
async fn same_origin(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.method() == axum::http::Method::POST && form_post_is_guarded(request.uri().path()) {
        let ours = format!("https://{}", state.base_domain);
        let headers = request.headers();
        let from = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| {
                headers
                    .get(header::REFERER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|r| url::Url::parse(r).ok())
                    .map(|u| u.origin().ascii_serialization())
            });
        if let Some(from) = from
            && from != ours
        {
            return (StatusCode::FORBIDDEN, "cross-origin form post refused").into_response();
        }
    }
    next.run(request).await
}

/// Resolve the caller's address once per request, for the handlers that rate
/// limit on it (`ratelimit::client_key`): the proxy's word when there is a
/// proxy, the peer when `main` served with connect info, a shared key
/// otherwise. In the request's extensions rather than recomputed per handler,
/// so there is one answer to "who is this" per request.
async fn client_address(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0);
    let key = ratelimit::client_key(request.headers(), peer);
    request.extensions_mut().insert(ratelimit::ClientKey(key));
    next.run(request).await
}

/// Validate a `BROLLY_WWW_REDIRECT` value: an absolute `https` (or `http`, for
/// a local surface) URL with no query and no fragment, returned without its
/// trailing slash.
///
/// The query and fragment are refused because the redirect *appends* the
/// incoming request's own path and query to this base — a configured query
/// would be silently dropped for every request that carries one, and a
/// fragment never reaches the server at all. A path is allowed and becomes a
/// prefix (`https://example.org/stuccoid` + `/pricing` ->
/// `https://example.org/stuccoid/pricing`).
pub fn parse_www_redirect(value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|e| format!("not a URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme must be http or https, not {}",
            url.scheme()
        ));
    }
    if url.query().is_some() {
        return Err(
            "a query has nowhere to go: the redirect appends the request's own query".into(),
        );
    }
    if url.fragment().is_some() {
        return Err("a fragment is never sent to a server".into());
    }
    // Reconstruction rather than `url.as_str()`: `Url::parse` keeps whatever
    // it was given, and a trailing slash on the base would double up against
    // a path that starts with one.
    let mut base = format!("{}://{}{}", url.scheme(), url.authority(), url.path());
    while base.ends_with('/') {
        base.pop();
    }
    if base.ends_with(':') || base.is_empty() {
        return Err("no host".into());
    }
    Ok(base)
}

/// Another app in front of this instance: StuccoID in front of
/// `id.stucco.software`, a marketing site in front of a pod provider.
///
/// Each URL hands one of brolly's own pages to that app. Unset, brolly serves
/// the page itself, so a deployment with no front end is unchanged. Read once
/// in `main` and validated there, like `BROLLY_WWW_REDIRECT`: a typo is a
/// startup failure with the value in the log.
#[derive(Clone, Debug, Default)]
pub struct FrontEnd {
    /// `BROLLY_HOME_URL`: where the apex `/` sends a visitor instead of
    /// rendering the login form. `/login` still renders, because every OAuth
    /// flow sends people there.
    pub home: Option<String>,
    /// `BROLLY_SIGNUP_URL`: where `/register` sends a visitor. Set, accounts
    /// are created by the front end alone: the public `POST /api/accounts` is
    /// not mounted, whatever `BROLLY_PUBLIC_REGISTRATION` says.
    pub signup: Option<String>,
    /// `BROLLY_ACCOUNT_HOME`: where `/account/profile` and `/account/delete`
    /// send a member. The front end owns the profile and the account's end.
    pub account_home: Option<String>,
    /// `BROLLY_SERVICE_TOKEN`, hashed (`db::hash_secret`): the front end's
    /// credential for the service API. Unset, the API is not mounted.
    pub service_token_hash: Option<String>,
}

/// Validate a front-end URL: absolute, `http` or `https`, with a host.
/// Returned as the URL parser normalizes it.
///
/// Unlike [`parse_www_redirect`] nothing is appended to it, so a query is
/// allowed and kept.
pub fn parse_front_end_url(value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|e| format!("not a URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme must be http or https, not {}",
            url.scheme()
        ));
    }
    if url.host_str().is_none() {
        return Err("no host".into());
    }
    Ok(url.to_string())
}

/// Send the `www` host wherever the deployment pointed it (`BROLLY_WWW_REDIRECT`).
///
/// Routing is by path, so without this the `www` host matches the apex's
/// routes — the unchecked ones (`/health` and `/static` among them) answer,
/// while the host-checked surfaces (the door, the dashboard and the console
/// since `0a465e0`, the OAuth sub-router, the pods) answer 404 — a broken
/// half-apex under a name no member can own (`www` is reserved). Configured,
/// every request to the host is sent to the configured base with its path
/// and query intact, so a deep link to `www.{base}/pricing` lands on the
/// target's `/pricing`.
///
/// **308, and everything redirects, not just `GET`.** The `www` host is not
/// a surface this server serves — it is an alias for one that lives elsewhere
/// — so there is no method or path here to be selective about. A browser
/// follows a 308 without changing the method or the body (RFC 9110
/// §15.4.9), which is what an alias owes every caller.
///
/// Layered inside `cors`, so a cross-origin script that fetches a `www` URL
/// still receives the CORS headers on the redirect it must be able to read.
async fn www_redirect(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Read the host, path and query before the request is consumed.
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(str::to_string);

    // Only the exact `www` subdomain, by the same normalization
    // `subdomain_user` applies (case, port), and only when a target is
    // configured — an unset variable leaves every host exactly as it was.
    if let Some(base) = state.www_redirect.as_deref()
        && extract::subdomain_user(&host, &state.base_domain).as_deref() == Some("www")
    {
        let location = match query {
            Some(query) => format!("{base}{path}?{query}"),
            None => format!("{base}{path}"),
        };
        return (
            StatusCode::PERMANENT_REDIRECT,
            [(header::LOCATION, location)],
            "www lives elsewhere",
        )
            .into_response();
    }

    next.run(request).await
}

/// Build the application router.
///
/// Adapters contribute their own routers here. Nothing else in the workspace
/// constructs a `Router` at the top level.
pub fn app(state: AppState, static_dir: &str) -> Router {
    // Solid-OIDC (ADR 0008). Its own router so `apex_only` can wrap the whole
    // surface: the guard has to run before extraction, or a wrong method or an
    // unparseable body answers on a user subdomain with 405/415 instead of the
    // 404 the ADR requires.
    let oauth = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(solid_oidc::discovery),
        )
        .route("/oauth/solid/jwks", get(solid_oidc::jwks))
        .route("/oauth/solid/register", post(solid_oidc::register))
        .route(
            "/oauth/solid/authorize",
            get(solid_oidc::authorize).post(solid_oidc::decide),
        )
        .route("/oauth/solid/token", post(solid_oidc::token))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            solid_oidc::apex_only,
        ));

    // Account creation as an API, for a signup surface on another origin. The
    // same `apex_only` guard for the same reason as the OAuth surface: a
    // member's subdomain is their pod, and an instance-level endpoint does not
    // answer there (ADR 0009). Not mounted at all when a front end owns
    // signup (`BROLLY_SIGNUP_URL`): it creates accounts through the service
    // API, and a second public door would create accounts it never sees.
    let accounts = if state.front_end.signup.is_some() {
        Router::new()
    } else {
        Router::new()
            .route("/api/accounts", post(auth::create_account))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                solid_oidc::apex_only,
            ))
    };

    // The service API, for the app in front of the instance (`FrontEnd`).
    // Not mounted without a token: an unconfigured instance has no such API.
    let internal = if state.front_end.service_token_hash.is_some() {
        internal_api::routes(state.clone())
    } else {
        Router::new()
    };

    // The instance's own pages — the door, the member dashboard, the admin
    // console — and nothing of a member's. A member's subdomain is their pod
    // (ADR 0009), and `apex_only` wraps the group for the reason it wraps the
    // OAuth surface: a login form on alice.<apex> is a place to type a
    // password the instance never named, and a session minted there would be
    // a host-only cookie on a member host — the one host a member's own
    // documents are served from, and so the one host a session cookie must
    // never exist on. `/` gets the same guard on its own route, below: ADR
    // 0010 reserves a member's root for a profile page that does not exist
    // yet, and until it does the root answers what `subdomain_fallback`
    // answers for `SubdomainRoute::Root` — a 404 — not the login form the
    // route order used to let through.
    let door = Router::new()
        // Auth surfaces ship with identity, not after it (plan §4.4).
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route(
            "/register",
            get(auth::register_form).post(auth::register_submit),
        )
        // POST so a prefetch or a cross-site <img> cannot log someone out.
        .route("/logout", post(auth::logout))
        // The member dashboard (plan §4.4).
        .route("/account", get(account::overview))
        .route(
            "/account/profile",
            get(account::profile_form).post(account::profile_submit),
        )
        .route(
            "/account/security",
            get(account::security).post(account::change_password),
        )
        .route(
            "/account/apps",
            get(account::apps).post(account::revoke_app),
        )
        .route("/account/export", get(account::export))
        .route(
            "/account/delete",
            get(account::delete_form).post(account::delete_account),
        )
        // The admin console (plan §4.4).
        .route("/admin", get(admin::overview))
        .route("/admin/users", get(admin::users))
        .route("/admin/users/{username}/quota", post(admin::set_quota))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            solid_oidc::apex_only,
        ));

    Router::new()
        // `/` is the login form, or the front end's homepage when there is
        // one (`auth::home`); `/login` is always the form. Collapsing them
        // would mean re-pointing five redirects that target the login form
        // (account.rs, solid_oidc.rs, mastodon_oauth.rs, atproto_oauth.rs,
        // admin.rs) — the fiddliest flows in the workspace.
        .route(
            "/",
            get(auth::home).layer(axum::middleware::from_fn_with_state(
                state.clone(),
                solid_oidc::apex_only,
            )),
        )
        .route("/health", get(health))
        // The door, the dashboard and the console: apex-only, below.
        .merge(door)
        // ActivityPub discovery. `/actor` is served on both the apex and
        // member subdomains and means a different actor on each — one route
        // with a host branch, because a route matches before the host is
        // looked at and two would shadow each other.
        // The WebID profile document. Subdomain-only: the apex's identity is
        // an actor, not a person. This is what a Solid client dereferences to
        // discover the issuer, so without it WebID login is impossible.
        // Since spec 6 (H1) it is writable by its owner: `PUT` replaces the
        // graph and `PATCH` patches it, both through the LDP write path with
        // the profile graph as the target. `DELETE` and `POST` — and any other
        // method — get the method router's own 405, which carries its `Allow`
        // (5b, H16). `/profile` stays a protocol resource in
        // `USER_PROTOCOL_RESOURCES`: this is a write handler on a projection,
        // not LDP content under `/~/`.
        .route(
            "/profile",
            get(profile::profile_document)
                .put(profile::put_document)
                .patch(profile::patch_document),
        )
        .route("/actor", get(activitypub::actor_document))
        // The actor's collections. Followers and following are public, as the
        // fediverse expects; the inbox is the member's home timeline (D6) and
        // is owner-only. POST /inbox — federation ingress — stays unrouted
        // until Phase 8, because accepting it without HTTP-signature
        // verification would let anyone write into anyone's timeline.
        .route("/followers", get(activitypub::followers_collection))
        .route("/following", get(activitypub::following_collection))
        .route("/inbox", get(activitypub::inbox_collection))
        // The publication surface (ADR 0012): a write here is a post,
        // the same write anywhere in the pod is private CRUD.
        .route("/outbox", post(outbox::publish))
        .route("/.well-known/webfinger", get(activitypub::webfinger))
        .route(
            "/.well-known/nodeinfo",
            get(activitypub::nodeinfo_discovery),
        )
        // The storage description (Solid Protocol §4.1). Served on every pod
        // subdomain; the handler resolves the host itself, as `/profile`
        // does, and 404s on the apex. `any`, not `get`: the method router's
        // own 405 would answer on the apex too, where the resource doesn't
        // exist, and the handler's 405 carries an `Allow` we chose.
        .route("/.well-known/solid", any(pod::storage_description))
        .route("/nodeinfo/2.1", get(activitypub::nodeinfo))
        // Mastodon owns the bare OAuth paths, because its clients hardcode
        // them and it is the only protocol with no discovery document to be
        // told otherwise (ADR 0008).
        .route("/api/v1/apps", post(mastodon_oauth::register_app))
        .route(
            "/oauth/authorize",
            get(mastodon_oauth::authorize).post(mastodon_oauth::decide),
        )
        .route("/oauth/token", post(mastodon_oauth::token))
        .route("/oauth/revoke", post(mastodon_oauth::revoke))
        // The Client API. Everything under /api/ answers JSON, including its
        // 404s — the predecessor let unmatched paths fall through to the LDP
        // router and hand clients RDF they cannot parse. Its upload routes
        // carry the one upload limit (spec 4, H3), threaded from the state so
        // the enforced number and the advertised one come from one place.
        .merge(mastodon_api::routes(state.max_upload_bytes))
        // XRPC on the apex, with the repo named by parameter — the shape a PDS
        // has and the endpoint the PLC document advertises.
        .merge(xrpc::routes())
        .merge(atproto_oauth::routes())
        .merge(oauth)
        .merge(accounts)
        .merge(internal)
        // Pod storage (ADR 0010). The catch-all lives INSIDE /~/, so it cannot
        // shadow a protocol endpoint — that is the whole point of the prefix.
        // The upload limit (spec 4, H3) is the method router's own layer, so
        // it bounds every body these routes take — RDF included — without
        // touching any other route's.
        .route(
            "/~/{*path}",
            get(pod::get)
                .put(pod::put)
                .post(pod::post)
                .patch(pod::patch)
                .delete(pod::delete)
                .options(pod::options)
                .layer(axum::extract::DefaultBodyLimit::max(state.max_upload_bytes)),
        )
        // The storage root. The wildcard above doesn't match an empty
        // remainder, so the root needs every method of its own. That includes
        // the ones it always refuses: without a route, axum answers 405 before
        // WAC runs, and the root's protections are unreachable (5b, H12).
        .route(
            "/~/",
            get(pod::get_root)
                .put(pod::put_root)
                .post(pod::post_root)
                .patch(pod::patch_root)
                .delete(pod::delete_root)
                .options(pod::options_root)
                .layer(axum::extract::DefaultBodyLimit::max(state.max_upload_bytes)),
        )
        .nest_service("/static", ServeDir::new(static_dir))
        // Default-deny on subdomains. No LDP fallback (ADR 0010).
        .fallback(pod::subdomain_fallback)
        // The `www` host, when the deployment points it somewhere
        // (`BROLLY_WWW_REDIRECT`). Inside the layers below so the redirect
        // still carries `nosniff` and answers a cross-origin caller's CORS
        // read.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            www_redirect,
        ))
        // `nosniff`, `frame-ancestors`, per host, and the referrer policy on
        // every response (spec 4, H4). One layer here, not per route:
        // per-route application is how a header ends up missing on the one
        // route that matters, and the cost of the redundant cases is zero.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        // Form posts come from our own pages or not at all.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            same_origin,
        ))
        // The caller's address for the door's rate limits, resolved once.
        .layer(axum::middleware::from_fn(client_address))
        // Outermost, so it covers the OAuth sub-router and the fallback too —
        // a 404 that a browser cannot read is a 404 nobody can debug.
        .layer(axum::middleware::from_fn(cors))
        .with_state(state)
}

/// `GET /health` — liveness probe. No auth, no dependencies.
async fn health() -> Response {
    ([("content-type", "application/json")], r#"{"status":"ok"}"#).into_response()
}

/// Render an Askama template into an HTML response.
///
/// The single rendering helper for the whole server. HTML is never built with
/// `format!` — see the UI invariants in the implementation plan §4.5.
pub fn render<T: askama::Template>(template: &T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "template render failed");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "template render failed",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod same_origin_tests {
    use super::*;

    #[test]
    fn a_listed_prefix_covers_the_paths_under_it_and_nothing_else() {
        assert!(form_post_is_guarded("/login"));
        assert!(form_post_is_guarded("/admin/users/alice/quota"));
        assert!(form_post_is_guarded("/admin/users/alice/anything-later"));
        assert!(
            !form_post_is_guarded("/admin/users"),
            "the list page itself is a GET"
        );
        assert!(
            !form_post_is_guarded("/admin/userspace"),
            "a prefix is a path prefix"
        );
        assert!(!form_post_is_guarded("/oauth/solid/token"));
    }
}

#[cfg(test)]
mod front_end_tests {
    use super::*;

    #[test]
    fn a_front_end_url_is_an_absolute_http_url() {
        assert_eq!(
            parse_front_end_url("https://stuccoid.stucco.software/account/create"),
            Ok("https://stuccoid.stucco.software/account/create".to_string())
        );
        assert_eq!(
            parse_front_end_url("http://localhost:5173/"),
            Ok("http://localhost:5173/".to_string())
        );
        // A bare origin gains the slash every browser would send anyway.
        assert_eq!(
            parse_front_end_url("https://stuccoid.stucco.software"),
            Ok("https://stuccoid.stucco.software/".to_string())
        );
    }

    #[test]
    fn what_is_not_a_front_end_url_is_refused() {
        assert!(parse_front_end_url("").is_err());
        assert!(parse_front_end_url("/account/create").is_err());
        assert!(parse_front_end_url("ftp://example.org/").is_err());
        assert!(parse_front_end_url("mailto:someone@example.org").is_err());
    }

    #[test]
    fn the_default_front_end_is_brolly_itself() {
        let front_end = FrontEnd::default();
        assert!(front_end.home.is_none());
        assert!(front_end.signup.is_none());
        assert!(front_end.account_home.is_none());
        assert!(front_end.service_token_hash.is_none());
    }
}
