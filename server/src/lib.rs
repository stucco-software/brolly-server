//! Composes the adapters, owns [`app`], and spawns workers.
//!
//! **This is the only crate that may depend on more than one adapter, and the
//! only crate that may define `app()`.** Both rules are enforced by
//! `tests/architecture.rs`; together they are what keeps the dependency graph
//! acyclic. See `docs/greenfield-implementation-plan.md` §2.1.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use axum::Router;
use axum::http::{Method, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use sqlx::PgPool;
use tower_http::services::ServeDir;

pub mod account;
pub mod activitypub;
pub mod admin;
pub mod atproto_oauth;
pub mod auth;
pub mod client_metadata;
pub mod consent;
pub mod mastodon_api;
pub mod mastodon_oauth;
pub mod outbox;
pub mod pod;
pub mod profile;
pub mod provision;
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
    /// Live commit events, for consumers already attached to the firehose.
    ///
    /// A broadcast channel and *not* the durable record — the log in Postgres
    /// is what lets a consumer that drops resume. This only saves attached
    /// consumers a poll. A lagging receiver is dropped by the channel rather
    /// than allowed to grow unbounded; it reconnects with its cursor and
    /// backfills, which is the path that already exists.
    pub commits: tokio::sync::broadcast::Sender<brolly_atproto::firehose::CommitEvent>,
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
/// One field on every page struct rather than five, because `base.html`'s
/// footer renders the fine print and Askama type-checks an `{% include %}`
/// against the *including* struct. The upside of the indirection is that a new
/// page cannot compile without it.
pub struct Chrome<'a> {
    pub instance_name: &'a str,
    pub instance_description: &'a str,
    pub source_url: &'a str,
    pub terms_url: Option<&'a str>,
    pub privacy_url: Option<&'a str>,
}

impl AppState {
    pub fn chrome(&self) -> Chrome<'_> {
        Chrome {
            instance_name: &self.instance_name,
            instance_description: &self.instance_description,
            source_url: &self.source_url,
            terms_url: self.terms_url.as_deref(),
            privacy_url: self.privacy_url.as_deref(),
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

    Router::new()
        // `/` and `/login` are one template on two routes. Collapsing them
        // would mean re-pointing five redirects that target the login form
        // (account.rs, solid_oidc.rs, mastodon_oauth.rs, atproto_oauth.rs,
        // admin.rs) — the fiddliest flows in the workspace.
        .route("/", get(auth::login_form))
        .route("/health", get(health))
        // Auth surfaces ship with identity, not after it (plan §4.4).
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route(
            "/register",
            get(auth::register_form).post(auth::register_submit),
        )
        // POST so a prefetch or a cross-site <img> cannot log someone out.
        .route("/logout", post(auth::logout))
        // The member dashboard (plan §4.4). Apex-only in practice because a
        // subdomain's `/account` is a pod path, not this.
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
        // The admin console (plan §4.4). Apex-only for the same reason as
        // `/account`, and `/admin/*` is already a reserved path on member
        // subdomains by ADR 0009.
        .route("/admin", get(admin::overview))
        .route("/admin/users", get(admin::users))
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
        // router and hand clients RDF they cannot parse.
        .merge(mastodon_api::routes())
        // XRPC on the apex, with the repo named by parameter — the shape a PDS
        // has and the endpoint the PLC document advertises.
        .merge(xrpc::routes())
        .merge(atproto_oauth::routes())
        .merge(oauth)
        // Pod storage (ADR 0010). The catch-all lives INSIDE /~/, so it cannot
        // shadow a protocol endpoint — that is the whole point of the prefix.
        .route(
            "/~/{*path}",
            get(pod::get)
                .put(pod::put)
                .post(pod::post)
                .patch(pod::patch)
                .delete(pod::delete)
                .options(pod::options),
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
                .options(pod::options_root),
        )
        .nest_service("/static", ServeDir::new(static_dir))
        // Default-deny on subdomains. No LDP fallback (ADR 0010).
        .fallback(pod::subdomain_fallback)
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
