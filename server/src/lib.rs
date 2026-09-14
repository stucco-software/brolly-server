//! Composes the adapters, owns [`app`], and spawns workers.
//!
//! **This is the only crate that may depend on more than one adapter, and the
//! only crate that may define `app()`.** Both rules are enforced by
//! `tests/architecture.rs`; together they are what keeps the dependency graph
//! acyclic. See `docs/greenfield-implementation-plan.md` §2.1.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use axum::Router;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use sqlx::PgPool;
use tower_http::services::ServeDir;

pub mod account;
pub mod activitypub;
pub mod admin;
pub mod atproto_oauth;
pub mod auth;
pub mod consent;
pub mod mastodon_api;
pub mod mastodon_oauth;
pub mod outbox;
pub mod pod;
pub mod provision;
pub mod solid_oidc;
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
        .route("/actor", get(activitypub::actor_document))
        // The publication surface (ADR 0012): a write here is a post,
        // the same write anywhere in the pod is private CRUD.
        .route("/outbox", post(outbox::publish))
        .route("/.well-known/webfinger", get(activitypub::webfinger))
        .route(
            "/.well-known/nodeinfo",
            get(activitypub::nodeinfo_discovery),
        )
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
        .route(
            "/~/",
            get(pod::get_root)
                .post(pod::post_root)
                .options(pod::options),
        )
        .nest_service("/static", ServeDir::new(static_dir))
        // Default-deny on subdomains. No LDP fallback (ADR 0010).
        .fallback(pod::subdomain_fallback)
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
