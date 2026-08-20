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

pub mod auth;
pub mod consent;
pub mod views;

/// Everything a handler needs. Composed here because `server` is the only crate
/// permitted to depend on more than one adapter.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub base_domain: String,
}

/// Build the application router.
///
/// Adapters contribute their own routers here. Nothing else in the workspace
/// constructs a `Router` at the top level.
pub fn app(state: AppState, static_dir: &str) -> Router {
    Router::new()
        .route("/", get(views::landing))
        .route("/health", get(health))
        // Auth surfaces ship with identity, not after it (plan §4.4).
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route(
            "/register",
            get(auth::register_form).post(auth::register_submit),
        )
        // POST so a prefetch or a cross-site <img> cannot log someone out.
        .route("/logout", post(auth::logout))
        .nest_service("/static", ServeDir::new(static_dir))
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
