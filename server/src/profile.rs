//! The WebID profile document, served at a member's `/profile`.
//!
//! This is the node every protocol asserts onto (D8) and the one a Solid client
//! is handed when somebody types their WebID into an app. Until now it was
//! reserved in [`brolly_identity::routing`] and served by nothing, so
//! dereferencing a WebID returned `501` — which meant no conformant Solid
//! client could discover the issuer, and therefore none could log a member in.
//!
//! Two audiences, one URL. A client asks for RDF and gets Turtle by default; a
//! browser asks for HTML and gets a page it can read. The negotiation checks
//! HTML *first* rather than deferring to [`brolly_domain::syntax::negotiate`],
//! because a browser sends `text/html,…,*/*;q=0.8` and the `*/*` arm would
//! otherwise hand it a Turtle download.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use brolly_domain::syntax;
use brolly_identity::db::User;
use brolly_identity::{extract, routing, webid};

use crate::{AppState, Chrome, render};

/// The subject IRI, its document, and where the pod lives.
struct Identity {
    webid: String,
    document: String,
    storage_root: String,
}

fn identity(username: &str, base_domain: &str) -> Identity {
    Identity {
        webid: webid::webid(username, base_domain),
        document: webid::profile_document(username, base_domain),
        storage_root: routing::storage_root(username, base_domain),
    }
}

/// Whether the caller would rather read this than parse it.
///
/// Deliberately not `syntax::negotiate`: that maps `*/*` to Turtle, and every
/// browser sends `*/*` as a low-quality fallback after `text/html`.
fn wants_html(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    accept
        .split(',')
        .map(|part| part.split(';').next().unwrap_or("").trim())
        .any(|media| media == "text/html" || media == "application/xhtml+xml")
}

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileDocument<'a> {
    chrome: Chrome<'a>,
    username: &'a str,
    webid: &'a str,
    storage_root: &'a str,
    issuer: &'a str,
    display_name: &'a str,
    bio: &'a str,
}

/// `GET /profile` on a member subdomain.
///
/// Apex has no profile — the instance's own identity is an actor, not a person
/// — so it 404s there rather than inventing one.
pub async fn profile_document(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let Some(username) = extract::subdomain_user(host, &state.base_domain) else {
        return not_found();
    };

    let user = match brolly_identity::db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) if user.is_active() => user,
        Ok(_) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "profile lookup failed");
            return server_error();
        }
    };

    let Ok(pod) = state.stores.pod(user.id) else {
        tracing::error!(user = %user.id, "pod unavailable serving a profile");
        return server_error();
    };

    let id = identity(&user.username, &state.base_domain);
    // The issuer is this instance. It is the same value `/.well-known/
    // openid-configuration` publishes, and a client compares the two.
    let issuer = format!("https://{}", state.base_domain);

    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());
    if wants_html(accept) {
        return html(&state, &user, &id, &issuer, &pod);
    }

    let quads = brolly_solid::profile::document(
        &pod.read_store(),
        &id.webid,
        &id.document,
        &id.storage_root,
        &issuer,
    );
    let format = syntax::negotiate(accept);
    match syntax::serialize(&quads, format) {
        Ok(body) => (
            [(header::CONTENT_TYPE, format.media_type().to_string())],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "serialising a profile failed");
            server_error()
        }
    }
}

fn html(
    state: &AppState,
    user: &User,
    id: &Identity,
    issuer: &str,
    pod: &brolly_store::resources::Pod,
) -> Response {
    let profile = brolly_solid::profile::read(&pod.read_store(), &id.webid, &id.document);
    render(&ProfileDocument {
        chrome: state.chrome(),
        username: &user.username,
        webid: &id.webid,
        storage_root: &id.storage_root,
        issuer,
        display_name: &profile.display_name,
        bio: &profile.bio,
    })
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "no such profile").into_response()
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Try again.",
    )
        .into_response()
}
