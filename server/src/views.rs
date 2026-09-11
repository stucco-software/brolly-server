//! Server-rendered views.
//!
//! Askama templates, progressive enhancement, no SPA (decision in the
//! implementation plan §4.2). Every form works with JavaScript disabled.

use askama::Template;
use axum::extract::State;
use axum::response::Response;
use axum_extra::extract::CookieJar;

use crate::AppState;
use crate::auth::session_user;
use crate::render;

#[derive(Template)]
#[template(path = "landing.html")]
struct Landing<'a> {
    instance_name: &'a str,
    /// `Some` when a member is signed in. The front door is the default
    /// post-login destination, so rendering it anonymously makes a successful
    /// login look like a failed one.
    username: Option<String>,
}

/// `GET /` — the front door.
///
/// Anonymous visitors land here. Per the plan's audience table (§4.1) this is
/// first contact and determines whether anyone joins at all, so it ships with
/// the same care as the dashboard rather than after it.
///
/// Signed-in members land here too, because `POST /login` redirects to `/`
/// when there is no `next`. The session is therefore read but never required:
/// an absent or stale cookie renders the anonymous page rather than an error.
pub async fn landing(State(state): State<AppState>, jar: CookieJar) -> Response {
    render(&Landing {
        instance_name: &state.instance_name,
        username: session_user(&state, &jar).await.map(|user| user.username),
    })
}
