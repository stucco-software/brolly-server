//! Server-rendered views.
//!
//! Askama templates, progressive enhancement, no SPA (decision in the
//! implementation plan §4.2). Every form works with JavaScript disabled.

use askama::Template;
use axum::response::Response;

use crate::render;

#[derive(Template)]
#[template(path = "landing.html")]
struct Landing<'a> {
    instance_name: &'a str,
}

/// `GET /` — the front door.
///
/// Anonymous visitors land here. Per the plan's audience table (§4.1) this is
/// first contact and determines whether anyone joins at all, so it ships with
/// the same care as the dashboard rather than after it.
pub async fn landing() -> Response {
    render(&Landing {
        instance_name: "Brolly",
    })
}
