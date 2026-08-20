//! Auth surfaces: login, register, invite redemption, logout.
//!
//! **The front door ships with identity, not after it** (plan §4.4). The
//! predecessor built a polished admin console that almost nobody sees while
//! login and registration stayed inline `format!("<…")` strings in
//! `auth_routes.rs` — the first thing a prospective member touched was the
//! least-finished thing in the product.
//!
//! Every form here works with JavaScript disabled: a `<form method="post">`
//! with a real action, no fetch, no client-side validation standing between the
//! user and the server. That is the progressive-enhancement decision in §4.2,
//! and it is enforced by `tests/ui_invariants.rs`.

use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use brolly_identity::db::{self, DbError};
use serde::Deserialize;

use crate::{AppState, render};

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "brolly_session";

/// One input on an auth form.
pub struct Field {
    pub name: &'static str,
    pub label: &'static str,
    pub kind: &'static str,
    pub value: String,
    pub required: bool,
    /// Drives the browser's password manager. Getting this wrong is why people
    /// end up with their username saved as their password.
    pub autocomplete: Option<&'static str>,
}

impl Field {
    fn text(name: &'static str, label: &'static str, autocomplete: &'static str) -> Self {
        Self {
            name,
            label,
            kind: "text",
            value: String::new(),
            required: true,
            autocomplete: Some(autocomplete),
        }
    }
    fn password(name: &'static str, label: &'static str, autocomplete: &'static str) -> Self {
        Self {
            name,
            label,
            kind: "password",
            value: String::new(),
            required: true,
            autocomplete: Some(autocomplete),
        }
    }
    fn optional_email(name: &'static str, label: &'static str) -> Self {
        Self {
            name,
            label,
            kind: "email",
            value: String::new(),
            required: false,
            autocomplete: Some("email"),
        }
    }
    fn keep(mut self, value: &str) -> Self {
        self.value = value.to_string();
        self
    }
}

/// "Already have an account? Log in" — the escape hatch from each form.
pub struct Alternate {
    pub prefix: &'static str,
    pub href: &'static str,
    pub text: &'static str,
}

#[derive(Template)]
#[template(path = "auth.html")]
struct AuthPage<'a> {
    instance_name: &'a str,
    heading: &'a str,
    intro: Option<&'a str>,
    error: Option<&'a str>,
    action: &'a str,
    submit: &'a str,
    fields: Vec<Field>,
    alternate: Option<Alternate>,
}

fn login_page<'a>(error: Option<&'a str>, username: &str) -> AuthPage<'a> {
    AuthPage {
        instance_name: "Brolly",
        heading: "Log in",
        intro: None,
        error,
        action: "/login",
        submit: "Log in",
        fields: vec![
            Field::text("username", "Username", "username").keep(username),
            Field::password("password", "Password", "current-password"),
        ],
        alternate: Some(Alternate {
            prefix: "Have an invite?",
            href: "/register",
            text: "Create an account",
        }),
    }
}

fn register_page<'a>(error: Option<&'a str>, username: &str, invite: &str) -> AuthPage<'a> {
    AuthPage {
        instance_name: "Brolly",
        heading: "Create an account",
        intro: Some("This server is invite-only. Your data lives in your own pod."),
        error,
        action: "/register",
        submit: "Create account",
        fields: vec![
            Field::text("invite", "Invite code", "off").keep(invite),
            Field::text("username", "Username", "username").keep(username),
            Field::optional_email("email", "Email (optional, for password resets)"),
            Field::password("password", "Password", "new-password"),
        ],
        alternate: Some(Alternate {
            prefix: "Already have an account?",
            href: "/login",
            text: "Log in",
        }),
    }
}

/// `GET /login`
pub async fn login_form() -> Response {
    render(&login_page(None, ""))
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

/// `POST /login`
pub async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    match db::authenticate(&state.pool, &form.username, &form.password).await {
        Ok(user) => {
            match db::create_session(&state.pool, user.id, time::Duration::days(30), None).await {
                Ok(token) => (jar.add(session_cookie(token)), Redirect::to("/")).into_response(),
                Err(e) => {
                    tracing::error!(error = %e, "session creation failed");
                    server_error()
                }
            }
        }
        Err(DbError::BadCredentials) => (
            StatusCode::UNAUTHORIZED,
            // One message for every failure mode, matching db::authenticate —
            // the page must not reveal whether the account exists.
            render(&login_page(
                Some("Incorrect username or password."),
                &form.username,
            )),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "login failed");
            server_error()
        }
    }
}

#[derive(Deserialize)]
pub struct RegisterForm {
    invite: String,
    username: String,
    email: String,
    password: String,
}

/// `GET /register`
pub async fn register_form() -> Response {
    render(&register_page(None, "", ""))
}

/// `POST /register`
///
/// The invite is redeemed *before* the user is created, so a failed creation
/// cannot consume an invite silently — and redemption is a single conditional
/// UPDATE, so two simultaneous registrations cannot both claim the last use.
pub async fn register_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<RegisterForm>,
) -> Response {
    if let Err(message) = validate_username(&form.username) {
        return (
            StatusCode::BAD_REQUEST,
            render(&register_page(Some(message), &form.username, &form.invite)),
        )
            .into_response();
    }
    if form.password.chars().count() < 12 {
        return (
            StatusCode::BAD_REQUEST,
            render(&register_page(
                Some("Use at least 12 characters. Length beats punctuation."),
                &form.username,
                &form.invite,
            )),
        )
            .into_response();
    }

    if db::redeem_invite(&state.pool, &form.invite).await.is_err() {
        return (
            StatusCode::BAD_REQUEST,
            render(&register_page(
                Some("That invite is not valid, has expired, or has been used up."),
                &form.username,
                "",
            )),
        )
            .into_response();
    }

    let email = (!form.email.trim().is_empty()).then(|| form.email.trim());
    match db::create_user(&state.pool, &form.username, email, &form.password, "member").await {
        Ok(user) => {
            match db::create_session(&state.pool, user.id, time::Duration::days(30), None).await {
                Ok(token) => (jar.add(session_cookie(token)), Redirect::to("/")).into_response(),
                Err(e) => {
                    tracing::error!(error = %e, "session creation failed after registration");
                    server_error()
                }
            }
        }
        Err(DbError::UsernameTaken) => (
            StatusCode::CONFLICT,
            render(&register_page(
                Some("That username is taken."),
                &form.username,
                &form.invite,
            )),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "registration failed");
            server_error()
        }
    }
}

/// `POST /logout`
///
/// POST, not GET: a link-prefetching browser or an `<img src="/logout">` on
/// another site must not be able to log someone out.
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE)
        && let Err(e) = db::revoke_session(&state.pool, cookie.value()).await
    {
        tracing::warn!(error = %e, "session revocation failed");
    }
    let jar = jar.remove(Cookie::from(SESSION_COOKIE));
    (jar, Redirect::to("/")).into_response()
}

fn session_cookie(token: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, token);
    cookie.set_http_only(true); // unreadable from JavaScript
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Lax); // survives a top-level navigation back
    cookie.set_path("/");
    cookie
}

/// Usernames become subdomains and WebIDs, so the rules are stricter than a
/// display name's — see `identity::webid`.
fn validate_username(username: &str) -> Result<(), &'static str> {
    const RESERVED: [&str; 8] = [
        "admin", "root", "api", "oauth", "www", "mail", "support", "brolly",
    ];

    if username.len() < 2 || username.len() > 32 {
        return Err("Usernames are 2 to 32 characters.");
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(
            "Use lowercase letters, digits and hyphens only — your username becomes a subdomain.",
        );
    }
    if username.starts_with('-') || username.ends_with('-') {
        return Err("Usernames cannot start or end with a hyphen.");
    }
    if RESERVED.contains(&username) {
        return Err("That username is reserved.");
    }
    Ok(())
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Try again.",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_must_be_subdomain_safe() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("alice-2026").is_ok());
        assert!(
            validate_username("Alice").is_err(),
            "uppercase breaks host matching"
        );
        assert!(
            validate_username("al.ice").is_err(),
            "a dot would nest a subdomain"
        );
        assert!(validate_username("-alice").is_err());
        assert!(validate_username("alice-").is_err());
        assert!(validate_username("a").is_err());
    }

    #[test]
    fn reserved_usernames_are_refused() {
        // These would shadow apex hosts or read as official.
        for name in ["admin", "api", "www", "oauth"] {
            assert!(
                validate_username(name).is_err(),
                "{name} should be reserved"
            );
        }
    }

    #[test]
    fn the_session_cookie_is_hardened() {
        let cookie = session_cookie("token".into());
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }
}
