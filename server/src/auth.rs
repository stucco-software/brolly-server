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
use axum::Extension;
use axum::Form;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use brolly_identity::db::{self, DbError, User};
use brolly_identity::webid;
use serde::Deserialize;
use serde_json::json;

use crate::ratelimit::{ClientKey, Gate, too_many};
use crate::{AppState, Chrome, render};

/// Name of the session cookie — identity's constant, so the two readers
/// (`CookieJar` here, `extract::credential` on the pod) can never disagree
/// on the name. See `brolly_identity::extract::SESSION_COOKIE` for why it is
/// `__Host-`-prefixed.
pub const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;

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
    chrome: Chrome<'a>,
    heading: &'a str,
    intro: Option<&'a str>,
    error: Option<&'a str>,
    action: &'a str,
    submit: &'a str,
    fields: Vec<Field>,
    alternate: Option<Alternate>,
}

/// Where to send someone after login.
///
/// Only a path on this host, never an absolute URL: `next` arrives in a query
/// parameter, so honouring `https://elsewhere.example` would turn the login
/// page into an open redirect that phishing can point at — and login is the
/// front of every OAuth flow, so the page it lands on is one a member has
/// every reason to trust.
///
/// "A path on this host" is decided the way a browser decides it, not by
/// looking at the first two characters. Browsers strip ASCII tab and newline
/// from a URL before parsing it and read a backslash as a slash (WHATWG URL
/// §4.4), so `/<TAB>/evil.example` and `/a\evil.example` are both
/// `//evil.example` — scheme-relative, another host — by the time one acts
/// on the `Location`. `HeaderValue` passes a tab through. So the rule is no
/// control character and no backslash anywhere in the value, on top of the
/// leading-slash shape.
fn safe_next(next: Option<&str>) -> Option<&str> {
    let next = next?;
    let looks_local = next.starts_with('/')
        && !next.starts_with("//")
        && !next.chars().any(|c| c.is_ascii_control() || c == '\\');
    looks_local.then_some(next)
}

/// The form action, carrying `next` through the POST.
fn login_action(next: Option<&str>) -> String {
    match safe_next(next) {
        Some(next) => {
            let query: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("next", next)
                .finish();
            format!("/login?{query}")
        }
        None => "/login".to_string(),
    }
}

fn login_page<'a>(
    state: &'a AppState,
    error: Option<&'a str>,
    username: &str,
    action: &'a str,
) -> AuthPage<'a> {
    AuthPage {
        chrome: state.chrome(),
        heading: "Log in",
        intro: None,
        error,
        action,
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

fn register_page<'a>(
    state: &'a AppState,
    error: Option<&'a str>,
    username: &str,
    invite: &str,
) -> AuthPage<'a> {
    // The door's policy is the deployment's, not the page's: an instance with
    // `BROLLY_PUBLIC_REGISTRATION` set asks for no invite, and one without it
    // is invite-only. The field is dropped rather than marked optional, so a
    // public signup form never suggests an invite exists to present.
    let (intro, mut fields) = if state.public_registration {
        ("Your data lives in your own pod.", vec![])
    } else {
        (
            "This server is invite-only. Your data lives in your own pod.",
            vec![Field::text("invite", "Invite code", "off").keep(invite)],
        )
    };
    fields.extend([
        Field::text("username", "Username", "username").keep(username),
        Field::optional_email("email", "Email (optional, for password resets)"),
        Field::password("password", "Password", "new-password"),
    ]);
    AuthPage {
        chrome: state.chrome(),
        heading: "Create an account",
        intro: Some(intro),
        error,
        action: "/register",
        submit: "Create account",
        fields,
        alternate: Some(Alternate {
            prefix: "Already have an account?",
            href: "/login",
            text: "Log in",
        }),
    }
}

/// `next` — where an interrupted flow wants to resume.
///
/// An OAuth authorize request that arrives without a session sends the member
/// here and expects them back; without this they log in and land on the
/// homepage while the app that sent them waits forever.
#[derive(Deserialize, Default)]
pub struct Next {
    next: Option<String>,
}

/// `GET /login`
///
/// A signed-in visitor is bounced to their dashboard rather than shown a form
/// they have no use for. `session_user` filters on `is_active`, so a disabled
/// member's stale cookie falls through to the form instead of looping.
pub async fn login_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<Next>,
) -> Response {
    if session_user(&state, &jar).await.is_some() {
        return Redirect::to("/account").into_response();
    }
    let action = login_action(query.next.as_deref());
    render(&login_page(&state, None, "", &action))
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

/// `POST /login`
pub async fn login_submit(
    State(state): State<AppState>,
    Query(query): Query<Next>,
    Extension(ClientKey(client)): Extension<ClientKey>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    // Two gates, both spent before the password is looked at: the address,
    // against one place spraying guesses across accounts, and the username,
    // against many places converging on one — the second is what makes
    // rotating addresses worthless. The username is normalised the way the
    // lookup normalises it, so `Alice` and `alice` are one bucket.
    let account = format!("user:{}", form.username.trim().to_lowercase());
    if let Err(wait) = state
        .limiter
        .check(Gate::Login, &format!("addr:{client}"))
        .and_then(|()| state.limiter.check(Gate::Login, &account))
    {
        return too_many(wait);
    }
    let action = login_action(query.next.as_deref());
    match db::authenticate(&state.pool, &form.username, &form.password).await {
        Ok(user) => {
            match db::create_session(&state.pool, user.id, time::Duration::days(30), None).await {
                Ok(token) => {
                    let destination = safe_next(query.next.as_deref()).unwrap_or("/account");
                    (jar.add(session_cookie(token)), Redirect::to(destination)).into_response()
                }
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
                &state,
                Some("Incorrect username or password."),
                &form.username,
                &action,
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
    /// Absent, not empty, when the form does not render the field — a public
    /// instance's form carries no invite input, so the browser posts no
    /// `invite` key at all. `#[serde(default)]` makes that an empty string
    /// rather than a 422 the form never meant to provoke.
    #[serde(default)]
    invite: String,
    username: String,
    email: String,
    password: String,
}

/// `GET /register`
///
/// Bounced for the same reason as `login_form`.
pub async fn register_form(State(state): State<AppState>, jar: CookieJar) -> Response {
    if session_user(&state, &jar).await.is_some() {
        return Redirect::to("/account").into_response();
    }
    render(&register_page(&state, None, "", ""))
}

/// What can go wrong creating a member, shared by the form and the API.
///
/// The two surfaces answer the same failures differently — a page re-rendered
/// with a message on one, a JSON error code on the other — so the core says
/// what went wrong and each surface decides what it looks like.
#[derive(Debug, PartialEq)]
pub(crate) enum RegistrationError {
    /// The username is not a valid subdomain-shaped handle. The detail is the
    /// same message the form has always shown.
    Username(String),
    UsernameTaken,
    EmailTaken,
    PasswordShort,
    /// A required invite was absent, or a presented one was invalid, expired
    /// or used up. The two cases share an code deliberately: the endpoint is
    /// not an oracle for which invite codes exist.
    InviteInvalid,
    ServerError,
}

/// Create a member and everything their account is: the row, the pod with its
/// storage root and ACL, and the ATProtocol identity.
///
/// The invite policy is the deployment's (`BROLLY_PUBLIC_REGISTRATION`): an
/// invite is *required* on a private instance and *optional* on a public one.
/// Optional, never ignored — a presented invite is redeemed even on a public
/// instance, because the bootstrap admin invite is how an empty instance gets
/// its first admin on either policy, and an admin invite silently treated as
/// no invite would register the operator as a plain member.
///
/// Everything that can be refused is refused *before* the invite is redeemed
/// — the username's shape, the password's length, and whether the username
/// and email are free — so a refusal does not consume an invite: the invitee
/// who typed a name somebody already has tries again with the same code.
/// Redemption is a single conditional UPDATE, so two simultaneous
/// registrations cannot both claim the last use; the one race left is two
/// registrations of the same free name at once, where the unique constraint
/// refuses the second after its invite was spent.
async fn create_member(
    state: &AppState,
    username: &str,
    email: Option<&str>,
    password: &str,
    invite: Option<&str>,
) -> Result<User, RegistrationError> {
    if let Err(message) = validate_username(username) {
        return Err(RegistrationError::Username(message.to_string()));
    }
    if password.chars().count() < 12 {
        return Err(RegistrationError::PasswordShort);
    }
    match db::find_by_username(&state.pool, username).await {
        Ok(Some(_)) => return Err(RegistrationError::UsernameTaken),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "username lookup failed at registration");
            return Err(RegistrationError::ServerError);
        }
    }
    if let Some(email) = email {
        match db::find_by_email(&state.pool, email).await {
            Ok(Some(_)) => return Err(RegistrationError::EmailTaken),
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "email lookup failed at registration");
                return Err(RegistrationError::ServerError);
            }
        }
    }

    // An invite says what the account becomes. An ordinary one grants nothing
    // and the redeemer is a member; the bootstrap invite an empty instance
    // mints for itself grants admin, which is the only way a first admin
    // exists at all (`admin::bootstrap`).
    let role = match (state.public_registration, invite) {
        // Private and no invite: the door does not open.
        (false, None) => return Err(RegistrationError::InviteInvalid),
        // A presented invite is redeemed under either policy.
        (_, Some(code)) => match db::redeem_invite(&state.pool, code).await {
            Ok(granted) => granted.unwrap_or_else(|| crate::admin::MEMBER.to_string()),
            Err(_) => return Err(RegistrationError::InviteInvalid),
        },
        // Public and no invite: a plain member.
        (true, None) => crate::admin::MEMBER.to_string(),
    };

    match db::create_user(&state.pool, username, email, password, &role).await {
        Ok(user) => {
            // Give them a pod they can write to. WAC grants nothing by
            // default, so without this the first write any new member attempts
            // is refused — and the pod looks fine from the outside.
            match state.stores.pod(user.id) {
                Ok(pod) => {
                    if let Err(e) = crate::provision::pod(&pod, &user.username, &state.base_domain)
                    {
                        tracing::error!(error = %e, user = %user.id, "pod provisioning failed");
                        return Err(RegistrationError::ServerError);
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, user = %user.id, "pod unavailable at registration");
                    return Err(RegistrationError::ServerError);
                }
            }

            // An ATProtocol identity, in the same breath. Deferring it to
            // "first use" means the first XRPC write is what discovers there is
            // no key, no DID and no repository — and an account that works in
            // three protocols and not the fourth reads as a bug in the fourth.
            match crate::provision::atproto_identity(
                &state.pool,
                &state.stores,
                user.id,
                &user.username,
                &state.base_domain,
                state.plc_client.as_ref(),
            )
            .await
            {
                Ok(identity) => {
                    // The identity event rides the live channel too, so a
                    // consumer attached at signup learns the did↔handle pairing
                    // from the stream instead of a poll (1, E). Durable
                    // consumers read it from the log, and the shared listener
                    // guarantees the delivery regardless of who wrote (1, G) —
                    // this send is the fast path that spares the notify round
                    // trip. `send` fails only when nobody is listening, which
                    // is normal.
                    if let Some(event) = identity.identity_event {
                        let _ = state
                            .commits
                            .send(brolly_atproto::firehose::Event::Identity(event));
                    }
                    tracing::info!(
                        user = %user.id,
                        did = %identity.did,
                        plc_registered = identity.plc_registered,
                        "atproto identity provisioned"
                    )
                }
                Err(e) => {
                    // Local provisioning failing is a real failure — the
                    // account would be permanently half-built. Network failure
                    // is not, and is handled inside as `plc_registered: false`.
                    tracing::error!(error = %e, user = %user.id, "atproto provisioning failed");
                    return Err(RegistrationError::ServerError);
                }
            }
            Ok(user)
        }
        Err(DbError::UsernameTaken) => Err(RegistrationError::UsernameTaken),
        Err(DbError::EmailTaken) => Err(RegistrationError::EmailTaken),
        Err(e) => {
            tracing::error!(error = %e, "registration failed");
            Err(RegistrationError::ServerError)
        }
    }
}

/// `POST /register`
///
/// The browser form. The invite field is rendered only on an invite-only
/// instance, but a public one still redeems an invite that is posted to it —
/// the bootstrap admin invite reaches an empty public instance through this
/// form as through the API.
pub async fn register_submit(
    State(state): State<AppState>,
    Extension(ClientKey(client)): Extension<ClientKey>,
    jar: CookieJar,
    Form(form): Form<RegisterForm>,
) -> Response {
    // One gate for both creation surfaces: an account is the most expensive
    // thing an anonymous caller can have the instance make.
    if let Err(wait) = state.limiter.check(Gate::Signup, &client) {
        return too_many(wait);
    }
    let email = (!form.email.trim().is_empty()).then(|| form.email.trim());
    let invite = (!form.invite.trim().is_empty()).then(|| form.invite.trim());
    let member = create_member(&state, &form.username, email, &form.password, invite).await;

    let user = match member {
        Ok(user) => user,
        Err(RegistrationError::Username(message)) => {
            return (
                StatusCode::BAD_REQUEST,
                render(&register_page(
                    &state,
                    Some(&message),
                    &form.username,
                    &form.invite,
                )),
            )
                .into_response();
        }
        Err(RegistrationError::PasswordShort) => {
            return (
                StatusCode::BAD_REQUEST,
                render(&register_page(
                    &state,
                    Some("Use at least 12 characters. Length beats punctuation."),
                    &form.username,
                    &form.invite,
                )),
            )
                .into_response();
        }
        Err(RegistrationError::InviteInvalid) => {
            return (
                StatusCode::BAD_REQUEST,
                render(&register_page(
                    &state,
                    Some("That invite is not valid, has expired, or has been used up."),
                    &form.username,
                    "",
                )),
            )
                .into_response();
        }
        Err(RegistrationError::UsernameTaken) => {
            return (
                StatusCode::CONFLICT,
                render(&register_page(
                    &state,
                    Some("That username is taken."),
                    &form.username,
                    &form.invite,
                )),
            )
                .into_response();
        }
        Err(RegistrationError::EmailTaken) => {
            return (
                StatusCode::CONFLICT,
                render(&register_page(
                    &state,
                    Some("That email already has an account."),
                    &form.username,
                    &form.invite,
                )),
            )
                .into_response();
        }
        Err(RegistrationError::ServerError) => return server_error(),
    };

    match db::create_session(&state.pool, user.id, time::Duration::days(30), None).await {
        Ok(token) => (jar.add(session_cookie(token)), Redirect::to("/account")).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "session creation failed after registration");
            server_error()
        }
    }
}

/// The account-creation API's request body.
#[derive(Deserialize)]
pub struct CreateAccount {
    username: String,
    /// Optional on every policy — an instance never requires an email, and
    /// brolly has no email path yet, so the address is stored for the day it
    // does rather than used.
    email: Option<String>,
    password: String,
    /// Required on a private instance, optional on a public one. A public
    /// deployment's signup surface simply omits it.
    invite: Option<String>,
}

/// `POST /api/accounts` — account creation as an API, for a signup surface on
/// another origin.
///
/// The form is for a person with a browser; this is for a first-party site or
/// app that wants to offer signup for the instance — the marketing page in
/// front of a public deployment, or an invite-based signup flow like the
/// predecessor StuccoID app ran against CSS's `.account` API. The policy is
/// the same env var the form reads: private instances require an invite here
/// exactly as there, so the API is not the way around an invite-only door.
///
/// Answers `201` with the new member's username and WebID and nothing else —
/// no session. A session here would be a `__Host-` cookie a cross-origin
/// script cannot use or set (`SameSite=Lax`; ADR 0018) and a bearer a signup
/// surface has no reason to hold; the member logs in through the front door
/// or OIDC like anyone else.
///
/// Apex-only, like the OAuth surface (ADR 0009): a member's subdomain is
/// their pod, and an instance-level endpoint does not answer there.
pub async fn create_account(
    State(state): State<AppState>,
    Extension(ClientKey(client)): Extension<ClientKey>,
    Json(request): Json<CreateAccount>,
) -> Response {
    if let Err(wait) = state.limiter.check(Gate::Signup, &client) {
        return too_many(wait);
    }
    let email = request
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty());
    let invite = request
        .invite
        .as_deref()
        .map(str::trim)
        .filter(|i| !i.is_empty());

    match create_member(&state, &request.username, email, &request.password, invite).await {
        Ok(user) => (
            StatusCode::CREATED,
            Json(json!({
                "username": user.username,
                "webid": webid::webid(&user.username, &state.base_domain),
            })),
        )
            .into_response(),
        Err(RegistrationError::Username(message)) => {
            account_error(StatusCode::BAD_REQUEST, "invalid_username", &message)
        }
        Err(RegistrationError::PasswordShort) => account_error(
            StatusCode::BAD_REQUEST,
            "password_too_short",
            "Use at least 12 characters. Length beats punctuation.",
        ),
        // The two invite failures are deliberately one code: the endpoint
        // does not tell a caller which invite codes exist, the same
        // indistinguishability the unknown-client refusal on `authorize`
        // preserves (spec 6, H3).
        Err(RegistrationError::InviteInvalid) => account_error(
            StatusCode::BAD_REQUEST,
            "invite_invalid",
            "An invite is required, or the one presented is not valid, has expired, or has been used up.",
        ),
        Err(RegistrationError::UsernameTaken) => account_error(
            StatusCode::CONFLICT,
            "username_taken",
            "That username is taken.",
        ),
        Err(RegistrationError::EmailTaken) => account_error(
            StatusCode::CONFLICT,
            "email_taken",
            "That email already has an account.",
        ),
        Err(RegistrationError::ServerError) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Something went wrong. Try again.",
            })),
        )
            .into_response(),
    }
}

/// An account-creation error as JSON, in the OAuth error shape the rest of
/// the server already speaks — `error` for the code a caller switches on,
/// `error_description` for the text a person can read.
fn account_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
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
    // Built from the cookie login set, not from the bare name: a `__Host-`
    // removal must carry `Secure` and `Path=/` or the browser drops it.
    let jar = jar.remove(session_cookie(String::new()));
    (jar, Redirect::to("/")).into_response()
}

/// The signed-in member, if there is one.
///
/// The permissive half of session handling: callers that can render or serve
/// something useful to an anonymous visitor use this, and callers that cannot
/// use `account::require_session`, which redirects to the login form instead.
/// A malformed, expired, or revoked cookie is indistinguishable from no cookie
/// here — deliberately, so a stale session degrades to logged-out rather than
/// to an error page.
pub(crate) async fn session_user(state: &AppState, jar: &CookieJar) -> Option<User> {
    let cookie = jar.get(SESSION_COOKIE)?;
    db::user_for_session(&state.pool, cookie.value())
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

/// The session cookie, with everything the `__Host-` prefix requires and
/// everything a session cookie should have. Also the shape of its removal:
/// a `__Host-` cookie can only be cleared by a `Set-Cookie` that carries the
/// prefix's attributes, so `logout` and `delete_account` build their removal
/// from this (`CookieJar::remove` keeps the attributes of the cookie it is
/// given and sets only the empty value, `Max-Age=0` and `Expires`).
pub(crate) fn session_cookie(token: String) -> Cookie<'static> {
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
    // A username is a subdomain, so the reservation is routing and
    // convention, not taste: names that would shadow the instance's own
    // hosts or read as official; the labels mail and DNS conventions give
    // meaning to under a wildcard (`mta-sts` publishes a mail policy for the
    // whole domain, `autoconfig`/`autodiscover` tell mail clients where to
    // send a password, `wpad` configures proxies); and the names a browser
    // or a person would take for infrastructure rather than a member.
    const RESERVED: &[&str] = &[
        // The instance's own
        "admin",
        "root",
        "api",
        "oauth",
        "www",
        "brolly",
        "login",
        "register",
        "account",
        "accounts",
        "auth",
        "id",
        "app",
        "apps",
        "status",
        "help",
        "docs",
        "support",
        "abuse",
        "security",
        // Mail
        "mail",
        "smtp",
        "imap",
        "pop",
        "pop3",
        "webmail",
        "mta-sts",
        "autoconfig",
        "autodiscover",
        "postmaster",
        "hostmaster",
        "webmaster",
        "noreply",
        "no-reply",
        // DNS, proxies, the host itself
        "ns",
        "ns1",
        "ns2",
        "dns",
        "wpad",
        "isatap",
        "localhost",
        "broadcasthost",
        // Static assets
        "static",
        "assets",
        "cdn",
        "media",
        "files",
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
    // The IDN prefix: a browser renders `xn--pple-43d` as `аpple`. The
    // charset above rules out non-ASCII; this rules out the ASCII that
    // becomes it.
    if username.starts_with("xn--") {
        return Err("Usernames cannot start with xn--.");
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
        // These would shadow apex hosts, read as official, or claim a label
        // that mail and DNS conventions give meaning to under the wildcard.
        for name in [
            "admin",
            "api",
            "www",
            "oauth",
            "mta-sts",
            "autoconfig",
            "autodiscover",
            "localhost",
            "ns1",
            "static",
            "cdn",
            "login",
            "account",
            "register",
            "status",
        ] {
            assert!(
                validate_username(name).is_err(),
                "{name} should be reserved"
            );
        }
    }

    #[test]
    fn a_punycode_label_is_refused() {
        // `xn--` is the IDN prefix: a browser renders `xn--pple-43d` as
        // `аpple`, and a username is a subdomain. The charset already rules
        // out non-ASCII; this rules out the ASCII that becomes it.
        assert!(validate_username("xn--pple-43d").is_err());
        assert!(validate_username("xn--80ak6aa92e").is_err());
        // Which does not catch a name that merely contains the letters.
        assert!(validate_username("txn--ok").is_ok());
    }

    #[test]
    fn next_is_a_local_path_or_nothing() {
        assert_eq!(safe_next(Some("/account")), Some("/account"));
        assert_eq!(
            safe_next(Some("/oauth/solid/authorize?x=1")),
            Some("/oauth/solid/authorize?x=1")
        );
        assert_eq!(safe_next(None), None);
        for bad in [
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example/",
            // Browsers strip ASCII tab and newline before parsing a URL
            // (WHATWG URL §4.4), so `/<TAB>/evil.example` is `//evil.example`
            // to every one of them — a scheme-relative URL to another host.
            // HeaderValue lets a tab through, so this has to be refused here.
            "/\t/evil.example/",
            "/\n/evil.example/",
            "/\r/evil.example/",
            // A backslash anywhere, not only second: `/a\evil.example` is
            // not a path either browser-side.
            "/a\\evil.example/",
            // Any other control character: it is never a path, and
            // HeaderValue refuses some of them with a 500.
            "/\x01/x",
            "/\x7f/x",
        ] {
            assert_eq!(
                safe_next(Some(bad)),
                None,
                "{bad:?} must not be a destination"
            );
        }
    }

    #[test]
    fn the_session_cookie_is_hardened() {
        let cookie = session_cookie("token".into());
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        // ADR 0018, control 6: the `__Host-` prefix is enforced by the
        // browser — Secure, Path=/, no Domain — and a subdomain cannot set
        // one for the apex or for any other host. Cookie tossing from a
        // member page ends here.
        assert!(
            cookie.name().starts_with("__Host-"),
            "got {}",
            cookie.name()
        );
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.domain(), None);
        // One name, defined once: the server's constant is identity's.
        assert_eq!(SESSION_COOKIE, brolly_identity::extract::SESSION_COOKIE);
    }
}
