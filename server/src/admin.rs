//! The admin console: who runs this instance, and how they got that way.
//!
//! Plan §4.1 describes this audience as "low traffic, high consequence", and
//! §4.4 schedules it against phases 5–7. See
//! `docs/specs/2026-09-09-admin-console.md` for the surface and its slices.
//!
//! Two things live here that are easy to conflate. **Authorization** is
//! [`require_admin`], which decides whether a request may see any of this.
//! **Bootstrap** is [`bootstrap`], which answers the question an operator asks
//! before there is anybody to authorize: a brand new instance has no admin, no
//! invite, and no way to register, so something has to break the cycle.

use askama::Template;
use axum::Form;
use axum::extract::rejection::{FormRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use brolly_domain::media::{format_size, parse_size};
use brolly_identity::db::{self, DbError, User};
use serde::Deserialize;

use crate::auth::session_user;
use crate::{AppState, Chrome, render};

/// The role an invite or a user carries to reach this console.
pub const ADMIN: &str = "admin";
/// The role everyone else has. Registration's default.
pub const MEMBER: &str = "member";

// --- bootstrap ---------------------------------------------------------------

/// Give a brand new instance a way in.
///
/// Registration is invite-only and invites come from an admin, so an instance
/// with no users has no path to its first one. The predecessor solved this with
/// `MYCORRIZA_ADMIN_PASSWORD` in the environment, which leaves a live
/// credential sitting in the deployment config forever.
///
/// This mints a single-use admin invite and logs it instead. It is better on
/// three counts: nothing durable is stored outside the database, the code is
/// useless the moment it is redeemed, and reading it needs log access rather
/// than a shell — which is what a platform deploy actually gives you.
///
/// The alternative considered and rejected was opening registration while the
/// instance is empty. That leaves a window in which whoever finds the URL first
/// owns the instance, and the window is exactly as long as the operator's
/// attention span.
///
/// Called on every start; does nothing once anyone has registered.
pub async fn bootstrap(pool: &sqlx::PgPool) -> Result<(), DbError> {
    if db::count_users(pool).await? > 0 {
        return Ok(());
    }

    let code = db::create_invite(pool, None, 1, None, Some(ADMIN)).await?;

    // `warn` rather than `info`: on a default filter this is the one line an
    // operator must not scroll past, and an instance with no admin is a real
    // if temporary problem.
    tracing::warn!(
        invite = %code,
        "no accounts yet — register with this invite to claim the instance; \
         it grants admin, is good for one use, and is shown on every start \
         until somebody registers"
    );
    Ok(())
}

// --- authorization -----------------------------------------------------------

/// Resolve an admin, or explain why not.
///
/// Anonymous visitors are redirected to log in and back, so a bookmarked admin
/// URL still leads somewhere. A signed-in member who is not an admin gets
/// **404, not 403**: 403 confirms both that the surface exists and that they
/// found a real URL, which on an instance whose admin set is one person is a
/// disclosure with nothing on the other side of the trade.
async fn require_admin(state: &AppState, jar: &CookieJar, path: &str) -> Result<User, Response> {
    match session_user(state, jar).await {
        Some(user) if user.is_admin() => Ok(user),
        Some(_) => Err(not_found()),
        None => {
            let query: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("next", path)
                .finish();
            Err(Redirect::to(&format!("/login?{query}")).into_response())
        }
    }
}

/// What a member sees at any of these paths, and what an admin sees at a
/// mistyped one. Deliberately identical to the router's own miss.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Try again.",
    )
        .into_response()
}

/// One tab in the console.
pub struct Tab {
    pub href: &'static str,
    pub label: &'static str,
    pub current: bool,
}

fn tabs(current: &str) -> Vec<Tab> {
    [("/admin", "Overview"), ("/admin/users", "Members")]
        .into_iter()
        .map(|(href, label)| Tab {
            href,
            label,
            current: href == current,
        })
        .collect()
}

// --- overview ----------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin/overview.html")]
struct OverviewPage<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    base_domain: &'a str,
    members: i64,
    admins: i64,
    /// Whether this instance delivers to remote inboxes (ADR 0016).
    ///
    /// The single most consequential fact about a deployment, and until now it
    /// was only discoverable by reading the source.
    federation: bool,
    /// Whether `did:plc` operations reach the real directory.
    plc_submit: bool,
}

/// `GET /admin`
pub async fn overview(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Err(response) = require_admin(&state, &jar, "/admin").await {
        return response;
    }

    let (Ok(members), Ok(admins)) = (
        db::count_users(&state.pool).await,
        db::count_admins(&state.pool).await,
    ) else {
        tracing::error!("admin overview could not count accounts");
        return server_error();
    };

    render(&OverviewPage {
        chrome: state.chrome(),
        tabs: tabs("/admin"),
        base_domain: &state.base_domain,
        members,
        admins,
        federation: brolly_activitypub::FEDERATION_ENABLED,
        plc_submit: state.plc_client.is_some(),
    })
}

// --- members -----------------------------------------------------------------

/// One row, ready to render.
///
/// A view rather than the `UserRow` itself: `created_at` is an
/// `OffsetDateTime`, whose `Display` is a full RFC 3339 timestamp. A table of
/// those is unreadable, and date formatting is not the template's job.
struct MemberView {
    username: String,
    role: String,
    status: String,
    did: Option<String>,
    created: String,
    /// The effective quota, formatted.
    quota: String,
    /// `set by @keeper, 2026-10-26` or `set 2026-10-26`; `None` when the
    /// member is on the instance default.
    quota_note: Option<String>,
    /// What the pod holds, formatted — or `unknown` when the directory
    /// cannot be read. Not `0`: a console about to set a limit must not
    /// show a full pod as empty.
    usage: String,
    /// What the field shows: the formatted override, or the value an admin
    /// just submitted and had refused.
    quota_entered: String,
    quota_error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/users.html")]
struct UsersPage<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    members: Vec<MemberView>,
}

/// A size an admin submitted for one member and had refused: the row it
/// belongs to, what they typed, and why it was refused.
struct Refused<'r> {
    username: &'r str,
    entered: &'r str,
    error: &'r str,
}

/// The members page, with at most one row's field carrying a refused value
/// and its error. `None` for a plain load.
async fn users_page<'a>(
    state: &'a AppState,
    refused: Option<Refused<'_>>,
) -> Result<UsersPage<'a>, ()> {
    let rows = db::list_users(&state.pool).await.map_err(|e| {
        tracing::error!(error = %e, "admin member list failed");
    })?;
    let members = rows
        .into_iter()
        .map(|row| {
            let quota = format_size(row.quota(state.pod_quota_bytes));
            let override_bytes = row.quota_bytes.map(|b| u64::try_from(b).unwrap_or(0));
            let quota_note = override_bytes.map(|_| match (row.quota_set_at, &row.quota_set_by) {
                (Some(at), Some(by)) => format!("set by @{by}, {}", at.date()),
                (Some(at), None) => format!("set {}", at.date()),
                // The CHECK says this cannot happen; say so rather than lie.
                (None, _) => "set".to_string(),
            });
            let (quota_entered, quota_error) = match &refused {
                Some(refused) if refused.username == row.username => {
                    (refused.entered.to_string(), Some(refused.error.to_string()))
                }
                _ => (override_bytes.map(format_size).unwrap_or_default(), None),
            };
            MemberView {
                usage: state
                    .stores
                    .pod_bytes(row.id)
                    .map(format_size)
                    .unwrap_or_else(|_| "unknown".to_string()),
                username: row.username,
                role: row.role,
                status: row.status,
                did: row.did_plc,
                // Date only. The time an account was created to the second has
                // never answered a question an operator was actually asking.
                created: row.created_at.date().to_string(),
                quota,
                quota_note,
                quota_entered,
                quota_error,
            }
        })
        .collect();
    Ok(UsersPage {
        chrome: state.chrome(),
        tabs: tabs("/admin/users"),
        members,
    })
}

/// `GET /admin/users`
pub async fn users(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Err(response) = require_admin(&state, &jar, "/admin/users").await {
        return response;
    }
    match users_page(&state, None).await {
        Ok(page) => render(&page),
        Err(()) => server_error(),
    }
}

#[derive(Deserialize)]
pub struct QuotaForm {
    quota: String,
}

/// `POST /admin/users/{username}/quota` — the console's first write.
///
/// Empty clears the override; otherwise the one size grammar. A refused size
/// re-renders the list as a 400 with the message against that row and the
/// value kept, and sets nothing. Lowering a quota below what a member holds
/// refuses their next add until they are under it; it deletes nothing.
///
/// The path and the form arrive as results and are opened only after the
/// guard: axum runs extractors before the handler, so a rejection there
/// would answer a member or an anonymous caller with a 400 or 422 where
/// [`require_admin`] promises a 404 or the login redirect — and tell them
/// the route exists.
pub async fn set_quota(
    State(state): State<AppState>,
    jar: CookieJar,
    username: Result<Path<String>, PathRejection>,
    form: Result<Form<QuotaForm>, FormRejection>,
) -> Response {
    let admin = match require_admin(&state, &jar, "/admin/users").await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    // Only an admin learns the request was malformed.
    let (Ok(Path(username)), Ok(Form(form))) = (username, form) else {
        return (StatusCode::BAD_REQUEST, "malformed request").into_response();
    };
    let member = match db::find_by_username(&state.pool, &username).await {
        Ok(Some(member)) => member,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "member lookup failed");
            return server_error();
        }
    };

    let entered = form.quota.trim();
    // The field is prefilled with the formatted override, so Save on an
    // untouched field posts it back. Writing it would re-stamp who set the
    // quota and when — a CLI-set value would become this admin's, today —
    // for a change nobody made.
    if member
        .quota_bytes
        .is_some_and(|b| entered == format_size(u64::try_from(b).unwrap_or(0)))
    {
        return Redirect::to("/admin/users").into_response();
    }
    let quota_bytes = if entered.is_empty() {
        None
    } else {
        match parse_size(entered) {
            Ok(bytes) => Some(i64::try_from(bytes).unwrap_or(i64::MAX)),
            Err(e) => {
                let error = e.to_string();
                let refused = Refused {
                    username: &username,
                    entered,
                    error: &error,
                };
                return match users_page(&state, Some(refused)).await {
                    Ok(page) => (StatusCode::BAD_REQUEST, render(&page)).into_response(),
                    Err(()) => server_error(),
                };
            }
        }
    };

    if let Err(e) = db::set_quota(&state.pool, member.id, quota_bytes, Some(admin.id)).await {
        tracing::error!(error = %e, member = %member.id, "setting a quota failed");
        return server_error();
    }
    tracing::info!(
        admin = %admin.username,
        member = %member.username,
        from = ?member.quota_bytes,
        to = ?quota_bytes,
        "quota set"
    );
    Redirect::to("/admin/users").into_response()
}
