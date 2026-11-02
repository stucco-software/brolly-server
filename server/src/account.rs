//! The member dashboard: overview, profile, security, apps, export, delete.
//!
//! Plan §4.4 puts this in Phase 4. §4.1 describes this audience as needing to
//! "understand what is theirs and how to leave with it", which is why export
//! and delete are surfaces here and not a support request — a pod you cannot
//! leave with is not yours.
//!
//! Server-rendered, every form a real `<form method="post">` (§4.2). Nothing
//! here needs JavaScript.

use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use brolly_identity::db::{self, DbError, User};
use brolly_identity::{routing, webid};
use brolly_solid::oidc::store as oidc_store;
use brolly_solid::profile::{self, Profile};
use brolly_store::resources::PodRead;
use serde::Deserialize;

use crate::auth::SESSION_COOKIE;
use crate::ratelimit::{Gate, too_many};
use crate::{AppState, Chrome, render};

/// One tab in the dashboard.
pub struct Tab {
    pub href: &'static str,
    pub label: &'static str,
    pub current: bool,
}

fn tabs(current: &str) -> Vec<Tab> {
    [
        ("/account", "Overview"),
        ("/account/profile", "Profile"),
        ("/account/security", "Security"),
        ("/account/apps", "Apps"),
        ("/account/export", "Export"),
        ("/account/delete", "Delete"),
    ]
    .into_iter()
    .map(|(href, label)| Tab {
        href,
        label,
        current: href == current,
    })
    .collect()
}

/// The session behind a dashboard request.
///
/// Both the user and the raw token: "log out everywhere else" needs to know
/// which session to keep.
struct Session {
    user: User,
    token: String,
}

/// Resolve the session, or send an anonymous visitor to log in and back.
async fn require_session(
    state: &AppState,
    jar: &CookieJar,
    path: &str,
) -> Result<Session, Response> {
    let redirect = || {
        let query: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("next", path)
            .finish();
        Redirect::to(&format!("/login?{query}")).into_response()
    };

    let Some(cookie) = jar.get(SESSION_COOKIE) else {
        return Err(redirect());
    };
    match db::user_for_session(&state.pool, cookie.value()).await {
        Ok(Some(user)) if user.is_active() => Ok(Session {
            user,
            token: cookie.value().to_string(),
        }),
        Ok(_) => Err(redirect()),
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed");
            Err(server_error())
        }
    }
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Try again.",
    )
        .into_response()
}

// --- overview ---------------------------------------------------------------

#[derive(Template)]
#[template(path = "account/overview.html")]
struct Overview<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    username: &'a str,
    webid: String,
    storage_root: String,
    did: Option<&'a str>,
    pod_bytes: u64,
    /// The effective quota: an admin's override or the instance default
    /// (`User::quota`). The meter's ceiling.
    quota_bytes: u64,
    /// 90% of it: where the meter turns.
    warn_at: u64,
    /// Both, formatted for the words beside the meter.
    used: String,
    quota: String,
    /// Whether to offer a way into the admin console.
    ///
    /// The console has no other entry point, and guessing `/admin` answers 404
    /// for a member — so without this an admin has no way to discover the
    /// surface they are responsible for.
    is_admin: bool,
}

/// `GET /account`
pub async fn overview(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session = match require_session(&state, &jar, "/account").await {
        Ok(s) => s,
        Err(response) => return response,
    };

    let pod_bytes = state.stores.pod_bytes(session.user.id).unwrap_or(0);
    let quota_bytes = session.user.quota(state.pod_quota_bytes);
    render(&Overview {
        chrome: state.chrome(),
        tabs: tabs("/account"),
        username: &session.user.username,
        webid: webid::webid(&session.user.username, &state.base_domain),
        storage_root: routing::storage_root(&session.user.username, &state.base_domain),
        did: session.user.did_plc.as_deref(),
        pod_bytes,
        quota_bytes,
        warn_at: quota_bytes / 10 * 9,
        used: brolly_domain::media::format_size(pod_bytes),
        quota: brolly_domain::media::format_size(quota_bytes),
        is_admin: session.user.is_admin(),
    })
}

// --- profile ----------------------------------------------------------------

#[derive(Template)]
#[template(path = "account/profile.html")]
struct ProfilePage<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    webid: String,
    display_name: String,
    bio: String,
    saved: bool,
}

#[derive(Deserialize)]
pub struct ProfileForm {
    display_name: String,
    bio: String,
}

#[derive(Deserialize, Default)]
pub struct Saved {
    #[serde(default)]
    saved: bool,
}

/// `GET /account/profile`
pub async fn profile_form(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(query): axum::extract::Query<Saved>,
) -> Response {
    let session = match require_session(&state, &jar, "/account/profile").await {
        Ok(s) => s,
        Err(response) => return response,
    };

    let Ok(pod) = state.stores.pod(session.user.id) else {
        return server_error();
    };
    let id = webid::webid(&session.user.username, &state.base_domain);
    let document = webid::profile_document(&session.user.username, &state.base_domain);
    let current = profile::read(&pod.read_store(), &id, &document);

    render(&ProfilePage {
        chrome: state.chrome(),
        tabs: tabs("/account/profile"),
        webid: id,
        display_name: current.display_name,
        bio: current.bio,
        saved: query.saved,
    })
}

/// `POST /account/profile`
///
/// Writes into the pod, never into Postgres. The predecessor migrated display
/// names out of the users table on principle and added a column back seven
/// weeks later; the read that forced it belongs to the server-agent index.
pub async fn profile_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ProfileForm>,
) -> Response {
    let session = match require_session(&state, &jar, "/account/profile").await {
        Ok(s) => s,
        Err(response) => return response,
    };

    let Ok(pod) = state.stores.pod(session.user.id) else {
        return server_error();
    };
    let id = webid::webid(&session.user.username, &state.base_domain);
    let document = webid::profile_document(&session.user.username, &state.base_domain);

    // Read before writing, in the same write, so this form edits only the two
    // fields it owns. `profile::write` replaces every predicate it manages, so
    // passing defaults for the flags would silently unlock a locked account
    // from a page that never mentions locking.
    let written = pod.write(|w| {
        let existing = profile::read(&*w, &id, &document);
        profile::write(
            w,
            &id,
            &document,
            &Profile {
                display_name: form.display_name,
                bio: form.bio,
                ..existing
            },
        )
    });
    match written {
        Ok(()) => Redirect::to("/account/profile?saved=true").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "profile write failed");
            server_error()
        }
    }
}

// --- security ---------------------------------------------------------------

#[derive(Template)]
#[template(path = "account/security.html")]
struct Security<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    sessions: i64,
    error: Option<&'a str>,
    saved: bool,
}

fn security_page<'a>(
    state: &'a AppState,
    error: Option<&'a str>,
    sessions: i64,
    saved: bool,
) -> Security<'a> {
    Security {
        chrome: state.chrome(),
        tabs: tabs("/account/security"),
        sessions,
        error,
        saved,
    }
}

#[derive(Deserialize)]
pub struct PasswordForm {
    current_password: String,
    new_password: String,
}

/// `GET /account/security`
pub async fn security(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(query): axum::extract::Query<Saved>,
) -> Response {
    let session = match require_session(&state, &jar, "/account/security").await {
        Ok(s) => s,
        Err(response) => return response,
    };
    let sessions = db::count_sessions(&state.pool, session.user.id)
        .await
        .unwrap_or(0);
    render(&security_page(&state, None, sessions, query.saved))
}

/// `POST /account/security` — change password.
///
/// Succeeding also ends every *other* session: someone changing their password
/// is often doing it because they think another session is not theirs.
pub async fn change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<PasswordForm>,
) -> Response {
    let session = match require_session(&state, &jar, "/account/security").await {
        Ok(s) => s,
        Err(response) => return response,
    };
    // Per member, not per address: the one way to guess a current password
    // is from inside a session, and the session is the member's wherever
    // the thief is sitting. Spent before anything is checked, so a refused
    // attempt changes nothing whether or not it was right.
    if let Err(wait) = state
        .limiter
        .check(Gate::PasswordChange, &session.user.id.to_string())
    {
        return too_many(wait);
    }
    let sessions = db::count_sessions(&state.pool, session.user.id)
        .await
        .unwrap_or(0);

    if form.new_password.chars().count() < 12 {
        return (
            StatusCode::BAD_REQUEST,
            render(&security_page(
                &state,
                Some("Use at least 12 characters. Length beats punctuation."),
                sessions,
                false,
            )),
        )
            .into_response();
    }

    match db::change_password(
        &state.pool,
        session.user.id,
        &form.current_password,
        &form.new_password,
    )
    .await
    {
        Ok(()) => {
            if let Err(e) =
                db::revoke_other_sessions(&state.pool, session.user.id, &session.token).await
            {
                tracing::error!(error = %e, "revoking other sessions failed after a password change");
            }
            // The ATProtocol sessions end too (2, G) — OAuth and legacy, both
            // tables. The member asked to end other sessions, and before this
            // only the browser ones ended; `oauth::revoke_all_for_user` existed
            // with no caller at all.
            if let Err(e) =
                brolly_atproto::oauth::revoke_all_for_user(&state.pool, session.user.id).await
            {
                tracing::error!(error = %e, "revoking ATProto OAuth tokens failed after a password change");
            }
            if let Err(e) =
                brolly_atproto::legacy::revoke_all_for_user(&state.pool, session.user.id).await
            {
                tracing::error!(error = %e, "revoking ATProto legacy sessions failed after a password change");
            }
            // And the Solid apps and the Mastodon clients: a refresh token or
            // a bearer is a session that outlives any browser, and the page
            // promises the others have ended. Both functions existed with no
            // caller here.
            if let Err(e) = oidc_store::revoke_all_for_user(&state.pool, session.user.id).await {
                tracing::error!(error = %e, "revoking Solid app grants failed after a password change");
            }
            if let Err(e) =
                brolly_mastodon::oauth::revoke_all_for_user(&state.pool, session.user.id).await
            {
                tracing::error!(error = %e, "revoking Mastodon client tokens failed after a password change");
            }
            Redirect::to("/account/security?saved=true").into_response()
        }
        Err(DbError::BadCredentials) => (
            StatusCode::UNAUTHORIZED,
            render(&security_page(
                &state,
                Some("That is not your current password."),
                sessions,
                false,
            )),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "password change failed");
            server_error()
        }
    }
}

// --- apps -------------------------------------------------------------------

#[derive(Template)]
#[template(path = "account/apps.html")]
struct Apps<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    apps: Vec<oidc_store::AuthorisedApp>,
    saved: bool,
}

/// `GET /account/apps`
pub async fn apps(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(query): axum::extract::Query<Saved>,
) -> Response {
    let session = match require_session(&state, &jar, "/account/apps").await {
        Ok(s) => s,
        Err(response) => return response,
    };

    let apps = match oidc_store::apps_for_user(&state.pool, session.user.id).await {
        Ok(apps) => apps,
        Err(e) => {
            tracing::error!(error = %e, "listing authorised apps failed");
            return server_error();
        }
    };

    render(&Apps {
        chrome: state.chrome(),
        saved: query.saved,
        tabs: tabs("/account/apps"),
        apps,
    })
}

#[derive(Deserialize)]
pub struct RevokeForm {
    client_id: String,
}

/// `POST /account/apps` — withdraw one app's access.
///
/// This is the promise the consent screen makes: "you can revoke this at any
/// time from your account settings."
pub async fn revoke_app(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<RevokeForm>,
) -> Response {
    let session = match require_session(&state, &jar, "/account/apps").await {
        Ok(s) => s,
        Err(response) => return response,
    };

    // Scoped by user *and* client, so a member cannot revoke anyone else's
    // grant to an app they happen to share.
    match oidc_store::revoke_app_for_user(&state.pool, session.user.id, &form.client_id).await {
        Ok(revoked) => {
            tracing::info!(user = %session.user.id, client = %form.client_id, revoked, "app access withdrawn");
            // Withdrawing an application's access to your pod is a security
            // action, and without the parameter the page comes back looking
            // almost the same — the row is simply gone.
            Redirect::to("/account/apps?saved=true").into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "revoking an app failed");
            server_error()
        }
    }
}

// --- export -----------------------------------------------------------------

/// `GET /account/export`
///
/// The whole pod as N-Quads. Complete, because D7's promise is that export is
/// complete — and N-Quads because it is the syntax that carries named graphs,
/// and the graphs are what make the dump re-importable rather than a pile of
/// triples with their resource identity lost.
pub async fn export(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session = match require_session(&state, &jar, "/account/export").await {
        Ok(s) => s,
        Err(response) => return response,
    };

    let Ok(pod) = state.stores.pod(session.user.id) else {
        return server_error();
    };
    // Every graph in the pod, through a read of the committed store.
    let quads: Vec<_> = pod
        .read_store()
        .quads_for_pattern(None, None, None, None)
        .filter_map(Result::ok)
        .collect();

    let body = match brolly_domain::syntax::serialize(
        &quads,
        brolly_domain::syntax::WriteFormat::NQuads,
    ) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, "export serialization failed");
            return server_error();
        }
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/n-quads".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}-pod.nq\"", session.user.username),
            ),
        ],
        body,
    )
        .into_response()
}

// --- delete -----------------------------------------------------------------

#[derive(Template)]
#[template(path = "account/delete.html")]
struct Delete<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    username: &'a str,
    error: Option<&'a str>,
}

#[derive(Deserialize)]
pub struct DeleteForm {
    confirm: String,
}

/// `GET /account/delete`
pub async fn delete_form(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session = match require_session(&state, &jar, "/account/delete").await {
        Ok(s) => s,
        Err(response) => return response,
    };
    render(&Delete {
        chrome: state.chrome(),
        tabs: tabs("/account/delete"),
        username: &session.user.username,
        error: None,
    })
}

/// `POST /account/delete`
///
/// The pod goes first. If the user row went first and the `rm -rf` then failed,
/// the bytes would be left with nothing pointing at them and no account able to
/// ask for them again.
pub async fn delete_account(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<DeleteForm>,
) -> Response {
    let session = match require_session(&state, &jar, "/account/delete").await {
        Ok(s) => s,
        Err(response) => return response,
    };

    // Typing the username is not ceremony: this is the one irreversible action
    // in the product, and it is reached from a nav tab.
    if form.confirm.trim() != session.user.username {
        return (
            StatusCode::BAD_REQUEST,
            render(&Delete {
                chrome: state.chrome(),
                tabs: tabs("/account/delete"),
                username: &session.user.username,
                error: Some("That did not match your username. Nothing has been deleted."),
            }),
        )
            .into_response();
    }

    if let Err(e) = state.stores.delete_pod(session.user.id) {
        tracing::error!(error = %e, user = %session.user.id, "deleting the pod failed");
        return server_error();
    }

    // The user row and the `#account` event land in one transaction (1, E):
    // an event for a deletion that did not happen makes a relay drop a live
    // repo, and a deletion without its event leaves the network serving a
    // deleted one. The pod is already gone either way — `rm -rf` is not
    // transactional — so the transaction covers what can be covered.
    //
    // Only a member with a DID announces: an account that never finished
    // provisioning has no identity the network ever learned, and an event a
    // consumer cannot resolve is noise.
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = %e, user = %session.user.id, "the deletion could not begin");
            return server_error();
        }
    };
    if let Err(e) = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(session.user.id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(error = %e, user = %session.user.id, "deleting the user failed");
        return server_error();
    }
    let account_event = match session.user.did_plc.as_deref() {
        Some(did) => {
            match brolly_atproto::firehose::record_account(&mut tx, did, false, Some("deleted"))
                .await
            {
                Ok(event) => Some(event),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        user = %session.user.id,
                        "recording the deletion's firehose event failed"
                    );
                    return server_error();
                }
            }
        }
        None => None,
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, user = %session.user.id, "the deletion could not commit");
        return server_error();
    }
    if let Some(event) = account_event {
        // The fast path (1, G): the transactional notify that rode the deletion
        // above is what the shared listener turns into a rebroadcast, so this
        // send is latency, not correctness. `send` fails only when nobody is
        // listening, which is normal.
        let _ = state
            .commits
            .send(brolly_atproto::firehose::Event::Account(event));
    }
    tracing::info!(user = %session.user.id, "account deleted");

    // Sessions cascade with the user row; clearing the cookie stops the browser
    // presenting a token that no longer resolves.
    (
        jar.remove(crate::auth::session_cookie(String::new())),
        Redirect::to("/"),
    )
        .into_response()
}
