//! The Mastodon Client API.
//!
//! **Everything under `/api/` answers JSON, including its failures.** The
//! predecessor let unmatched `/api/v*` paths fall through to the Solid/LDP
//! router, so a client polling an endpoint we had not built got RDF or an HTML
//! error page back. Clients cannot parse that; they surface it as an
//! unexplained failure, and the member sees a broken tab with no reason.
//!
//! The catch-all is mounted as a wildcard route rather than as the app's
//! fallback, because the app's fallback belongs to the pod's default-deny
//! (ADR 0010). Axum matches literal segments before wildcards, so this cannot
//! shadow a real endpoint — a test asserts it anyway, since "cannot shadow" is
//! exactly the kind of claim that stops being true.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use brolly_identity::db::{self, User};
use brolly_identity::{extract, webid};
use brolly_mastodon::oauth::Grant;
use brolly_mastodon::{instance, oauth, status_id, timeline, translate};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;

/// Default and maximum page sizes, matching Mastodon's.
const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 40;

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(instance::error(message))).into_response()
}

/// Mastodon's own 404 body, used everywhere a record is missing.
fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "Record not found")
}

fn unauthorized() -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        "The access token is invalid or expired",
    )
}

fn host_of(headers: &HeaderMap) -> &str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
}

/// The Client API is apex-only, like the OAuth surface it authenticates with.
fn wrong_host(state: &AppState, headers: &HeaderMap) -> bool {
    extract::subdomain_user(host_of(headers), &state.base_domain).is_some()
}

/// Resolve a bearer token to the member holding it.
///
/// Credential parsing goes through `identity::extract` — the only place in the
/// workspace permitted to read an `Authorization` header, enforced by
/// `tests/architecture.rs`.
async fn authenticated(state: &AppState, headers: &HeaderMap) -> Option<(User, Grant)> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let credential = extract::credential(authorization, None)?;

    let brolly_identity::Credential::Bearer(token) = credential else {
        // A DPoP-bound Solid token presented here is not a Mastodon token, and
        // honouring it without its proof would make the binding decorative.
        return None;
    };

    let grant = oauth::verify_token(&state.pool, &token).await.ok()??;
    let user = db::find_by_id(&state.pool, grant.user_id).await.ok()??;
    user.is_active().then_some((user, grant))
}

/// Build the `Author` the translation layer needs.
async fn author_for(state: &AppState, user: &User) -> translate::Author {
    let profile = match state.stores.pod(user.id) {
        Ok(pod) => brolly_solid::profile::read(
            &pod,
            &webid::webid(&user.username, &state.base_domain),
            &webid::profile_document(&user.username, &state.base_domain),
        ),
        Err(_) => brolly_solid::profile::Profile::default(),
    };
    translate::Author {
        user_id: user.id,
        username: user.username.clone(),
        display_name: profile.display_name,
        bio: profile.bio,
        locked: false,
        bot: false,
        discoverable: true,
        created_at: String::new(),
    }
}

/// Resolve an actor IRI to a local member, if it is one.
async fn local_author(state: &AppState, actor: &str) -> Option<translate::Author> {
    // An actor IRI is `https://<user>.<base>/actor`; the WebID helper already
    // knows how to read a username out of one of ours, and returns None for
    // anything remote.
    let username = actor
        .strip_suffix("/actor")
        .map(|base| format!("{base}/profile#me"))
        .and_then(|webid| webid::local_username(&webid, &state.base_domain))?;
    let user = db::find_by_username(&state.pool, &username).await.ok()??;
    Some(author_for(state, &user).await)
}

// --- instance ------------------------------------------------------------------

async fn counts(state: &AppState) -> (i64, i64) {
    let users = sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM users WHERE status = 'active'")
        .fetch_one(&state.pool)
        .await
        .map(|(n,)| n)
        .unwrap_or_default();
    let posts = brolly_store::index::count_notes(state.stores.instance()).unwrap_or_default();
    (users, posts)
}

pub async fn instance_v1(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let (users, posts) = counts(&state).await;
    Json(instance::instance_v1(
        &state.base_domain,
        "Brolly",
        "A private community server.",
        users,
        posts,
    ))
    .into_response()
}

pub async fn instance_v2(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let (users, posts) = counts(&state).await;
    Json(instance::instance_v2(
        &state.base_domain,
        "Brolly",
        "A private community server.",
        users,
        posts,
    ))
    .into_response()
}

// --- accounts ------------------------------------------------------------------

pub async fn verify_credentials(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, _)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    let author = author_for(&state, &user).await;
    let mut account = translate::account(&author, &state.base_domain);
    // `source` appears only on your own account, and clients read it to
    // populate the preferences panel.
    account["source"] = json!({
        "privacy": "public",
        "sensitive": false,
        "language": Value::Null,
        "note": account["note"].clone(),
        "fields": [],
    });
    Json(account).into_response()
}

pub async fn account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some(user_id) = translate::account_id_to_uuid(&id) else {
        return not_found();
    };
    match db::find_by_id(&state.pool, user_id).await {
        Ok(Some(user)) if user.is_active() => {
            let author = author_for(&state, &user).await;
            Json(translate::account(&author, &state.base_domain)).into_response()
        }
        _ => not_found(),
    }
}

/// Pull a repeated query parameter out of a raw query string.
///
/// Clients send `id[]=a&id[]=b`, and some send `id=a&id=b`. Neither folds into
/// a `Vec` through `serde_urlencoded`, which is what axum's `Query` uses — the
/// bracket form is a *different key*, and the bare form keeps only one value.
/// So the query is parsed directly and both spellings are accepted.
fn repeated(query: Option<&str>, name: &str) -> Vec<String> {
    let bracketed = format!("{name}[]");
    form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == name || *key == bracketed)
        .map(|(_, value)| value.into_owned())
        .collect()
}

/// `GET /api/v1/accounts/relationships`
///
/// Clients call this constantly — every profile view, and every timeline render
/// that shows a follow button. The predecessor had it missing entirely, so it
/// hit the JSON-404 catch-all and every follow button rendered in the wrong
/// state until the member interacted with it.
pub async fn relationships(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    if authenticated(&state, &headers).await.is_none() {
        return unauthorized();
    }

    // Follow state lives in RDF collections, and reading it per-id is Phase 6's
    // follow work. Until then the honest answer is "not following", which is
    // what an empty relationship says — and it is the same answer Mastodon
    // gives for an account you have no relationship with.
    let relationships: Vec<Value> = repeated(query.as_deref(), "id")
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "following": false,
                "showing_reblogs": false,
                "notifying": false,
                "followed_by": false,
                "blocking": false,
                "blocked_by": false,
                "muting": false,
                "muting_notifications": false,
                "requested": false,
                "domain_blocking": false,
                "endorsed": false,
                "note": "",
            })
        })
        .collect();

    Json(relationships).into_response()
}

// --- timelines -----------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct TimelineQuery {
    limit: Option<usize>,
    max_id: Option<String>,
}

fn page_limit(requested: Option<usize>) -> usize {
    requested.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// `GET /api/v1/timelines/home` — the viewer's own inbox (D6).
pub async fn home_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TimelineQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, grant)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    if !oauth::has_scope(&grant.scopes, "read:statuses") {
        return error(StatusCode::FORBIDDEN, "This action requires read scope");
    }

    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };

    // `max_id` is a status id; the cursor the collection pages on is receipt
    // time. Translating between them is a lookup of the row it names.
    let cursor = query.max_id.as_deref().and_then(|id| {
        let inbox = webid::inbox(&user.username, &state.base_domain);
        timeline::home(&pod, &inbox, MAX_LIMIT * 4, None)
            .into_iter()
            .find(|row| {
                status_id::note_id_from_iri(row.note["id"].as_str().unwrap_or_default())
                    .and_then(|note| status_id::encode(note, user.id))
                    .is_some_and(|encoded| encoded == id)
            })
            .map(|row| row.cursor)
    });

    let inbox = webid::inbox(&user.username, &state.base_domain);
    let rows = timeline::home(&pod, &inbox, page_limit(query.limit), cursor.as_deref());

    let mut statuses = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(author) = local_author(&state, &row.author_actor).await
            && let Some(status) = translate::try_status(&row.note, &author, &state.base_domain)
        {
            statuses.push(status);
        }
    }
    Json(statuses).into_response()
}

/// `GET /api/v1/timelines/public` — the server index (ADR 0005 R1).
pub async fn public_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TimelineQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }

    let iris = match brolly_store::index::public_note_iris(
        state.stores.instance(),
        page_limit(query.limit),
        None,
    ) {
        Ok(iris) => iris,
        Err(e) => {
            tracing::error!(error = %e, "public timeline query failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "Timeline unavailable");
        }
    };

    // Dereference only this page, from each author's own pod (D5).
    let mut notes = Vec::with_capacity(iris.len());
    for iri in &iris {
        notes.push(fetch_note(&state, iri).await);
    }
    let mut index = notes.into_iter();
    let rows = timeline::public(&iris, |_| index.next().flatten());

    let mut statuses = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(author) = local_author(&state, &row.author_actor).await
            && let Some(status) = translate::try_status(&row.note, &author, &state.base_domain)
        {
            statuses.push(status);
        }
    }
    Json(statuses).into_response()
}

/// Read one note out of its author's pod, given its IRI.
async fn fetch_note(state: &AppState, iri: &str) -> Option<Value> {
    let username = iri
        .strip_prefix("https://")
        .and_then(|rest| rest.split_once('.'))
        .map(|(user, _)| user.to_string())?;
    let user = db::find_by_username(&state.pool, &username).await.ok()??;
    let pod = state.stores.pod(user.id).ok()?;
    brolly_store::collection::read_record(&pod, iri)
}

// --- statuses ------------------------------------------------------------------

/// `GET /api/v1/statuses/{id}`
///
/// The id decodes to a note identifier and an owner, so this is a decode plus a
/// primary-key lookup — no index, no routing table (ADR 0015).
pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((note_id, owner)) = status_id::decode(&id) else {
        return not_found();
    };
    let Ok(Some(user)) = db::find_by_id(&state.pool, owner).await else {
        return not_found();
    };
    if !user.is_active() {
        return not_found();
    }

    let iri = status_id::note_iri(&note_id, &user.username, &state.base_domain);
    let Ok(pod) = state.stores.pod(user.id) else {
        return not_found();
    };
    let Some(note) = brolly_store::collection::read_record(&pod, &iri) else {
        return not_found();
    };

    let author = author_for(&state, &user).await;
    match translate::try_status(&note, &author, &state.base_domain) {
        Some(status) => Json(status).into_response(),
        None => not_found(),
    }
}

// --- stubs and the catch-all -----------------------------------------------------

/// Endpoints that exist, are empty, and say so in JSON.
fn stub(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// `/api/*` that matched nothing.
///
/// A JSON 404 rather than the pod's default-deny, so a client polling an
/// endpoint we have not built gets something it can parse. No write is faked:
/// an unimplemented POST lands here too and answers 404 rather than pretending.
pub async fn unmatched() -> Response {
    not_found()
}

/// Mount the Client API.
pub fn routes() -> Router<AppState> {
    let mut router = Router::new()
        .route("/api/v1/instance", get(instance_v1))
        .route("/api/v2/instance", get(instance_v2))
        .route(
            "/api/v1/accounts/verify_credentials",
            get(verify_credentials),
        )
        .route("/api/v1/accounts/relationships", get(relationships))
        .route("/api/v1/accounts/{id}", get(account))
        .route("/api/v1/timelines/home", get(home_timeline))
        .route("/api/v1/timelines/public", get(public_timeline))
        .route("/api/v1/statuses/{id}", get(status));

    // Empty reads. Behind auth, matching Mastodon — except the public ones,
    // which clients fetch before login.
    for (path, body) in brolly_mastodon::instance::EMPTY_READS {
        router = router.route(
            path,
            get(
                move |State(state): State<AppState>, headers: HeaderMap| async move {
                    if wrong_host(&state, &headers) {
                        return not_found();
                    }
                    if authenticated(&state, &headers).await.is_none() {
                        return unauthorized();
                    }
                    stub(body)
                },
            ),
        );
    }
    for (path, body) in brolly_mastodon::instance::PUBLIC_EMPTY_READS {
        router = router.route(path, get(move || async move { stub(body) }));
    }

    // Last, and a wildcard: axum matches literal segments first, so this
    // catches only what nothing else claimed.
    router.route(
        "/api/{*rest}",
        get(unmatched)
            .post(unmatched)
            .put(unmatched)
            .patch(unmatched)
            .delete(unmatched),
    )
}
