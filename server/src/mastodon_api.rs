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
use axum::routing::{get, post};
use axum::{Json, Router};
use brolly_identity::db::{self, User};
use brolly_identity::{extract, webid};
use brolly_mastodon::oauth::Grant;
use brolly_mastodon::{compose, instance, oauth, status_id, timeline, translate};
use brolly_store::resources::{Pod, PodRead};
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
            &pod.read_store(),
            &webid::webid(&user.username, &state.base_domain),
            &webid::profile_document(&user.username, &state.base_domain),
        ),
        Err(_) => brolly_solid::profile::Profile::blank(),
    };
    translate::Author {
        user_id: user.id,
        username: user.username.clone(),
        display_name: profile.display_name,
        bio: profile.bio,
        // Read, not hardcoded. These were accepted and ignored before, so an
        // account that said it was locked rendered as locked and behaved as
        // open.
        locked: profile.locked,
        bot: profile.bot,
        discoverable: profile.discoverable,
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
    // The public timeline is unauthenticated, and this is where each note's
    // author is resolved for it — a disabled account's posts must vanish
    // here, since nothing upstream of this filters by status.
    let user = db::find_by_username(&state.pool, &username)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)?;
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
        &state.instance_name,
        &state.instance_description,
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
        &state.instance_name,
        &state.instance_description,
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
        timeline::home(&pod.read_store(), &inbox, MAX_LIMIT * 4, None)
            .into_iter()
            .find(|row| {
                status_id::note_id_from_iri(row.note["id"].as_str().unwrap_or_default())
                    .and_then(|note| status_id::encode(note, user.id))
                    .is_some_and(|encoded| encoded == id)
            })
            .map(|row| row.cursor)
    });

    let inbox = webid::inbox(&user.username, &state.base_domain);
    let rows = timeline::home(
        &pod.read_store(),
        &inbox,
        page_limit(query.limit),
        cursor.as_deref(),
    );

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
    // Same reasoning as local_author: `public_note_iris` is a store-index
    // query with no notion of account status, so a disabled member's note
    // must be dropped here, at the point it is fetched by owner.
    let user = db::find_by_username(&state.pool, &username)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)?;
    let pod = state.stores.pod(user.id).ok()?;
    brolly_store::collection::read_record(&pod.read_store(), iri)
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
    let Some(note) = brolly_store::collection::read_record(&pod.read_store(), &iri) else {
        return not_found();
    };

    let author = author_for(&state, &user).await;
    match translate::try_status(&note, &author, &state.base_domain) {
        Some(status) => Json(status).into_response(),
        None => not_found(),
    }
}

// --- media ---------------------------------------------------------------------

/// Where a member's uploads live inside their pod.
fn media_iri(username: &str, base_domain: &str, id: &str) -> String {
    format!("https://{username}.{base_domain}/~/media/{id}")
}

/// Alt text, stored on the media resource itself.
///
/// It has to live somewhere the resource can be read back from *before* it is
/// attached, because `PUT /api/v1/media/{id}` is how clients set a description
/// while the composer is still open.
const ALT_TEXT: &str = "https://brolly.id/ns#altText";

/// The `Subject` a member's own API call acts as.
///
/// Built so media writes go through the same WAC evaluation as every other
/// write (§2.8: one authorization layer under every protocol). Bypassing it
/// here would make the Mastodon surface the one place authorization is not
/// checked, which is exactly the shape of the predecessor's problem.
fn subject_for(state: &AppState, user: &User, grant: &Grant) -> brolly_identity::Subject {
    brolly_identity::Subject::local(
        user.id,
        user.did_plc.clone().unwrap_or_default(),
        webid::webid(&user.username, &state.base_domain),
        brolly_identity::Scope::parse(&grant.scopes),
        brolly_identity::Via::MastodonBearer,
    )
}

fn media_json(id: &str, url: &str, media_type: &str, description: Option<&str>) -> Value {
    let kind = match media_type.split('/').next().unwrap_or_default() {
        "image" => "image",
        "video" => "video",
        "audio" => "audio",
        _ => "unknown",
    };
    json!({
        "id": id,
        "type": kind,
        "url": url,
        "preview_url": url,
        "remote_url": Value::Null,
        "description": description,
        "blurhash": Value::Null,
        "meta": json!({}),
    })
}

/// `POST /api/v1/media` and `/api/v2/media`
pub async fn upload_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, grant)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    if !oauth::has_scope(&grant.scopes, "write:media") {
        return error(StatusCode::FORBIDDEN, "This action requires write scope");
    }

    let mut bytes: Option<Vec<u8>> = None;
    let mut media_type = String::new();
    let mut description: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or_default() {
            "file" => {
                media_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            "description" => description = field.text().await.ok(),
            _ => {}
        }
    }

    let Some(bytes) = bytes.filter(|b| !b.is_empty()) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Validation failed: File can't be blank",
        );
    };

    let id = status_id::mint_note_id();
    let path = format!("/~/media/{id}");
    let base = format!("https://{}.{}", user.username, state.base_domain);

    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };
    let blobs = state.stores.blobs(user.id).ok();

    if let Err(e) = brolly_solid::ldp::put(
        &pod,
        blobs.as_ref(),
        &base,
        &path,
        &subject_for(&state, &user, &grant),
        &bytes,
        &media_type,
        &brolly_identity::routing::storage_root(&user.username, &state.base_domain),
    ) {
        tracing::error!(error = %e, "media upload failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Upload failed");
    }

    let iri = media_iri(&user.username, &state.base_domain, &id);
    if let Some(text) = description.as_deref().filter(|d| !d.trim().is_empty()) {
        set_alt_text(&pod, &iri, text);
    }

    let media_id = status_id::encode(&id, user.id).unwrap_or(id);
    (
        StatusCode::OK,
        Json(media_json(
            &media_id,
            &iri,
            &media_type,
            description.as_deref(),
        )),
    )
        .into_response()
}

fn set_alt_text(pod: &Pod, iri: &str, text: &str) {
    use oxigraph_model::{Literal, NamedNode, NamedOrBlankNode, Quad, Term};
    let node = NamedNode::new_unchecked(iri);
    let quad = Quad::new(
        NamedOrBlankNode::NamedNode(node.clone()),
        NamedNode::new_unchecked(ALT_TEXT),
        Term::Literal(Literal::new_simple_literal(text)),
        oxigraph_model::GraphName::NamedNode(node),
    );
    // The media resource is under the storage root, so this is written the
    // way it always was until the pod keeps resource metadata.
    if let Err(e) = pod.write(|w| w.legacy_under_root().insert(&[quad])) {
        tracing::warn!(error = %e, "storing alt text failed");
    }
}

fn alt_text(pod: &impl PodRead, iri: &str) -> Option<String> {
    brolly_store::collection::literal(pod, iri, ALT_TEXT)
}

/// `PUT /api/v1/media/{id}` — set or change alt text.
///
/// Works before *and* after the media is attached, because a client keeps the
/// composer open while the member types a description.
pub async fn update_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, grant)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    if !oauth::has_scope(&grant.scopes, "write:media") {
        return error(StatusCode::FORBIDDEN, "This action requires write scope");
    }

    let Some((local_id, owner)) = status_id::decode(&id) else {
        return not_found();
    };
    // Mastodon's semantics: someone else's attachment is *not found*, not
    // forbidden — a 403 would confirm it exists.
    if owner != user.id {
        return not_found();
    }

    #[derive(Deserialize, Default)]
    struct Update {
        description: Option<String>,
    }
    let update: Update = serde_urlencoded::from_bytes(&body)
        .or_else(|_| serde_json::from_slice(&body))
        .unwrap_or_default();

    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };
    let iri = media_iri(&user.username, &state.base_domain, &local_id);
    if brolly_solid::ldp::blob_digest(&pod.read_store(), &iri).is_none() {
        return not_found();
    }

    if let Some(text) = update.description.as_deref() {
        set_alt_text(&pod, &iri, text);
    }

    let media_type = brolly_store::collection::literal(
        &pod.read_store(),
        &iri,
        brolly_solid::ldp::BLOB_MEDIA_TYPE,
    )
    .unwrap_or_else(|| "application/octet-stream".into());
    Json(media_json(
        &id,
        &iri,
        &media_type,
        alt_text(&pod.read_store(), &iri).as_deref(),
    ))
    .into_response()
}

/// `GET /api/v1/media/{id}` — clients poll this for processing state.
pub async fn get_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, _)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    let Some((local_id, owner)) = status_id::decode(&id) else {
        return not_found();
    };
    if owner != user.id {
        return not_found();
    }
    let Ok(pod) = state.stores.pod(user.id) else {
        return not_found();
    };
    let iri = media_iri(&user.username, &state.base_domain, &local_id);
    if brolly_solid::ldp::blob_digest(&pod.read_store(), &iri).is_none() {
        return not_found();
    }
    let media_type = brolly_store::collection::literal(
        &pod.read_store(),
        &iri,
        brolly_solid::ldp::BLOB_MEDIA_TYPE,
    )
    .unwrap_or_else(|| "application/octet-stream".into());
    Json(media_json(
        &id,
        &iri,
        &media_type,
        alt_text(&pod.read_store(), &iri).as_deref(),
    ))
    .into_response()
}

// --- composition -----------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct StatusForm {
    status: Option<String>,
    spoiler_text: Option<String>,
    sensitive: Option<bool>,
    language: Option<String>,
    visibility: Option<String>,
    in_reply_to_id: Option<String>,
}

/// `POST /api/v1/statuses`
///
/// Publishes through the *same* delivery path as the outbox. The predecessor
/// had a second fan-out here that queried a table a migration had dropped, and
/// swallowed the error — so statuses were delivered to nobody, silently.
pub async fn create_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, grant)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    if !oauth::has_scope(&grant.scopes, "write:statuses") {
        return error(StatusCode::FORBIDDEN, "This action requires write scope");
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let form: StatusForm = if content_type.contains("json") {
        serde_json::from_slice(&body).unwrap_or_default()
    } else {
        serde_urlencoded::from_bytes(&body).unwrap_or_default()
    };
    let media_ids = repeated(std::str::from_utf8(&body).ok(), "media_ids");

    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };

    // Resolve each media id, and refuse any that is not this member's. An
    // attachment silently dropped here is the exact defect being closed.
    let mut attachments = Vec::new();
    for media_id in &media_ids {
        let Some((local_id, owner)) = status_id::decode(media_id) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Validation failed: Media attachment not found",
            );
        };
        if owner != user.id {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Validation failed: Media attachment not found",
            );
        }
        let iri = media_iri(&user.username, &state.base_domain, &local_id);
        let Some(_) = brolly_solid::ldp::blob_digest(&pod.read_store(), &iri) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Validation failed: Media attachment not found",
            );
        };
        attachments.push(compose::Attachment {
            media_type: brolly_store::collection::literal(
                &pod.read_store(),
                &iri,
                brolly_solid::ldp::BLOB_MEDIA_TYPE,
            )
            .unwrap_or_else(|| "application/octet-stream".into()),
            description: alt_text(&pod.read_store(), &iri),
            url: iri,
        });
    }

    let in_reply_to = form.in_reply_to_id.as_deref().and_then(|id| {
        let (note, owner) = status_id::decode(id)?;
        Some((note, owner))
    });
    let in_reply_to_iri = match in_reply_to {
        Some((note, owner)) => match db::find_by_id(&state.pool, owner).await {
            Ok(Some(parent)) => Some(status_id::note_iri(
                &note,
                &parent.username,
                &state.base_domain,
            )),
            _ => None,
        },
        None => None,
    };

    let composition = compose::Composition {
        text: form.status.unwrap_or_default(),
        spoiler_text: form.spoiler_text.unwrap_or_default(),
        sensitive: form.sensitive.unwrap_or(false),
        language: form.language,
        visibility: form.visibility.unwrap_or_else(|| "public".into()),
        in_reply_to: in_reply_to_iri,
        attachments,
    };

    if let Err(e) = compose::validate(&composition) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
    }

    let actor = webid::actor(&user.username, &state.base_domain);
    let followers = webid::followers(&user.username, &state.base_domain);
    let published = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let mut note = compose::note(&composition, &actor, &followers, &published);
    let base = format!("https://{}.{}", user.username, state.base_domain);
    let note_id = status_id::mint_note_id();
    note["id"] = json!(format!("{base}/~/notes/{note_id}"));

    let activity = json!({
        "type": "Create",
        "id": format!("{base}/~/activities/{}", uuid::Uuid::new_v4()),
        "actor": actor,
        "published": published,
        "to": note["to"].clone(),
        "cc": note["cc"].clone(),
        "object": note.clone(),
    });

    match crate::outbox::deliver(&state, &user, &actor, &activity).await {
        Ok(()) => {}
        Err(crate::outbox::DeliverError::Refused(refusal)) => {
            return error(StatusCode::BAD_REQUEST, refusal.describe());
        }
        Err(crate::outbox::DeliverError::Failed) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Try again.",
            );
        }
    }

    let author = author_for(&state, &user).await;
    match translate::try_status(&note, &author, &state.base_domain) {
        Some(status) => (StatusCode::OK, Json(status)).into_response(),
        None => error(StatusCode::INTERNAL_SERVER_ERROR, "Could not render status"),
    }
}

// --- profile flags and follow requests ---------------------------------------------

#[derive(Deserialize, Default)]
pub struct CredentialsUpdate {
    display_name: Option<String>,
    note: Option<String>,
    locked: Option<bool>,
    bot: Option<bool>,
    discoverable: Option<bool>,
}

/// `PATCH /api/v1/accounts/update_credentials`
///
/// Every field is optional and absent means *unchanged* — a client sending only
/// `locked` must not blank the display name it did not mention.
pub async fn update_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, grant)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    if !oauth::has_scope(&grant.scopes, "write:accounts") {
        return error(StatusCode::FORBIDDEN, "This action requires write scope");
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let update: CredentialsUpdate = if content_type.contains("json") {
        serde_json::from_slice(&body).unwrap_or_default()
    } else {
        serde_urlencoded::from_bytes(&body).unwrap_or_default()
    };

    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };
    let id = webid::webid(&user.username, &state.base_domain);
    let document = webid::profile_document(&user.username, &state.base_domain);

    let written = pod.write(|w| {
        // Merge onto what is stored, so an absent field is untouched rather
        // than reset. The predecessor's version of this is where `locked` went
        // to die. Read in the same write, so nothing lands in between.
        let mut profile = brolly_solid::profile::read(&*w, &id, &document);
        if let Some(name) = update.display_name {
            profile.display_name = name;
        }
        if let Some(note) = update.note {
            profile.bio = note;
        }
        if let Some(locked) = update.locked {
            profile.locked = locked;
        }
        if let Some(bot) = update.bot {
            profile.bot = bot;
        }
        if let Some(discoverable) = update.discoverable {
            profile.discoverable = discoverable;
        }
        brolly_solid::profile::write(w, &id, &document, &profile)
    });
    if let Err(e) = written {
        tracing::error!(error = %e, "profile update failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Update failed");
    }

    let author = author_for(&state, &user).await;
    Json(translate::account(&author, &state.base_domain)).into_response()
}

/// `GET /api/v1/follow_requests`
pub async fn follow_requests(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    let Some((user, _)) = authenticated(&state, &headers).await else {
        return unauthorized();
    };
    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };

    let actor = webid::actor(&user.username, &state.base_domain);
    // Bound before the loop, so no read of the pod is held across its awaits.
    let pending = brolly_activitypub::follows::pending(&pod.read_store(), &actor);
    let mut accounts = Vec::new();
    for follower in pending {
        if let Some(author) = local_author(&state, &follower).await {
            accounts.push(translate::account(&author, &state.base_domain));
        }
    }
    Json(accounts).into_response()
}

/// `POST /api/v1/follow_requests/{id}/authorize` and `/reject`.
async fn resolve_request(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    approve: bool,
) -> Response {
    let Some((user, grant)) = authenticated(state, headers).await else {
        return unauthorized();
    };
    if !oauth::has_scope(&grant.scopes, "write:follows") {
        return error(StatusCode::FORBIDDEN, "This action requires follow scope");
    }
    let Some(requester_id) = translate::account_id_to_uuid(id) else {
        return not_found();
    };
    let Ok(Some(requester)) = db::find_by_id(&state.pool, requester_id).await else {
        return not_found();
    };
    let Ok(pod) = state.stores.pod(user.id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Pod unavailable");
    };

    let actor = webid::actor(&user.username, &state.base_domain);
    let follower = webid::actor(&requester.username, &state.base_domain);

    // Only a *pending* request can be resolved. Approving something nobody
    // asked for would manufacture a follower.
    if !brolly_activitypub::follows::pending(&pod.read_store(), &actor).contains(&follower) {
        return not_found();
    }

    let outcome = pod.write(|w| {
        if approve {
            brolly_activitypub::follows::approve(w, &follower, &actor)
        } else {
            brolly_activitypub::follows::reject(w, &follower, &actor)
        }
    });
    if let Err(e) = outcome {
        tracing::error!(error = %e, "resolving a follow request failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Update failed");
    }

    Json(json!({
        "id": id,
        "following": false,
        "followed_by": approve,
        "requested": false,
        "showing_reblogs": false,
        "notifying": false,
        "blocking": false,
        "blocked_by": false,
        "muting": false,
        "muting_notifications": false,
        "domain_blocking": false,
        "endorsed": false,
        "note": "",
    }))
    .into_response()
}

pub async fn authorize_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    resolve_request(&state, &headers, &id, true).await
}

pub async fn reject_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found();
    }
    resolve_request(&state, &headers, &id, false).await
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
        .route("/api/v1/statuses/{id}", get(status))
        .route("/api/v1/statuses", post(create_status))
        .route("/api/v1/media", post(upload_media))
        .route("/api/v2/media", post(upload_media))
        .route("/api/v1/media/{id}", get(get_media).put(update_media))
        .route(
            "/api/v1/accounts/update_credentials",
            axum::routing::patch(update_credentials),
        )
        .route("/api/v1/follow_requests", get(follow_requests))
        .route(
            "/api/v1/follow_requests/{id}/authorize",
            post(authorize_follow),
        )
        .route("/api/v1/follow_requests/{id}/reject", post(reject_follow));

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
