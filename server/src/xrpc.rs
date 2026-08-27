//! The XRPC surface: `com.atproto.repo.*` and `com.atproto.sync.*`.
//!
//! Served on the **apex**, with the repo named by a `repo` parameter, because
//! that is the shape a PDS has and the endpoint the PLC document advertises
//! (`atproto_pds` → `https://<base>`). Member subdomains keep `/xrpc/`
//! reserved rather than served (ADR 0009), so nothing there can shadow it.
//!
//! Errors use XRPC's own shape — `{"error": "...", "message": "..."}` with the
//! error name in PascalCase — not ours. A client that gets a differently-shaped
//! body cannot tell an expected failure from a broken server, which is the same
//! reasoning that made every `/api/` path answer Mastodon's error shape.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, body::Bytes};
use axum_extra::extract::CookieJar;
use brolly_atproto::blocks::PodBlocks;
use brolly_atproto::keys::SigningKey;
use brolly_atproto::{ingest, repo, state};
use brolly_identity::db::{self, User};
use brolly_identity::{extract, webid};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::SESSION_COOKIE;

/// XRPC's error body.
fn xrpc_error(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({"error": error, "message": message}))).into_response()
}

fn invalid_request(message: &str) -> Response {
    xrpc_error(StatusCode::BAD_REQUEST, "InvalidRequest", message)
}

fn not_found(message: &str) -> Response {
    xrpc_error(StatusCode::NOT_FOUND, "RecordNotFound", message)
}

fn auth_required() -> Response {
    xrpc_error(
        StatusCode::UNAUTHORIZED,
        "AuthenticationRequired",
        "this method requires authentication",
    )
}

/// Apex-only, matching the endpoint the PLC document publishes.
fn wrong_host(state: &AppState, headers: &HeaderMap) -> bool {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    extract::subdomain_user(host, &state.base_domain).is_some()
}

/// Who is making this call.
///
/// A **DPoP-bound ATProtocol token** first, because that is what a real client
/// presents; a session cookie second, so the browser dashboard and tests can
/// drive the same endpoints. Session-only auth was a placeholder — it is
/// useless to any client that is not a browser on this origin.
///
/// The proof is verified against the presented token, not merely present: a
/// bound token accepted without its proof is a bearer token wearing a costume.
async fn caller(state: &AppState, headers: &HeaderMap, jar: &CookieJar) -> Option<User> {
    if let Some(user) = token_caller(state, headers).await {
        return Some(user);
    }
    let cookie = jar.get(SESSION_COOKIE)?;
    db::user_for_session(&state.pool, cookie.value())
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

async fn token_caller(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?;
    let credential = extract::credential(Some(authorization), None)?;
    let brolly_identity::Credential::Dpop { token, .. } = credential else {
        // A plain `Bearer` here is not an ATProtocol credential. Honouring one
        // would accept a token whose binding was never checked.
        return None;
    };

    let grant = brolly_atproto::oauth::verify_token(&state.pool, "access", &token)
        .await
        .ok()
        .flatten()?;

    // The proof must be for this request and must name the key the token was
    // issued to.
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok())?;
    let url = format!("https://{}/xrpc/", state.base_domain);
    let method = "POST";
    let verified = brolly_identity::dpop::verify(
        proof,
        method,
        &url,
        Some(&token),
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .ok()?;
    if verified.thumbprint != grant.dpop_jkt {
        tracing::warn!("an ATProtocol token was presented by a key it was not issued to");
        return None;
    }

    db::find_by_id(&state.pool, grant.user_id)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

/// Resolve a `repo` parameter — a DID or a handle — to a member.
///
/// Both are accepted because both appear in the wild, but they are not
/// equivalent: the DID is the identity and the handle is a rented alias for it
/// (D11), so a handle lookup is a convenience and a DID lookup is the truth.
async fn resolve_repo(state: &AppState, repo: &str) -> Option<User> {
    // **DID forms first.** A handle check runs `strip_suffix(".<base>")`, and
    // `did:web:alice.brolly.test` ends in the base domain too — so ordering the
    // handle branch first silently turns every did:web into the nonsense
    // username `did:web:alice` and resolves nothing.
    if let Some(did) = repo.strip_prefix("did:plc:") {
        let row: Option<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE did_plc = $1")
            .bind(format!("did:plc:{did}"))
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
        return match row {
            Some((id,)) => db::find_by_id(&state.pool, id).await.ok().flatten(),
            None => None,
        };
    }

    // `did:web` is routing-only (D11), so it is resolved structurally from the
    // host rather than looked up.
    if let Some(host) = repo.strip_prefix("did:web:") {
        return match extract::subdomain_user(host, &state.base_domain) {
            Some(username) => db::find_by_username(&state.pool, &username)
                .await
                .ok()
                .flatten(),
            None => None,
        };
    }

    // A handle: `alice.brolly.test`.
    if let Some(handle) = repo.strip_suffix(&format!(".{}", state.base_domain)) {
        return db::find_by_username(&state.pool, handle)
            .await
            .ok()
            .flatten();
    }

    // A bare username, which clients send more often than the spec suggests.
    db::find_by_username(&state.pool, repo).await.ok().flatten()
}

/// A member's repo, its blocks, and its signing key.
struct RepoHandle {
    user: User,
    blocks_for: std::sync::Arc<brolly_store::StoreManager>,
    root: atrium_repo::Cid,
}

impl RepoHandle {
    /// `None` rather than a panic: this runs per request, and a member whose
    /// block directory cannot be opened should get a 500 rather than take the
    /// server down with them.
    ///
    /// `Option` rather than `Result<_, Response>` because a `Response` is a
    /// large `Err` variant to carry on every call, and the caller already knows
    /// which error it wants — [`storage_unavailable`].
    fn blocks(&self) -> Option<PodBlocks> {
        match self.blocks_for.repo_blocks(self.user.id) {
            Ok(blobs) => Some(PodBlocks::new(blobs)),
            Err(e) => {
                tracing::error!(error = %e, user = %self.user.id, "repo blocks unavailable");
                None
            }
        }
    }
}

fn storage_unavailable() -> Response {
    xrpc_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalServerError",
        "repository storage is unavailable",
    )
}

async fn open_repo(state: &AppState, user: User) -> Result<RepoHandle, Response> {
    let Ok(Some(current)) = state::load(&state.pool, user.id).await else {
        return Err(not_found("this repository does not exist"));
    };
    let Ok(root) = current.root_cid.parse() else {
        return Err(xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "the stored repo root is unreadable",
        ));
    };
    Ok(RepoHandle {
        user,
        blocks_for: std::sync::Arc::clone(&state.stores),
        root,
    })
}

async fn signing_key(state: &AppState, user: &User) -> Result<SigningKey, Response> {
    let stored = db::load_key(&state.pool, user.id, brolly_atproto::keys::ATPROTO_SIGNING)
        .await
        .ok()
        .flatten();
    let Some((private, _)) = stored else {
        return Err(not_found("this repository has no signing key"));
    };
    SigningKey::from_bytes(&private).map_err(|e| {
        tracing::error!(error = %e, "loading a signing key failed");
        xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "signing key unavailable",
        )
    })
}

// --- reads --------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GetRecordQuery {
    repo: String,
    collection: String,
    rkey: String,
}

/// `com.atproto.repo.getRecord`
pub async fn get_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GetRecordQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let Some(user) = resolve_repo(&state, &query.repo).await else {
        return not_found("could not resolve that repository");
    };
    let handle = match open_repo(&state, user).await {
        Ok(handle) => handle,
        Err(response) => return response,
    };

    let Some(blocks) = handle.blocks() else {
        return storage_unavailable();
    };
    match repo::get_record::<Value>(blocks, handle.root, &query.collection, &query.rkey).await {
        Ok(Some(value)) => Json(json!({
            "uri": ingest::at_uri(
                &did_of(&handle.user, &state),
                &query.collection,
                &query.rkey,
            ),
            "value": value,
        }))
        .into_response(),
        Ok(None) => not_found("no such record"),
        Err(e) => invalid_request(&e.to_string()),
    }
}

/// The DID a repo is published under.
///
/// Falls back to `did:web` derived from the host when PLC registration has not
/// happened — D11 keeps `did:web` for routing, and a repo has to be addressable
/// before Phase 8 submits its `did:plc`.
fn did_of(user: &User, state: &AppState) -> String {
    user.did_plc
        .clone()
        .unwrap_or_else(|| format!("did:web:{}.{}", user.username, state.base_domain))
}

#[derive(Deserialize)]
pub struct DescribeRepoQuery {
    repo: String,
}

/// `com.atproto.repo.describeRepo`
pub async fn describe_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DescribeRepoQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let Some(user) = resolve_repo(&state, &query.repo).await else {
        return not_found("could not resolve that repository");
    };
    let did = did_of(&user, &state);
    let handle = format!("{}.{}", user.username, state.base_domain);

    Json(json!({
        "handle": handle,
        "did": did,
        "didDoc": {
            "id": did,
            "alsoKnownAs": [format!("at://{handle}")],
        },
        "collections": [],
        // The handle resolves to this DID on this host, which is what a
        // consumer checks before trusting the pairing.
        "handleIsCorrect": true,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct SyncQuery {
    did: String,
}

/// `com.atproto.sync.getRepo` — the whole repo as a CAR.
///
/// This is both the sync primitive and the member's data export, which is why
/// it is the same bytes rather than a separate "export" format that could
/// drift from what the network sees.
pub async fn get_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let Some(user) = resolve_repo(&state, &query.did).await else {
        return not_found("could not resolve that repository");
    };
    let handle = match open_repo(&state, user).await {
        Ok(handle) => handle,
        Err(response) => return response,
    };

    let Some(blocks) = handle.blocks() else {
        return storage_unavailable();
    };
    match repo::export_car(blocks, handle.root).await {
        Ok(car) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/vnd.ipld.car")],
            car,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "CAR export failed");
            xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "could not export the repository",
            )
        }
    }
}

// --- writes -------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WriteRecord {
    repo: Option<String>,
    collection: String,
    rkey: Option<String>,
    record: Value,
}

/// `com.atproto.repo.createRecord` and `putRecord`.
///
/// Writes land in **both** places, and that is the point: the repo is what the
/// network syncs, and the pod is what every other protocol reads (D7's faithful
/// layer). A record in one and not the other is a member whose data exists for
/// some readers and not others.
pub async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let Some(user) = caller(&state, &headers, &jar).await else {
        return auth_required();
    };
    let Ok(input) = serde_json::from_slice::<WriteRecord>(&body) else {
        return invalid_request("body must be a JSON object with collection and record");
    };

    // Writing to someone else's repo is not a permissions question to answer
    // later; it is refused here.
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        );
    }

    // A record must declare its own type, or the faithful layer has nowhere to
    // put its fields that would not collide with another lexicon's.
    let mut record = input.record;
    if record.get("$type").is_none() {
        record["$type"] = json!(input.collection);
    }

    let rkey = input
        .rkey
        .unwrap_or_else(brolly_mastodon::status_id::mint_note_id);

    let handle = match open_repo(&state, user.clone()).await {
        Ok(handle) => handle,
        Err(response) => return response,
    };
    let key = match signing_key(&state, &user).await {
        Ok(key) => key,
        Err(response) => return response,
    };

    let Some(blocks) = handle.blocks() else {
        return storage_unavailable();
    };
    let (record_cid, new_root) = match repo::put_record(
        blocks,
        handle.root,
        &key,
        &input.collection,
        &rkey,
        &record,
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => return invalid_request(&e.to_string()),
    };

    if let Err(e) = state::advance(&state.pool, user.id, &new_root.to_string()).await {
        tracing::error!(error = %e, "advancing the repo failed after a write");
        return xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "the record was written but the repo pointer did not move",
        );
    }

    // And into the pod, faithfully, so the other protocols can see it.
    let uri = ingest::at_uri(&did_of(&user, &state), &input.collection, &rkey);
    if let Ok(pod) = state.stores.pod(user.id)
        && let Err(e) = ingest::ingest(
            &pod,
            &record,
            &uri,
            &webid::webid(&user.username, &state.base_domain),
            &webid::profile_document(&user.username, &state.base_domain),
        )
    {
        tracing::error!(error = %e, "faithful ingest failed after a repo write");
    }

    Json(json!({"uri": uri, "cid": record_cid.to_string()})).into_response()
}

#[derive(Deserialize)]
pub struct DeleteRecord {
    repo: Option<String>,
    collection: String,
    rkey: String,
}

/// `com.atproto.repo.deleteRecord`
pub async fn delete_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let Some(user) = caller(&state, &headers, &jar).await else {
        return auth_required();
    };
    let Ok(input) = serde_json::from_slice::<DeleteRecord>(&body) else {
        return invalid_request("body must name a collection and rkey");
    };
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        );
    }

    let handle = match open_repo(&state, user.clone()).await {
        Ok(handle) => handle,
        Err(response) => return response,
    };
    let key = match signing_key(&state, &user).await {
        Ok(key) => key,
        Err(response) => return response,
    };

    let Some(blocks) = handle.blocks() else {
        return storage_unavailable();
    };
    let new_root = match repo::delete_record(
        blocks,
        handle.root,
        &key,
        &input.collection,
        &input.rkey,
    )
    .await
    {
        Ok(root) => root,
        Err(e) => return invalid_request(&e.to_string()),
    };

    if let Err(e) = state::advance(&state.pool, user.id, &new_root.to_string()).await {
        tracing::error!(error = %e, "advancing the repo failed after a delete");
    }

    Json(json!({})).into_response()
}

/// `com.atproto.server.describeServer`
pub async fn describe_server(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    Json(json!({
        "did": format!("did:web:{}", state.base_domain),
        "availableUserDomains": [format!(".{}", state.base_domain)],
        // Invite-only, said in the field an ATProtocol client reads.
        "inviteCodeRequired": true,
        "links": {},
    }))
    .into_response()
}

/// Anything under `/xrpc/` we do not implement.
///
/// XRPC names an unimplemented method specifically, so a client can tell "this
/// server does not do that" from "this server is broken".
pub async fn unknown_method(Path(nsid): Path<String>) -> Response {
    xrpc_error(
        StatusCode::NOT_IMPLEMENTED,
        "MethodNotImplemented",
        &format!("{nsid} is not implemented by this server"),
    )
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(describe_server),
        )
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.putRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        // Last, and a wildcard: literal segments match first.
        .route(
            "/xrpc/{nsid}",
            get(unknown_method).post(unknown_method).put(unknown_method),
        )
}
