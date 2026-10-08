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
use brolly_atproto::firehose::CommitEvent;
use brolly_atproto::keys::SigningKey;
use brolly_atproto::tid::Tid;
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

/// The lexicon's own error for a write whose compare-and-set did not hold
/// (1, C) — the shape `putRecord`/`applyWrites` define in atrium-api's
/// generated types: `error: "InvalidSwap"` with a message.
fn invalid_swap(message: &str) -> Response {
    xrpc_error(StatusCode::BAD_REQUEST, "InvalidSwap", message)
}

/// A write the spec's size limits refuse (1, B).
fn payload_too_large(message: &str) -> Response {
    xrpc_error(StatusCode::PAYLOAD_TOO_LARGE, "PayloadTooLarge", message)
}

/// A write whose compare-and-set lost the head after every retry (1, C).
///
/// The server-side retry makes this invisible to clients in the ordinary
/// race; what reaches here is a write that kept losing for three attempts
/// straight, which is contention a client should see rather have swallowed.
fn write_conflict() -> Response {
    xrpc_error(
        StatusCode::CONFLICT,
        "ConcurrentWrite",
        "the repository moved while this write was in flight",
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

    // The proof must be for this request, must name the key the token was
    // issued to, and must not have been presented before.
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok())?;
    let url = format!("https://{}/xrpc/", state.base_domain);
    let method = "POST";
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let unspent = brolly_identity::dpop::verify(proof, method, &url, Some(&token), now).ok()?;
    if !unspent.bound_to(&grant.dpop_jkt) {
        tracing::warn!("an ATProtocol token was presented by a key it was not issued to");
        return None;
    }
    match unspent.spend(&state.pool, now).await {
        Ok(_) => {}
        Err(brolly_identity::dpop::DpopError::Storage(e)) => {
            tracing::error!(error = %e, "recording a DPoP proof failed");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "an ATProtocol DPoP proof was refused");
            return None;
        }
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
///
/// **Every branch filters `is_active`, and none of them is redundant.** A
/// disabled account must be unreachable by *any* spelling of its address, and
/// the four branches are four separate lookups — dropping the filter from one
/// leaves a way in. This is the whole of moderation on the ATProto read path:
/// `getRecord`, `describeRepo` and `sync.getRepo` are unauthenticated, so
/// nothing downstream of here would catch it. The two write callers filter
/// their *caller* rather than their target, which is a different question.
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
            Some((id,)) => db::find_by_id(&state.pool, id)
                .await
                .ok()
                .flatten()
                .filter(User::is_active),
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
                .flatten()
                .filter(User::is_active),
            None => None,
        };
    }

    // A handle: `alice.brolly.test`.
    if let Some(handle) = repo.strip_suffix(&format!(".{}", state.base_domain)) {
        return db::find_by_username(&state.pool, handle)
            .await
            .ok()
            .flatten()
            .filter(User::is_active);
    }

    // A bare username, which clients send more often than the spec suggests.
    db::find_by_username(&state.pool, repo)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

/// A member's repo, its blocks, and its signing key.
struct RepoHandle {
    user: User,
    blocks_for: std::sync::Arc<brolly_store::StoreManager>,
    root: atrium_repo::Cid,
    /// The head's current rev — the floor the new commit's rev must clear,
    /// and half of what the compare-and-set checks (1, C).
    rev: Tid,
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
        rev: current.rev,
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
    match repo::get_record(blocks, handle.root, &query.collection, &query.rkey).await {
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

/// How many attempts a plain write gets before its conflict is surfaced (1, C).
const WRITE_ATTEMPTS: usize = 3;

/// What a write named as the head it must land against (1, C).
#[derive(Debug, Clone)]
enum HeadSwap {
    /// A plain write: the client named no prior state, so the server retries
    /// the whole write when the head moves first — optimistic concurrency,
    /// the reference PDS's own behaviour, and the difference between two tabs
    /// writing at once and a spurious failure in bsky.app.
    Plain,
    /// A swap write: the head must be exactly this commit. No retry, ever —
    /// the client bought exactly that answer.
    AtCommit(String),
}

/// A write as it landed: the applied batch and the head it replaced, which
/// is everything the announcement and the response need.
struct Landed {
    applied: brolly_atproto::repo::Applied,
    /// The commit CID the head held before this write moved it.
    prev_cid: String,
}

/// Perform a write against the head: open, apply, compare-and-set — and for
/// a plain write, do it all again from the new head when the head moved
/// first (1, C).
///
/// A retry re-signs against a root the client never saw, but the client
/// never *named* a root — it asked for a write, and got the commit that
/// landed. A swap write never retries: the client named the exact prior
/// state, and the mismatch is the answer `InvalidSwap`.
async fn perform_write(
    state: &AppState,
    user: &User,
    writes: Vec<brolly_atproto::repo::PlannedWrite>,
    head: HeadSwap,
) -> Result<Landed, Response> {
    for attempt in 0..WRITE_ATTEMPTS {
        let handle = match open_repo(state, user.clone()).await {
            Ok(handle) => handle,
            Err(response) => return Err(response),
        };
        if let HeadSwap::AtCommit(expected) = &head
            && handle.root.to_string() != *expected
        {
            return Err(invalid_swap(
                "swapCommit did not match the current repo commit",
            ));
        }

        let key = match signing_key(state, user).await {
            Ok(key) => key,
            Err(response) => return Err(response),
        };
        let Some(blocks) = handle.blocks() else {
            return Err(storage_unavailable());
        };
        let applied = match brolly_atproto::repo::apply(
            blocks,
            handle.root,
            &key,
            writes.clone(),
            &handle.rev,
        )
        .await
        {
            Ok(applied) => applied,
            Err(e) => return Err(write_refused(e)),
        };

        // Compare-and-set: the head moves only from the root this write read,
        // and only forward in rev (1, C).
        match state::advance(
            &state.pool,
            user.id,
            &handle.root.to_string(),
            &applied.commit.to_string(),
            &applied.rev,
        )
        .await
        {
            Ok(_) => {
                return Ok(Landed {
                    applied,
                    prev_cid: handle.root.to_string(),
                });
            }
            Err(state::AdvanceError::Conflict) => {
                if matches!(head, HeadSwap::Plain) && attempt + 1 < WRITE_ATTEMPTS {
                    // Re-read the head, re-apply the ops to the new root,
                    // re-sign — minted past the new head's rev (1, C).
                    continue;
                }
                return Err(if matches!(head, HeadSwap::Plain) {
                    write_conflict()
                } else {
                    invalid_swap("swapCommit did not match the current repo commit")
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "advancing the repo failed after a write");
                return Err(xrpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    "the record was written but the repo pointer did not move",
                ));
            }
        }
    }
    Err(write_conflict())
}

/// A refused write, as the lexicon spells the refusal (1, B).
fn write_refused(e: brolly_atproto::repo::RepoError) -> Response {
    match e {
        brolly_atproto::repo::RepoError::InvalidSwap(_) => invalid_swap(&e.to_string()),
        brolly_atproto::repo::RepoError::TooLarge(_) => payload_too_large(&e.to_string()),
        brolly_atproto::repo::RepoError::Signing(m) => {
            tracing::error!(error = %m, "signing a commit failed");
            xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "the commit could not be signed",
            )
        }
        _ => invalid_request(&e.to_string()),
    }
}

/// Record a commit on the firehose and hand it to attached consumers.
///
/// The durable write comes first and the broadcast second, deliberately: a
/// consumer that misses the broadcast resumes from the log, but an event that
/// was broadcast and never logged is invisible to anyone who reconnects.
///
/// A failure here does not fail the write. The record is already committed to
/// the repo, and refusing a successful write because its announcement failed
/// would be the worse outcome — the log is repairable, a rejected write the
/// client believes failed is not.
async fn announce(state: &AppState, did: &str, landed: &Landed) {
    let applied = &landed.applied;
    let commit = brolly_atproto::firehose::NewCommit {
        did,
        commit_cid: &applied.commit.to_string(),
        prev_cid: Some(&landed.prev_cid),
        rev: &applied.rev,
        since_rev: Some(&applied.since_rev),
        prev_data: Some(&applied.prev_data.to_string()),
        ops: applied
            .ops
            .iter()
            .map(|op| brolly_atproto::firehose::NewOp {
                action: op.action,
                path: op.path.clone(),
                record_cid: op.record_cid.as_ref().map(atrium_repo::Cid::to_string),
                prev_cid: op.prev_cid.as_ref().map(atrium_repo::Cid::to_string),
            })
            .collect(),
    };
    match brolly_atproto::firehose::record(&state.pool, &commit).await {
        Ok(event) => {
            // `send` fails only when nobody is listening, which is normal.
            let _ = state.commits.send(event);
        }
        Err(e) => tracing::error!(error = %e, "recording a firehose event failed"),
    }
}

/// And into the pod, faithfully, so the other protocols can see it (D7).
///
/// One op per non-delete write, paired with the record the caller asked for;
/// a delete leaves the pod copy alone, exactly as the single delete always
/// has. Best effort and explicitly so — the repo is the source of truth the
/// network syncs, and a pod hiccup must not fail a landed write.
async fn ingest_written(
    state: &AppState,
    user: &User,
    ops: &[brolly_atproto::repo::AppliedOp],
    records: &[Value],
) {
    let Ok(pod) = state.stores.pod(user.id) else {
        tracing::error!(user = %user.id, "the pod is unavailable after a repo write");
        return;
    };
    let did = did_of(user, state);
    let webid = webid::webid(&user.username, &state.base_domain);
    let document = webid::profile_document(&user.username, &state.base_domain);
    for (op, record) in ops.iter().zip(records) {
        if op.action == brolly_atproto::firehose::Action::Delete {
            continue;
        }
        let Some((collection, rkey)) = op.path.split_once('/') else {
            continue;
        };
        let uri = ingest::at_uri(&did, collection, rkey);
        if let Err(e) = pod
            .write(|w| Ok(ingest::ingest(w, record, &uri, &webid, &document)))
            .map_err(ingest::IngestError::from)
            .flatten()
        {
            tracing::error!(error = %e, "faithful ingest failed after a repo write");
        }
    }
}

/// The write endpoints' shared answer: auth, the target check, and then the
/// write itself — landed, announced, and ingested.
async fn commit_write(
    state: &AppState,
    user: &User,
    writes: Vec<brolly_atproto::repo::PlannedWrite>,
    head: HeadSwap,
    records: Vec<Value>,
) -> Result<Landed, Response> {
    let landed = perform_write(state, user, writes, head).await?;
    announce(state, &did_of(user, state), &landed).await;
    ingest_written(state, user, &landed.applied.ops, &records).await;
    Ok(landed)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRecord {
    repo: Option<String>,
    collection: String,
    rkey: Option<String>,
    record: Value,
    swap_commit: Option<String>,
}

/// `com.atproto.repo.createRecord`.
///
/// Creates, never replaces: an occupied path is `InvalidSwap` before
/// anything is signed. The rkey is minted as a TID when the caller supplies
/// none; a supplied one is validated against the lexicon's grammar (1, B).
///
/// Writes land in **both** places, and that is the point: the repo is what the
/// network syncs, and the pod is what every other protocol reads (D7's faithful
/// layer). A record in one and not the other is a member whose data exists for
/// some readers and not others.
async fn create_record(
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
    let Ok(input) = serde_json::from_slice::<CreateRecord>(&body) else {
        return invalid_request("body must be a JSON object with collection and record");
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

    // A record must declare its own type, or the faithful layer has nowhere to
    // put its fields that would not collide with another lexicon's.
    let mut record = input.record;
    if record.get("$type").is_none() {
        record["$type"] = json!(input.collection);
    }

    let write = match brolly_atproto::repo::PlannedWrite::create(
        &input.collection,
        input.rkey.as_deref(),
        &record,
    ) {
        Ok(write) => write,
        Err(e) => return write_refused(e),
    };
    let head = match input.swap_commit {
        // A swap write never retries (1, C).
        Some(cid) => HeadSwap::AtCommit(cid),
        None => HeadSwap::Plain,
    };

    let landed = match commit_write(&state, &user, vec![write], head, vec![record]).await {
        Ok(landed) => landed,
        Err(response) => return response,
    };
    write_response(&state, &user, &landed)
}

/// The create/put answer: the lexicon's `uri`, `cid`, and the commit that
/// landed the write.
fn write_response(state: &AppState, user: &User, landed: &Landed) -> Response {
    let applied = &landed.applied;
    let Some(op) = applied.ops.first() else {
        return xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "the write landed without an op",
        );
    };
    let Some((collection, rkey)) = op.path.split_once('/') else {
        return xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "the write landed without a path",
        );
    };
    Json(json!({
        "uri": ingest::at_uri(&did_of(user, state), collection, rkey),
        "cid": op.record_cid.map(|cid| cid.to_string()),
        "commit": {
            "cid": applied.commit.to_string(),
            "rev": applied.rev.as_str(),
        },
    }))
    .into_response()
}

/// A nullable-and-optional field, kept distinguishable (1, B).
///
/// `putRecord`'s `swapRecord` is deliberately both: absent means no
/// requirement, `null` means "must not exist", a CID means "must be at
/// exactly this". Plain `Option<Option<T>>` collapses the first two — serde
/// maps `null` straight to the outer `None` — so the field is deserialized
/// with the inner option preserved and defaulted only when absent.
fn double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutRecord {
    repo: Option<String>,
    collection: String,
    rkey: String,
    record: Value,
    /// Nullable *and* optional, deliberately (1, B).
    #[serde(default, deserialize_with = "double_option")]
    swap_record: Option<Option<String>>,
    swap_commit: Option<String>,
}

/// `com.atproto.repo.putRecord`: upsert, as the lexicon defines it — absent
/// creates, present replaces — with compare-and-set on both the record and
/// the head when the client names either (1, B).
async fn put_record(
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
    let Ok(input) = serde_json::from_slice::<PutRecord>(&body) else {
        return invalid_request("body must be a JSON object with collection, rkey and record");
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

    let mut record = input.record;
    if record.get("$type").is_none() {
        record["$type"] = json!(input.collection);
    }

    let swap = match brolly_atproto::repo::RecordSwap::parse(
        input.swap_record.as_ref().map(|swap| swap.as_deref()),
    ) {
        Ok(swap) => swap,
        Err(e) => return write_refused(e),
    };
    let write = match brolly_atproto::repo::PlannedWrite::put(
        &input.collection,
        &input.rkey,
        &record,
        swap,
    ) {
        Ok(write) => write,
        Err(e) => return write_refused(e),
    };
    let head = match input.swap_commit {
        Some(cid) => HeadSwap::AtCommit(cid),
        None => HeadSwap::Plain,
    };

    let landed = match commit_write(&state, &user, vec![write], head, vec![record]).await {
        Ok(landed) => landed,
        Err(response) => return response,
    };
    write_response(&state, &user, &landed)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwapRecord {
    repo: Option<String>,
    collection: String,
    rkey: String,
    record: Value,
    /// Required, and may be `null`: `null` is "must not exist", a CID is
    /// "must be at exactly this" (1, B).
    #[serde(default, deserialize_with = "double_option")]
    swap_record: Option<Option<String>>,
    /// Required: the head must be exactly this commit (1, B).
    swap_commit: Option<String>,
}

/// `com.atproto.repo.swapRecord` — brolly's strict route over the same
/// compare-and-set `putRecord` expresses with optional parameters (1, B).
///
/// Both swap parameters are required here, because a client that has synced
/// the repo knows both — the record it read and the commit it read it at —
/// and a route that demands them cannot be sent half a compare-and-set by
/// mistake. No retry, ever; every refusal is `InvalidSwap`.
async fn swap_record(
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
    let Ok(input) = serde_json::from_slice::<SwapRecord>(&body) else {
        return invalid_request(
            "body must be a JSON object with collection, rkey, record, swapRecord and swapCommit",
        );
    };
    let (Some(swap_record), Some(swap_commit)) = (input.swap_record, input.swap_commit) else {
        return invalid_request("both swapRecord and swapCommit are required");
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

    let mut record = input.record;
    if record.get("$type").is_none() {
        record["$type"] = json!(input.collection);
    }

    let swap = match brolly_atproto::repo::RecordSwap::parse(Some(swap_record.as_deref())) {
        Ok(swap) => swap,
        Err(e) => return write_refused(e),
    };
    let write = match brolly_atproto::repo::PlannedWrite::put(
        &input.collection,
        &input.rkey,
        &record,
        swap,
    ) {
        Ok(write) => write,
        Err(e) => return write_refused(e),
    };

    let landed = match commit_write(
        &state,
        &user,
        vec![write],
        HeadSwap::AtCommit(swap_commit),
        vec![record],
    )
    .await
    {
        Ok(landed) => landed,
        Err(response) => return response,
    };
    write_response(&state, &user, &landed)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwapCommit {
    repo: Option<String>,
    collection: String,
    rkey: String,
    record: Value,
    /// Required: the head must be exactly this commit (1, B).
    commit_cid: String,
}

/// `com.atproto.repo.swapCommit` — a write against the head *only if* the
/// head is exactly that commit (1, B).
///
/// This is the compare-and-set C's retry half needs to be reachable by a
/// client that has synced the repo: it names the commit it read, and if the
/// head has moved, `InvalidSwap` is the whole answer. No retry, ever.
async fn swap_commit(
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
    let Ok(input) = serde_json::from_slice::<SwapCommit>(&body) else {
        return invalid_request(
            "body must be a JSON object with collection, rkey, record and commitCid",
        );
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

    let mut record = input.record;
    if record.get("$type").is_none() {
        record["$type"] = json!(input.collection);
    }

    let write = match brolly_atproto::repo::PlannedWrite::put(
        &input.collection,
        &input.rkey,
        &record,
        brolly_atproto::repo::RecordSwap::Any,
    ) {
        Ok(write) => write,
        Err(e) => return write_refused(e),
    };

    let landed = match commit_write(
        &state,
        &user,
        vec![write],
        HeadSwap::AtCommit(input.commit_cid),
        vec![record],
    )
    .await
    {
        Ok(landed) => landed,
        Err(response) => return response,
    };
    write_response(&state, &user, &landed)
}

#[derive(Deserialize)]
#[serde(tag = "$type", rename_all = "camelCase")]
enum ApplyWrite {
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        collection: String,
        rkey: Option<String>,
        value: Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        collection: String,
        rkey: String,
        value: Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete { collection: String, rkey: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyWrites {
    repo: Option<String>,
    writes: Vec<ApplyWrite>,
    swap_commit: Option<String>,
}

/// `com.atproto.repo.applyWrites`: a batch applied in **one commit** — one MST
/// revision, one signature, one event with one op per write (1, B).
///
/// Atomic: any invalid op refuses the whole batch before anything is signed.
async fn apply_writes(
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
    let Ok(input) = serde_json::from_slice::<ApplyWrites>(&body) else {
        return invalid_request("body must be a JSON object with a non-empty writes array");
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
    if input.writes.is_empty() {
        return invalid_request("writes must not be empty");
    }
    if input.writes.len() > brolly_atproto::repo::MAX_BATCH_OPS {
        return invalid_request(&format!(
            "a batch is capped at {} writes",
            brolly_atproto::repo::MAX_BATCH_OPS
        ));
    }

    // The plan and the records, in the order the batch applies them. A value
    // without a `$type` is given its collection's, exactly as a single write
    // is.
    let mut writes = Vec::with_capacity(input.writes.len());
    let mut records = Vec::with_capacity(input.writes.len());
    for write in &input.writes {
        let planned = match write {
            ApplyWrite::Create {
                collection,
                rkey,
                value,
            } => {
                let mut record = value.clone();
                if record.get("$type").is_none() {
                    record["$type"] = json!(collection);
                }
                records.push(record.clone());
                brolly_atproto::repo::PlannedWrite::create(collection, rkey.as_deref(), &record)
            }
            ApplyWrite::Update {
                collection,
                rkey,
                value,
            } => {
                let mut record = value.clone();
                if record.get("$type").is_none() {
                    record["$type"] = json!(collection);
                }
                records.push(record.clone());
                brolly_atproto::repo::PlannedWrite::update(collection, rkey, &record)
            }
            ApplyWrite::Delete { collection, rkey } => {
                records.push(Value::Null);
                brolly_atproto::repo::PlannedWrite::delete(collection, rkey)
            }
        };
        match planned {
            Ok(planned) => writes.push(planned),
            Err(e) => return write_refused(e),
        }
    }
    let head = match input.swap_commit {
        Some(cid) => HeadSwap::AtCommit(cid),
        None => HeadSwap::Plain,
    };

    let landed = match commit_write(&state, &user, writes, head, records).await {
        Ok(landed) => landed,
        Err(response) => return response,
    };

    // One result per write, in order: the uri and cid it landed at.
    let did = did_of(&user, &state);
    let results: Vec<Value> = landed
        .applied
        .ops
        .iter()
        .map(|op| match op.path.split_once('/') {
            Some((collection, rkey)) => json!({
                "uri": ingest::at_uri(&did, collection, rkey),
                "cid": op.record_cid.map(|cid| cid.to_string()),
            }),
            None => json!({}),
        })
        .collect();
    Json(json!({
        "commit": {
            "cid": landed.applied.commit.to_string(),
            "rev": landed.applied.rev.as_str(),
        },
        "results": results,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecord {
    repo: Option<String>,
    collection: String,
    rkey: String,
}

/// `com.atproto.repo.deleteRecord`
async fn delete_record(
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

    let write = match brolly_atproto::repo::PlannedWrite::delete(&input.collection, &input.rkey) {
        Ok(write) => write,
        Err(e) => return write_refused(e),
    };

    // A plain write: no swap was named, so the head's movement is retried
    // through rather than answered (1, C).
    match commit_write(&state, &user, vec![write], HeadSwap::Plain, Vec::new()).await {
        Ok(_) => Json(json!({})).into_response(),
        Err(response) => response,
    }
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

// --- firehose ---------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct SubscribeQuery {
    /// Where to resume from. Absent means "only what happens next".
    cursor: Option<i64>,
}

/// `com.atproto.sync.subscribeRepos` — the commit stream.
///
/// Backfill from the cursor first, then live. Ungated (ADR 0016): consumers
/// connect *to* us, so there is nothing outbound to suppress, and a PDS nobody
/// can subscribe to is one nobody can read.
///
/// The backfill happens **before** the socket goes live, in sequence order, so
/// a consumer never sees a newer commit before an older one — which would make
/// `prev` unverifiable on its side.
/// Note the extractor ordering hazard here, which bit twice already in this
/// codebase (`Form` on the Mastodon consent decision and on revoke): extractors
/// run **before** the handler body, so `WebSocketUpgrade` answers 400 to a
/// non-websocket request before `wrong_host` can answer 404.
///
/// That is tolerable *only* because the 400 is identical on the apex and on a
/// subdomain, so it distinguishes nothing — unlike the `Form` case, where the
/// rejection revealed that a path existed where it should not. A real
/// handshake reaches the body and is refused there, and the test drives it that
/// way rather than with a bare GET.
pub async fn subscribe_repos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SubscribeQuery>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    ws.on_upgrade(move |socket| stream_commits(state, query.cursor, socket))
}

/// A commit event as a wire frame: the CAR diff slice built at emission time
/// from the log's pointers plus the member's blocks (1, D, D5), then the
/// frame around it.
///
/// `None` is a skip, not an empty frame. A member whose blocks cannot be
/// reached — deleted, disabled, or with storage that will not open — cannot
/// have a diff built, and emitting the event with empty blocks would pretend
/// a diff no consumer could invert. The event is skipped with an error log;
/// the cursor moves past it, and a consumer that wants that repo's history
/// resyncs it by other means. (The *reason* a member's events stop being
/// frameable is chunk 4's `#account` event, not this function's silence.)
///
/// The member is resolved through the same resolver every other repo read
/// uses — `did:plc` from the table, `did:web` structurally — with its
/// `is_active` filter: the firehose is an unauthenticated read path, and this
/// is the moderation stance that path already takes everywhere else.
async fn frame_commit(state: &AppState, event: &CommitEvent) -> Option<Vec<u8>> {
    let Some(user) = resolve_repo(state, &event.did).await else {
        tracing::error!(
            did = %event.did,
            seq = event.seq,
            "the member behind a logged commit cannot be resolved; skipping its event"
        );
        return None;
    };
    let Ok(blobs) = state.stores.repo_blocks(user.id) else {
        tracing::error!(
            did = %event.did,
            seq = event.seq,
            "the member's repo blocks cannot be opened; skipping its event"
        );
        return None;
    };
    let mut blocks = PodBlocks::new(blobs);
    let car = match repo::event_diff_car(&mut blocks, event).await {
        Ok(car) => car,
        Err(e) => {
            tracing::error!(
                did = %event.did,
                seq = event.seq,
                error = %e,
                "the CAR diff slice for a logged commit cannot be built; skipping its event"
            );
            return None;
        }
    };
    match brolly_atproto::firehose::frame(event, &car) {
        Ok(frame) => Some(frame),
        Err(e) => {
            tracing::error!(
                did = %event.did,
                seq = event.seq,
                error = %e,
                "framing a logged commit failed; skipping its event"
            );
            None
        }
    }
}

async fn stream_commits(
    state: AppState,
    cursor: Option<i64>,
    mut socket: axum::extract::ws::WebSocket,
) {
    use axum::extract::ws::Message;
    use brolly_atproto::firehose;

    // How much history one page of backfill carries. A consumer far behind
    // makes several passes rather than one unbounded query.
    const PAGE: i64 = 500;

    let mut position = cursor;
    loop {
        let events = match firehose::since(&state.pool, position, PAGE).await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!(error = %e, "firehose backfill failed");
                return;
            }
        };
        if events.is_empty() {
            break;
        }
        for event in &events {
            // A frame is built at emission time, from the log's pointers plus
            // the member's blocks (D5) — an event that cannot be built is
            // skipped loudly rather than emitted hollow (1, D).
            let Some(frame) = frame_commit(&state, event).await else {
                continue;
            };
            if socket.send(Message::Binary(frame.into())).await.is_err() {
                // The consumer went away mid-backfill. It has its cursor and
                // will resume; nothing to clean up.
                return;
            }
            position = Some(event.seq);
        }
    }

    // Live tail. A consumer that stays connected keeps receiving; one that
    // drops resumes from the log, which is why the log exists.
    let mut live = state.commits.subscribe();
    while let Ok(event) = live.recv().await {
        if position.is_some_and(|seen| event.seq <= seen) {
            // Already delivered during backfill — the overlap window between
            // draining the table and attaching to the channel.
            continue;
        }
        let Some(frame) = frame_commit(&state, &event).await else {
            continue;
        };
        if socket.send(Message::Binary(frame.into())).await.is_err() {
            return;
        }
        position = Some(event.seq);
    }
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
            "/xrpc/com.atproto.sync.subscribeRepos",
            get(subscribe_repos),
        )
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(describe_server),
        )
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
        .route("/xrpc/com.atproto.repo.swapRecord", post(swap_record))
        .route("/xrpc/com.atproto.repo.swapCommit", post(swap_commit))
        // Last, and a wildcard: literal segments match first.
        .route(
            "/xrpc/{nsid}",
            get(unknown_method).post(unknown_method).put(unknown_method),
        )
}
