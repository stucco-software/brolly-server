//! The XRPC surface: `com.atproto.repo.*`, `com.atproto.sync.*`, and the
//! `com.atproto.server.*` session endpoints.
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
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, body::Bytes};
use brolly_atproto::blocks::PodBlocks;
use brolly_atproto::firehose::{self, CommitEvent};
use brolly_atproto::keys::SigningKey;
use brolly_atproto::tid::Tid;
use brolly_atproto::{ingest, legacy, repo, service_auth, state};
use brolly_identity::db::{self, DbError, User};
use brolly_identity::dpop;
use brolly_identity::{extract, webid};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::session_token;

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

fn auth_required(state: &AppState) -> Response {
    with_bearer_challenge(
        state,
        xrpc_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "this method requires authentication",
        ),
    )
}

/// The draft's own discovery challenge on a 401 (stage 2, D): a client
/// starting from a hostname is told where the authorization server is, by the
/// protected-resource document chunk 3 landed. Appended rather than inserted,
/// so an RFC 9449 challenge already on the answer keeps the lead.
fn with_bearer_challenge(state: &AppState, mut response: Response) -> Response {
    let challenge = format!(
        "Bearer resource_metadata=\"https://{}/.well-known/oauth-protected-resource\"",
        state.base_domain
    );
    // Unreachable in practice: a configured base domain is header-safe. A
    // 401 without the challenge still beats a 200.
    if let Ok(value) = header::HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .append(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// RFC 9449's DPoP challenge for a presented-but-refused DPoP credential
/// (stage 2, D), with the fresh nonce the retry needs. Beside it, the draft's
/// discovery challenge — a client whose credential was refused may also need
/// to find the authorization server, and RFC 7235 allows one challenge per
/// scheme, so the two coexist. The body stays coarse — the machine-readable
/// detail is in the header, per RFC 9449 — so the response is shaped exactly
/// like any other auth-required answer apart from the headers.
fn dpop_challenge(state: &AppState, error: &str, description: &str) -> Response {
    let mut response = xrpc_error(
        StatusCode::UNAUTHORIZED,
        "AuthenticationRequired",
        "this method requires authentication",
    );
    // A description is a quoted string: any quote inside it is exchanged
    // rather than escaped, so an error message cannot break the challenge
    // apart — and `from_str` refuses anything a header cannot carry.
    let challenge = format!(
        "DPoP error=\"{error}\", error_description=\"{}\"",
        description.replace('"', "'")
    );
    // Unreachable in practice: the descriptions above are header-safe. The
    // nonce and the discovery challenge still teach the retry.
    if let Ok(value) = header::HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    let mut response = with_bearer_challenge(state, response);
    let nonce = dpop::current_nonce(&state.dpop_nonce_secret, now());
    // Unreachable in practice: base64url is always a legal header value. A
    // 401 without the nonce still beats a 200.
    if let Ok(nonce) = header::HeaderValue::from_str(&nonce) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), nonce);
    }
    response
}

/// An authenticated answer is private to the requester (stage 2, D):
/// `Cache-Control: private` so no shared cache stores it, and `Vary:
/// Authorization` so none that could varies it by anything but the credential
/// that earned it — one member's authorized response must not reach another
/// from a cache.
fn private(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private"),
    );
    response.headers_mut().insert(
        header::VARY,
        header::HeaderValue::from_static("Authorization"),
    );
    response
}

/// The reference's own wire shape for a missing scope (stage 2, D):
/// `@atproto/oauth-scopes` throws `ScopeMissingError` (403, exposed) with
/// exactly this message. Not a 401 — the credential is authenticated; it is
/// the *grant* that is missing — and not an invented name or message either:
/// the client's recovery is keyed on the name, and a different one is a
/// protocol fork.
fn scope_missing(scope: &str) -> Response {
    xrpc_error(
        StatusCode::FORBIDDEN,
        "ScopeMissingError",
        &format!("Missing required scope \"{scope}\""),
    )
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// The lexicon's own name for a refresh token that is unknown or spent (2, A).
fn invalid_token(state: &AppState) -> Response {
    with_bearer_challenge(
        state,
        xrpc_error(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "this session token is invalid",
        ),
    )
}

/// The lexicon's own name for a refresh token past its expiry (2, A) — a
/// different answer than an invalid one, because a client's recovery differs:
/// re-login, not a retry.
fn expired_token(state: &AppState) -> Response {
    with_bearer_challenge(
        state,
        xrpc_error(
            StatusCode::UNAUTHORIZED,
            "ExpiredToken",
            "this session token has expired",
        ),
    )
}

fn internal_error() -> Response {
    xrpc_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalServerError",
        "something went wrong serving this request",
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

/// How a caller authenticated, narrowed to what the session surface asks
/// (2, B): the privilege matrix reads provenance, not identity.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallerKind {
    /// The dashboard's session cookie: a primary-password login, in a browser.
    Cookie,
    /// An ATProtocol OAuth token, DPoP-bound, carrying the scopes it was
    /// granted — what the scope gate reads (stage 2, D).
    Oauth { scopes: Vec<String> },
    /// A legacy session token through the primary password.
    PrimaryPassword,
    /// A legacy session token through an app password, carrying the one fact
    /// the privilege matrix reads: that password's `privileged` flag.
    AppPassword { privileged: bool },
}

/// The scopes an authenticated method asserts it needs (stage 2, D).
///
/// `atproto` is the base scope every token the profile issues carries;
/// `transition:generic` is the one write authority — repo writes and
/// `getServiceAuth` — is granted by.
const SCOPE_ATPROTO: &str = "atproto";
const SCOPE_TRANSITION_GENERIC: &str = "transition:generic";

impl CallerKind {
    /// The management half of the privilege matrix (2, B): app-password
    /// management is a primary-password action — the HTTP API spec's own
    /// sentence about what app passwords may not do — and a browser session
    /// cookie is one. OAuth tokens never manage app passwords: the profile's
    /// `transition:generic` explicitly excludes account management.
    fn may_manage_app_passwords(&self) -> bool {
        matches!(self, CallerKind::Cookie | CallerKind::PrimaryPassword)
    }

    /// The email half (2, B): primary sessions see the email fields, an
    /// app-password session only when its app password is privileged, and an
    /// OAuth token never — nothing in its grant says it may.
    fn may_see_email(&self) -> bool {
        match self {
            CallerKind::Cookie | CallerKind::PrimaryPassword => true,
            CallerKind::AppPassword { privileged } => *privileged,
            CallerKind::Oauth { .. } => false,
        }
    }

    /// The scope gate (stage 2, D): an OAuth token holds only the scopes it
    /// was granted; the cookie and legacy arms predate scopes and carry the
    /// full authority of a primary-password login.
    fn has_scope(&self, scope: &str) -> bool {
        match self {
            CallerKind::Oauth { scopes } => scopes.iter().any(|granted| granted == scope),
            _ => true,
        }
    }
}

/// Who is making this call, and how they authenticated.
struct Caller {
    user: User,
    kind: CallerKind,
}

/// Who is making this call, and how they authenticated — or the refusal that
/// must become the response, ready-built. `Err` carries a `Response` because
/// the refusals have their own shapes (stage 2, D): the nonce and
/// `invalid_dpop_proof` challenges carry headers a generic `auth_required`
/// cannot. Every other refusal is still `auth_required`, built where it is
/// returned so no call site repeats it.
async fn caller(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
) -> Result<Caller, Response> {
    // The Authorization header, when there is one, carries the credential the
    // caller meant (extract's precedence): a DPoP-bound OAuth token, or the
    // legacy pair's access half.
    if let Some(authorization) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        && let Some(credential) = extract::credential(Some(authorization), None)
    {
        match credential {
            // The DPoP arm is terminal (stage 2, D): a presented-but-refused
            // DPoP credential answers with its own challenge, so it no longer
            // falls to the cookie below — a browser session would only mask
            // what the client needs to fix.
            brolly_identity::Credential::Dpop { token, .. } => {
                return token_caller(state, headers, method, uri, &token).await;
            }
            // The legacy arm (2, A): the access half of an opaque pair, in its
            // own table. A Mastodon token lands here too, fails the lookup,
            // and falls to the cookie below — the refusal a presented-but-
            // unknown credential always got.
            brolly_identity::Credential::Bearer(token) => {
                if let Some(caller) = legacy_caller(state, &token).await {
                    return Ok(caller);
                }
            }
            brolly_identity::Credential::Session(_) => {}
        }
    }
    // The cookie fallback stays last (2, D): the browser dashboard and the
    // tests, as before this grew the token arms.
    let token = session_token(headers).ok_or_else(|| auth_required(state))?;
    let user = db::user_for_session(&state.pool, &token)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
        .ok_or_else(|| auth_required(state))?;
    Ok(Caller {
        user,
        kind: CallerKind::Cookie,
    })
}

/// The bearer arm of `caller` (2, A): a legacy access token, resolved against
/// its own table with the kind in the lookup — so a refresh token presented
/// here fails the query, not a check after it.
async fn legacy_caller(state: &AppState, token: &str) -> Option<Caller> {
    let grant = legacy::verify_access(&state.pool, token)
        .await
        .ok()
        .flatten()?;
    let user = db::find_by_id(&state.pool, grant.user_id)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)?;
    let kind = match grant.app_password_id {
        None => CallerKind::PrimaryPassword,
        Some(_) => CallerKind::AppPassword {
            privileged: grant.privileged,
        },
    };
    Some(Caller { user, kind })
}

/// The DPoP arm of `caller` (stage 2, D), rebuilt in the order the spec
/// fixes: the proof first, then the grant.
///
/// **The proof is verified and spent before the token's grant is read.** The
/// proof binds to the presented token *string* — the `ath` claim — which the
/// `Authorization` header already carries, so nothing about the grant is
/// needed to check it, and an unknown token's proof is spent anyway:
/// fail-closed, the rule PAR already states. This closes the ordering hole
/// `identity/src/dpop.rs`'s module doc assigns here — a proof replayed
/// against a valid token, after being spent on an unknown one's request,
/// fails on the spend.
async fn token_caller(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    token: &str,
) -> Result<Caller, Response> {
    // 1. The proof, against this very request. A DPoP-bound token without one
    //    is a presented-but-refused credential: RFC 9449's challenge is the
    //    client's recovery.
    let Some(proof) = headers.get("dpop").and_then(|h| h.to_str().ok()) else {
        return Err(dpop_challenge(
            state,
            "invalid_dpop_proof",
            "a DPoP-bound token requires a DPoP proof on every request",
        ));
    };
    // 2. The request's own `htm`/`htu` (stage 2, D): the method and URL the
    //    client actually used — `https://{base}{path}` — not a hardcoded
    //    pair. The hardcoded `POST …/xrpc/` this replaces could never have
    //    matched `getServiceAuth`, a GET.
    let url = format!("https://{}{}", state.base_domain, uri.path());
    let at = now();
    // The ATProtocol profile requires nonces (stage 2, C): the current and
    // previous bucket's values are the ones a proof may carry.
    let accepted = dpop::accepted_nonces(&state.dpop_nonce_secret, at);
    let unspent = match dpop::verify(
        proof,
        method.as_str(),
        &url,
        Some(token),
        at,
        Some(&accepted),
    ) {
        Ok(unspent) => unspent,
        // The one refusal with its own error name (stage 2, C): the
        // client's recovery is a retry with the fresh nonce.
        Err(dpop::DpopError::NonceRequired) => {
            return Err(dpop_challenge(
                state,
                "use_dpop_nonce",
                "retry with a proof carrying this nonce in its nonce claim",
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "an ATProtocol DPoP proof was refused");
            return Err(dpop_challenge(state, "invalid_dpop_proof", &e.to_string()));
        }
    };
    // 3. Spent before the grant is read (stage 2, D) — the ordering that
    //    closes the replay hole: whatever the grant lookup below says, this
    //    proof is dead. The spent proof's thumbprint is what the key binding
    //    below checks, so nothing needs the grant first.
    let spent = match unspent.spend(&state.pool, at).await {
        Ok(spent) => spent,
        Err(dpop::DpopError::Replayed) => {
            tracing::warn!("an ATProtocol DPoP proof was replayed");
            return Err(dpop_challenge(
                state,
                "invalid_dpop_proof",
                "this proof has already been used",
            ));
        }
        Err(dpop::DpopError::Storage(storage)) => {
            // Fail closed: a proof that cannot be recorded as spent must
            // not authorize anything.
            tracing::error!(error = %storage, "recording a DPoP proof failed");
            return Err(internal_error());
        }
        Err(e) => {
            tracing::warn!(error = %e, "an ATProtocol DPoP proof was refused");
            return Err(dpop_challenge(state, "invalid_dpop_proof", &e.to_string()));
        }
    };
    // 4. Only now the grant (stage 2, D): the token's own row, the key it was
    //    issued to, and the member it speaks for.
    let grant = brolly_atproto::oauth::verify_token(&state.pool, "access", token)
        .await
        .ok()
        .flatten();
    let Some(grant) = grant else {
        // The proof was spent above; the token is simply not one this server
        // issued, or no longer one it honors.
        return Err(auth_required(state));
    };
    if spent.thumbprint != grant.dpop_jkt {
        tracing::warn!("an ATProtocol token was presented by a key it was not issued to");
        return Err(dpop_challenge(
            state,
            "invalid_dpop_proof",
            "the proof's key is not the key this token was issued to",
        ));
    }
    let user = db::find_by_id(&state.pool, grant.user_id)
        .await
        .ok()
        .flatten()
        .filter(User::is_active);
    let Some(user) = user else {
        return Err(auth_required(state));
    };
    Ok(Caller {
        user,
        kind: CallerKind::Oauth {
            scopes: grant
                .scope
                .split(' ')
                .filter(|scope| !scope.is_empty())
                .map(str::to_string)
                .collect(),
        },
    })
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
    resolve_user(state, repo, true).await
}

/// Resolve a repo identifier to its member.
///
/// The one place every identifier form is accepted, and the one place the
/// `is_active` filter is decided: every repo surface refuses a takendown
/// member's data (`resolve_repo`), except `sync.getRepoStatus` — whose entire
/// job is to *report* the takedown to a crawler that already indexed the repo
/// (stage 3, A), and which therefore resolves without the filter.
async fn resolve_user(state: &AppState, repo: &str, active_only: bool) -> Option<User> {
    let found = |user: Option<User>| match active_only {
        true => user.filter(User::is_active),
        false => user,
    };

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
            Some((id,)) => found(db::find_by_id(&state.pool, id).await.ok().flatten()),
            None => None,
        };
    }

    // `did:web` is routing-only (D11), so it is resolved structurally from the
    // host rather than looked up.
    if let Some(host) = repo.strip_prefix("did:web:") {
        return match extract::subdomain_user(host, &state.base_domain) {
            Some(username) => found(
                db::find_by_username(&state.pool, &username)
                    .await
                    .ok()
                    .flatten(),
            ),
            None => None,
        };
    }

    // A handle: `alice.brolly.test`.
    if let Some(handle) = repo.strip_suffix(&format!(".{}", state.base_domain)) {
        return found(
            db::find_by_username(&state.pool, handle)
                .await
                .ok()
                .flatten(),
        );
    }

    // A bare username, which clients send more often than the spec suggests.
    found(db::find_by_username(&state.pool, repo).await.ok().flatten())
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

pub(crate) async fn signing_key(state: &AppState, user: &User) -> Result<SigningKey, Response> {
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
    /// The version asked for. The repo holds only the current one, so a CID
    /// that is not it is a record this host does not have.
    cid: Option<String>,
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
    match repo::get_record_entry(blocks, handle.root, &query.collection, &query.rkey).await {
        Ok(Some((cid, _)))
            if query
                .cid
                .as_deref()
                .is_some_and(|asked| asked != cid.to_string()) =>
        {
            not_found("no such record")
        }
        Ok(Some((cid, value))) => Json(json!({
            "uri": ingest::at_uri(
                &did_of(&handle.user, &state),
                &query.collection,
                &query.rkey,
            ),
            "cid": cid.to_string(),
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
pub(crate) fn did_of(user: &User, state: &AppState) -> String {
    user.did_plc
        .clone()
        .unwrap_or_else(|| format!("did:web:{}.{}", user.username, state.base_domain))
}

#[derive(Deserialize)]
pub struct ResolveHandleQuery {
    handle: String,
}

/// The member a handle names, if it names one here (stage 3, B).
///
/// A handle is a domain name, `{username}.{base}`, and nothing else: the
/// bare username `resolve_repo` tolerates for `repo` is not a handle, and a
/// port is not part of one. Case-insensitive, as DNS is. A takendown member's
/// handle resolves to nothing, as their repo does.
pub(crate) async fn member_by_handle(state: &AppState, handle: &str) -> Option<User> {
    if handle.contains(':') {
        return None;
    }
    let username = extract::subdomain_user(handle, &state.base_domain)?;
    db::find_by_username(&state.pool, &username)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

/// `com.atproto.identity.resolveHandle` (stage 3, B): a member's handle to
/// their DID — `did:plc` once registered, the derived `did:web` before (D11).
///
/// A handle that does not resolve is this endpoint's normal outcome, not a
/// fault, so it is the reference's own `InvalidRequest` and message.
pub async fn resolve_handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ResolveHandleQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    match member_by_handle(&state, &query.handle).await {
        Some(user) => Json(json!({"did": did_of(&user, &state)})).into_response(),
        None => invalid_request("Unable to resolve handle"),
    }
}

/// `app.bsky.actor.getPreferences` (stage 3, C): the member's preferences,
/// read from the document in their pod.
pub async fn get_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The reference's own gate: account state, asked for with the full scope.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(pod) = state.stores.pod(user.id) else {
        return private(storage_unavailable());
    };
    let root = brolly_identity::routing::storage_root(&user.username, &state.base_domain);
    let items = brolly_atproto::preferences::read(&pod.read_store(), &root);
    private(Json(json!({ "preferences": items })).into_response())
}

/// `app.bsky.actor.putPreferences` (stage 3, C): replace the member's
/// preferences — an LDP write to their pod, not a repo commit, so nothing
/// reaches the firehose.
pub async fn put_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(input) = serde_json::from_slice::<Value>(&body) else {
        return private(invalid_request(
            "body must be a JSON object with preferences",
        ));
    };
    let items = match brolly_atproto::preferences::validate(&input) {
        Ok(items) => items,
        Err(e) => return private(invalid_request(&e.to_string())),
    };
    // A pod write like any other, so it counts against the member's quota.
    if !crate::pod::within_quota(&state, &user, body.len()) {
        return private(xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "the pod is at its quota",
        ));
    }
    let Ok(pod) = state.stores.pod(user.id) else {
        return private(storage_unavailable());
    };
    let root = brolly_identity::routing::storage_root(&user.username, &state.base_domain);
    match pod.write(|w| brolly_atproto::preferences::write(w, &root, items)) {
        Ok(_) => private(StatusCode::OK.into_response()),
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "storing preferences failed");
            private(storage_unavailable())
        }
    }
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

/// Set a page's `cursor` only when there is a next page.
///
/// The lexicons declare `cursor` an optional *string*: absent means "last
/// page", and a strict validator (the reference's own) refuses `null` where a
/// string is declared — so the last page leaves the key out rather than
/// sending one.
fn with_cursor(page: &mut Value, cursor: Option<String>) {
    if let Some(cursor) = cursor {
        page["cursor"] = json!(cursor);
    }
}

#[derive(Deserialize)]
pub struct ListRecordsQuery {
    repo: String,
    collection: String,
    limit: Option<u32>,
    cursor: Option<String>,
    reverse: Option<bool>,
}

/// `com.atproto.repo.listRecords` (stage 3, A): a collection's records, in
/// `rkey` order, paged by cursor.
pub async fn list_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListRecordsQuery>,
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
    // 1–100, the lexicon's own bounds; the default 50 is the reference's.
    let limit = match query.limit.unwrap_or(50) {
        1..=100 => query.limit.unwrap_or(50),
        _ => {
            return invalid_request("limit must be between 1 and 100");
        }
    };

    let Some(mut blocks) = handle.blocks() else {
        return storage_unavailable();
    };
    let did = did_of(&handle.user, &state);
    match repo::list_records(
        &mut blocks,
        handle.root,
        &query.collection,
        query.cursor.as_deref(),
        limit as usize,
        query.reverse.unwrap_or(false),
    )
    .await
    {
        Ok((records, cursor)) => {
            let mut page = json!({
                "records": records.iter().map(|record| json!({
                    "uri": ingest::at_uri(&did, &query.collection, &record.rkey),
                    "cid": record.cid.to_string(),
                    "value": record.value,
                })).collect::<Vec<_>>(),
            });
            with_cursor(&mut page, cursor);
            Json(page).into_response()
        }
        // A collection the grammar refuses is the caller's; anything else is
        // ours, and a 400 would tell the client to fix a request that was fine.
        Err(repo::RepoError::BadPath(e)) => invalid_request(&e),
        Err(e) => {
            tracing::error!(error = %e, "listing records failed");
            xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "could not read the repository",
            )
        }
    }
}

/// A real `com.atproto.repo.describeRepo` (stage 3, A): the collections the
/// repo actually holds, not the placeholder it always answered with.
#[derive(Deserialize)]
pub struct DescribeRepoQuery {
    repo: String,
}

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
    let handle_name = format!("{}.{}", user.username, state.base_domain);

    let collections = match open_repo(&state, user).await {
        Ok(handle) => match handle.blocks() {
            // A walk that fails is a fault to surface, not an empty repo to
            // describe: an empty `collections` is a claim about the data.
            Some(mut blocks) => match repo::collections(&mut blocks, handle.root).await {
                Ok(collections) => collections,
                Err(e) => {
                    tracing::error!(error = %e, "listing a repo's collections failed");
                    return xrpc_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalServerError",
                        "could not read the repository",
                    );
                }
            },
            None => return storage_unavailable(),
        },
        // A member with no repo yet: the honest description is the empty one,
        // not a 404 — the member resolves, and their repo simply holds nothing.
        Err(_) => Vec::new(),
    };

    Json(json!({
        "handle": handle_name,
        "did": did,
        "didDoc": {
            "id": did,
            "alsoKnownAs": [format!("at://{handle_name}")],
        },
        "collections": collections,
        // The handle resolves to this DID on this host, which is what a
        // consumer checks before trusting the pairing.
        "handleIsCorrect": true,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct GetBlocksQuery {
    did: String,
    cids: Vec<String>,
}

/// `com.atproto.sync.getBlocks` (stage 3, A): the requested blocks that exist,
/// framed as a CAR with the repo's current root in its header.
pub async fn get_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    // axum-extra's `Query`, not axum's: the lexicon's `cids` is a repeated
    // parameter (`cids=a&cids=b`), and `serde_urlencoded` cannot gather a
    // repeated key into a `Vec`. `serde_html_form` can.
    axum_extra::extract::Query(query): axum_extra::extract::Query<GetBlocksQuery>,
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
    let Some(mut blocks) = handle.blocks() else {
        return storage_unavailable();
    };

    let mut cids = Vec::with_capacity(query.cids.len());
    for cid in &query.cids {
        match cid.parse() {
            Ok(cid) => cids.push(cid),
            Err(_) => return invalid_request("cids must be CIDs"),
        }
    }
    match repo::blocks_car(&mut blocks, handle.root, &cids).await {
        Ok(car) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/vnd.ipld.car")],
            car,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "block CAR failed");
            xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "could not read the requested blocks",
            )
        }
    }
}

/// `com.atproto.sync.getLatestCommit` (stage 3, A): the repo's current root
/// and rev, straight off the state row — the table's whole job.
pub async fn get_latest_commit(
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
    Json(json!({
        "commit": handle.root.to_string(),
        "rev": handle.rev.as_str(),
    }))
    .into_response()
}

/// `com.atproto.sync.getRepoStatus` (stage 3, A): what happened to a repo a
/// crawler has already indexed. A takendown account is *reported*, not hidden
/// — the caller filter enforces takedowns everywhere it matters, and this is
/// the one endpoint whose job is to tell the network what happened.
pub async fn get_repo_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    // No `is_active` filter: a takendown member still has a status, and it is
    // this one.
    let Some(user) = resolve_user(&state, &query.did, false).await else {
        return xrpc_error(
            StatusCode::BAD_REQUEST,
            "RepoNotFound",
            "could not find the repo",
        );
    };
    let active = user.is_active();
    let mut doc = json!({
        "did": did_of(&user, &state),
        "active": active,
    });
    if active {
        // The lexicon's `rev`: the repo's current rev, given only while
        // active. A member with no repo yet has none to give.
        if let Ok(Some(current)) = state::load(&state.pool, user.id).await {
            doc["rev"] = json!(current.rev.as_str());
        }
    } else {
        doc["status"] = json!("takendown");
    }
    Json(doc).into_response()
}

/// One row of `sync.listRepos` (stage 3, A): the member's DID, the repo's
/// head, and the rev the head carries.
#[derive(sqlx::FromRow)]
struct ListedRepo {
    did: String,
    head: String,
    rev: String,
    active: bool,
}

#[derive(Deserialize)]
pub struct ListReposQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// `com.atproto.sync.listRepos` (stage 3, A): every member with a repo,
/// ordered by DID — the enumeration a relay crawls with. The derived
/// `did:web` sorts beside the `did:plc`s because the DID expression is what
/// both order and cursor are computed on, in one place.
pub async fn list_repos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListReposQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    // 1–1000, the lexicon's own bounds; the default 500 is the reference's.
    let limit = query.limit.unwrap_or(500);
    if !(1..=1000).contains(&limit) {
        return invalid_request("limit must be between 1 and 1000");
    }
    // The empty string sorts before every DID, so "no cursor" is the same
    // comparison as any other — one query shape, no special case. Both the
    // order and the cursor comparison are `COLLATE "C"`: byte order, the same
    // on every deployment whatever the database's locale.
    let cursor = query.cursor.unwrap_or_default();
    let base = state.base_domain.clone();

    let rows: Result<Vec<ListedRepo>, _> = sqlx::query_as(
        "SELECT COALESCE(u.did_plc, 'did:web:' || u.username || '.' || $3) COLLATE \"C\" AS did, \
                r.root_cid AS head, r.rev, u.status = 'active' AS active \
         FROM users u JOIN atproto_repos r ON r.user_id = u.id \
         WHERE COALESCE(u.did_plc, 'did:web:' || u.username || '.' || $3) COLLATE \"C\" > $1 \
         ORDER BY did LIMIT $2",
    )
    .bind(cursor)
    .bind((limit + 1) as i64)
    .bind(&base)
    .fetch_all(&state.pool)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "listing repos failed");
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "could not list the repositories",
            );
        }
    };

    // limit + 1 fetched: the extra row is only the "there is more" signal.
    let more = rows.len() > limit as usize;
    let page: Vec<ListedRepo> = rows.into_iter().take(limit as usize).collect();
    let cursor = more
        .then(|| page.last().map(|repo| repo.did.clone()))
        .flatten();

    // A takendown member stays listed, reported as such — the same answer
    // `getRepoStatus` gives, so a relay that enumerates learns what a relay
    // that asks would.
    let mut body = json!({
        "repos": page.iter().map(|repo| {
            let mut entry = json!({
                "did": repo.did,
                "head": repo.head,
                "rev": repo.rev,
                "active": repo.active,
            });
            if !repo.active {
                entry["status"] = json!("takendown");
            }
            entry
        }).collect::<Vec<_>>(),
    });
    with_cursor(&mut body, cursor);
    Json(body).into_response()
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
        brolly_atproto::repo::RepoError::Lexicon(m) => {
            tracing::error!(error = %m, "a vendored lexicon could not judge a record");
            xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "the record could not be validated",
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
/// The broadcast is the **fast path**, not the correctness mechanism (1, G):
/// the notify that `record` rides inside its transaction is what the shared
/// listener turns into a rebroadcast, and *that* is what reaches subscribers
/// no matter which process wrote. This send spares this process's own writes
/// the notify→listen→read round trip; the duplicate it creates — the listener
/// rebroadcasts what was already sent here — is absorbed by the consumer's
/// seq dedupe.
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
            let _ = state
                .commits
                .send(brolly_atproto::firehose::Event::Commit(event));
        }
        Err(e) => tracing::error!(error = %e, "recording a firehose event failed"),
    }
}

/// And into the pod, faithfully, so the other protocols can see it (D7).
///
/// One op per non-delete write, from the record as committed (stage 4a,
/// H1), so the pod never says something the repo does not; a delete leaves
/// the pod copy alone, exactly as the single delete always has. Best effort
/// and explicitly so — the repo is the source of truth the network syncs, and
/// a pod hiccup must not fail a landed write.
async fn ingest_written(state: &AppState, user: &User, ops: &[brolly_atproto::repo::AppliedOp]) {
    let Ok(pod) = state.stores.pod(user.id) else {
        tracing::error!(user = %user.id, "the pod is unavailable after a repo write");
        return;
    };
    let did = did_of(user, state);
    let webid = webid::webid(&user.username, &state.base_domain);
    let document = webid::profile_document(&user.username, &state.base_domain);
    for op in ops {
        let Some(committed) = op.record.as_ref() else {
            continue; // a delete leaves the pod copy alone, as always
        };
        let record = brolly_atproto::data_model::to_json(committed);
        let Some((collection, rkey)) = op.path.split_once('/') else {
            continue;
        };
        let uri = ingest::at_uri(&did, collection, rkey);
        if let Err(e) = pod
            .write(|w| Ok(ingest::ingest(w, &record, &uri, &webid, &document)))
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
) -> Result<Landed, Response> {
    let landed = perform_write(state, user, writes, head).await?;
    announce(state, &did_of(user, state), &landed).await;
    ingest_written(state, user, &landed.applied.ops).await;
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
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The scope gate (stage 2, D): repo writes assert `transition:generic`.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(input) = serde_json::from_slice::<CreateRecord>(&body) else {
        return private(invalid_request(
            "body must be a JSON object with collection and record",
        ));
    };
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return private(xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        ));
    }

    let write = match brolly_atproto::repo::PlannedWrite::create(
        &input.collection,
        input.rkey.as_deref(),
        &input.record,
        brolly_atproto::record::Validate::Optimistic,
    ) {
        Ok(write) => write,
        Err(e) => return private(write_refused(e)),
    };
    let head = match input.swap_commit {
        // A swap write never retries (1, C).
        Some(cid) => HeadSwap::AtCommit(cid),
        None => HeadSwap::Plain,
    };

    let landed = match commit_write(&state, &user, vec![write], head).await {
        Ok(landed) => landed,
        Err(response) => return private(response),
    };
    private(write_response(&state, &user, &landed))
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
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The scope gate (stage 2, D): repo writes assert `transition:generic`.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(input) = serde_json::from_slice::<PutRecord>(&body) else {
        return private(invalid_request(
            "body must be a JSON object with collection, rkey and record",
        ));
    };
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return private(xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        ));
    }

    let swap = match brolly_atproto::repo::RecordSwap::parse(
        input.swap_record.as_ref().map(|swap| swap.as_deref()),
    ) {
        Ok(swap) => swap,
        Err(e) => return private(write_refused(e)),
    };
    let write = match brolly_atproto::repo::PlannedWrite::put(
        &input.collection,
        &input.rkey,
        &input.record,
        swap,
        brolly_atproto::record::Validate::Optimistic,
    ) {
        Ok(write) => write,
        Err(e) => return private(write_refused(e)),
    };
    let head = match input.swap_commit {
        Some(cid) => HeadSwap::AtCommit(cid),
        None => HeadSwap::Plain,
    };

    let landed = match commit_write(&state, &user, vec![write], head).await {
        Ok(landed) => landed,
        Err(response) => return private(response),
    };
    private(write_response(&state, &user, &landed))
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
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The scope gate (stage 2, D): repo writes assert `transition:generic`.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(input) = serde_json::from_slice::<SwapRecord>(&body) else {
        return private(invalid_request(
            "body must be a JSON object with collection, rkey, record, swapRecord and swapCommit",
        ));
    };
    let (Some(swap_record), Some(swap_commit)) = (input.swap_record, input.swap_commit) else {
        return private(invalid_request(
            "both swapRecord and swapCommit are required",
        ));
    };
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return private(xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        ));
    }

    let swap = match brolly_atproto::repo::RecordSwap::parse(Some(swap_record.as_deref())) {
        Ok(swap) => swap,
        Err(e) => return private(write_refused(e)),
    };
    let write = match brolly_atproto::repo::PlannedWrite::put(
        &input.collection,
        &input.rkey,
        &input.record,
        swap,
        brolly_atproto::record::Validate::Optimistic,
    ) {
        Ok(write) => write,
        Err(e) => return private(write_refused(e)),
    };

    let landed =
        match commit_write(&state, &user, vec![write], HeadSwap::AtCommit(swap_commit)).await {
            Ok(landed) => landed,
            Err(response) => return private(response),
        };
    private(write_response(&state, &user, &landed))
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
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The scope gate (stage 2, D): repo writes assert `transition:generic`.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(input) = serde_json::from_slice::<SwapCommit>(&body) else {
        return private(invalid_request(
            "body must be a JSON object with collection, rkey, record and commitCid",
        ));
    };
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return private(xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        ));
    }

    let write = match brolly_atproto::repo::PlannedWrite::put(
        &input.collection,
        &input.rkey,
        &input.record,
        brolly_atproto::repo::RecordSwap::Any,
        brolly_atproto::record::Validate::Optimistic,
    ) {
        Ok(write) => write,
        Err(e) => return private(write_refused(e)),
    };

    let landed = match commit_write(
        &state,
        &user,
        vec![write],
        HeadSwap::AtCommit(input.commit_cid),
    )
    .await
    {
        Ok(landed) => landed,
        Err(response) => return private(response),
    };
    private(write_response(&state, &user, &landed))
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
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The scope gate (stage 2, D): repo writes assert `transition:generic`.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(input) = serde_json::from_slice::<ApplyWrites>(&body) else {
        return private(invalid_request(
            "body must be a JSON object with a non-empty writes array",
        ));
    };
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return private(xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        ));
    }
    if input.writes.is_empty() {
        return private(invalid_request("writes must not be empty"));
    }
    if input.writes.len() > brolly_atproto::repo::MAX_BATCH_OPS {
        return private(invalid_request(&format!(
            "a batch is capped at {} writes",
            brolly_atproto::repo::MAX_BATCH_OPS
        )));
    }

    // The plan, in the order the batch applies it. Each value passes the same
    // envelope a single write's record does.
    let mut writes = Vec::with_capacity(input.writes.len());
    for write in &input.writes {
        let planned = match write {
            ApplyWrite::Create {
                collection,
                rkey,
                value,
            } => brolly_atproto::repo::PlannedWrite::create(
                collection,
                rkey.as_deref(),
                value,
                brolly_atproto::record::Validate::Optimistic,
            ),
            ApplyWrite::Update {
                collection,
                rkey,
                value,
            } => brolly_atproto::repo::PlannedWrite::update(
                collection,
                rkey,
                value,
                brolly_atproto::record::Validate::Optimistic,
            ),
            ApplyWrite::Delete { collection, rkey } => {
                brolly_atproto::repo::PlannedWrite::delete(collection, rkey)
            }
        };
        match planned {
            Ok(planned) => writes.push(planned),
            Err(e) => return private(write_refused(e)),
        }
    }
    let head = match input.swap_commit {
        Some(cid) => HeadSwap::AtCommit(cid),
        None => HeadSwap::Plain,
    };

    let landed = match commit_write(&state, &user, writes, head).await {
        Ok(landed) => landed,
        Err(response) => return private(response),
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
    private(
        Json(json!({
            "commit": {
                "cid": landed.applied.commit.to_string(),
                "rev": landed.applied.rev.as_str(),
            },
            "results": results,
        }))
        .into_response(),
    )
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
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("no such repository on this host");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The scope gate (stage 2, D): repo writes assert `transition:generic`.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    let user = caller.user;
    let Ok(input) = serde_json::from_slice::<DeleteRecord>(&body) else {
        return private(invalid_request("body must name a collection and rkey"));
    };
    if let Some(target) = input.repo.as_deref()
        && resolve_repo(&state, target).await.map(|u| u.id) != Some(user.id)
    {
        return private(xrpc_error(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "you can only write to your own repository",
        ));
    }

    let write = match brolly_atproto::repo::PlannedWrite::delete(&input.collection, &input.rkey) {
        Ok(write) => write,
        Err(e) => return private(write_refused(e)),
    };

    // A plain write: no swap was named, so the head's movement is retried
    // through rather than answered (1, C).
    match commit_write(&state, &user, vec![write], HeadSwap::Plain).await {
        Ok(_) => private(Json(json!({})).into_response()),
        Err(response) => private(response),
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

// --- sessions (2, A and 2, B) --------------------------------------------------
//
// The legacy session surface: four session endpoints, three app-password
// ones, all apex-only like every other XRPC method. The tokens are the HTTP
// API spec's opaque pair; `adapters/atproto/src/legacy.rs` owns their rows.

/// The lexicon's `datetime` format: RFC 3339, the same wire format the
/// firehose frames its timestamps in.
fn wire_time(at: time::OffsetDateTime) -> String {
    // A Postgres timestamp is always inside RFC 3339's range; the `None` arm
    // exists only because the API returns `Result`.
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// The shape every session answer shares (2, A): the lexicon's required
/// fields, plus the email fields only for a session allowed to see them (2, B).
fn session_view(state: &AppState, user: &User, email_visible: bool) -> Value {
    let mut view = json!({
        "handle": format!("{}.{}", user.username, state.base_domain),
        "did": did_of(user, state),
        // `status` is omitted: a disabled member's credentials stop resolving
        // on their next request — the moderation stance every other surface
        // already takes (2, A).
        "active": true,
    });
    if email_visible && let Some(email) = &user.email {
        view["email"] = json!(email);
        view["emailConfirmed"] = json!(user.email_verified);
    }
    view
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionInput {
    identifier: String,
    password: String,
    // `authFactorToken` and `allowTakendown` are accepted and ignored (2,
    // non-goals): there is no mail path to carry a factor, and the flag only
    // *widens* access for taken-down accounts, so ignoring it is the safe
    // direction.
}

/// Resolve a login identifier in every form brolly can name (2, A): `did:plc`
/// (stored), `did:web` (derived from the subdomain), handle, email.
///
/// DID forms first, for the same suffix reason `resolve_repo` orders DID
/// first: a `did:web` handle ends in the base domain too. Unlike
/// `resolve_repo`, no `is_active` filter: a disabled member's *valid*
/// credentials answer `AccountTakedown`, which must not be reachable without
/// them.
async fn login_user(state: &AppState, identifier: &str) -> Option<User> {
    if let Some(did) = identifier.strip_prefix("did:plc:") {
        let row: Option<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE did_plc = $1")
            .bind(format!("did:plc:{did}"))
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
        let (id,) = row?;
        return db::find_by_id(&state.pool, id).await.ok().flatten();
    }
    // `did:web` is routing-only (D11): resolved structurally, never stored.
    if let Some(host) = identifier.strip_prefix("did:web:") {
        let username = extract::subdomain_user(host, &state.base_domain)?;
        return db::find_by_username(&state.pool, &username)
            .await
            .ok()
            .flatten();
    }
    // A handle: `alice.brolly.test`.
    if let Some(handle) = identifier.strip_suffix(&format!(".{}", state.base_domain))
        && let Some(user) = db::find_by_username(&state.pool, handle)
            .await
            .ok()
            .flatten()
    {
        return Some(user);
    }
    // Email, last: the one identifier form no other surface resolves.
    if identifier.contains('@') {
        return db::find_by_email(&state.pool, identifier)
            .await
            .ok()
            .flatten();
    }
    None
}

/// `com.atproto.server.createSession` (2, A).
pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let Ok(input) = serde_json::from_slice::<CreateSessionInput>(&body) else {
        return invalid_request("body must name an identifier and a password");
    };
    let Some(user) = login_user(&state, &input.identifier).await else {
        // A login for nobody costs the same one Argon2 run as a wrong
        // password for somebody — the `authenticate` pattern (2, A).
        db::dummy_verify(&input.password);
        return auth_required(&state);
    };

    // The app-password table first — an indexed SHA-256 lookup — then Argon2
    // against the primary hash (2, A).
    let app_password = legacy::find_app_password(&state.pool, user.id, &input.password)
        .await
        .ok()
        .flatten();
    let (app_password_id, email_visible) = match app_password {
        Some((id, privileged)) => (Some(id), privileged),
        None => match db::verify_primary_password(&state.pool, user.id, &input.password).await {
            Ok(Some(true)) => (None, true),
            Ok(_) => return auth_required(&state),
            Err(e) => {
                tracing::error!(error = %e, "the primary password check failed");
                return internal_error();
            }
        },
    };

    // Only now, with the credentials proven, does the account's status answer
    // (2, A): brolly's `disabled` is the spec's `takendown` — the moderation
    // reading of the two — and the lexicon's own error name says so.
    if !user.is_active() {
        return with_bearer_challenge(
            &state,
            xrpc_error(
                StatusCode::UNAUTHORIZED,
                "AccountTakedown",
                "this account has been taken down",
            ),
        );
    }

    let pair = match legacy::issue_pair(&state.pool, user.id, app_password_id).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "issuing a legacy session failed");
            return internal_error();
        }
    };
    let mut view = session_view(&state, &user, email_visible);
    view["accessJwt"] = json!(pair.access);
    view["refreshJwt"] = json!(pair.refresh);
    Json(view).into_response()
}

/// `com.atproto.server.getSession` (2, A): the current session, for the bearer
/// access token.
pub async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The scope gate (stage 2, D): `getSession` asserts the base `atproto`
    // scope — the one every token the profile issues carries.
    if !caller.kind.has_scope(SCOPE_ATPROTO) {
        return private(scope_missing(SCOPE_ATPROTO));
    }
    private(
        Json(session_view(
            &state,
            &caller.user,
            caller.kind.may_see_email(),
        ))
        .into_response(),
    )
}

/// The `Bearer` credential of a request, read through the identity-owned
/// parser: `refreshSession` and `deleteSession` authenticate with the refresh
/// half of the pair, which `caller`'s bearer arm — access only (2, A) — does
/// not resolve.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())?;
    match extract::credential(Some(authorization), None)? {
        brolly_identity::Credential::Bearer(token) => Some(token),
        _ => None,
    }
}

/// `com.atproto.server.refreshSession` (2, A): authenticate with the
/// *refresh* token, rotate the pair under the same `session_id`.
pub async fn refresh_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let Some(token) = bearer_token(&headers) else {
        return auth_required(&state);
    };
    let grant = match legacy::inspect_refresh(&state.pool, &token).await {
        Ok(legacy::RefreshToken::Valid(grant)) => grant,
        Ok(legacy::RefreshToken::Expired) => return expired_token(&state),
        Ok(legacy::RefreshToken::Invalid) => return invalid_token(&state),
        Err(e) => {
            tracing::error!(error = %e, "classifying a refresh token failed");
            return internal_error();
        }
    };
    let Ok(Some(user)) = db::find_by_id(&state.pool, grant.user_id).await else {
        return invalid_token(&state);
    };
    // A disabled member's refresh answers the lexicon's own name (2, A), for
    // the same reason `createSession` does.
    if !user.is_active() {
        return with_bearer_challenge(
            &state,
            xrpc_error(
                StatusCode::UNAUTHORIZED,
                "AccountTakedown",
                "this account has been taken down",
            ),
        );
    }
    let pair = match legacy::rotate_pair(&state.pool, &grant).await {
        Ok(Some(pair)) => pair,
        // The classification above is a snapshot; the rotation is the race's
        // arbiter (2, A): `None` means another refresh of the same session
        // won, and a rotated refresh token is an invalid one.
        Ok(None) => return invalid_token(&state),
        Err(e) => {
            tracing::error!(error = %e, "rotating a legacy session failed");
            return internal_error();
        }
    };
    let mut view = session_view(&state, &user, grant.may_see_email());
    view["accessJwt"] = json!(pair.access);
    view["refreshJwt"] = json!(pair.refresh);
    Json(view).into_response()
}

/// `com.atproto.server.deleteSession` (2, A): authenticate with the refresh
/// token, revoke every row sharing its `session_id` — the access token dies
/// with the session, not at expiry.
pub async fn delete_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let Some(token) = bearer_token(&headers) else {
        return auth_required(&state);
    };
    match legacy::inspect_refresh(&state.pool, &token).await {
        Ok(legacy::RefreshToken::Valid(grant)) => {
            match legacy::revoke_session(&state.pool, grant.session_id).await {
                // Zero rows is still success: the session is revoked, by this
                // request or by the one that raced it.
                Ok(_) => Json(json!({})).into_response(),
                Err(e) => {
                    tracing::error!(error = %e, "revoking a legacy session failed");
                    internal_error()
                }
            }
        }
        Ok(legacy::RefreshToken::Expired) => expired_token(&state),
        Ok(legacy::RefreshToken::Invalid) => invalid_token(&state),
        Err(e) => {
            tracing::error!(error = %e, "classifying a refresh token failed");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateAppPasswordInput {
    name: String,
    privileged: Option<bool>,
}

/// The privilege answer (2, B): app-password management is a primary-password
/// action — the HTTP API spec's own sentence about what app passwords may not
/// do — and OAuth tokens never manage them at all.
fn app_password_management_forbidden() -> Response {
    xrpc_error(
        StatusCode::FORBIDDEN,
        "Forbidden",
        "app passwords are managed with your primary password",
    )
}

/// `com.atproto.server.createAppPassword` (2, B): the one response the
/// plaintext ever appears in.
pub async fn create_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if !caller.kind.may_manage_app_passwords() {
        return private(app_password_management_forbidden());
    }
    let Ok(input) = serde_json::from_slice::<CreateAppPasswordInput>(&body) else {
        return private(invalid_request("body must name the app password"));
    };
    let name = input.name.trim();
    if name.is_empty() {
        return private(invalid_request("the name must not be empty"));
    }
    match legacy::create_app_password(
        &state.pool,
        caller.user.id,
        name,
        input.privileged.unwrap_or(false),
    )
    .await
    {
        Ok((row, password)) => private(
            Json(json!({
                "name": row.name,
                "password": password,
                "createdAt": wire_time(row.created_at),
                "privileged": row.privileged,
            }))
            .into_response(),
        ),
        Err(DbError::AppPasswordNameTaken) => private(invalid_request(
            "you already have an app password with that name",
        )),
        Err(e) => {
            tracing::error!(error = %e, "creating an app password failed");
            private(internal_error())
        }
    }
}

/// `com.atproto.server.listAppPasswords` (2, B): the list without the
/// password — the lexicon's list schema omits the field, and the stored hash
/// could not return one anyway.
pub async fn list_app_passwords(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if !caller.kind.may_manage_app_passwords() {
        return private(app_password_management_forbidden());
    }
    match legacy::list_app_passwords(&state.pool, caller.user.id).await {
        Ok(rows) => private(
            Json(json!({
                "passwords": rows
                    .iter()
                    .map(|row| json!({
                        "name": row.name,
                        "createdAt": wire_time(row.created_at),
                        "privileged": row.privileged,
                    }))
                    .collect::<Vec<_>>(),
            }))
            .into_response(),
        ),
        Err(e) => {
            tracing::error!(error = %e, "listing app passwords failed");
            private(internal_error())
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeAppPasswordInput {
    name: String,
}

/// `com.atproto.server.revokeAppPassword` (2, B): the row dies, and the
/// `ON DELETE CASCADE` kills its sessions *immediately* — the property an
/// opaque-token server has that the reference's self-asserting JWTs do not.
pub async fn revoke_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if !caller.kind.may_manage_app_passwords() {
        return private(app_password_management_forbidden());
    }
    let Ok(input) = serde_json::from_slice::<RevokeAppPasswordInput>(&body) else {
        return private(invalid_request("body must name the app password"));
    };
    match legacy::revoke_app_password(&state.pool, caller.user.id, &input.name).await {
        // The lexicon defines no error for an unknown name, and a password
        // that is not there is the state it asks for.
        Ok(_) => private(Json(json!({})).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "revoking an app password failed");
            private(internal_error())
        }
    }
}

// --- getServiceAuth (stage 2, D) ------------------------------------------------

#[derive(Deserialize)]
pub struct GetServiceAuthQuery {
    /// The service being called: a DID, optionally `did#serviceId` naming one
    /// of its services.
    aud: String,
    /// The one method the token authorizes. Optional: absent means the token
    /// carries no `lxm`, and the verifier decides what that authorizes.
    lxm: Option<String>,
    /// The token's `exp`, as a Unix timestamp. Optional: 60 s out by default.
    exp: Option<i64>,
}

/// `com.atproto.server.getServiceAuth` (stage 2, D): a short-lived service
/// token signed with the member's `atproto_signing` key — the key the PLC
/// document publishes, the identity that signs commits — scoped to one
/// audience and, when `lxm` names it, one method.
///
/// The consumer is stage 3's `atproto-proxy` forwarding; the endpoint is the
/// lexicon's shape and nothing more.
pub async fn get_service_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Query(query): Query<GetServiceAuthQuery>,
) -> Response {
    if wrong_host(&state, &headers) {
        return not_found("not served here");
    }
    let caller = match caller(&state, &headers, &method, &uri).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // The write scope (stage 2, D): minting a token that speaks for the
    // member's repo is write authority, and `getServiceAuth` asserts the same
    // scope a repo write does.
    if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
        return private(scope_missing(SCOPE_TRANSITION_GENERIC));
    }
    // `aud` and `lxm` are validated with atrium's own grammars, the way stage
    // 1 validated NSIDs: a DID — its `#serviceId` fragment is not DID syntax,
    // and survives into the token's `aud` — and an NSID.
    if !service_auth::valid_audience(&query.aud) {
        return private(invalid_request(
            "aud must be a DID, optionally did#serviceId",
        ));
    }
    if let Some(lxm) = query.lxm.as_deref()
        && !service_auth::valid_method(lxm)
    {
        return private(invalid_request("lxm must be an NSID"));
    }
    // `exp`: the lexicon's own window — not in the past, not further out than
    // five minutes; absent means the 60 s lifetime `service_auth.rs` already
    // commits to.
    let at = now();
    let exp = match query.exp {
        Some(exp) if exp <= at || exp > at + service_auth::MAX_EXP_SECONDS => {
            return private(xrpc_error(
                StatusCode::BAD_REQUEST,
                "BadExpiration",
                "exp must be in the future and at most five minutes out",
            ));
        }
        Some(exp) => exp,
        None => at + service_auth::TTL_SECONDS,
    };
    let key = match signing_key(&state, &caller.user).await {
        Ok(key) => key,
        Err(response) => return private(response),
    };
    match service_auth::issue(
        &key,
        &did_of(&caller.user, &state),
        &query.aud,
        query.lxm.as_deref(),
        exp,
        at,
    ) {
        Ok(token) => private(Json(json!({"token": token})).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "issuing a service auth token failed");
            private(internal_error())
        }
    }
}

// --- firehose ---------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct SubscribeQuery {
    /// Where to resume from (1, F). The cursor is the last event processed,
    /// exclusive.
    ///
    /// The event-stream spec's three cases: absent means the current position
    /// — live only; `0` means the whole retained window from its oldest row;
    /// and a cursor inside the window is backfilled from and then tailed. (This
    /// handler used to treat an absent cursor as `0` — backfilling the entire
    /// log to whoever asked for nothing — which the spec's text rules out, so
    /// the meaning changed here rather than the spec's.)
    cursor: Option<i64>,
}

/// `com.atproto.sync.subscribeRepos` — the commit stream.
///
/// Attach live first, then backfill, then tail (1, F) — the order is the
/// correctness claim, argued on `stream_commits`.
///
/// Ungated (ADR 0016): consumers connect *to* us, so there is nothing
/// outbound to suppress, and a PDS nobody can subscribe to is one nobody
/// can read.
///
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
/// frameable is the `#account` event, which says so on the wire (1, E) — not
/// this function's silence.)
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

/// One logged event as a wire frame, dispatched on its kind (1, E).
///
/// `#commit` is the only kind that needs the member — its blocks are built at
/// emission time from the member's storage (D5) — so it has its own path with
/// its own failure handling. `#identity` and `#account` are self-contained:
/// the DID is the subject, and they must *not* resolve the member, because an
/// `#account` event's whole job is to be emittable about a member who is
/// already gone.
async fn frame_event(state: &AppState, event: &firehose::Event) -> Option<Vec<u8>> {
    match event {
        firehose::Event::Commit(commit) => frame_commit(state, commit).await,
        firehose::Event::Identity(identity) => match firehose::identity_frame(identity) {
            Ok(frame) => Some(frame),
            Err(e) => {
                tracing::error!(
                    did = %identity.did,
                    seq = identity.seq,
                    error = %e,
                    "framing a logged identity event failed; skipping its event"
                );
                None
            }
        },
        firehose::Event::Account(account) => match firehose::account_frame(account) {
            Ok(frame) => Some(frame),
            Err(e) => {
                tracing::error!(
                    did = %account.did,
                    seq = account.seq,
                    error = %e,
                    "framing a logged account event failed; skipping its event"
                );
                None
            }
        },
    }
}

/// One subscriber's stream: attach live, backfill, then tail (1, F).
///
/// The order is the whole design. The old order — drain the table, then
/// subscribe — had a gap an event fit through exactly once per connection:
/// anything committed after the last page was read but before the channel was
/// subscribed was in neither. Subscribing *first* makes the gap structurally
/// impossible — every event is in the table (committed before the last page
/// read) or in the broadcast's bounded ring (sent after the subscription was
/// taken), and what the overlap leaves in both is absorbed by the seq dedupe
/// below.
///
/// The ring is the bounded buffer the spec asks for, and the lexicon already
/// names what falling behind it means: `ConsumerTooSlow`, an error frame and a
/// close — the consumer reconnects with its cursor, which is the designed
/// recovery and the reason the error is an answer rather than silence.
async fn stream_commits(
    state: AppState,
    cursor: Option<i64>,
    mut socket: axum::extract::ws::WebSocket,
) {
    use axum::extract::ws::Message;
    use tokio::sync::broadcast::error::RecvError;

    // How much history one page of backfill carries. A consumer far behind
    // makes several passes rather than one unbounded query.
    const PAGE: i64 = 500;

    // Attach live first (1, F) — before any table read below. The broadcast's
    // own ring is the bounded buffer: capacity events can pile up here while
    // the backfill runs, and a consumer that falls further behind is named
    // `ConsumerTooSlow` at the drain below rather than allowed to grow without
    // bound.
    let mut live = state.commits.subscribe();

    let mut position = cursor;
    if let Some(cursor) = cursor {
        // The cursor-ful cases are below. A cursor-less consumer takes the
        // live tail as-is: no table read, and no position filter — which
        // means a rebroadcast the shared listener is still catching up on can
        // arrive as a frame. That is deliberate: the frame is true, recent,
        // and cheaper to absorb than to filter, and the alternative (seeding
        // the position from a head read) would reopen exactly the gap the
        // attach-first order closed (1, F, 1, G).
        // A cursor ahead of the head is a client bug the stream names rather
        // than absorbs (1, F): the lexicon's `FutureCursor`, an error frame,
        // and the close the event-stream spec mandates after one. An empty log
        // has a head of zero for this purpose — a cursor into an empty stream
        // is still ahead of it.
        let head = match firehose::head(&state.pool).await {
            Ok(head) => head.unwrap_or(0),
            Err(e) => {
                tracing::error!(error = %e, "reading the firehose head failed");
                return;
            }
        };
        if cursor > head {
            close_with(
                &mut socket,
                firehose::error_frame(
                    firehose::FUTURE_CURSOR,
                    "the cursor is ahead of the stream's head",
                ),
            )
            .await;
            return;
        }

        // A cursor whose next event may have fallen off the log gets advice
        // rather than silence (1, E, 1, F): `#info {name: "OutdatedCursor"}` —
        // synthesized here, never logged, because it is about *this*
        // connection's cursor — and then the oldest retained row. The boundary
        // is `oldest - 1`: a cursor exactly one below the oldest row is the
        // normal resume position and has missed nothing. (The only way below
        // it today is a bigserial gap — a rolled-back insert consumes a seq —
        // where the advice is over-cautious and harmless; when retention
        // exists, the same advice is exactly right.)
        match firehose::oldest(&state.pool).await {
            Ok(Some(oldest)) if cursor < oldest - 1 => {
                match firehose::info_frame(firehose::OUTDATED_CURSOR) {
                    Ok(frame) => {
                        if socket.send(Message::Binary(frame.into())).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "framing an OutdatedCursor info failed")
                    }
                }
                position = Some(oldest - 1);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "reading the firehose's oldest row failed");
                return;
            }
        }

        // Backfill, in pages, by seq, so a consumer never sees a newer commit
        // before an older one — which would make `prev` unverifiable on its
        // side.
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
                let Some(frame) = frame_event(&state, event).await else {
                    continue;
                };
                if socket.send(Message::Binary(frame.into())).await.is_err() {
                    // The consumer went away mid-backfill. It has its cursor and
                    // will resume; nothing to clean up.
                    return;
                }
                position = Some(event.seq());
            }
        }
    }

    // Live tail: the buffered overlap first, then everything as it happens. A
    // consumer that stays connected keeps receiving; one that drops resumes
    // from the log, which is why the log exists.
    loop {
        let event = match live.recv().await {
            Ok(event) => event,
            Err(RecvError::Lagged(missed)) => {
                // The consumer fell `missed` events behind the ring's bound.
                // The lexicon names this outcome — `ConsumerTooSlow` — and the
                // designed recovery is the cursor: reconnect and backfill
                // (1, F).
                tracing::warn!(missed, "a firehose consumer fell behind the buffer");
                close_with(
                    &mut socket,
                    firehose::error_frame(
                        firehose::CONSUMER_TOO_SLOW,
                        "the consumer fell behind the buffer; reconnect with a cursor to resume",
                    ),
                )
                .await;
                return;
            }
            // The server is shutting down; there is nothing to close against.
            Err(RecvError::Closed) => return,
        };
        if position.is_some_and(|seen| event.seq() <= seen) {
            // Already delivered — the structural overlap (1, F, 1, G): an event
            // can be in the last backfill page *and* in the ring (it committed
            // while the page was being read), and it is in the ring twice when
            // the writer's fast-path send is rebroadcast by the shared
            // listener. The dedupe absorbs both; with the attach-first order
            // there is no gap left for it to miss, only this overlap to absorb.
            continue;
        }
        let Some(frame) = frame_event(&state, &event).await else {
            continue;
        };
        if socket.send(Message::Binary(frame.into())).await.is_err() {
            return;
        }
        position = Some(event.seq());
    }
}

/// An error frame, then the close the event-stream spec mandates immediately
/// after one.
async fn close_with(socket: &mut axum::extract::ws::WebSocket, frame: Result<Vec<u8>, String>) {
    match frame {
        Ok(frame) => {
            // A send failure here is the consumer already gone — the close is
            // moot either way.
            let _ = socket
                .send(axum::extract::ws::Message::Binary(frame.into()))
                .await;
        }
        Err(e) => tracing::error!(error = %e, "framing a stream error failed"),
    }
}

/// Anything under `/xrpc/` we do not implement — forwarded to the AppView
/// when it is the AppView's to answer (stage 3, D), 501 otherwise.
///
/// XRPC names an unimplemented method specifically, so a client can tell "this
/// server does not do that" from "this server is broken".
pub async fn unknown_method(
    State(state): State<AppState>,
    Path(nsid): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: axum::body::Body,
) -> Response {
    let not_implemented = || {
        xrpc_error(
            StatusCode::NOT_IMPLEMENTED,
            "MethodNotImplemented",
            &format!("{nsid} is not implemented by this server"),
        )
    };
    let Some(appview) = state.appview.clone() else {
        return not_implemented();
    };
    if wrong_host(&state, &headers) || !crate::appview::forwardable(&nsid) {
        return not_implemented();
    }
    // A client naming a different service than ours is asking for a route
    // this server does not have; forwarding it to our AppView anyway would
    // answer from the wrong service.
    if let Some(target) = headers.get("atproto-proxy").and_then(|h| h.to_str().ok()) {
        let did = target.split('#').next().unwrap_or_default();
        if did != appview.did() {
            return not_implemented();
        }
    }

    // Credentials only from `Authorization`: the dashboard's cookie is a
    // browser session on this origin, and a cross-site page must not be able
    // to make the member's key vouch for a call they never made. A request
    // with no `Authorization` forwards anonymously; one with a bad credential
    // is refused, not downgraded.
    let token = if headers.contains_key(header::AUTHORIZATION) {
        let caller = match caller(&state, &headers, &method, &uri).await {
            Ok(caller) => caller,
            Err(response) => return response,
        };
        if !caller.kind.has_scope(SCOPE_TRANSITION_GENERIC) {
            return private(scope_missing(SCOPE_TRANSITION_GENERIC));
        }
        let key = match signing_key(&state, &caller.user).await {
            Ok(key) => key,
            Err(response) => return private(response),
        };
        let at = now();
        match service_auth::issue(
            &key,
            &did_of(&caller.user, &state),
            appview.did(),
            Some(&nsid),
            at + service_auth::TTL_SECONDS,
            at,
        ) {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::error!(error = %e, "minting a service token for the AppView failed");
                return private(xrpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    "could not authorize the call to the AppView",
                ));
            }
        }
    } else {
        None
    };

    let path_and_query = uri
        .path_and_query()
        .map_or(uri.path(), |pq| pq.as_str())
        .to_owned();
    let authenticated = token.is_some();
    let response = appview
        .forward(method, &path_and_query, &headers, body, token)
        .await;
    if authenticated {
        private(response)
    } else {
        response
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle),
        )
        .route("/xrpc/app.bsky.actor.getPreferences", get(get_preferences))
        .route("/xrpc/app.bsky.actor.putPreferences", post(put_preferences))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.sync.getBlocks", get(get_blocks))
        .route(
            "/xrpc/com.atproto.sync.getLatestCommit",
            get(get_latest_commit),
        )
        .route("/xrpc/com.atproto.sync.getRepoStatus", get(get_repo_status))
        .route("/xrpc/com.atproto.sync.listRepos", get(list_repos))
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
        // The legacy session surface (2, A and 2, B), apex-only like the rest.
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(create_session),
        )
        .route("/xrpc/com.atproto.server.getSession", get(get_session))
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.createAppPassword",
            post(create_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.listAppPasswords",
            get(list_app_passwords),
        )
        .route(
            "/xrpc/com.atproto.server.revokeAppPassword",
            post(revoke_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(get_service_auth),
        )
        // Last, and a wildcard: literal segments match first.
        .route(
            "/xrpc/{nsid}",
            get(unknown_method).post(unknown_method).put(unknown_method),
        )
}
