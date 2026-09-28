//! HTTP wiring for the pod: subdomain resolution and the LDP routes.
//!
//! Routing follows ADR 0010 exactly. `/~/**` reaches the LDP handlers; the
//! protocol resources are explicit routes, and the storage description
//! (`/.well-known/solid`) is one of them, generated here rather than stored;
//! everything else on a subdomain is a
//! `404` with no fallback. The catch-all lives *inside* the storage prefix, so
//! it cannot shadow a protocol endpoint.

use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use brolly_authz::AccessMode;
use brolly_domain::{syntax, vocab};
use brolly_identity::db::{self, User};
use brolly_identity::dpop::DpopError;
use brolly_identity::routing::{SubdomainRoute, subdomain_route};
use brolly_identity::{Credential, Scope, Subject, Via, extract, routing, webid};
use brolly_solid::conditional::{self, Preconditions};
use brolly_solid::ldp::{self, Description, LdpError};
use brolly_solid::oidc::tokens;
use brolly_solid::patch;
use brolly_solid::storage;
use brolly_solid::storage_description;
use brolly_store::resources::{Kind, Pod};
use std::sync::Arc;

use crate::AppState;

/// Everything a pod request needs once the host and credential are resolved.
pub struct PodRequest {
    pub user: User,
    pub subject: Subject,
    /// A credential was presented and verified. H1 turns a refusal into 401
    /// or 403 from this alone, never from whether the target exists.
    pub authenticated: bool,
    pub pod: Arc<Pod>,
    /// This pod's binary storage, for LDP-NR.
    pub blobs: brolly_store::BlobStore,
    pub base: String,
    /// The instance's apex origin, for `WWW-Authenticate`'s `as_uri` (H3).
    pub apex: String,
    pub storage_root: String,
    /// The member's WebID: `solid:owner` on the storage root (H6), and the
    /// only place in a pod response that names the person rather than the pod.
    pub webid: String,
}

/// Resolve the subdomain to a user, and the credential to a [`Caller`].
///
/// Handlers never see a header. This is the only path from an HTTP request to a
/// `Subject` on the pod surface.
///
/// `uri` is the request's **original** URI, before axum's `Path` extractor
/// percent-decodes anything: `htu_matches` is exact string equality
/// (`identity/src/dpop.rs:397`), so a URL rebuilt from the decoded path fails
/// against a proof the client signed correctly (H15).
async fn resolve(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
) -> Result<PodRequest, Response> {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let Some(username) = extract::subdomain_user(host, &state.base_domain) else {
        return Err((StatusCode::NOT_FOUND, "no such pod").into_response());
    };

    let user = match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) if user.is_active() => user,
        Ok(_) => return Err((StatusCode::NOT_FOUND, "no such pod").into_response()),
        Err(e) => {
            tracing::error!(error = %e, "pod lookup failed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    let pod = match state.stores.pod(user.id) {
        Ok(pod) => pod,
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "pod store unavailable");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    let blobs = match state.stores.blobs(user.id) {
        Ok(blobs) => blobs,
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "pod blob store unavailable");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    let base = format!("https://{username}.{}", state.base_domain);
    let apex = format!("https://{}", state.base_domain);
    // The pod is resolved before the credential, so a bad credential sent to a
    // pod that doesn't exist is still 404. That is a routing answer, not an
    // access decision, like `subdomain_fallback`'s.
    let caller = match subject_for(state, headers, method, &format!("{base}{}", uri.path())).await {
        Ok(caller) => caller,
        Err(refused) => return Err(unauthorized(refused, &apex)),
    };
    Ok(PodRequest {
        storage_root: routing::storage_root(&username, &state.base_domain),
        webid: webid::webid(&username, &state.base_domain),
        base,
        apex,
        user,
        subject: caller.subject,
        authenticated: caller.authenticated,
        pod,
        blobs,
    })
}

/// Who is calling, and whether they proved it.
pub(crate) struct Caller {
    pub subject: Subject,
    /// A credential was presented **and** verified.
    ///
    /// Not `Subject::agent()`: a service-auth subject has `webid: None` and
    /// reports `Agent::Anonymous` (`identity/src/subject.rs:103-110`), but it
    /// authenticated, so H1 owes it a 403 rather than a challenge it has
    /// already satisfied. False for no credential at all, and for a session
    /// cookie that no longer resolves.
    pub authenticated: bool,
}

impl Caller {
    /// Nobody in particular. WAC decides whether that is enough, so a public
    /// resource is readable without a credential.
    fn anonymous() -> Caller {
        Caller {
            subject: Subject::anonymous(),
            authenticated: false,
        }
    }

    /// A subject that came from a credential we verified.
    fn verified(subject: Subject) -> Caller {
        Caller {
            subject,
            authenticated: true,
        }
    }
}

/// Why a presented credential produced no subject (H2).
///
/// **Only an `Authorization` header gets here.** A `brolly_session` cookie is
/// `SameSite=Lax` (`server/tests/auth_flow.rs:249`), so a browser sends it on
/// any top-level navigation: a logged-out member opening a public image in
/// their own pod never offered it, and meeting them with a challenge for a
/// credential they did not present would be wrong. A cookie that doesn't
/// resolve falls through to [`Caller::anonymous`] and H1 decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The token: a header we couldn't parse, or a token that is unknown,
    /// expired, revoked, or carries a WebID this instance doesn't host.
    /// RFC 6750 §3.1's `invalid_token`.
    Token,
    /// The proof: not signed by the token's key, the wrong `htm` or `htu`,
    /// outside the freshness window, or a replayed `jti`. RFC 9449 §7.1's
    /// `invalid_dpop_proof`.
    Proof,
    /// A bare bearer token that resolved to nobody.
    Bearer,
    /// We could not tell — a database failure while verifying. Ours, not the
    /// caller's, so it is a 500 and not a challenge to retry.
    Unavailable,
}

/// `WWW-Authenticate` for a caller who has to authenticate (H3).
///
/// `as_uri` is a Solid-OIDC §9.1 MUST: the scheme has no discovery mechanism
/// of its own, and RFC 9449 §7.1's `DPoP` parameters (`realm`, `scope`,
/// `error`, `error_description`, `algs`) include none. `apex` is the
/// instance's apex origin, byte-identical to what the profile publishes as
/// `solid:oidcIssuer` (`server/src/profile.rs:96`) and to the `iss` claim
/// (`server/src/solid_oidc.rs:43`).
///
/// `algs` names ES256 alone, because that is all we verify
/// (`identity/src/dpop.rs:336`), and advertising more would be a lie. `realm`
/// is omitted: RFC 6750 §3 and RFC 9449 §7.1 both make it optional and
/// Solid-OIDC doesn't use it.
/// `error_description` is omitted because it would be the only place in this
/// surface where a refusal explains itself to an unauthenticated caller, and
/// its values are either obvious ("expired") or something an attacker would
/// like to know ("replayed").
fn dpop_challenge(apex: &str, error: Option<&str>) -> String {
    let mut challenge = format!("DPoP algs=\"ES256\", as_uri=\"{apex}\"");
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    challenge
}

/// Answer a refused credential: 401 with a challenge, or 500 when the failure
/// was ours.
///
/// An absent credential is **not** routed through here — it has no `error` to
/// report, and it is `ldp_error` that discovers it was refused at all. It gets
/// `dpop_challenge(apex, None)`.
pub(crate) fn unauthorized(refused: Refused, apex: &str) -> Response {
    let challenge = match refused {
        Refused::Token => dpop_challenge(apex, Some("invalid_token")),
        Refused::Proof => dpop_challenge(apex, Some("invalid_dpop_proof")),
        // Mastodon's API tokens reach pod URLs through `Credential::Bearer`,
        // and a Mastodon client can do nothing with a `DPoP` challenge. An
        // *absent* credential still gets `DPoP` only: the pod is
        // proof-of-possession by default, and offering `Bearer` unprompted
        // invites a client to send a bare token that will be refused.
        Refused::Bearer => "Bearer error=\"invalid_token\"".to_string(),
        Refused::Unavailable => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    challenge_response(challenge)
}

/// 401 carrying `challenge`.
fn challenge_response(challenge: String) -> Response {
    match HeaderValue::from_str(&challenge) {
        Ok(value) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, value)],
            "unauthorized",
        )
            .into_response(),
        // Unreachable: every part of the challenge is a constant or a hostname
        // we built. A 401 without a challenge still beats a 200.
        Err(_) => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}

/// Turn whatever credential the request carried into a [`Caller`].
///
/// An absent credential is anonymous rather than rejected: WAC decides whether
/// anonymous is enough, so public resources work without one. An
/// `Authorization` header that doesn't verify is a [`Refused`], **not**
/// anonymity (H2), and the request is not retried without it: an expired token
/// must look like an expired token, or an app whose session lapsed mid-edit
/// sees its own resources vanish instead of a challenge it can act on.
///
/// `method` is typed rather than a string so no caller can pass a literal:
/// the whole of H15 was one call site handing a `HEAD` the verifier's `"GET"`.
pub(crate) async fn subject_for(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    url: &str,
) -> Result<Caller, Refused> {
    let authorization = match headers.get(header::AUTHORIZATION).map(|h| h.to_str()) {
        // Bytes that aren't UTF-8 are still a presented credential. Dropping
        // them would hand the request to a session cookie the client didn't
        // mean, or to anonymity.
        Some(Err(_)) => return Err(Refused::Token),
        Some(Ok(value)) => Some(value),
        None => None,
    };
    let cookie = headers.get(header::COOKIE).and_then(|h| h.to_str().ok());

    let Some(credential) = extract::credential(authorization, cookie) else {
        // An `Authorization` header we could not parse is still a presented
        // credential, and `extract::credential` does not fall back to the
        // cookie past it; no header at all is anonymity.
        if authorization.is_some() {
            return Err(Refused::Token);
        }
        return Ok(Caller::anonymous());
    };
    // The proof travels in its own header, so it is attached separately.
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok());
    let credential = extract::with_proof(credential, proof);

    match credential {
        Credential::Session(token) => match db::user_for_session(&state.pool, &token).await {
            Ok(Some(user)) => Ok(Caller::verified(Subject::local(
                user.id,
                user.did_plc.clone().unwrap_or_default(),
                webid::webid(&user.username, &state.base_domain),
                Scope::parse("webid"),
                Via::Session,
            ))),
            // A cookie is not a presented credential (H2), so a stale one is
            // anonymity and not a challenge.
            _ => Ok(Caller::anonymous()),
        },
        Credential::Dpop { token, proof } => {
            // Token and proof are verified together or not at all: a token
            // whose `cnf.jkt` does not match the proof was not presented by
            // its holder, and a bound token with no proof is refused rather
            // than downgraded to bearer semantics.
            //
            // A bound token's claims arrive `Unspent`. Spending records the
            // proof so it can't be sent again.
            let proof = (!proof.is_empty()).then_some(proof);
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = match tokens::verify_access(
                &state.provider_key,
                &token,
                proof.as_deref(),
                method.as_str(),
                url,
                now,
            ) {
                Ok(tokens::Access::Bearer(claims)) => claims,
                Ok(tokens::Access::Bound(unspent)) => match unspent.spend(&state.pool, now).await {
                    Ok(claims) => claims,
                    Err(DpopError::Storage(e)) => {
                        tracing::error!(error = %e, "recording a DPoP proof failed");
                        return Err(Refused::Unavailable);
                    }
                    // A replayed `jti` lands here, and it is a proof failure:
                    // the token is fine and refreshing it would not help.
                    Err(e) => {
                        tracing::warn!(error = %e, "Solid access token proof refused");
                        return Err(Refused::Proof);
                    }
                },
                Err(e @ tokens::TokenError::Jwt(_)) => {
                    tracing::debug!(error = %e, "Solid access token rejected");
                    return Err(Refused::Token);
                }
                // `Dpop`, `WrongHolder` and `ProofRequired`. Each says the
                // token was readable and the proof was not good enough for it.
                Err(e) => {
                    tracing::debug!(error = %e, "Solid access token proof rejected");
                    return Err(Refused::Proof);
                }
            };
            solid_subject(state, claims).await.map(Caller::verified)
        }
        // Mastodon's bearer tokens. Note what is *not* happening here: a
        // Solid access token presented as a bearer does not resolve, because
        // this looks the token up in Mastodon's own table rather than trying
        // to verify it as a JWT. Accepting a DPoP-bound token without its
        // proof is what would make the binding decorative.
        Credential::Bearer(token) => {
            match brolly_mastodon::oauth::verify_token(&state.pool, &token).await {
                Ok(Some(grant)) => match db::find_by_id(&state.pool, grant.user_id).await {
                    Ok(Some(user)) if user.is_active() => Ok(Caller::verified(Subject::local(
                        user.id,
                        user.did_plc.clone().unwrap_or_default(),
                        webid::webid(&user.username, &state.base_domain),
                        Scope::parse(&grant.scopes),
                        Via::MastodonBearer,
                    ))),
                    Ok(_) => Err(Refused::Bearer),
                    Err(e) => {
                        tracing::error!(error = %e, "a bearer grant's user lookup failed");
                        Err(Refused::Unavailable)
                    }
                },
                Ok(None) => Err(Refused::Bearer),
                Err(e) => {
                    tracing::error!(error = %e, "bearer token lookup failed");
                    Err(Refused::Unavailable)
                }
            }
        }
    }
}

/// Turn verified Solid-OIDC claims into a `Subject`.
///
/// The WebID in the token decides who is calling, not the subdomain being
/// visited: an app holding Bob's token is Bob wherever it reads.
///
/// A token we minted whose WebID this instance doesn't host, or whose member
/// is gone, resolves to nobody, so it is the token that is wrong. Accepting
/// other issuers is stage 6. A failure to look the member up is ours (H2).
async fn solid_subject(state: &AppState, claims: tokens::AccessClaims) -> Result<Subject, Refused> {
    let Some(username) = webid::local_username(&claims.webid, &state.base_domain) else {
        return Err(Refused::Token);
    };
    let user = match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) if user.is_active() => user,
        Ok(_) => return Err(Refused::Token),
        Err(e) => {
            tracing::error!(error = %e, "a Solid token's member lookup failed");
            return Err(Refused::Unavailable);
        }
    };

    Ok(Subject::local(
        user.id,
        user.did_plc.clone().unwrap_or_default(),
        claims.webid,
        Scope::parse(&claims.scope),
        Via::SolidDpop,
    ))
}

/// Turn a refusal from `ldp` into a response.
///
/// `authenticated` and `apex` are what this layer knows and `ldp` doesn't:
/// whether a credential was presented and verified, and where to send a
/// caller who has to get one. Together with [`LdpError::Denied`], they give
/// H1's table:
///
/// | Caller | Holds the mode | Exists | Answer |
/// |---|---|---|---|
/// | unauthenticated | no | either | 401 + `WWW-Authenticate` |
/// | authenticated | no | either | 403 |
/// | either | yes | no | 404 |
///
/// The status never depends on whether the target exists. That replaces
/// stage 0's A2 rule, "a caller without the required mode gets `NotFound`",
/// while keeping what that rule protected. An unauthenticated caller gets 401
/// for `/~/secret` and for `/~/does-not-exist` and can't tell them apart. An
/// authenticated one gets 403 for both.
fn ldp_error(error: LdpError, authenticated: bool, apex: &str) -> Response {
    match error {
        LdpError::Denied if authenticated => (StatusCode::FORBIDDEN, "forbidden").into_response(),
        // No credential, or a cookie that no longer resolves. Credentials that
        // were presented and failed were refused in `resolve`, before WAC ran,
        // with their own `error=` (H2).
        LdpError::Denied => challenge_response(dpop_challenge(apex, None)),
        // Only a caller who holds the mode ever gets here; see `ldp::read`.
        LdpError::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
        // `delete` answers this itself, with the caller's `Allow`: a 405
        // without one breaks RFC 9110 §15.5.6 (H16), and the `Allow` depends
        // on modes this function can't see. Nothing else produces it, so
        // reaching here means a new producer that needs the same treatment.
        LdpError::Undeletable => {
            tracing::error!("Undeletable reached ldp_error; its caller must build the 405");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        // Stage 0's 403, unchanged by this chunk. 5b's chunk 5 makes this 409
        // with a body describing the problem, which Solid Protocol §5.4
        // requires.
        LdpError::NotEmpty => (
            StatusCode::FORBIDDEN,
            "a container with members cannot be deleted",
        )
            .into_response(),
        LdpError::OutsideStorage => (
            StatusCode::NOT_FOUND,
            "not found; user storage lives under /~/",
        )
            .into_response(),
        LdpError::Syntax(e) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, e.to_string()).into_response(),
        LdpError::NotRdf => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "this resource takes an RDF body",
        )
            .into_response(),
        LdpError::ContainmentChange => (
            StatusCode::CONFLICT,
            "a container's members change only by creating or deleting them",
        )
            .into_response(),
        LdpError::BlobMissing => {
            tracing::error!("a blob was released under a write that still needed it");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        LdpError::PreconditionFailed => {
            (StatusCode::PRECONDITION_FAILED, "precondition failed").into_response()
        }
        LdpError::Store(e) => {
            tracing::error!(error = %e, "ldp storage failure");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// A 405 for a resource that exists and can't be deleted: the storage root, or
/// its ACL (Solid Protocol §5.4, H12).
///
/// Only reached after `ldp` has authorized the DELETE. A caller without the
/// mode got 401 or 403 before `Undeletable` could be returned (H4:
/// authorization before method availability), so the `Allow` here, from the
/// same description `OPTIONS` would give, tells the caller nothing it couldn't
/// have asked for. H4's table already leaves `DELETE` out for these two
/// targets. No `Link` goes out: H6 is for successful reads and creates.
fn refuse_deletion(request: &PodRequest, path: &str) -> Response {
    let description = match ldp::describe(&request.pod, &request.base, path, &request.subject) {
        Ok(description) => description,
        Err(e) => return ldp_error(e, request.authenticated, &request.apex),
    };
    let resource = format!("{}{path}", request.base);
    let allow = allowed(&description, &resource, &request.storage_root).join(", ");
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, allow)],
        "the storage root and its ACL can't be deleted",
    )
        .into_response()
}

fn wac_allow(granted: &[brolly_authz::AccessMode]) -> String {
    use brolly_authz::AccessMode::*;
    let names: Vec<&str> = granted
        .iter()
        .map(|m| match m {
            Read => "read",
            Write => "write",
            Append => "append",
            Control => "control",
        })
        .collect();
    format!("user=\"{}\"", names.join(" "))
}

/// What [`patch`] matches on, and so what `Accept-Patch` advertises. A third
/// syntax here would advertise a 415.
const ACCEPT_PATCH: &str = "text/n3, application/sparql-update";

/// H4: the methods this caller may use on this target, in a fixed order.
///
/// Computed from the caller's modes and whether the target exists. Nothing is
/// decided by kind: `POST` is offered on documents too, because `append_in`
/// appends to one and [`post`] routes it.
fn allowed(description: &Description, resource: &str, storage_root: &str) -> Vec<&'static str> {
    let exists = description.exists();
    let write = description.holds(AccessMode::Write);
    let mut methods = Vec::new();
    if exists && description.holds(AccessMode::Read) {
        methods.extend(["GET", "HEAD"]);
    }
    if write {
        methods.push("PUT");
    }
    // Needs an existing target: there is no container to mint a member in,
    // and no document to append to.
    if exists && (write || description.holds(AccessMode::Append)) {
        methods.push("POST");
    }
    // Not offered to an Append-only caller, though the protocol would allow
    // it: `ldp::patch_in` requires Write, and 5c owns that change.
    if write {
        methods.push("PATCH");
    }
    // Authorization is decided before this: a caller without Write gets H1's
    // refusal, not a 405 telling them the target is special.
    if write && exists && !undeletable(resource, storage_root) {
        methods.push("DELETE");
    }
    methods.push("OPTIONS");
    methods
}

/// The storage root and the storage root's own ACL: the two resources Solid
/// Protocol §5.4 forbids deleting, and whose `Allow` must not list `DELETE`.
fn undeletable(resource: &str, storage_root: &str) -> bool {
    resource == storage_root || resource == format!("{storage_root}.acl")
}

/// H5: what a `PUT` to this target may carry.
///
/// The condition is `ldp::put_if`'s own `rdf_only`, spelled the same way on
/// purpose, and it reads the IRI, not the metadata: `put_if` refuses a binary
/// for `/~/new/` whether or not `/~/new/` exists yet.
fn accept_put(resource: &str) -> &'static str {
    if storage::is_container(resource) || ldp::governed(resource).is_some() {
        ldp::accepted_write_types()
    } else {
        "*/*"
    }
}

/// H4 and H5: `Allow`, and an `Accept-*` for each write method it names.
///
/// One builder for `OPTIONS`, `GET` and `HEAD`. CTS reads `Allow` from a
/// `GET`, SolidOS from whichever it made last, and two builders would drift.
///
/// Each `Accept-*` goes out only when its method is allowed. Solid §5.2
/// states the MUST unconditionally; we narrow it, as CSS does, because
/// advertising a method the caller can't use is the same lie as a wrong
/// `Allow`.
fn affordances(
    description: &Description,
    resource: &str,
    storage_root: &str,
) -> Vec<(header::HeaderName, String)> {
    let methods = allowed(description, resource, storage_root);
    let mut out = vec![(header::ALLOW, methods.join(", "))];
    if methods.contains(&"PATCH") {
        out.push((
            header::HeaderName::from_static("accept-patch"),
            ACCEPT_PATCH.to_string(),
        ));
    }
    if methods.contains(&"POST") {
        out.push((
            header::HeaderName::from_static("accept-post"),
            ldp::accepted_write_types().to_string(),
        ));
    }
    if methods.contains(&"PUT") {
        out.push((
            header::HeaderName::from_static("accept-put"),
            accept_put(resource).to_string(),
        ));
    }
    out
}

/// Put built headers onto a response.
///
/// A value that isn't a legal header value is dropped, not panicked on. None
/// of ours can be illegal: they are ASCII lists built here and `ldp`'s own
/// constants.
fn apply(response: &mut Response, headers: Vec<(header::HeaderName, String)>) {
    for (name, value) in headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
}

/// H6's `Link` set: what this resource is, where its rules are, which storage
/// it belongs to, and — on the root — whose it is.
///
/// One `Link` field with a value per link, comma-joined. `type` repeats its
/// relation for each class rather than listing several URIs under one `rel=`,
/// because that is the only form RFC 8288 defines and the only one every
/// client parser handles; it is also what LDP's own examples show.
///
/// `kind` is `None` when the target doesn't exist — an `OPTIONS` asking "may I
/// create here?" (H4). Then no `rel="type"` goes out at all: LDP §4.2.1.4 asks
/// for one on every response to an LDPR's URI, and we narrow it deliberately,
/// because a response about a resource that isn't there must not imply what
/// kind of thing would be. The `acl` and `storageDescription` links still go:
/// both exist whether or not the target does, and the ACL link is what a
/// client needs to *create* the rules for what it is about to write.
fn links(
    base: &str,
    resource: &str,
    storage_root: &str,
    owner: &str,
    kind: Option<Kind>,
) -> String {
    let is_root = resource == storage_root;
    let mut values: Vec<String> = Vec::new();

    if let Some(kind) = kind {
        let mut types = vec![vocab::LDP_RESOURCE];
        match kind {
            // Solid and CTS name `ldp:BasicContainer`; generic LDP clients
            // match `ldp:Container`. Sending one of them blinds the other.
            Kind::Container => {
                types.push(vocab::LDP_CONTAINER);
                types.push(vocab::LDP_BASIC_CONTAINER);
            }
            Kind::NonRdfSource => types.push(vocab::LDP_NON_RDF_SOURCE),
            // An `.acl` is an RDF source like any other document: LDP names no
            // auxiliary class, and inventing one would be ours alone.
            Kind::RdfSource | Kind::Auxiliary => types.push(vocab::LDP_RDF_SOURCE),
        }
        if is_root {
            // Solid Protocol §4.1: the storage MUST say so on its own URI.
            types.push(vocab::PIM_STORAGE);
        }
        values.extend(types.into_iter().map(|t| format!("<{t}>; rel=\"type\"")));
    }

    values.push(format!("<{}>; rel=\"acl\"", ldp::acl_iri(resource)));
    values.push(format!(
        "<{}>; rel=\"{}\"",
        storage_description::iri(base),
        vocab::SOLID_STORAGE_DESCRIPTION
    ));
    if is_root {
        // §4.1 constrains the form and leaves the choice to us. We advertise
        // it because the description names an owner anyway, and a client
        // holding the root shouldn't need a second request to learn whose.
        values.push(format!("<{owner}>; rel=\"{}\"", vocab::SOLID_OWNER));
    }
    values.join(", ")
}

/// Every header a pod resource's `GET`, `HEAD` and `OPTIONS` carry about the
/// resource and the caller: H4's `Allow`, H5's `Accept-*` and H6's `Link`.
///
/// The one entry point for all three methods, so SolidOS — which draws its
/// affordances from whichever it made last — can't get two answers for one
/// resource. [`affordances`] is the part that depends only on the
/// description; this adds what depends on the pod.
fn headers_for(
    request: &PodRequest,
    resource: &str,
    description: &Description,
) -> Vec<(header::HeaderName, String)> {
    let mut out = affordances(description, resource, &request.storage_root);
    out.push((
        header::LINK,
        links(
            &request.base,
            resource,
            &request.storage_root,
            &request.webid,
            description.kind(),
        ),
    ));
    out
}

/// A request's `If-Match` and `If-None-Match`.
///
/// Each header may arrive on several lines, which mean the same as one line
/// joined with commas (RFC 9110 §5.3). Bytes that aren't UTF-8 go in lossily.
/// They can't match a version, which is ASCII, so an `If-Match` made only of
/// them fails, and an `If-None-Match` made only of them holds.
fn preconditions(headers: &HeaderMap) -> Preconditions {
    let field = |name: header::HeaderName| -> Option<String> {
        let lines: Vec<String> = headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        (!lines.is_empty()).then(|| lines.join(", "))
    };
    Preconditions::from_fields(
        field(header::IF_MATCH).as_deref(),
        field(header::IF_NONE_MATCH).as_deref(),
    )
}

/// `GET /~/*path`, and `HEAD`, which axum routes here without the body.
///
/// Sends `ETag` (the resource's version) and `Last-Modified`, and answers 304
/// to an `If-None-Match` naming the current version. Only here: a write's
/// response carries no `ETag`, because the server transforms what it stores
/// (RFC 9110 §9.3.4).
pub async fn get(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    let outcome = match ldp::read(
        &request.pod,
        Some(&request.blobs),
        &request.base,
        &path,
        &request.subject,
        accept,
    ) {
        Ok(outcome) => outcome,
        Err(e) => return ldp_error(e, request.authenticated, &request.apex),
    };

    // After `read` succeeded, so after the Read check, and against the version
    // from the same snapshot as the body. A caller without Read was refused
    // above, 401 or 403, whatever they sent.
    let etag = conditional::etag(&outcome.version);
    if preconditions(&headers).not_modified(&outcome.version) {
        // RFC 9110 §15.4.5: a 304 carries the ETag and no body.
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }

    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, outcome.media_type.clone()),
            (
                header::HeaderName::from_static("wac-allow"),
                wac_allow(&outcome.description.granted),
            ),
            (header::ETAG, etag),
        ],
        outcome.body,
    )
        .into_response();
    // H4–H6: the same builder `OPTIONS` uses, over the description `read`
    // took from the body's own snapshot.
    let resource = format!("{}{path}", request.base);
    apply(
        &mut response,
        headers_for(&request, &resource, &outcome.description),
    );
    // Omitted rather than wrong if the stored time isn't one we can render.
    if let Some(date) = conditional::http_date(&outcome.modified)
        && let Ok(value) = HeaderValue::from_str(&date)
    {
        response.headers_mut().insert(header::LAST_MODIFIED, value);
    }
    response
}

/// `PUT /~/*path`
pub async fn put(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("text/turtle");

    match ldp::put_if(
        &request.pod,
        Some(&request.blobs),
        &request.base,
        &path,
        &request.subject,
        &body,
        content_type,
        &request.storage_root,
        &preconditions(&headers),
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ldp_error(e, request.authenticated, &request.apex),
    }
}

/// `POST /~/*path`
pub async fn post(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("text/turtle");

    match ldp::append_if(
        &request.pod,
        Some(&request.blobs),
        &request.base,
        &path,
        &request.subject,
        &body,
        content_type,
        &request.storage_root,
        &preconditions(&headers),
    ) {
        Ok(created) => (StatusCode::CREATED, [(header::LOCATION, created)]).into_response(),
        Err(e) => ldp_error(e, request.authenticated, &request.apex),
    }
}

/// `PATCH /~/*path` — N3 Patch or SPARQL Update, both through one solver.
pub async fn patch(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let patch_body = match content_type.split(';').next().unwrap_or_default().trim() {
        "text/n3" => ldp::PatchBody::N3(&body),
        "application/sparql-update" => match std::str::from_utf8(&body) {
            Ok(sparql) => ldp::PatchBody::SparqlUpdate(sparql),
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "body is not UTF-8").into_response();
            }
        },
        other => {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("PATCH accepts text/n3 or application/sparql-update, not {other}"),
            )
                .into_response();
        }
    };

    // WAC, the preconditions, the patch and the write, in one transaction.
    // The two content-type refusals above come first: RFC 9110 §13.2.1
    // evaluates a precondition only when the request would otherwise succeed.
    match ldp::patch_if(
        &request.pod,
        &request.base,
        &path,
        &request.subject,
        patch_body,
        &request.storage_root,
        &preconditions(&headers),
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(patch::PatchError::Ldp(e)) => ldp_error(e, request.authenticated, &request.apex),
        Err(patch::PatchError::Precondition(m)) => (StatusCode::CONFLICT, m).into_response(),
        Err(patch::PatchError::NotCurrent) => {
            (StatusCode::PRECONDITION_FAILED, "precondition failed").into_response()
        }
        Err(patch::PatchError::EscapesGraph) => (
            StatusCode::FORBIDDEN,
            "a PATCH may not name a GRAPH or WITH",
        )
            .into_response(),
        Err(patch::PatchError::Malformed(m) | patch::PatchError::NotAPatch(m)) => {
            (StatusCode::BAD_REQUEST, m).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "patch failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `DELETE /~/*path`
pub async fn delete(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    match ldp::delete_if(
        &request.pod,
        &request.base,
        &path,
        &request.subject,
        &request.storage_root,
        &preconditions(&headers),
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(LdpError::Undeletable) => refuse_deletion(&request, &path),
        Err(e) => ldp_error(e, request.authenticated, &request.apex),
    }
}

/// `GET /~/` — the storage root itself.
///
/// A wildcard route does not match an empty remainder, so the root container
/// needs its own entry or the pod root would 404.
pub async fn get_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Response {
    get(state, method, uri, headers, Path(String::new())).await
}

/// `POST /~/`
pub async fn post_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    post(state, method, uri, headers, Path(String::new()), body).await
}

/// `PUT /~/`.
///
/// The wildcard route doesn't match an empty remainder (see [`get_root`]).
/// Without these entries, axum's method router answered every write to the
/// root with its own 405, before any handler ran. `ldp`'s root protections
/// were unreachable over HTTP, and a caller with no access was told the
/// target is special (H12). Each one delegates, so WAC runs first and
/// refuses in the ordinary way.
pub async fn put_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    put(state, method, uri, headers, Path(String::new()), body).await
}

/// `PATCH /~/`. See [`put_root`].
pub async fn patch_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    patch(state, method, uri, headers, Path(String::new()), body).await
}

/// `DELETE /~/`. Always refused: after the Write check, `ldp::delete_in`
/// answers `Undeletable`, which is a 405 (§5.4). See [`put_root`].
pub async fn delete_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Response {
    delete(state, method, uri, headers, Path(String::new())).await
}

/// `OPTIONS /~/*path`: what *this* caller may do with *this* resource.
///
/// Resolves the pod, authenticates and evaluates WAC like any other method.
/// The handler this replaces took no state, no path and no credential, and
/// gave every resource in every pod the same `Allow`. Answers 204, which CTS
/// accepts as well as 200, with H4's `Allow` and H5's `Accept-*`.
///
/// A CORS preflight never gets here. `lib.rs`'s middleware answers an
/// `OPTIONS` carrying `Access-Control-Request-Method` before routing, and a
/// preflight carries no credentials by definition.
pub async fn options(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let description = match ldp::describe(&request.pod, &request.base, &path, &request.subject) {
        Ok(description) => description,
        Err(e) => return ldp_error(e, request.authenticated, &request.apex),
    };
    // H4: gated on holding *any* mode, not on Read. An Append-only caller,
    // the drop box and the inbox, is the one that most needs to learn it may
    // POST. A caller with nothing gets H1's 401 or 403, the same whether or
    // not the target exists, so this is not an existence oracle. A caller
    // with a mode on a target that doesn't exist gets 204 and the `Allow` a
    // creation would have.
    if description.granted.is_empty() {
        return ldp_error(LdpError::Denied, request.authenticated, &request.apex);
    }
    let resource = format!("{}{path}", request.base);
    let mut response = StatusCode::NO_CONTENT.into_response();
    apply(
        &mut response,
        headers_for(&request, &resource, &description),
    );
    response
}

/// `OPTIONS /~/`: the storage root itself. A wildcard route doesn't match
/// an empty remainder (see [`get_root`]), and without this the root would get
/// no per-caller `Allow`, which is the one place `DELETE` must be left out.
///
/// Takes the same extractors as its wildcard twin and forwards them, so a
/// DPoP proof on `OPTIONS /~/` is checked against the method and URL it
/// signed (H15), like everywhere else.
pub async fn options_root(
    state: State<AppState>,
    method: Method,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Response {
    options(state, method, uri, headers, Path(String::new())).await
}

/// Anything on a subdomain that is not `/~/` and not a protocol resource.
///
/// ADR 0010's default-deny. There is no LDP fallback here, which is why a
/// misrouted OAuth request cannot become a pod write.
pub async fn subdomain_fallback(State(state): State<AppState>, uri: axum::http::Uri) -> Response {
    let path = uri.path();
    match subdomain_route(path) {
        SubdomainRoute::UserStorage => (
            // Every method under `/~/` is routed, and a method axum doesn't
            // route there gets axum's own 405, which carries its own `Allow`.
            // So this arm serves the bare `/~` alone: the storage prefix
            // without its slash, which no route matches and which supports no
            // method. RFC 9110 §15.5.6 requires `Allow` on a 405 (H16), and
            // §10.2.1 lets it be empty, which is the true answer here. Whether
            // `/~` should redirect to `/~/` belongs to 5c's `/foo` vs `/foo/`.
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "")],
            "user storage lives under /~/",
        )
            .into_response(),
        SubdomainRoute::ProtocolResource => (
            StatusCode::NOT_IMPLEMENTED,
            "this protocol resource is not implemented yet",
        )
            .into_response(),
        SubdomainRoute::Root | SubdomainRoute::NotFound => (
            StatusCode::NOT_FOUND,
            [(
                header::LINK,
                format!("<https://{}{}>; rel=\"canonical\"", state.base_domain, path),
            )],
            "not found; user storage lives under /~/",
        )
            .into_response(),
    }
}

/// `/.well-known/solid` — the storage description (Solid Protocol §4.1, H8).
///
/// World-readable and read-only, and WAC never enters into it. It says what a
/// client needs to know *before* it has a credential — which storage this is
/// and whose — and it is generated from the routing table, so there is no
/// stored resource for an ACL to govern.
///
/// Routed in `app()` beside `webfinger` and `nodeinfo`, so it never reaches
/// [`subdomain_fallback`] and has no entry in `USER_PROTOCOL_RESOURCES`, which
/// feeds only that fallback. Routes aren't host-scoped, so the subdomain is
/// resolved here, as `/profile` resolves it, and the apex 404s.
///
/// Every method is routed here (`any`), so this decides: the apex and an
/// unknown pod are 404 whatever the method — a 405 there would say the
/// resource exists — and on a pod anything but a read is 405 with our own
/// `Allow` (H16).
pub async fn storage_description(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    const ALLOW: &str = "GET, HEAD, OPTIONS";

    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let Some(username) = extract::subdomain_user(host, &state.base_domain) else {
        return (StatusCode::NOT_FOUND, "no such pod").into_response();
    };
    match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) if user.is_active() => {}
        Ok(_) => return (StatusCode::NOT_FOUND, "no such pod").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "pod lookup failed serving a storage description");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    match method {
        // Axum strips the body from a HEAD at the top-level route, whichever
        // method router endpoint answered it.
        Method::GET | Method::HEAD => {}
        Method::OPTIONS => {
            return (StatusCode::NO_CONTENT, [(header::ALLOW, ALLOW)]).into_response();
        }
        _ => {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, ALLOW)],
                "the storage description is generated, and read-only",
            )
                .into_response();
        }
    }

    let base = format!("https://{username}.{}", state.base_domain);
    let quads = storage_description::document(&base, &webid::webid(&username, &state.base_domain));
    let format = syntax::negotiate(headers.get(header::ACCEPT).and_then(|h| h.to_str().ok()));
    match syntax::serialize(&quads, format) {
        Ok(body) => (
            [(header::CONTENT_TYPE, format.media_type().to_string())],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "serialising a storage description failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `WWW-Authenticate` on the response `refused` produces.
    fn challenge_of(refused: Refused, apex: &str) -> String {
        let response = unauthorized(refused, apex);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .to_string()
    }

    /// 5a uses the codes `pod.rs` already has; 5b revisits them.
    #[test]
    fn the_new_ldp_refusals_have_status_codes() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::NotRdf, true, apex).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            ldp_error(LdpError::ContainmentChange, true, apex).status(),
            StatusCode::CONFLICT,
            "Solid Protocol §5.3"
        );
        assert_eq!(
            ldp_error(LdpError::BlobMissing, true, apex).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// H1's table at the only place that knows both halves. The failure this
    /// guards is a `Denied` answered 403 to a caller who never presented a
    /// credential: they are told "no" with nothing they can do about it, which
    /// is exactly the state an app with an expired token is in.
    #[test]
    fn a_denial_is_401_or_403_by_whether_the_caller_authenticated() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::Denied, false, apex).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ldp_error(LdpError::Denied, true, apex).status(),
            StatusCode::FORBIDDEN
        );
    }

    /// Nothing was presented, so nothing was found fault with: RFC 6750 §3.1
    /// defines `error` only for a credential that *was* sent. An `error` here
    /// would tell an anonymous prober something about a credential it never
    /// had.
    #[test]
    fn the_challenge_on_a_denial_names_no_error() {
        let response = ldp_error(LdpError::Denied, false, "https://brolly.test");
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            r#"DPoP algs="ES256", as_uri="https://brolly.test""#
        );
    }

    /// The disclosure boundary, from the other side: `NotFound` is the only
    /// variant that may become a 404, because it is the only one `ldp` emits
    /// after the caller has been allowed to know.
    #[test]
    fn only_a_permitted_caller_can_be_told_a_resource_is_missing() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::NotFound, false, apex).status(),
            StatusCode::NOT_FOUND
        );
        assert_ne!(
            ldp_error(LdpError::Denied, true, apex).status(),
            StatusCode::NOT_FOUND
        );
    }

    /// `delete` builds `Undeletable`'s 405 itself, because its `Allow` needs
    /// the caller's modes. Reaching `ldp_error` with it means a new producer
    /// that skipped that, and a loud 500 beats a 405 without `Allow`
    /// (RFC 9110 §15.5.6). `NotEmpty` stays 403 until chunk 5 makes it a 409
    /// with a body; if it moved early to anything but 409, a `DELETE` of a
    /// populated container would claim the method isn't allowed.
    #[test]
    fn undeletable_is_built_by_delete_and_a_populated_container_is_still_403() {
        let apex = "https://brolly.test";
        assert_eq!(
            ldp_error(LdpError::Undeletable, true, apex).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ldp_error(LdpError::NotEmpty, true, apex).status(),
            StatusCode::FORBIDDEN
        );
    }

    /// H3's challenge is the only thing a refused client can act on, so its
    /// exact shape is load-bearing: a Solid client reads `as_uri` to find the
    /// issuer and refuses to authenticate against one it wasn't configured
    /// for. The failure this guards is a challenge naming an algorithm we do
    /// not verify, or an issuer that disagrees with the one the profile
    /// publishes as `solid:oidcIssuer`.
    #[test]
    fn the_challenge_names_es256_and_the_apex() {
        assert_eq!(
            dpop_challenge("https://brolly.test", None),
            r#"DPoP algs="ES256", as_uri="https://brolly.test""#
        );
    }

    /// RFC 9449 §7.1 defines `invalid_dpop_proof` precisely because
    /// `invalid_token` tells a client to refresh a token that is fine — it
    /// would refresh, re-sign the same broken proof, and loop. Collapsing the
    /// two codes is the failure this guards.
    #[test]
    fn a_broken_proof_and_a_broken_token_are_told_apart() {
        assert_eq!(
            challenge_of(Refused::Token, "https://brolly.test"),
            r#"DPoP algs="ES256", as_uri="https://brolly.test", error="invalid_token""#
        );
        assert_eq!(
            challenge_of(Refused::Proof, "https://brolly.test"),
            r#"DPoP algs="ES256", as_uri="https://brolly.test", error="invalid_dpop_proof""#
        );
    }

    /// Mastodon's API tokens reach pod URLs as bare bearers, and a Mastodon
    /// client can do nothing with a `DPoP` challenge — it has no key to sign
    /// a proof with and would loop on a challenge it cannot satisfy.
    #[test]
    fn a_bare_bearer_gets_a_bearer_challenge() {
        assert_eq!(
            challenge_of(Refused::Bearer, "https://brolly.test"),
            r#"Bearer error="invalid_token""#
        );
    }

    /// A database failure while verifying is ours, not the caller's. Blaming
    /// the credential would have a client throw away a perfectly good token
    /// and re-run a login flow over an outage.
    #[test]
    fn a_failure_to_verify_is_not_blamed_on_the_credential() {
        assert_eq!(
            unauthorized(Refused::Unavailable, "https://brolly.test").status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // --- H4 and H5: what a caller may do ---------------------------------------

    use brolly_authz::AccessMode::{Append, Control, Read, Write};
    use brolly_store::resources::{Kind, ResourceMeta};

    const ROOT: &str = "https://alice.brolly.test/~/";
    const DOC: &str = "https://alice.brolly.test/~/note";
    const ALL: [AccessMode; 4] = [Read, Write, Append, Control];

    /// A description, as `ldp::describe` would give it, for `kind` (`None`:
    /// nothing there) and a caller holding `granted`.
    fn described(kind: Option<Kind>, granted: &[AccessMode]) -> Description {
        Description {
            meta: kind.map(|kind| ResourceMeta {
                kind,
                modified: "2026-09-23T10:00:00.000Z".into(),
                version: "01J8Z3T5V7W9X1Y3Z5A7B9C1D3".into(),
                blob: None,
            }),
            granted: granted.to_vec(),
            public: Vec::new(),
        }
    }

    fn allow_line(kind: Option<Kind>, granted: &[AccessMode], resource: &str) -> String {
        allowed(&described(kind, granted), resource, ROOT).join(", ")
    }

    fn value_of<'a>(headers: &'a [(header::HeaderName, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.as_str())
    }

    /// H4's table, row by row, on a document that exists. What this guards is
    /// a method promised to a caller whose mode `ldp` will refuse it for.
    #[test]
    fn allow_names_only_what_the_modes_permit() {
        let doc = Some(Kind::RdfSource);
        assert_eq!(
            allow_line(doc, &ALL, DOC),
            "GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS"
        );
        assert_eq!(allow_line(doc, &[Read], DOC), "GET, HEAD, OPTIONS");
        // POST appends to a document as well as minting a container's member.
        // PATCH needs Write in `ldp::patch_in`, so an appender isn't offered it.
        assert_eq!(allow_line(doc, &[Append], DOC), "POST, OPTIONS");
        assert_eq!(
            allow_line(doc, &[Read, Append], DOC),
            "GET, HEAD, POST, OPTIONS"
        );
        // Control governs the resource's ACL, not the resource.
        assert_eq!(allow_line(doc, &[Control], DOC), "OPTIONS");
    }

    /// Nothing there: what a creation could do. `GET` would 404 and `DELETE`
    /// would 404, and there is no container to `POST` into.
    #[test]
    fn an_absent_target_is_offered_creation_and_not_reading() {
        assert_eq!(allow_line(None, &ALL, DOC), "PUT, PATCH, OPTIONS");
        assert_eq!(allow_line(None, &[Read, Append], DOC), "OPTIONS");
    }

    /// Solid Protocol §5.4 names exactly two undeletable resources. Any other
    /// ACL, and any other container, stays deletable: WAC §3.2 makes deleting
    /// an ACL the way to revert to inheritance.
    #[test]
    fn only_the_root_and_its_own_acl_are_never_offered_delete() {
        let container = Some(Kind::Container);
        let acl = Some(Kind::Auxiliary);
        let root_acl = format!("{ROOT}.acl");
        assert!(!allow_line(container, &ALL, ROOT).contains("DELETE"));
        assert!(!allow_line(acl, &ALL, &root_acl).contains("DELETE"));
        assert!(allow_line(container, &ALL, &format!("{ROOT}notes/")).contains("DELETE"));
        assert!(allow_line(acl, &ALL, &format!("{ROOT}notes/.acl")).contains("DELETE"));
        assert!(allow_line(acl, &ALL, &format!("{DOC}.acl")).contains("DELETE"));
    }

    /// H5: each `Accept-*` goes out only when its method is in `Allow`. A
    /// header advertising a method the caller can't use is as wrong as an
    /// `Allow` that lists it.
    #[test]
    fn each_accept_header_follows_its_method() {
        let doc = Some(Kind::RdfSource);

        let full = affordances(&described(doc, &ALL), DOC, ROOT);
        assert_eq!(value_of(&full, "accept-patch"), Some(ACCEPT_PATCH));
        assert_eq!(
            value_of(&full, "accept-post"),
            Some(ldp::accepted_write_types())
        );
        assert_eq!(value_of(&full, "accept-put"), Some("*/*"));

        let reader = affordances(&described(doc, &[Read]), DOC, ROOT);
        assert_eq!(value_of(&reader, "allow"), Some("GET, HEAD, OPTIONS"));
        for name in ["accept-patch", "accept-post", "accept-put"] {
            assert_eq!(value_of(&reader, name), None, "{name} offered to a reader");
        }

        let appender = affordances(&described(doc, &[Append]), DOC, ROOT);
        assert!(value_of(&appender, "accept-post").is_some());
        assert_eq!(value_of(&appender, "accept-patch"), None);
        assert_eq!(value_of(&appender, "accept-put"), None);
    }

    /// The rule is `ldp::put_if`'s own `rdf_only`: a container or an ACL takes
    /// RDF, anything else takes whatever it's sent. A drift between the two
    /// would promise a 415.
    #[test]
    fn a_container_and_an_acl_take_rdf_only_on_put() {
        let rdf = ldp::accepted_write_types();
        assert_eq!(accept_put(ROOT), rdf);
        assert_eq!(
            accept_put(&format!("{ROOT}notes/")),
            rdf,
            "even before it exists"
        );
        assert_eq!(accept_put(&format!("{ROOT}.acl")), rdf);
        assert_eq!(accept_put(&format!("{DOC}.acl.acl")), rdf);
        assert_eq!(accept_put(DOC), "*/*");
        assert_eq!(accept_put(&format!("{ROOT}photo.png")), "*/*");
        assert!(!rdf.contains("rdf+xml"), "ADR 0007");
    }

    // --- H6 and H7: what a resource says about itself -------------------------

    const TEST_BASE: &str = "https://alice.brolly.test";
    const TEST_OWNER: &str = "https://alice.brolly.test/profile#me";

    fn links_for(resource: &str, kind: Option<Kind>) -> String {
        links(TEST_BASE, resource, ROOT, TEST_OWNER, kind)
    }

    /// The failure this guards: no `rel="type"` anywhere, so a client had to
    /// parse the body to tell a container from a document — which it cannot do
    /// at all for a binary.
    #[test]
    fn a_resource_announces_its_ldp_kinds() {
        let document = links_for(&format!("{ROOT}note"), Some(Kind::RdfSource));
        assert!(
            document.contains("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\""),
            "{document}"
        );
        assert!(
            document.contains("<http://www.w3.org/ns/ldp#RDFSource>; rel=\"type\""),
            "{document}"
        );

        let binary = links_for(&format!("{ROOT}paper.pdf"), Some(Kind::NonRdfSource));
        assert!(
            binary.contains("ldp#NonRDFSource>; rel=\"type\""),
            "{binary}"
        );

        // Both classes: Solid and CTS name `ldp:BasicContainer`, generic LDP
        // clients match `ldp:Container`, and one of the two audiences goes
        // blind if only one goes out.
        let container = links_for(&format!("{ROOT}notes/"), Some(Kind::Container));
        assert!(
            container.contains("ldp#Container>; rel=\"type\""),
            "{container}"
        );
        assert!(
            container.contains("ldp#BasicContainer>; rel=\"type\""),
            "{container}"
        );

        // An `.acl` is an RDF source like any other document. Nothing in LDP
        // names an auxiliary class, and inventing one would be a lie a client
        // would have to special-case.
        let acl = links_for(&format!("{ROOT}notes/.acl"), Some(Kind::Auxiliary));
        assert!(acl.contains("ldp#RDFSource>; rel=\"type\""), "{acl}");
    }

    /// §4.1's MUST. Without it a client that walks up from a resource never
    /// learns where the storage begins, and 5a stated it only inside a body
    /// the client had to already be reading.
    #[test]
    fn only_the_storage_root_is_a_storage_and_has_an_owner() {
        let root = links_for(ROOT, Some(Kind::Container));
        assert!(
            root.contains("<http://www.w3.org/ns/pim/space#Storage>; rel=\"type\""),
            "{root}"
        );
        assert!(
            root.contains(
                "<https://alice.brolly.test/profile#me>; \
                 rel=\"http://www.w3.org/ns/solid/terms#owner\""
            ),
            "{root}"
        );

        let inside = links_for(&format!("{ROOT}notes/"), Some(Kind::Container));
        assert!(!inside.contains("space#Storage"), "{inside}");
        assert!(!inside.contains("terms#owner"), "{inside}");
    }

    /// H7 over the wire. The old concatenation pointed a client at
    /// `x.acl.acl`, which it would then create as an ordinary resource.
    #[test]
    fn the_acl_link_is_the_acl_that_governs_the_target() {
        let document = links_for(&format!("{ROOT}note"), Some(Kind::RdfSource));
        assert!(
            document.contains("<https://alice.brolly.test/~/note.acl>; rel=\"acl\""),
            "{document}"
        );

        let acl = links_for(&format!("{ROOT}note.acl"), Some(Kind::Auxiliary));
        assert!(
            acl.contains("<https://alice.brolly.test/~/note.acl>; rel=\"acl\""),
            "{acl}"
        );
        assert!(!acl.contains(".acl.acl"), "{acl}");
    }

    /// Every resource in a storage links its description (§4.1), whatever kind
    /// it is and whether or not it exists.
    #[test]
    fn every_resource_points_at_the_storage_description() {
        for (resource, kind) in [
            (format!("{ROOT}note"), Some(Kind::RdfSource)),
            (ROOT.to_string(), Some(Kind::Container)),
            (format!("{ROOT}nothing-here"), None),
        ] {
            let link = links_for(&resource, kind);
            assert!(
                link.contains(
                    "<https://alice.brolly.test/.well-known/solid>; \
                     rel=\"http://www.w3.org/ns/solid/terms#storageDescription\""
                ),
                "{resource}: {link}"
            );
        }
    }

    /// An `OPTIONS` asking "may I create here?" (H4) gets an answer that
    /// claims no kind: a target that doesn't exist has none, and implying one
    /// would make the header an existence oracle.
    #[test]
    fn a_target_that_does_not_exist_claims_no_kind() {
        let link = links_for(&format!("{ROOT}nothing-here"), None);
        assert!(!link.contains("rel=\"type\""), "{link}");
        assert!(
            link.contains("<https://alice.brolly.test/~/nothing-here.acl>; rel=\"acl\""),
            "{link}"
        );
    }
}
