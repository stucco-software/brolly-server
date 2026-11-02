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
use brolly_solid::ldp::{self, Description, LdpError, LdpOutcome};
use brolly_solid::oidc::{keys, tokens};
use brolly_solid::patch;
use brolly_solid::storage;
use brolly_solid::storage_description;
use brolly_store::resources::{Kind, Pod};
use std::sync::Arc;
use url::Url;

use crate::AppState;
use oxigraph_model::NamedNode;

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
/// `path` is the request's target inside `/~/`, percent-decoded — the shape
/// the gate below needs, where `uri`'s raw path could hide a `%2E`-spelled
/// suffix.
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
    path: &str,
) -> Result<PodRequest, Response> {
    // H1 (spec 5d): an auxiliary of an auxiliary is a fiction, and the 404
    // for it is decided here — by the IRI's shape alone, before any lookup
    // and before WAC, so every method answers it, not only the write paths.
    // The resource can never exist, so 404 is truthful, and it cannot leak
    // anything: the shape is syntactic public knowledge, and no lookup
    // happens (5b H1's auth-before-target rule protects *lookups*). The
    // store's double-suffix refusal is the defence in depth under this.
    if ldp::is_double_auxiliary(path) {
        return Err((StatusCode::NOT_FOUND, "no such resource").into_response());
    }

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

    // A target is an IRI before it is anything else. The decoded path becomes
    // the resource IRI, and the IRI becomes the ACL candidate list the access
    // decision is built from, so a path that cannot be one has no business
    // reaching either: it is a 400 by its shape alone, for every method and
    // every caller, before the credential is looked at — the shape is public
    // knowledge, and there is nothing a 401 would protect.
    if let Err(rule) = well_formed_path(path, uri.path(), &base) {
        return Err((StatusCode::BAD_REQUEST, rule).into_response());
    }

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

/// Is `decoded` — the request's path, `/~/…`, percent-decoded — one the pod
/// can name a resource by? `raw` is the same path before decoding.
///
/// Four refusals, each with the one-line reason the 400 carries:
///
/// * A percent-encoded slash. `%2F` decodes to `/`, so `a%2Fb` and `a/b`
///   would be one resource reached by two spellings, of which only one is
///   the IRI the server mints, lists and authorizes.
/// * A control character — which includes the NUL that `%00` decodes to.
/// * A dot segment or an empty segment. The router does not normalise them,
///   so `pub/../x` would be a resource literally named `../x` inside `pub/`:
///   governed by `pub/.acl`, listed by `pub/` as a member every client
///   resolves to `x`. The trailing empty segment of a container path is the
///   one empty segment that means something.
/// * Anything else an IRI reference cannot carry — `>`, space, `}`, `|`,
///   `\`, `"` and the rest — decided by parsing `base` + `decoded` as the IRI
///   it is about to become.
fn well_formed_path(decoded: &str, raw: &str, base: &str) -> Result<(), &'static str> {
    if raw.to_ascii_lowercase().contains("%2f") {
        return Err("a percent-encoded slash is not a path separator");
    }
    if decoded.chars().any(char::is_control) {
        return Err("a path cannot contain a control character");
    }
    let inside = decoded.strip_prefix("/~/").unwrap_or(decoded);
    let segments: Vec<&str> = inside.split('/').collect();
    let last = segments.len().saturating_sub(1);
    for (i, segment) in segments.iter().enumerate() {
        if *segment == "." || *segment == ".." {
            return Err("a path cannot contain a dot segment");
        }
        if segment.is_empty() && i != last {
            return Err("a path cannot contain an empty segment");
        }
    }
    if NamedNode::new(format!("{base}{decoded}")).is_err() {
        return Err("a path must be a valid IRI reference");
    }
    Ok(())
}

/// Does the pod have room for `incoming` more bytes under its quota?
///
/// The quota is the member's: an admin's override if one is set, else the
/// instance default — `User::quota` decides, and the row is the one every
/// write handler already loaded, so this costs no query. Measured, not
/// tracked: the pod's directory on disk — store and blobs together — is
/// the one number that cannot drift from what the member actually holds,
/// and a write that frees space makes room again without bookkeeping.
/// Conservative on a replace: the incoming bytes count in full even where
/// they displace old ones.
///
/// Fails open. A pod whose size cannot be read is an operational fault to
/// log loudly, not a reason to refuse a member their own write — the quota
/// bounds what one grant can cost the instance; it is not the thing that
/// keeps the instance up.
pub(crate) fn within_quota(state: &AppState, user: &User, incoming: usize) -> bool {
    match state.stores.pod_bytes(user.id) {
        Ok(used) => used.saturating_add(incoming as u64) <= user.quota(state.pod_quota_bytes),
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "could not measure the pod for its quota");
            true
        }
    }
}

/// 507 (RFC 4918 §11.5): the server cannot store the representation. The
/// one status whose meaning is exactly this, and one a WebDAV-aware Solid
/// client already knows.
fn quota_exceeded() -> Response {
    (StatusCode::INSUFFICIENT_STORAGE, "the pod is at its quota").into_response()
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
    ///
    /// `pub(crate)` because the profile page degrades an unverifiable caller
    /// to it for its depiction check (spec 4, H6): the page itself is public
    /// and stays public, so a credential that does not verify is checked as
    /// the anonymous caller it effectively is rather than failing the page.
    pub(crate) fn anonymous() -> Caller {
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
/// **Only an `Authorization` header gets here.** A `__Host-brolly_session`
/// cookie is `SameSite=Lax` (`auth::tests::the_session_cookie_is_hardened`),
/// so a browser sends it on any top-level navigation: a logged-out member
/// opening a public image in their own pod never offered it, and meeting them
/// with a challenge for a credential they did not present would be wrong. A
/// cookie that doesn't resolve falls through to [`Caller::anonymous`] and H1
/// decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The token: a header we couldn't parse, or a token that is unknown,
    /// expired, revoked, or carries a WebID this instance doesn't host — or a
    /// foreign issuer's token the remote path refused, for any of its causes
    /// (spec 6, H5). RFC 6750 §3.1's `invalid_token`.
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
    let session = crate::auth::session_token(headers);

    let Some(credential) = extract::credential(authorization, session) else {
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
            // its holder, and a token with no binding is refused rather than
            // downgraded to bearer semantics — our key also signs ID tokens,
            // which name the same WebID and go to every relying party.
            //
            // The claims arrive `Unspent`. Spending records the proof so it
            // can't be sent again.
            let proof = (!proof.is_empty()).then_some(proof);
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            // The issuer split (spec 6, H5): a token whose `iss` names another
            // Solid-OIDC issuer takes the remote path — its key is not ours,
            // so there is nothing here to verify it with until the issuer's
            // own discovery document and key set have been fetched. Our own
            // tokens — and a malformed or `iss`-less one — stay on today's
            // path, unchanged.
            if let Some(iss) =
                tokens::foreign_issuer(&token, &format!("https://{}", state.base_domain))
            {
                return remote_solid_subject(
                    state,
                    &iss,
                    &token,
                    proof.as_deref(),
                    method.as_str(),
                    url,
                    now,
                )
                .await;
            }
            let claims = match tokens::verify_access(
                &state.provider_key,
                &token,
                proof.as_deref(),
                method.as_str(),
                url,
                now,
            ) {
                Ok(unspent) => match unspent.spend(&state.pool, now).await {
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
/// The fast path, for tokens our own issuer minted: the WebID must be one
/// this instance hosts and an active member. A foreign issuer's tokens take
/// [`remote_solid_subject`]. A failure to look the member up is ours (H2).
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

// --- the remote path (spec 6, H5) ---------------------------------------------
//
// A token another Solid-OIDC issuer signed: verified against that issuer's
// own key set, and trusted for the WebID it names only once the WebID's own
// document says the issuer may speak for it. Without the binding, anyone who
// can serve HTTPS can publish a discovery document and a key set, and every
// ACL grant to any WebID becomes redeemable by whoever stands up an endpoint.

/// The `iss` claim as an HTTPS origin (spec 6, H5): scheme, host, optional
/// port, and no path, query, fragment, or userinfo.
///
/// The ecosystem's issuers are origins, and the two discovery conventions —
/// OIDC's append, RFC 8414's insert-between-host-and-path — disagree on where
/// the well-known goes for a path-bearing issuer, so a path-bearing `iss` is a
/// malformed token rather than a fetch to guess at.
fn issuer_origin(iss: &str) -> Option<Url> {
    let url = Url::parse(iss).ok()?;
    if url.scheme() != "https"
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(url)
}

/// The same mapping the fast path gives a token error (spec 6, H5): a JWT
/// failure is the token's, the rest say the proof was not good enough for it.
fn remote_refusal(error: tokens::TokenError) -> Refused {
    match error {
        tokens::TokenError::Jwt(_) => Refused::Token,
        _ => Refused::Proof,
    }
}

/// The remote half of the Solid branch (spec 6, H5): a token another
/// Solid-OIDC issuer signed.
///
/// Every failure on the path is the same answer — 401 `invalid_token` —
/// without distinguishing a fetch failure from a bad signature from an
/// unbound WebID, because the resource server is not an oracle for which
/// foreign issuers are up or which WebIDs exist. The one exception is the
/// proof, which runs exactly as it does on the fast path: a failure there is
/// `invalid_dpop_proof`, so a client with a good token signs a fresh proof
/// instead of refreshing.
///
/// A token naming a *local* WebID is refused by the binding, full stop: our
/// profiles publish exactly one `solid:oidcIssuer` — this instance's apex —
/// and H1 makes that triple server-authoritative, so no foreign issuer can
/// ever be authoritative for a WebID this instance hosts. There is no local
/// special case to preserve the member's activity check — the binding already
/// closes that gate, and WAC, the only thing the pod surface consults, never
/// wanted the local user anyway.
async fn remote_solid_subject(
    state: &AppState,
    iss: &str,
    token: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
    now: i64,
) -> Result<Caller, Refused> {
    // 1. The issuer must be an HTTPS origin, before any fetch (H5).
    let Some(origin) = issuer_origin(iss) else {
        tracing::debug!(iss, "a foreign issuer is not an HTTPS origin");
        return Err(Refused::Token);
    };

    // 2. The issuer's discovery document, cached per issuer (H5). Its
    //    `issuer` must be the `iss` claim — discovery cannot be used to
    //    launder one issuer for another.
    let Ok(well_known) = origin.join(".well-known/openid-configuration") else {
        tracing::debug!(iss, "the well-known URL would not build");
        return Err(Refused::Token);
    };
    let discovery = match state.issuer_discovery.fetch(&well_known).await {
        Ok(discovery) if discovery.issuer == iss => discovery,
        _ => {
            tracing::debug!(iss, "a foreign issuer's discovery did not name it");
            return Err(Refused::Token);
        }
    };

    // 3. The issuer's key set, fetched from the `jwks_uri` the discovery
    //    document names, same transport rules, cached per issuer (H5).
    let Ok(jwks_uri) = Url::parse(&discovery.jwks_uri) else {
        tracing::debug!(iss, "a foreign issuer's jwks_uri is not a URL");
        return Err(Refused::Token);
    };
    let verify = |jwks: &tokens::RemoteJwks| {
        tokens::verify_remote_access(jwks, token, proof, method, url, now)
    };
    let unspent = match state.issuer_jwks.fetch(&jwks_uri).await {
        // 4 and 5. The signature — ES256 only, the key chosen by the token's
        //          `kid` — `aud`, `exp`, and the required `cnf.jkt`, then the
        //          proof, which runs exactly as today.
        Ok(jwks) => match verify(&jwks) {
            Ok(unspent) => unspent,
            // An unknown `kid` is what a rotation looks like from the
            // outside: exactly one re-fetch, then refuse (H5).
            Err(tokens::TokenError::Jwt(keys::JwtError::UnknownKey(_))) => {
                match state.issuer_jwks.refetch(&jwks_uri).await {
                    Ok(fresh) => verify(&fresh).map_err(|e| {
                        tracing::debug!(error = %e, "a foreign access token was rejected");
                        remote_refusal(e)
                    })?,
                    Err(_) => {
                        tracing::debug!(iss, "a foreign issuer's key set could not be re-fetched");
                        return Err(Refused::Token);
                    }
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "a foreign access token was rejected");
                return Err(remote_refusal(e));
            }
        },
        Err(_) => {
            tracing::debug!(iss, "a foreign issuer's key set could not be fetched");
            return Err(Refused::Token);
        }
    };

    // The jti spend, exactly as the fast path spends it — before the gates
    // that follow, as it does there: a captured proof cannot be retried until
    // one attempt works (RFC 9449).
    let claims = match unspent.spend(&state.pool, now).await {
        Ok(claims) => claims,
        Err(DpopError::Storage(e)) => {
            tracing::error!(error = %e, "recording a DPoP proof failed");
            return Err(Refused::Unavailable);
        }
        Err(e) => {
            tracing::warn!(error = %e, "Solid access token proof refused");
            return Err(Refused::Proof);
        }
    };

    // 6. Bind the WebID to the issuer (H5): dereference the token's `webid`
    //    and require the `iss` among the document's `solid:oidcIssuer`
    //    values — the WebID's own assertion, read from the WebID.
    let bound = match Url::parse(&claims.webid) {
        Ok(webid) => match state.webid_documents.fetch(&webid).await {
            Ok(document) => document.names(iss),
            Err(_) => false,
        },
        Err(_) => false,
    };
    if !bound {
        tracing::debug!(iss, "a WebID does not name this issuer");
        return Err(Refused::Token);
    }

    // 7. The remote subject (H5): the WebID as the authenticated agent, and
    //    no local user — the shape `Subject::remote` exists for.
    Ok(Caller::verified(Subject::remote(
        claims.webid,
        Scope::parse(&claims.scope),
        Via::SolidDpop,
    )))
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
///
/// The profile's writes answer from the same table (spec 6, H1): its owner
/// check is an authorization decision, and `Denied` is the same refusal.
pub(crate) fn ldp_error(error: LdpError, authenticated: bool, apex: &str) -> Response {
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
        // §5.4 and §4.2.1 both require the body, not just the status: a client
        // that gets a bare 409 has nothing to act on. The body is the error's
        // own `Display`, so the two have one source.
        error @ (LdpError::NotEmpty | LdpError::MemberMetadata) => {
            (StatusCode::CONFLICT, error.to_string()).into_response()
        }
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
        // 415 with the list in the body (spec 4, H2): the type is syntactically
        // fine, this server just doesn't store it as media, and the body is
        // the error's own Display so the list has one source. Produced after
        // the WAC check, so only a caller who may write learns the list.
        error @ LdpError::ContentTypeNotAllowed(_) => {
            (StatusCode::UNSUPPORTED_MEDIA_TYPE, error.to_string()).into_response()
        }
        // 422, not 415 or 409 (spec 5c, H8): the request is well-formed and
        // the media type is one this server stores, just not over a resource
        // of the other kind, and no other request is in the way. The body is
        // the error's own `Display`, which names the recorded kind and the
        // incoming content type, so a client knows which of the two to change.
        error @ LdpError::KindChange { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response()
        }
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
        // `post` answers this itself, with the target's `Allow`: RFC 9110
        // §15.5.6 requires one on a 405, and it depends on modes this function
        // can't see. Nothing else produces it, so reaching here means a new
        // producer that needs the same treatment.
        LdpError::NotAPostTarget => {
            tracing::error!("NotAPostTarget reached ldp_error; its caller must build the 405");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        // The body names the slug and the rule (spec 5c H1): a client that
        // asked for a name it can't have needs to know which and why, not
        // just that it can't.
        LdpError::InvalidSlug(rule) => (StatusCode::BAD_REQUEST, rule).into_response(),
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

/// A 405 for a POST to a document-shaped target (spec 5c, H3): POST is a
/// container method, and the append it used to perform is a `PATCH` with
/// `INSERT`.
///
/// Only reached after `ldp` has authorized the POST, so a caller with no mode
/// at all got 401 or 403 before `NotAPostTarget` could be returned, and the
/// `Allow` here — from the same builder `OPTIONS` uses, whose `POST` line is
/// the same container-shape rule — tells the caller nothing an `OPTIONS`
/// wouldn't, and cannot disagree with it.
fn refuse_post(request: &PodRequest, path: &str) -> Response {
    let description = match ldp::describe(&request.pod, &request.base, path, &request.subject) {
        Ok(description) => description,
        Err(e) => return ldp_error(e, request.authenticated, &request.apex),
    };
    let resource = format!("{}{path}", request.base);
    let allow = allowed(&description, &resource, &request.storage_root).join(", ");
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, allow)],
        "POST is a container method; POST to this resource is not supported",
    )
        .into_response()
}

/// Does this request's `Link` headers ask for a container member (spec 5c,
/// H2)?
///
/// Parsed per RFC 8288: several `Link` fields, comma-separated values within
/// one, quoted parameter values, and a `rel` that is itself a
/// space-separated token list. The type target must match `ldp:BasicContainer`
/// or `ldp:Container` **exactly** — never by substring — and only a `rel`
/// token that is `type` decides anything. Any other type target is ignored:
/// the body's content type decides document vs binary, because that is the
/// one creation fact a body *can* express.
fn link_requests_container(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            split_link_value(value, ',')
                .iter()
                .any(|field| field_names_container(field))
        })
}

/// One comma-separated `Link` value: does it name a container type?
fn field_names_container(field: &str) -> bool {
    let mut params = split_link_value(field, ';').into_iter();
    let Some(target) = params.next().and_then(|p| link_target(p)) else {
        return false;
    };
    if target != vocab::LDP_BASIC_CONTAINER && target != vocab::LDP_CONTAINER {
        return false;
    }
    params.any(|param| {
        let mut name_value = param.splitn(2, '=');
        if !name_value
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("rel")
        {
            return false;
        }
        match name_value.next() {
            // `rel="type"` or `rel="alternate type"`: a token list, quoted
            // or bare, case-insensitive (RFC 8288 §3).
            Some(value) => unquote(value)
                .split_whitespace()
                .any(|token| token.eq_ignore_ascii_case("type")),
            None => false,
        }
    })
}

/// The `<iri>` at the head of a `Link` field, if there is one.
fn link_target(param: &str) -> Option<&str> {
    let param = param.trim();
    param.strip_prefix('<')?.strip_suffix('>')
}

/// Strip one pair of surrounding double quotes, if the value carries them.
fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Split a `Link` value on `sep`, outside a `<...>` target or a `"..."`
/// quoted parameter (RFC 8288's `link-value` grammar: a URI-Reference may
/// carry separators, and a quoted string may carry anything).
fn split_link_value(value: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_target = false;
    let mut in_quotes = false;
    for (i, b) in value.char_indices() {
        match b {
            '<' => in_target = true,
            '>' => in_target = false,
            '"' => in_quotes = !in_quotes,
            c if c == sep && !in_target && !in_quotes => {
                parts.push(&value[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// One `WAC-Allow` field value (WAC §6.1).
///
/// `granted` is the caller's effective modes; `public` is a second
/// `granted_modes` probe with an anonymous subject, run by `ldp` **inside the
/// read's snapshot** so both components describe the same ACL — a builder out
/// here would be working after `Pod::read` closed it.
///
/// Both groups are always spelled, empty or not: §6.1's ABNF allows an empty
/// group, and a client has to be able to tell "not public" from "the server
/// didn't say". On an `.acl`, `granted_modes` is all-or-nothing on Control
/// (`ldp.rs`), so `public=` there is empty unless the ACL grants Control to
/// everyone.
fn wac_allow(granted: &[AccessMode], public: &[AccessMode]) -> String {
    format!(
        "user=\"{}\", public=\"{}\"",
        mode_names(granted),
        mode_names(public)
    )
}

fn mode_names(modes: &[AccessMode]) -> String {
    modes
        .iter()
        .map(|m| match m {
            AccessMode::Read => "read",
            AccessMode::Write => "write",
            AccessMode::Append => "append",
            AccessMode::Control => "control",
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// What [`patch`] matches on, and so what `Accept-Patch` advertises. A third
/// syntax here would advertise a 415.
const ACCEPT_PATCH: &str = "text/n3, application/sparql-update";

/// H4: the methods this caller may use on this target, in a fixed order.
///
/// Computed from the caller's modes, whether the target exists, and — for
/// `POST` alone — the target's shape: POST is a container method (spec 5c,
/// H3), offered iff the target IRI ends in `/` and the caller holds
/// Append-or-Write on it. Existence is irrelevant, the same way it is for
/// `PUT` and `PATCH`, the other creation methods: a missing container-shaped
/// target is POSTable, and its intermediate containers are auto-created on
/// the way in.
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
    if storage::is_container(resource) && (write || description.holds(AccessMode::Append)) {
        methods.push("POST");
    }
    // H5: insert-only patches are an Append operation, so an Append-only
    // caller is offered PATCH — and `Accept-Patch` with it, since each
    // `Accept-*` follows its method. A deleting patch still needs Write, and
    // `ldp::patch_in` says so.
    if write || description.holds(AccessMode::Append) {
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
/// for `/~/new/` whether or not `/~/new/` exists yet. A `.meta` joins the
/// `.acl` targets (spec 5d, H4), so its `Accept-Put` advertises the RDF types.
fn accept_put(resource: &str) -> &'static str {
    if storage::is_container(resource) || ldp::is_auxiliary(resource) {
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

/// H6's `Link` set: what this resource is, where its rules and its
/// description are, which storage it belongs to, and — on the root — whose it
/// is.
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
/// kind of thing would be. The `acl`, `describedby` and `storageDescription`
/// links still go: all three exist whether or not the target does, and the
/// ACL and description links are what a client needs to *create* the rules
/// and the description for what it is about to write.
///
/// The auxiliary links (spec 5d, H3):
///
/// - `describedby` points at `meta_iri(resource)`, on every non-auxiliary
///   resource, always sent, exists or not — the same contract as `acl`.
///   Omitted on auxiliaries: their described target is the subject,
///   announced there.
/// - A `.meta` sends `describes` (RFC 6892) pointing at its subject, and its
///   `acl` points at the *subject's* `acl_iri` — the ACL that actually
///   governs it under H2, where `acl_iri` on the `.meta` itself would name
///   `x.meta.acl`, a double-suffix fiction H1 answers 404. (An `.acl`'s own
///   `acl` link stays itself, 5b H7.)
fn links(
    base: &str,
    resource: &str,
    storage_root: &str,
    owner: &str,
    kind: Option<Kind>,
) -> String {
    let is_root = resource == storage_root;
    let subject = ldp::describes(resource);
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
            // An `.acl` and a `.meta` are RDF sources like any other document:
            // LDP names no auxiliary class, and inventing one would be ours
            // alone.
            Kind::RdfSource | Kind::Auxiliary => types.push(vocab::LDP_RDF_SOURCE),
        }
        if is_root {
            // Solid Protocol §4.1: the storage MUST say so on its own URI.
            types.push(vocab::PIM_STORAGE);
        }
        values.extend(types.into_iter().map(|t| format!("<{t}>; rel=\"type\"")));
    }

    // H3 (spec 5d): a `.meta` is governed by its subject's rule, so the
    // subject's ACL is the IRI to advertise.
    let acl_target = match subject {
        Some(subject) => ldp::acl_iri(subject),
        None => ldp::acl_iri(resource),
    };
    values.push(format!("<{acl_target}>; rel=\"acl\""));
    if let Some(subject) = subject {
        values.push(format!("<{subject}>; rel=\"{}\"", vocab::DESCRIBES));
    } else if !ldp::is_auxiliary(resource) {
        values.push(format!(
            "<{}>; rel=\"{}\"",
            ldp::meta_iri(resource),
            vocab::DESCRIBEDBY
        ));
    }
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
/// resource and the caller: H4's `Allow`, H5's `Accept-*`, H6's `Link` and
/// H9's `WAC-Allow`.
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
    out.push((
        header::HeaderName::from_static("wac-allow"),
        wac_allow(&description.granted, &description.public),
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

/// The request's `Content-Type`, or `None` for Solid §2.1's 400
/// ([`missing_content_type`]).
///
/// `empty_is_rdf` is true for `PUT` and `POST`, where a body with no bytes is
/// an empty RDF document — the way a client creates an empty resource (5a), and
/// the one case `ldp::prepare` still needs a default for. It is false for
/// `PATCH`: there is no empty patch, so a PATCH with no type is refused
/// whatever its length.
///
/// Checked after `resolve`, so a caller whose credential doesn't verify still
/// gets the 401 CTS expects on every method, rather than a 400 for a header
/// they forgot. A header that isn't valid UTF-8 is treated as absent: it can't
/// name a media type we parse, and a 415 for it would send the client guessing.
pub(crate) fn content_type<'h>(
    headers: &'h HeaderMap,
    body: &[u8],
    empty_is_rdf: bool,
) -> Option<&'h str> {
    match headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
    {
        Some(value) => Some(value),
        None if empty_is_rdf && body.is_empty() => Some("text/turtle"),
        None => None,
    }
}

/// Solid §2.1's 400, naming the header that was missing.
pub(crate) fn missing_content_type() -> Response {
    (
        StatusCode::BAD_REQUEST,
        "a request with a body needs a Content-Type header (Solid Protocol §2.1)",
    )
        .into_response()
}

/// A PATCH body by its content type (5c, H7): `text/n3` is an N3 Patch,
/// `application/sparql-update` a SPARQL Update, and anything else is a 415
/// naming what a PATCH takes.
///
/// One builder for every PATCH handler — the pod's and the profile's (spec 6,
/// H1) — so the two surfaces refuse identically.
#[allow(clippy::result_large_err)] // a `Response` is the refusal; boxing it would tax every caller
pub(crate) fn patch_body<'b>(
    content_type: &str,
    body: &'b [u8],
) -> Result<ldp::PatchBody<'b>, Response> {
    match content_type.split(';').next().unwrap_or_default().trim() {
        "text/n3" => Ok(ldp::PatchBody::N3(body)),
        "application/sparql-update" => match std::str::from_utf8(body) {
            Ok(sparql) => Ok(ldp::PatchBody::SparqlUpdate(sparql)),
            Err(_) => Err((StatusCode::BAD_REQUEST, "body is not UTF-8").into_response()),
        },
        other => Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("PATCH accepts text/n3 or application/sparql-update, not {other}"),
        )
            .into_response()),
    }
}

/// A [`PatchError`] into a response, shared by every PATCH handler — the pod's
/// and the profile's (spec 6, H1) — so a 409 or a 403 cannot mean two things on
/// two surfaces.
pub(crate) fn patch_error(error: patch::PatchError, authenticated: bool, apex: &str) -> Response {
    match error {
        patch::PatchError::Ldp(e) => ldp_error(e, authenticated, apex),
        patch::PatchError::Precondition(m) => (StatusCode::CONFLICT, m).into_response(),
        patch::PatchError::NotCurrent => {
            (StatusCode::PRECONDITION_FAILED, "precondition failed").into_response()
        }
        patch::PatchError::EscapesGraph => (
            StatusCode::FORBIDDEN,
            "a PATCH may only insert or delete in the resource it addresses",
        )
            .into_response(),
        patch::PatchError::Malformed(m) | patch::PatchError::NotAPatch(m) => {
            (StatusCode::BAD_REQUEST, m).into_response()
        }
        e => {
            tracing::error!(error = %e, "patch failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `GET /~/*path`, and `HEAD`, which axum routes here without the body.
///
/// Sends `ETag` — the resource's version and the representation's syntax,
/// `"{version}.{syntax}"` — and `Last-Modified`, and answers 304 to an
/// `If-None-Match` naming the representation it would have sent. A tag for
/// another syntax is a full response (H10). Only here: a write's response
/// carries no `ETag`, because the server transforms what it stores
/// (RFC 9110 §9.3.4).
pub async fn get(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri, &path).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());

    let mut outcome = match ldp::read(
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
    let resource = format!("{}{path}", request.base);

    // After `read` succeeded, so after the Read check, and against the version
    // and syntax from the same snapshot and negotiation as the body. A caller
    // without Read was refused above, 401 or 403, whatever they sent.
    if preconditions(&headers).not_modified(&outcome.version, outcome.syntax) {
        let mut response = (
            StatusCode::NOT_MODIFIED,
            axum::body::Body::new(NotModifiedBody),
        )
            .into_response();
        read_headers(&mut response, &request, &resource, &outcome);
        return response;
    }

    // Taken rather than cloned: `read_headers` borrows the outcome, and a pod
    // read can be megabytes.
    let body = std::mem::take(&mut outcome.body);
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, outcome.media_type.clone())],
        body,
    )
        .into_response();
    read_headers(&mut response, &request, &resource, &outcome);
    response
}

/// The body of a 304: nothing, with its size deliberately left unstated.
///
/// RFC 9110 §8.6: a server MUST NOT send `Content-Length` on a 304 unless it
/// equals the length the 200 would have had. Axum stamps `Content-Length` on
/// every top-level response whose body reports an *exact* size before it
/// leaves the router, so an ordinary empty body goes out as
/// `content-length: 0` — telling a cache that revalidates to overwrite the
/// length it stored with zero. This body reports no exact size, so axum adds
/// nothing, and it reports itself finished, so hyper treats it as empty and
/// writes no length and no chunked encoding either (a 304 can't have a body).
struct NotModifiedBody;

impl http_body::Body for NotModifiedBody {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }

    // The default, spelled out because it is the point: a lower bound of zero
    // and no upper bound is not `exact()`, so axum leaves `Content-Length`
    // alone.
    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::default()
    }
}

/// Everything a `GET` or `HEAD` answers with **except** the representation:
/// no `Content-Type`, no body.
///
/// The 200 and the 304 share it, so the two differ in exactly the status and
/// the representation metadata. RFC 9110 §15.4.5 requires `ETag` and `Vary`
/// on a 304; the rest is control and resource metadata — `Allow`, `Accept-*`,
/// `WAC-Allow`, `Link` — which its SHOULD NOT does not cover, and a client
/// that revalidates must not lose the affordances it had.
///
/// `Last-Modified` *is* a deviation: §15.4.5 excuses cache-guiding metadata
/// only "if the response does not have an ETag field", and ours does. We send
/// it anyway, for the same reason. `Content-Location`, `Cache-Control` and
/// `Expires` are absent because a 200 from this server doesn't send them
/// either.
fn read_headers(
    response: &mut Response,
    request: &PodRequest,
    resource: &str,
    outcome: &LdpOutcome,
) {
    // H4–H6 and H9: the same builder `OPTIONS` uses, over the description
    // `read` took from the body's own snapshot.
    apply(
        response,
        headers_for(request, resource, &outcome.description),
    );

    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&conditional::etag(&outcome.version, outcome.syntax)) {
        headers.insert(header::ETAG, value);
    }
    // Omitted rather than wrong if the stored time isn't one we can render.
    if let Some(date) = conditional::http_date(&outcome.modified)
        && let Ok(value) = HeaderValue::from_str(&date)
    {
        headers.insert(header::LAST_MODIFIED, value);
    }
    // Appended, never inserted: the CORS layer is outermost and adds `Origin`
    // to this same field (H10, H14). A binary is not negotiated — its bytes
    // are the same for every `Accept` — so claiming it varies would fragment
    // a cache for nothing.
    if outcome.syntax != conditional::BINARY {
        headers.append(header::VARY, HeaderValue::from_static("Accept"));
    }
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
    let request = match resolve(&state, &headers, &method, &uri, &path).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    // The quota, before the body is parsed or a lock is taken: a write the
    // pod has no room for is refused as cheaply as a 404.
    if !within_quota(&state, &request.user, body.len()) {
        return quota_exceeded();
    }
    let Some(content_type) = content_type(&headers, &body, true) else {
        return missing_content_type();
    };

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
        // LDP's rule, and what every Solid client branches on. The `Link` set
        // is H6's, from the same helper a GET uses, so a client that creates a
        // resource learns its kind without a second request.
        Ok(ldp::Written::Created) => {
            let resource = format!("{}{path}", request.base);
            let mut response =
                (StatusCode::CREATED, [(header::LOCATION, resource.clone())]).into_response();
            // A description that fails to read doesn't undo the write: the 201
            // and its `Location` still go out.
            if let Ok(description) =
                ldp::describe(&request.pod, &request.base, &path, &request.subject)
            {
                apply(
                    &mut response,
                    vec![(
                        header::LINK,
                        links(
                            &request.base,
                            &resource,
                            &request.storage_root,
                            &request.webid,
                            description.kind(),
                        ),
                    )],
                );
            }
            response
        }
        Ok(ldp::Written::Replaced) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ldp_error(e, request.authenticated, &request.apex),
    }
}

/// `POST /~/*path` — create a member of a container (spec 5c, H1–H4).
///
/// `Slug` names the member when it can be made one safe segment; `Link
/// rel="type"` naming an LDP container class asks for a container. A
/// document-shaped target is a 405 with the target's own `Allow`. The 201
/// carries the same `Link` set a creating `PUT` sends, so a client that just
/// made a container learns its kind and its ACL IRI in the response that
/// minted it.
pub async fn post(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, &method, &uri, &path).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    // The quota, before the body is parsed or a lock is taken: a write the
    // pod has no room for is refused as cheaply as a 404.
    if !within_quota(&state, &request.user, body.len()) {
        return quota_exceeded();
    }
    let Some(content_type) = content_type(&headers, &body, true) else {
        return missing_content_type();
    };
    // Read before the write; `append_in` refuses a document-shaped target
    // (H3) before it validates either, so an unpostable target is refused
    // whatever the headers say.
    let slug = headers.get("slug").and_then(|value| value.to_str().ok());
    let requested = if link_requests_container(&headers) {
        ldp::RequestedKind::Container
    } else {
        ldp::RequestedKind::Auto
    };

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
        slug,
        requested,
    ) {
        Ok(ldp::Minted { member, kind }) => {
            let mut response =
                (StatusCode::CREATED, [(header::LOCATION, member.clone())]).into_response();
            // H4: the same `Link` set a creating `PUT` sends (5b H6), so the
            // client learns what it made and where its rules are without a
            // second request. A `links` that fails to build doesn't undo the
            // write: the 201 and its `Location` still go out.
            apply(
                &mut response,
                vec![(
                    header::LINK,
                    links(
                        &request.base,
                        &member,
                        &request.storage_root,
                        &request.webid,
                        Some(kind),
                    ),
                )],
            );
            response
        }
        // H3: `append_in` already ran the WAC check, so a caller with no mode
        // saw 401 or 403 before this. The `Allow` is the same builder `OPTIONS`
        // uses, and its `POST` line follows the same container-shape rule.
        Err(LdpError::NotAPostTarget) => refuse_post(&request, &path),
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
    let request = match resolve(&state, &headers, &method, &uri, &path).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    // The quota, before the body is parsed or a lock is taken: a write the
    // pod has no room for is refused as cheaply as a 404.
    if !within_quota(&state, &request.user, body.len()) {
        return quota_exceeded();
    }
    let Some(content_type) = content_type(&headers, &body, false) else {
        return missing_content_type();
    };

    let patch_body = match patch_body(content_type, &body) {
        Ok(body) => body,
        Err(response) => return response,
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
        // H4: creation and modification are not indistinguishable on the
        // wire. The `Link` set is the same one a creating `PUT` sends, so a
        // client that just made a resource learns its kind and where its
        // rules are without a second request. A description that fails to
        // read doesn't undo the write: the 201 and its `Location` still go
        // out.
        Ok(ldp::Written::Created) => {
            let resource = format!("{}{path}", request.base);
            let mut response =
                (StatusCode::CREATED, [(header::LOCATION, resource.clone())]).into_response();
            if let Ok(description) =
                ldp::describe(&request.pod, &request.base, &path, &request.subject)
            {
                apply(
                    &mut response,
                    vec![(
                        header::LINK,
                        links(
                            &request.base,
                            &resource,
                            &request.storage_root,
                            &request.webid,
                            description.kind(),
                        ),
                    )],
                );
            }
            response
        }
        Ok(ldp::Written::Replaced) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => patch_error(e, request.authenticated, &request.apex),
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
    let request = match resolve(&state, &headers, &method, &uri, &path).await {
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
    let request = match resolve(&state, &headers, &method, &uri, &path).await {
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
    // What the caller may *do* here is H4's answer; whether anything is
    // *there* is Read's to tell. The `rel="type"` links go out only for a
    // target that exists, so to a caller without Read — the inbox's
    // Append-only poster — the target is described as if absent: the same
    // `Link` set, the same `Allow`, whether or not something is at the path.
    // Nothing else in the headers depends on existence for such a caller:
    // GET and HEAD need Read, DELETE needs Write, and the creation methods
    // are offered whether or not the target exists.
    let description = if description.holds(AccessMode::Read) {
        description
    } else {
        Description {
            meta: None,
            granted: description.granted,
            public: description.public,
        }
    };
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
///
/// The bare storage prefix, `/~`, is the one trailing-slash redirect there is
/// (spec 5c, H9): it names no resource, so sending it to `/~/` merges nothing.
/// Inside storage, `/foo` and `/foo/` stay two distinct resources with no
/// redirect in either direction. They are distinct IRIs; the storage layer,
/// the ACL placement (`ldp::acl_iri`) and 5a's kind rules already treat them
/// so; and both may exist at once — a document and a container — so a
/// redirect would make two resources one.
pub async fn subdomain_fallback(State(state): State<AppState>, uri: axum::http::Uri) -> Response {
    let path = uri.path();
    match subdomain_route(path) {
        SubdomainRoute::UserStorage => {
            // Every method under `/~/` is routed, and a method axum doesn't
            // route there gets axum's own 405, which carries its own `Allow`.
            // So this arm serves the bare `/~` alone: the storage prefix
            // without its slash, which no route matches. Every method on it
            // is sent to `/~/` (spec 5c, H9). 308 and not 301: RFC 9110
            // §15.4.9 has the client repeat the method and the body, where a
            // 301 lets an over-helpful one turn `PUT /~` into `GET /~/`
            // (§15.4.2). The query goes along, or the redirect would name a
            // different request. A browser doesn't follow a redirect that
            // answers a CORS preflight, so a preflighted script aimed at `/~`
            // fails as it did under the 405 this replaces; the redirect is
            // for the clients that do follow.
            let location = match uri.query() {
                Some(query) => format!("{}?{query}", routing::USER_STORAGE_ROOT),
                None => routing::USER_STORAGE_ROOT.to_string(),
            };
            (
                StatusCode::PERMANENT_REDIRECT,
                [(header::LOCATION, location)],
                "user storage lives under /~/",
            )
                .into_response()
        }
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

    /// H8 (spec 5c): a kind-changing `PUT` is a 422 whose body names the
    /// recorded kind and the incoming content type — the two facts a client
    /// needs to see which one it got wrong.
    #[test]
    fn a_kind_change_is_a_422_naming_the_kind_and_the_content_type() {
        let response = ldp_error(
            LdpError::KindChange {
                recorded: Kind::NonRdfSource,
                incoming: "text/turtle".into(),
            },
            true,
            "https://brolly.test",
        );
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_text(response);
        assert!(body.contains("ldp:NonRDFSource"), "{body}");
        assert!(body.contains("text/turtle"), "{body}");
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
    /// (RFC 9110 §15.5.6).
    #[test]
    fn undeletable_is_built_by_delete_not_by_ldp_error() {
        assert_eq!(
            ldp_error(LdpError::Undeletable, true, "https://brolly.test").status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// §5.4 and §4.2.1 require the status *and* a body describing the error,
    /// so a client can tell "empty it first" or "re-read and retry" from "you
    /// may not". A 403 said the last of those, which was never true.
    #[test]
    fn a_populated_container_and_changed_member_metadata_are_409s_with_a_body() {
        for (error, section) in [
            (LdpError::NotEmpty, "Solid Protocol §5.4"),
            (LdpError::MemberMetadata, "Solid Protocol §4.2.1"),
        ] {
            let said = error.to_string();
            let response = ldp_error(error, true, "https://brolly.test");
            assert_eq!(response.status(), StatusCode::CONFLICT, "{section}");
            let body = body_text(response);
            assert_eq!(body, said, "{section}: the body is the error's own text");
        }
    }

    /// A response's body, which these tests build in memory and never stream.
    fn body_text(response: Response) -> String {
        let bytes = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
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

    /// H4's table, row by row. What this guards is a method promised to a
    /// caller whose mode `ldp` will refuse it for. POST is a container method
    /// (spec 5c, H3) and PATCH an Append operation (H5), so the document rows
    /// and the container rows disagree on purpose.
    #[test]
    fn allow_names_only_what_the_modes_permit() {
        let doc = Some(Kind::RdfSource);
        let container = Some(Kind::Container);
        assert_eq!(
            allow_line(doc, &ALL, DOC),
            "GET, HEAD, PUT, PATCH, DELETE, OPTIONS"
        );
        assert_eq!(allow_line(doc, &[Read], DOC), "GET, HEAD, OPTIONS");
        // An Append-only caller may insert (H5), but not POST into — nor
        // PUT, replace, or delete — a document.
        assert_eq!(allow_line(doc, &[Append], DOC), "PATCH, OPTIONS");
        assert_eq!(
            allow_line(doc, &[Read, Append], DOC),
            "GET, HEAD, PATCH, OPTIONS"
        );
        // POST is offered on the container's shape, whatever the caller holds
        // beyond the Append that creating in it needs.
        assert_eq!(
            allow_line(container, &ALL, &format!("{ROOT}notes/")),
            "GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS"
        );
        assert_eq!(
            allow_line(container, &[Append], &format!("{ROOT}notes/")),
            "POST, PATCH, OPTIONS"
        );
        // Control governs the resource's ACL, not the resource.
        assert_eq!(allow_line(doc, &[Control], DOC), "OPTIONS");
    }

    /// Nothing there: what a creation could do. `GET` would 404 and `DELETE`
    /// would 404, and there is no container to `POST` into.
    #[test]
    fn an_absent_target_is_offered_creation_and_not_reading() {
        assert_eq!(allow_line(None, &ALL, DOC), "PUT, PATCH, OPTIONS");
        // A creating, insert-only PATCH is an Append operation (H5), so an
        // Append holder is offered the creation method it may use.
        assert_eq!(allow_line(None, &[Read, Append], DOC), "PATCH, OPTIONS");
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
        let container = Some(Kind::Container);

        // A document takes PATCH and PUT, and never POST (spec 5c, H3: POST is
        // a container method).
        let full = affordances(&described(doc, &ALL), DOC, ROOT);
        assert_eq!(value_of(&full, "accept-patch"), Some(ACCEPT_PATCH));
        assert_eq!(value_of(&full, "accept-post"), None);
        assert_eq!(value_of(&full, "accept-put"), Some("*/*"));

        // A container takes all three write methods.
        let full_container =
            affordances(&described(container, &ALL), &format!("{ROOT}notes/"), ROOT);
        assert_eq!(
            value_of(&full_container, "accept-post"),
            Some(ldp::accepted_write_types())
        );

        let reader = affordances(&described(doc, &[Read]), DOC, ROOT);
        assert_eq!(value_of(&reader, "allow"), Some("GET, HEAD, OPTIONS"));
        for name in ["accept-patch", "accept-post", "accept-put"] {
            assert_eq!(value_of(&reader, name), None, "{name} offered to a reader");
        }

        let appender = affordances(&described(doc, &[Append]), DOC, ROOT);
        // H5: insert-only patches are an Append operation, so PATCH — and its
        // `Accept-Patch` — are the appender's.
        assert!(value_of(&appender, "accept-post").is_none());
        assert_eq!(value_of(&appender, "accept-patch"), Some(ACCEPT_PATCH));
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
