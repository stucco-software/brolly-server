//! HTTP wiring for the pod: subdomain resolution and the LDP routes.
//!
//! Routing follows ADR 0010 exactly. `/~/**` reaches the LDP handlers; the
//! protocol resources are explicit routes; everything else on a subdomain is a
//! `404` with no fallback. The catch-all lives *inside* the storage prefix, so
//! it cannot shadow a protocol endpoint.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use brolly_identity::db::{self, User};
use brolly_identity::dpop::DpopError;
use brolly_identity::routing::{SubdomainRoute, subdomain_route};
use brolly_identity::{Credential, Scope, Subject, Via, extract, routing, webid};
use brolly_solid::conditional::{self, Preconditions};
use brolly_solid::ldp::{self, LdpError};
use brolly_solid::oidc::tokens;
use brolly_solid::patch;
use brolly_store::resources::Pod;
use std::sync::Arc;

use crate::AppState;

/// Everything a pod request needs once the host and credential are resolved.
pub struct PodRequest {
    pub user: User,
    pub subject: Subject,
    pub pod: Arc<Pod>,
    /// This pod's binary storage, for LDP-NR.
    pub blobs: brolly_store::BlobStore,
    pub base: String,
    pub storage_root: String,
}

/// Resolve the subdomain to a user, and the credential to a `Subject`.
///
/// Handlers never see a header. This is the only path from an HTTP request to a
/// `Subject` on the pod surface.
async fn resolve(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
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
    let subject = subject_for(state, headers, method, &format!("{base}{path}")).await;
    Ok(PodRequest {
        storage_root: routing::storage_root(&username, &state.base_domain),
        base,
        user,
        subject,
        pod,
        blobs,
    })
}

/// Turn whatever credential the request carried into a `Subject`.
///
/// An unauthenticated request is anonymous rather than rejected: WAC decides
/// whether anonymous is enough, so public resources work without a credential.
pub(crate) async fn subject_for(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    url: &str,
) -> Subject {
    let anonymous = Subject {
        user_id: None,
        did: None,
        webid: None,
        scope: Scope::default(),
        via: Via::Session,
    };

    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let cookie = headers.get(header::COOKIE).and_then(|h| h.to_str().ok());

    let Some(credential) = extract::credential(authorization, cookie) else {
        return anonymous;
    };
    // The proof travels in its own header, so it is attached separately.
    let proof = headers.get("dpop").and_then(|h| h.to_str().ok());
    let credential = extract::with_proof(credential, proof);

    match credential {
        Credential::Session(token) => match db::user_for_session(&state.pool, &token).await {
            Ok(Some(user)) => Subject::local(
                user.id,
                user.did_plc.clone().unwrap_or_default(),
                webid::webid(&user.username, &state.base_domain),
                Scope::parse("webid"),
                Via::Session,
            ),
            _ => anonymous,
        },
        Credential::Dpop { token, proof } => {
            // Token and proof are verified together or not at all: a token whose
            // `cnf.jkt` does not match the proof was not presented by its holder,
            // and a bound token with no proof is refused rather than downgraded
            // to bearer semantics.
            //
            // A bound token's claims arrive `Unspent`. Spending records the proof
            // so it can't be sent again. A replay, or a failure to record the
            // proof, leaves the caller anonymous, like any other bad proof.
            let proof = (!proof.is_empty()).then_some(proof);
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = match tokens::verify_access(
                &state.provider_key,
                &token,
                proof.as_deref(),
                method,
                url,
                now,
            ) {
                Ok(tokens::Access::Bearer(claims)) => claims,
                Ok(tokens::Access::Bound(unspent)) => match unspent.spend(&state.pool, now).await {
                    Ok(claims) => claims,
                    Err(DpopError::Storage(e)) => {
                        tracing::error!(error = %e, "recording a DPoP proof failed");
                        return anonymous;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Solid access token proof refused");
                        return anonymous;
                    }
                },
                Err(e) => {
                    tracing::debug!(error = %e, "Solid access token rejected");
                    return anonymous;
                }
            };
            solid_subject(state, claims).await.unwrap_or(anonymous)
        }
        // Mastodon's bearer tokens. Note what is *not* happening here: a
        // Solid access token presented as a bearer does not resolve, because
        // this looks the token up in Mastodon's own table rather than trying
        // to verify it as a JWT. Accepting a DPoP-bound token without its
        // proof is what would make the binding decorative.
        Credential::Bearer(token) => {
            match brolly_mastodon::oauth::verify_token(&state.pool, &token).await {
                Ok(Some(grant)) => match db::find_by_id(&state.pool, grant.user_id).await {
                    Ok(Some(user)) if user.is_active() => Subject::local(
                        user.id,
                        user.did_plc.clone().unwrap_or_default(),
                        webid::webid(&user.username, &state.base_domain),
                        Scope::parse(&grant.scopes),
                        Via::MastodonBearer,
                    ),
                    _ => anonymous,
                },
                Ok(None) => anonymous,
                Err(e) => {
                    tracing::error!(error = %e, "bearer token lookup failed");
                    anonymous
                }
            }
        }
    }
}

/// Turn verified Solid-OIDC claims into a `Subject`.
///
/// The WebID in the token decides who is calling, not the subdomain being
/// visited: an app holding Bob's token is Bob wherever it reads.
async fn solid_subject(state: &AppState, claims: tokens::AccessClaims) -> Option<Subject> {
    let username = webid::local_username(&claims.webid, &state.base_domain)?;
    let user = db::find_by_username(&state.pool, &username)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)?;

    Some(Subject::local(
        user.id,
        user.did_plc.clone().unwrap_or_default(),
        claims.webid,
        Scope::parse(&claims.scope),
        Via::SolidDpop,
    ))
}

fn ldp_error(error: LdpError) -> Response {
    match error {
        // An unauthorized reader is told the resource does not exist; see
        // `ldp::read`.
        LdpError::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
        LdpError::Forbidden => (StatusCode::FORBIDDEN, "forbidden").into_response(),
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
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, "GET", &path).await {
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
        Err(e) => return ldp_error(e),
    };

    // After `read` succeeded, so after the Read check, and against the version
    // from the same snapshot as the body. A caller without Read got 404 above
    // whatever they sent.
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
                wac_allow(&outcome.granted),
            ),
            (
                header::LINK,
                format!("<{}{path}.acl>; rel=\"acl\"", request.base),
            ),
            (header::ETAG, etag),
        ],
        outcome.body,
    )
        .into_response();
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
    headers: HeaderMap,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, "PUT", &path).await {
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
        Err(e) => ldp_error(e),
    }
}

/// `POST /~/*path`
pub async fn post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, "POST", &path).await {
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
        Err(e) => ldp_error(e),
    }
}

/// `PATCH /~/*path` — N3 Patch or SPARQL Update, both through one solver.
pub async fn patch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, "PATCH", &path).await {
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
        Err(patch::PatchError::Ldp(e)) => ldp_error(e),
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
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let path = format!("/~/{path}");
    let request = match resolve(&state, &headers, "DELETE", &path).await {
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
        Err(e) => ldp_error(e),
    }
}

/// `GET /~/` — the storage root itself.
///
/// A wildcard route does not match an empty remainder, so the root container
/// needs its own entry or the pod root would 404.
pub async fn get_root(state: State<AppState>, headers: HeaderMap) -> Response {
    get(state, headers, Path(String::new())).await
}

/// `POST /~/`
pub async fn post_root(
    state: State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    post(state, headers, Path(String::new()), body).await
}

/// `OPTIONS /~/*path`
pub async fn options() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (
                header::ALLOW,
                "GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS".to_string(),
            ),
            (
                header::HeaderName::from_static("accept-patch"),
                "text/n3, application/sparql-update".to_string(),
            ),
            (
                header::HeaderName::from_static("accept-post"),
                ldp::accepted_write_types().to_string(),
            ),
        ],
    )
        .into_response()
}

/// Anything on a subdomain that is not `/~/` and not a protocol resource.
///
/// ADR 0010's default-deny. There is no LDP fallback here, which is why a
/// misrouted OAuth request cannot become a pod write.
pub async fn subdomain_fallback(State(state): State<AppState>, uri: axum::http::Uri) -> Response {
    let path = uri.path();
    match subdomain_route(path) {
        SubdomainRoute::UserStorage => {
            // Reached only if the storage routes did not match, e.g. a bad method.
            (StatusCode::METHOD_NOT_ALLOWED, "unsupported method").into_response()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 5a uses the codes `pod.rs` already has; 5b revisits them.
    #[test]
    fn the_new_ldp_refusals_have_status_codes() {
        assert_eq!(
            ldp_error(LdpError::NotRdf).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            ldp_error(LdpError::ContainmentChange).status(),
            StatusCode::CONFLICT,
            "Solid Protocol §5.3"
        );
        assert_eq!(
            ldp_error(LdpError::BlobMissing).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
