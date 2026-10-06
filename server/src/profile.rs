//! The WebID profile document, served at a member's `/profile`.
//!
//! This is the node every protocol asserts onto (D8) and the one a Solid client
//! is handed when somebody types their WebID into an app. Until now it was
//! reserved in [`brolly_identity::routing`] and served by nothing, so
//! dereferencing a WebID returned `501` — which meant no conformant Solid
//! client could discover the issuer, and therefore none could log a member in.
//!
//! Two audiences, one URL. A client asks for RDF and gets Turtle by default; a
//! browser asks for HTML and gets a page it can read. The negotiation checks
//! HTML *first* rather than deferring to [`brolly_domain::syntax::negotiate`],
//! because a browser sends `text/html,…,*/*;q=0.8` and the `*/*` arm would
//! otherwise hand it a Turtle download.
//!
//! Since spec 6 (H1) the document is also writable, by its owner: a `PUT`
//! replaces the graph and a `PATCH` patches it, both delegated to the LDP
//! write path with the profile graph as the target, and the five positions the
//! projection derives reserved against the write. `DELETE` and `POST` stay
//! 405s — the profile is the member's identity document, not a resource to be
//! unmade.

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use brolly_authz::AccessMode;
use brolly_domain::syntax;
use brolly_identity::db::User;
use brolly_identity::{extract, routing, webid};
use brolly_solid::profile as graph;

use crate::{AppState, Chrome, render};

/// The subject IRI, its document, and where the pod lives.
struct Identity {
    webid: String,
    document: String,
    storage_root: String,
}

fn identity(username: &str, base_domain: &str) -> Identity {
    Identity {
        webid: webid::webid(username, base_domain),
        document: webid::profile_document(username, base_domain),
        storage_root: routing::storage_root(username, base_domain),
    }
}

/// The member whose subdomain this is: their account, their pod, and their
/// identity IRIs.
///
/// Every `/profile` handler resolves the same way — the apex has no profile
/// (the instance's identity is an actor, not a person), an unknown or inactive
/// member's subdomain is nobody's, and both are 404s decided before any
/// credential is looked at, as `pod::resolve` decides them.
async fn member(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(User, std::sync::Arc<brolly_store::resources::Pod>, Identity), Response> {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let Some(username) = extract::subdomain_user(host, &state.base_domain) else {
        return Err(not_found());
    };

    let user = match brolly_identity::db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) if user.is_active() => user,
        Ok(_) => return Err(not_found()),
        Err(e) => {
            tracing::error!(error = %e, "profile lookup failed");
            return Err(server_error());
        }
    };

    let Ok(pod) = state.stores.pod(user.id) else {
        tracing::error!(user = %user.id, "pod unavailable serving a profile");
        return Err(server_error());
    };

    let id = identity(&user.username, &state.base_domain);
    Ok((user, pod, id))
}

/// The refusal for a caller who is not the profile's owner (spec 6, H1), or
/// `None` when they are: the caller's authenticated WebID must be the
/// profile's `foaf:primaryTopic` — the member whose profile this is.
///
/// No WAC evaluation and no ACL inheritance: the profile is protocol state
/// outside the storage root — the same reasoning `graph::write` already
/// encodes — and the member's identity document is not shareable
/// infrastructure, so there are no modes to compute and nobody to share with.
/// Anyone else — anonymous, another member, a foreign WebID — gets 401 or 403
/// per stage 5b's H1, from the same table `pod::ldp_error` turns `Denied`
/// into: the status depends on the credential alone, never on the graph.
///
/// `Option`, not `Result<(), Response>`: a `Response` is a large `Err` to
/// carry on every call, and the caller's `if let` says the same thing.
fn owner_refusal(caller: &crate::pod::Caller, webid: &str, apex: &str) -> Option<Response> {
    (caller.subject.webid.as_deref() != Some(webid)).then(|| {
        crate::pod::ldp_error(
            brolly_solid::ldp::LdpError::Denied,
            caller.authenticated,
            apex,
        )
    })
}

/// Whether the caller would rather read this than parse it.
///
/// Deliberately not `syntax::negotiate`: that maps `*/*` to Turtle, and every
/// browser sends `*/*` as a low-quality fallback after `text/html`.
fn wants_html(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    accept
        .split(',')
        .map(|part| part.split(';').next().unwrap_or("").trim())
        .any(|media| media == "text/html" || media == "application/xhtml+xml")
}

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileDocument<'a> {
    chrome: Chrome<'a>,
    username: &'a str,
    webid: &'a str,
    storage_root: &'a str,
    issuer: &'a str,
    display_name: &'a str,
    bio: &'a str,
    /// The `foaf:depiction` target (spec 4, H6), already filtered to what the
    /// requesting caller can read — `None` renders nothing, and the template
    /// has no say in the decision.
    depiction: Option<&'a str>,
}

/// `GET /profile` on a member subdomain.
///
/// Apex has no profile — the instance's own identity is an actor, not a person
/// — so it 404s there rather than inventing one.
pub async fn profile_document(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (user, pod, id) = match member(&state, &headers).await {
        Ok(member) => member,
        Err(response) => return response,
    };

    // The issuer is this instance. It is the same value `/.well-known/
    // openid-configuration` publishes, and a client compares the two.
    let issuer = format!("https://{}", state.base_domain);

    let accept = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok());
    if wants_html(accept) {
        return html(&state, &user, &id, &issuer, &pod, &headers, &method).await;
    }

    let quads = graph::document(
        &pod.read_store(),
        &id.webid,
        &id.document,
        &id.storage_root,
        &issuer,
    );
    let format = syntax::negotiate(accept);
    match syntax::serialize(&quads, format) {
        Ok(body) => (
            [(header::CONTENT_TYPE, format.media_type().to_string())],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "serialising a profile failed");
            server_error()
        }
    }
}

/// `PUT /profile` — replace the profile graph (spec 6, H1).
///
/// LDP `PUT` semantics over the projection's backing graph, delegating to the
/// LDP write path's body handling with the profile graph as the target: RDF
/// only, parsed into the document's own graph, replacing it wholesale. The
/// five positions the projection derives are dropped on the way in, and a body
/// that omits the dashboard's predicates clears them — absent
/// `as:manuallyApprovesFollowers` reads as *false*, so a locked account comes
/// back unlocked. That is H1's recorded consequence, not a bug to fix:
/// reserving the five instead would make the `PUT` silently drop triples it
/// accepted.
///
/// Owner-only, per H1 — see [`owner_refusal`].
///
/// Always 204, never 201: the profile exists from the moment the pod does —
/// the projection serves it whatever the graph holds — so a `PUT` replaces
/// and never creates.
pub async fn put_document(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (_user, pod, id) = match member(&state, &headers).await {
        Ok(member) => member,
        Err(response) => return response,
    };
    let apex = format!("https://{}", state.base_domain);

    // The proof's `htu` is the document's own IRI: the route matches this one
    // path exactly, so there is nothing to rebuild from the request's URI the
    // way the pod's handlers must (H15).
    let caller = match crate::pod::subject_for(&state, &headers, &method, &id.document).await {
        Ok(caller) => caller,
        Err(refused) => return crate::pod::unauthorized(refused, &apex),
    };
    // The same order the pod's `PUT` answers in: the credential is verified,
    // then §2.1's 400 for a missing Content-Type (H17), then authorization.
    let Some(content_type) = crate::pod::content_type(&headers, &body, true) else {
        return crate::pod::missing_content_type();
    };
    if let Some(refusal) = owner_refusal(&caller, &id.webid, &apex) {
        return refusal;
    }

    match graph::put(&pod, &id.webid, &id.document, &body, content_type) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        // The same table the pod's writes answer from. Only a syntax refusal
        // (`415`), `NotRdf` (`415`) and a store failure (`500`) can arise here;
        // the rest of the table is the write path's, and this is its
        // [`graph::put`] call.
        Err(e) => crate::pod::ldp_error(e, caller.authenticated, &apex),
    }
}

/// `PATCH /profile` — patch the profile graph (spec 6, H1).
///
/// Through the same solver every other patch takes, scoped to the profile
/// graph, with 5c's parse and classification of the body — an insert-only
/// patch is Append, any delete is Write; the owner check has already
/// authorized the write, so the classification gates nothing here — and the
/// reserved positions filtered from the result.
///
/// Owner-only, per H1 — see [`owner_refusal`]. Always 204: like the `PUT`,
/// this replaces and never creates.
pub async fn patch_document(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (_user, pod, id) = match member(&state, &headers).await {
        Ok(member) => member,
        Err(response) => return response,
    };
    let apex = format!("https://{}", state.base_domain);

    let caller = match crate::pod::subject_for(&state, &headers, &method, &id.document).await {
        Ok(caller) => caller,
        Err(refused) => return crate::pod::unauthorized(refused, &apex),
    };
    let Some(content_type) = crate::pod::content_type(&headers, &body, false) else {
        return crate::pod::missing_content_type();
    };
    let body = match crate::pod::patch_body(content_type, &body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Some(refusal) = owner_refusal(&caller, &id.webid, &apex) {
        return refusal;
    }

    match graph::patch(&pod, &id.webid, &id.document, body) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => crate::pod::patch_error(e, caller.authenticated, &apex),
    }
}

/// The profile page (HTML), with the depiction rendered only for a caller who
/// can read its target (spec 4, H6).
///
/// This is the one surface that embeds the bytes' fetch in a page it serves,
/// so it is the one surface that checks: the JSON surfaces emit the IRI with
/// no access check at all, because a pointer leaks a path, not bytes — and
/// the RDF branch of this same URL serves the member's triples, depiction
/// included, to whoever asks. The page still does not serve the bytes itself;
/// the browser's own fetch of the `img` is the pod's `GET`, WAC and all. The
/// check is the page declining to point at what its caller cannot have.
async fn html(
    state: &AppState,
    user: &User,
    id: &Identity,
    issuer: &str,
    pod: &brolly_store::resources::Pod,
    headers: &HeaderMap,
    method: &Method,
) -> Response {
    let read = pod.read_store();
    let profile = brolly_solid::profile::read(&read, &id.webid, &id.document);

    // H6: "public read on the depiction target is the member's call", so the
    // caller is resolved for the check alone — the page is public and stays
    // public. A credential that does not verify degrades to the anonymous
    // caller rather than failing the page: the RDF branch serves anyone, the
    // credential here only ever *adds* the depiction, and anonymous renders
    // only what the world can read. The bytes are not at stake either way;
    // their fetch is the pod's own `GET`.
    let caller = crate::pod::subject_for(state, headers, method, &id.document)
        .await
        .unwrap_or_else(|refused| {
            tracing::debug!(?refused, "the profile page's caller did not verify");
            crate::pod::Caller::anonymous()
        });
    let depiction = brolly_solid::profile::depiction(&read, &id.webid, &id.document)
        .filter(|target| reads_target(pod, &id.storage_root, target, &caller.subject));

    render(&ProfileDocument {
        chrome: state.chrome(),
        username: &user.username,
        webid: &id.webid,
        storage_root: &id.storage_root,
        issuer,
        display_name: &profile.display_name,
        bio: &profile.bio,
        depiction: depiction.as_deref(),
    })
}

/// H6 (spec 4): can `subject` read `target`, as this pod's own `GET` of the
/// target would decide?
///
/// The same evaluation the pod surface takes — `ldp::granted_modes` walks the
/// target's ACL chain inside one read snapshot, so the page and a direct fetch
/// of the target can never disagree about who reads what. The target must be
/// in this pod's storage: `foaf:depiction` points at "any pod binary", and a
/// target elsewhere — another member's pod, a remote IRI, a protocol route on
/// this host — is not this pod's to evaluate. Unevaluable does not render,
/// which is the same answer the browser's fetch of it would get from the
/// default-deny; a member who wants a cross-pod avatar publishes it with the
/// target's own `.acl`, on the pod that holds it.
fn reads_target(
    pod: &brolly_store::resources::Pod,
    storage_root: &str,
    target: &str,
    subject: &brolly_identity::Subject,
) -> bool {
    let Some(rest) = target.strip_prefix(storage_root) else {
        return false;
    };
    let base = storage_root.strip_suffix("/~/").unwrap_or(storage_root);
    let path = format!("/~/{rest}");
    pod.read(|r| {
        Ok(brolly_solid::ldp::granted_modes(r, base, &path, subject).contains(&AccessMode::Read))
    })
    .unwrap_or(false)
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "no such profile").into_response()
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Try again.",
    )
        .into_response()
}
