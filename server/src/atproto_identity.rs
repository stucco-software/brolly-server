//! The documents that make a member's handle and DID resolvable from outside
//! (stage 3, B): `/.well-known/atproto-did` and `/.well-known/did.json`, both
//! on the **member subdomain** — the handle's own origin — and never on the
//! apex, which is not a handle and names no member.
//!
//! Routes are not host-scoped, so each handler resolves the subdomain itself,
//! the way `/.well-known/solid` and `/profile` do, and 404s anywhere else.
//! `/.well-known/*` is reserved on member subdomains (ADR 0009), so nothing a
//! member stores can shadow either document.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use brolly_identity::db::User;
use serde_json::json;

use crate::AppState;
use crate::xrpc::{did_of, member_by_handle, signing_key};

/// Both documents are stable for as long as the member's DID and key are, and
/// a resolver that re-fetched them per request would hammer its targets.
const CACHE: &str = "public, max-age=3600";

/// The member whose subdomain this request arrived on.
async fn member_of_host(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok())?;
    member_by_handle(state, host.split(':').next().unwrap_or_default()).await
}

fn no_such_handle() -> Response {
    (StatusCode::NOT_FOUND, "no such handle").into_response()
}

/// `GET /.well-known/atproto-did` — the HTTPS handle-resolution method.
///
/// The body is the bare DID as `text/plain`. Not `did=…`: that prefix belongs
/// to the DNS method's `_atproto` TXT record, and a resolver reading this
/// document takes the body as the DID verbatim.
pub async fn atproto_did(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = member_of_host(&state, &headers).await else {
        return no_such_handle();
    };
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, CACHE),
        ],
        did_of(&user, &state),
    )
        .into_response()
}

/// `GET /.well-known/did.json` — the `did:web` document for the derived
/// `did:web:{username}.{base}`.
///
/// Routing only (D11): it makes the derived DID resolvable, with the key that
/// actually signs the member's commits and the PDS at the base origin, and it
/// does not demote `did:plc` from its wire-format place.
pub async fn did_json(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = member_of_host(&state, &headers).await else {
        return no_such_handle();
    };
    let key = match signing_key(&state, &user).await {
        Ok(key) => key,
        Err(_) => return no_such_handle(),
    };
    let handle = format!("{}.{}", user.username, state.base_domain);
    let did = format!("did:web:{handle}");
    let did_key = key.did_key();
    // The multibase half of the `did:key`: the same encoded public key, which
    // is what `publicKeyMultibase` carries for a `Multikey` method.
    let multibase = did_key.strip_prefix("did:key:").unwrap_or(&did_key);

    (
        [
            (header::CONTENT_TYPE, "application/did+json"),
            (header::CACHE_CONTROL, CACHE),
        ],
        axum::Json(json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ],
            "id": did,
            "alsoKnownAs": [format!("at://{handle}")],
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase,
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": format!("https://{}", state.base_domain),
            }],
        })),
    )
        .into_response()
}
