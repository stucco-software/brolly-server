//! ActivityPub discovery over HTTP: actor documents, WebFinger, NodeInfo.
//!
//! `/actor` is served on both the apex and member subdomains and means
//! different things on each — the instance actor (D4) on the apex, a member's
//! on a subdomain. That is one route with a host branch rather than two routes,
//! because a route is matched before the host is looked at and two would
//! shadow each other.
//!
//! WebFinger and NodeInfo describe the *instance*, so they are apex-only. On a
//! member subdomain they 404: two answers to the same question is worse than
//! one.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use brolly_activitypub::actor;
use brolly_identity::db::{self, User};
use brolly_identity::{extract, instance, webid};
use serde::Deserialize;
use serde_json::Value;

use crate::AppState;

/// What an actor document is served as. A client that receives
/// `application/json` will often refuse to treat the document as an actor.
const ACTIVITY_JSON: &str = "application/activity+json";
/// WebFinger's own media type (RFC 7033), which Mastodon checks.
const JRD_JSON: &str = "application/jrd+json";

fn json_response(content_type: &str, body: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type.to_string())],
        body.to_string(),
    )
        .into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn server_error() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn host_of(headers: &HeaderMap) -> &str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
}

/// The member this subdomain belongs to, if they exist and are active.
///
/// A suspended account must stop federating: leaving its actor resolvable means
/// remote instances keep delivering to it and keep showing it as live.
async fn active_member(state: &AppState, username: &str) -> Option<User> {
    db::find_by_username(&state.pool, username)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

// --- actor documents --------------------------------------------------------

/// `GET /actor` — the member's on a subdomain, the instance's on the apex.
pub async fn actor_document(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match extract::subdomain_user(host_of(&headers), &state.base_domain) {
        Some(username) => member_actor(&state, &username).await,
        None => json_response(
            ACTIVITY_JSON,
            actor::application(&state.base_domain, &state.instance_actor.public_key_pem),
        ),
    }
}

async fn member_actor(state: &AppState, username: &str) -> Response {
    let Some(user) = active_member(state, username).await else {
        return not_found();
    };

    // Generated on first federation rather than at signup: an account that
    // never federates never needs one, and RSA-2048 generation is not free.
    let keys = match instance::load_or_create_actor_keys(
        &state.pool,
        user.id,
        brolly_activitypub::keys::generate,
    )
    .await
    {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "actor key unavailable");
            return server_error();
        }
    };

    // Name and summary are projected from the pod (D8) — the actor document is
    // a view of the WebID's triples, never a second copy of them. The icon is
    // the same projection one protocol over (spec 4, H6): the depiction
    // target, read beside the profile's own fields because the form does not
    // own it, emitted with no access check — a pointer, not bytes.
    let (profile, depiction) = match state.stores.pod(user.id) {
        Ok(pod) => {
            let read = pod.read_store();
            let webid = webid::webid(&user.username, &state.base_domain);
            let document = webid::profile_document(&user.username, &state.base_domain);
            (
                brolly_solid::profile::read(&read, &webid, &document),
                brolly_solid::profile::depiction(&read, &webid, &document),
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, user = %user.id, "pod unavailable; serving actor without profile");
            (brolly_solid::profile::Profile::blank(), None)
        }
    };

    json_response(
        ACTIVITY_JSON,
        actor::person(
            &user.username,
            &state.base_domain,
            &keys.public_key_pem,
            &profile.display_name,
            &profile.bio,
            depiction.as_deref(),
            actor::Flags {
                locked: profile.locked,
                bot: profile.bot,
                discoverable: profile.discoverable,
            },
        ),
    )
}

// --- WebFinger --------------------------------------------------------------

#[derive(Deserialize)]
pub struct WebfingerQuery {
    resource: Option<String>,
}

/// `GET /.well-known/webfinger` (ADR 0005 R9).
///
/// The lookup that happens before any user context exists, and how every remote
/// instance first finds a member.
pub async fn webfinger(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WebfingerQuery>,
) -> Response {
    if extract::subdomain_user(host_of(&headers), &state.base_domain).is_some() {
        return not_found();
    }

    let Some(resource) = query.resource.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            "a resource parameter is required, e.g. ?resource=acct:alice@example",
        )
            .into_response();
    };
    let Some((username, host)) = actor::parse_resource(resource) else {
        return (StatusCode::BAD_REQUEST, "unrecognised resource").into_response();
    };

    // Answering for a host we do not serve would vouch for a handle that is not
    // ours, and a resolver that trusted it would send someone else's delivery
    // here.
    if host != state.base_domain.to_ascii_lowercase() {
        return not_found();
    }
    if active_member(&state, &username).await.is_none() {
        return not_found();
    }

    json_response(JRD_JSON, actor::webfinger(&username, &state.base_domain))
}

// --- NodeInfo ---------------------------------------------------------------

/// `GET /.well-known/nodeinfo`
pub async fn nodeinfo_discovery(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if extract::subdomain_user(host_of(&headers), &state.base_domain).is_some() {
        return not_found();
    }
    json_response(
        "application/json",
        actor::nodeinfo_discovery(&state.base_domain),
    )
}

/// `GET /nodeinfo/2.1`
///
/// Public and unauthenticated — aggregators scrape it — so it carries counts
/// and nothing else.
pub async fn nodeinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if extract::subdomain_user(host_of(&headers), &state.base_domain).is_some() {
        return not_found();
    }

    let users: i64 =
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM users WHERE status = 'active'")
            .fetch_one(&state.pool)
            .await
            .map(|(n,)| n)
            .unwrap_or_default();

    // Counted from the server index, which is the only place that knows across
    // all members without opening every pod.
    let posts = brolly_store::index::count_notes(state.stores.instance()).unwrap_or_default();

    json_response("application/json", actor::nodeinfo(users, posts))
}

// --- the actor's collections -------------------------------------------------

/// An AS2 `OrderedCollection` rendered whole.
///
/// No paging. These are small on a private community server, and a `first`
/// page that never gets a second one is a lie in the shape of a standard. Add
/// paging when a collection is big enough to need it, not before.
fn ordered_collection(id: &str, items: Vec<String>) -> Value {
    serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": id,
        "type": "OrderedCollection",
        "totalItems": items.len(),
        "orderedItems": items,
    })
}

/// `GET /followers` and `GET /following` on a member subdomain.
///
/// Public, matching `/actor` and the fediverse's own convention: a follower
/// list is how another server decides whether it already knows you.
async fn follow_collection(state: &AppState, headers: &HeaderMap, which: Which) -> Response {
    let Some(username) = extract::subdomain_user(host_of(headers), &state.base_domain) else {
        return not_found();
    };
    let Some(user) = active_member(state, &username).await else {
        return not_found();
    };
    let Ok(pod) = state.stores.pod(user.id) else {
        tracing::error!(user = %user.id, "pod unavailable serving a collection");
        return server_error();
    };

    let actor = webid::actor(&username, &state.base_domain);
    let (id, items) = match which {
        Which::Followers => (
            webid::followers(&username, &state.base_domain),
            brolly_activitypub::follows::followers(&pod.read_store(), &actor),
        ),
        Which::Following => (
            webid::following(&username, &state.base_domain),
            brolly_activitypub::follows::following(&pod.read_store(), &actor),
        ),
    };
    json_response(ACTIVITY_JSON, ordered_collection(&id, items))
}

enum Which {
    Followers,
    Following,
}

pub async fn followers_collection(State(state): State<AppState>, headers: HeaderMap) -> Response {
    follow_collection(&state, &headers, Which::Followers).await
}

pub async fn following_collection(State(state): State<AppState>, headers: HeaderMap) -> Response {
    follow_collection(&state, &headers, Which::Following).await
}

/// `GET /inbox` on a member subdomain.
///
/// **Owner only.** Your inbox is your home timeline (D6), which makes it the
/// one collection here that is not public — serving it to anonymous callers
/// would publish who you follow and everything they have sent you.
///
/// 404 rather than 403 for a caller who is not the owner, matching
/// `require_admin`: 403 confirms the resource exists and that the caller found
/// a real member, which is a disclosure with nothing on the other side of it.
pub async fn inbox_collection(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let Some(username) = extract::subdomain_user(host_of(&headers), &state.base_domain) else {
        return not_found();
    };
    let Some(user) = active_member(&state, &username).await else {
        return not_found();
    };

    let inbox = webid::inbox(&username, &state.base_domain);
    let caller = match crate::pod::subject_for(&state, &headers, &method, &inbox).await {
        Ok(caller) => caller,
        // H2 reaches here too. Without it, a client whose token expired is
        // downgraded to anonymous, this handler's owner check then fails, and
        // the member is told their own inbox does not exist.
        Err(refused) => {
            return crate::pod::unauthorized(refused, &format!("https://{}", state.base_domain));
        }
    };
    // Stage 0's rule stands: a caller who is not the owner gets 404, because
    // 403 would confirm both that the inbox exists and that the caller found a
    // real member. H1's table is about WAC on pod resources; this collection
    // is not one (H15).
    if caller.subject.user_id != Some(user.id) {
        return not_found();
    }

    let Ok(pod) = state.stores.pod(user.id) else {
        tracing::error!(user = %user.id, "pod unavailable serving an inbox");
        return server_error();
    };

    let items = brolly_store::collection::members(&pod.read_store(), &inbox);
    json_response(ACTIVITY_JSON, ordered_collection(&inbox, items))
}
