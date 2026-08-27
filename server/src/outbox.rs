//! Publication and delivery.
//!
//! `POST /outbox` is the publication surface (ADR 0012). A write here is a
//! post; the same data written anywhere in the pod is private CRUD (D9). That
//! boundary is the whole of the decision, and it is why this handler exists
//! separately from the LDP ones rather than being a flag on them.
//!
//! **Delivery is in-process for local recipients.** `activitypub_federation`
//! drops local inboxes before signing — `build_tasks` filters on
//! `is_local_url` — so same-instance activities were never going to travel over
//! HTTP anyway; the framework assumes the application handles them. See ADR
//! 0014 for what that costs against D12 and why it was accepted.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use brolly_activitypub::follows;
use brolly_activitypub::processor::{self, Recipient};
use brolly_identity::db::{self, User};
use brolly_identity::{extract, webid};
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::SESSION_COOKIE;

/// Wrap a bare object in the `Create` that publishes it.
///
/// A client may POST either an activity or a plain object; ActivityPub says the
/// server wraps the latter. Doing it here means every downstream stage sees an
/// activity and none of them has to ask.
fn as_activity(body: &Value, actor: &str, base: &str, now: &str) -> Value {
    const ACTIVITY_TYPES: [&str; 6] = ["Create", "Follow", "Like", "Announce", "Delete", "Undo"];

    let kind = body["type"].as_str().unwrap_or("Note");
    let id = format!("{base}/~/activities/{}", uuid::Uuid::new_v4());

    if ACTIVITY_TYPES.contains(&kind) {
        let mut activity = body.clone();
        activity["id"] = json!(id);
        activity["actor"] = json!(actor);
        if activity.get("published").is_none() {
            activity["published"] = json!(now);
        }
        return activity;
    }

    // A bare object: give it its own IRI in the author's pod, then wrap it.
    let mut object = body.clone();
    // A ULID, not a UUIDv4, and the reason lives one protocol over: ADR 0015
    // builds Mastodon's status ID out of this identifier, and Mastodon clients
    // are permitted to sort IDs lexically. A v4 local part would claim an
    // ordering it does not have. Nothing else about publication cares, which is
    // why this is the only line that mentions it.
    let object_id = format!(
        "{base}/~/notes/{}",
        brolly_mastodon::status_id::mint_note_id()
    );
    object["id"] = json!(object_id);
    object["attributedTo"] = json!(actor);
    if object.get("published").is_none() {
        object["published"] = json!(now);
    }

    json!({
        "type": "Create",
        "id": id,
        "actor": actor,
        "published": now,
        "to": body.get("to").cloned().unwrap_or_else(|| json!([])),
        "cc": body.get("cc").cloned().unwrap_or_else(|| json!([])),
        "object": object,
    })
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// `POST /outbox` — publish on the member's behalf.
pub async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: axum::body::Bytes,
) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let Some(username) = extract::subdomain_user(host, &state.base_domain) else {
        return (StatusCode::NOT_FOUND, "no such outbox").into_response();
    };

    let Some(caller) = session_user(&state, &jar).await else {
        return (StatusCode::UNAUTHORIZED, "log in to publish").into_response();
    };
    // The outbox publishes *as* its owner, so the caller has to be them.
    if caller.username != username {
        return (
            StatusCode::FORBIDDEN,
            "you can only publish to your own outbox",
        )
            .into_response();
    }

    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "body is not JSON").into_response();
    };

    let base = format!("https://{username}.{}", state.base_domain);
    let actor = webid::actor(&username, &state.base_domain);
    let activity = as_activity(&payload, &actor, &base, &now());

    match deliver(&state, &caller, &actor, &activity).await {
        Ok(()) => (
            StatusCode::CREATED,
            [
                (
                    header::CONTENT_TYPE,
                    "application/activity+json".to_string(),
                ),
                (
                    header::LOCATION,
                    activity["id"].as_str().unwrap_or_default().to_string(),
                ),
            ],
            activity.to_string(),
        )
            .into_response(),
        Err(response) => response,
    }
}

async fn session_user(state: &AppState, jar: &CookieJar) -> Option<User> {
    let cookie = jar.get(SESSION_COOKIE)?;
    db::user_for_session(&state.pool, cookie.value())
        .await
        .ok()
        .flatten()
        .filter(User::is_active)
}

/// Store the activity in the author's pod, then deliver it.
async fn deliver(
    state: &AppState,
    author: &User,
    actor: &str,
    activity: &Value,
) -> Result<(), Response> {
    let received = now();
    let Ok(author_pod) = state.stores.pod(author.id) else {
        return Err(server_error());
    };

    // The author holds their own post — content lives in exactly one place (D2)
    // and this is it. A Delete removes rather than stores.
    if activity["type"] == "Delete" {
        if let Err(e) = processor::process(
            &author_pod,
            Recipient::Member {
                inbox: &webid::inbox(&author.username, &state.base_domain),
            },
            activity,
            &received,
        ) {
            tracing::error!(error = %e, "removing the author's copy failed");
            return Err(server_error());
        }
    } else if let Err(e) = brolly_activitypub::inbox::deliver(
        &author_pod,
        &webid::outbox(&author.username, &state.base_domain),
        activity,
        &received,
    ) {
        tracing::error!(error = %e, "storing the author's copy failed");
        return Err(server_error());
    }

    // A Follow is also a relationship, not only a notification.
    if activity["type"] == "Follow"
        && let Some(target) = activity["object"].as_str()
    {
        let _ = follows::record_following(&author_pod, actor, target);
    }

    for inbox in recipients(state, &author_pod, actor, activity) {
        let Ok(url) = url::Url::parse(&inbox) else {
            continue;
        };
        // D12: the switch runs on every delivery, local or not.
        if !brolly_activitypub::should_deliver(&url, &state.base_domain) {
            tracing::debug!(%inbox, "remote delivery suppressed; federation is off");
            continue;
        }
        deliver_locally(state, &inbox, actor, activity, &received).await;
    }

    // The instance is a recipient like any other (D4), and its processor writes
    // the pointer row. This is the only way anything reaches the public index.
    if let Err(e) = processor::process(
        state.stores.instance(),
        Recipient::Instance,
        activity,
        &received,
    ) {
        tracing::error!(error = %e, "indexing failed");
    }

    Ok(())
}

/// Which inboxes this activity is for.
fn recipients(
    state: &AppState,
    author_pod: &brolly_store::Store,
    actor: &str,
    activity: &Value,
) -> Vec<String> {
    let mut inboxes: Vec<String> = follows::followers(author_pod, actor)
        .into_iter()
        .map(|follower| inbox_for(&follower))
        .collect();

    // A Follow, Like or Delete also goes to whoever it is *about*, who is
    // usually not a follower — that is the whole point of the notification.
    if let Some(target) = activity["object"].as_str()
        && let Some(inbox) = inbox_of_actor_or_note(state, target)
    {
        inboxes.push(inbox);
    }

    inboxes.sort();
    inboxes.dedup();
    inboxes
}

/// The inbox of an actor IRI.
fn inbox_for(actor: &str) -> String {
    format!("{}/inbox", actor.trim_end_matches("/actor"))
}

/// The inbox to notify about `target`, which may be an actor or a note.
///
/// A note IRI names its owner — that is why status lookup needs no routing
/// table — so a Like on `https://alice.host/~/notes/1` reaches alice.
fn inbox_of_actor_or_note(state: &AppState, target: &str) -> Option<String> {
    let url = url::Url::parse(target).ok()?;
    let host = url.host_str()?;
    let username = extract::subdomain_user(host, &state.base_domain)?;
    Some(webid::inbox(&username, &state.base_domain))
}

/// Hand an activity to a local recipient, in process.
async fn deliver_locally(
    state: &AppState,
    inbox: &str,
    _actor: &str,
    activity: &Value,
    received: &str,
) {
    let Ok(url) = url::Url::parse(inbox) else {
        return;
    };
    let Some(host) = url.host_str() else { return };
    let Some(username) = extract::subdomain_user(host, &state.base_domain) else {
        // The instance's own inbox is handled by the Instance recipient below.
        return;
    };

    let Ok(Some(user)) = db::find_by_username(&state.pool, &username).await else {
        return;
    };
    if !user.is_active() {
        return;
    }
    let Ok(pod) = state.stores.pod(user.id) else {
        return;
    };

    // A Follow arriving establishes the relationship in the recipient's pod,
    // which is what delivery reads to resolve recipients next time.
    if activity["type"] == "Follow"
        && let Some(target) = activity["object"].as_str()
        && let Some(follower) = activity["actor"].as_str()
    {
        let _ = follows::record(&pod, follower, target);
    }

    if let Err(e) = processor::process(&pod, Recipient::Member { inbox }, activity, received) {
        tracing::error!(error = %e, %inbox, "local delivery failed");
    }
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Try again.",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR: &str = "https://alice.brolly.test/actor";
    const BASE: &str = "https://alice.brolly.test";

    #[test]
    fn a_bare_object_is_wrapped_in_a_create() {
        let activity = as_activity(
            &json!({"type": "Note", "content": "hello", "to": ["public"]}),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );

        assert_eq!(activity["type"], "Create");
        assert_eq!(activity["actor"], ACTOR);
        assert_eq!(activity["object"]["content"], "hello");
        assert_eq!(activity["object"]["attributedTo"], ACTOR);
        assert_eq!(
            activity["to"],
            json!(["public"]),
            "addressing must survive the wrap, or a public post becomes private"
        );
    }

    #[test]
    fn a_wrapped_object_gets_an_iri_in_its_authors_pod() {
        let activity = as_activity(
            &json!({"type": "Note", "content": "hello"}),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        let object = activity["object"]["id"].as_str().expect("an object IRI");
        assert!(
            object.starts_with("https://alice.brolly.test/~/"),
            "content lives in the author's pod (D2): {object}"
        );
    }

    #[test]
    fn an_activity_is_left_as_one() {
        for kind in ["Follow", "Like", "Announce", "Delete", "Undo"] {
            let activity = as_activity(
                &json!({"type": kind, "object": "https://bob.brolly.test/actor"}),
                ACTOR,
                BASE,
                "2026-08-26T12:00:00Z",
            );
            assert_eq!(activity["type"], kind, "{kind} was rewrapped");
            assert_eq!(activity["object"], "https://bob.brolly.test/actor");
            assert_eq!(activity["actor"], ACTOR);
        }
    }

    #[test]
    fn the_actor_is_always_the_outbox_owner() {
        // A client must not be able to publish as somebody else by saying so.
        let activity = as_activity(
            &json!({"type": "Create", "actor": "https://mallory.example/actor"}),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        assert_eq!(activity["actor"], ACTOR);
    }

    #[test]
    fn an_inbox_is_derived_from_an_actor_iri() {
        assert_eq!(
            inbox_for("https://bob.brolly.test/actor"),
            "https://bob.brolly.test/inbox"
        );
    }
}
