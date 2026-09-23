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
use brolly_activitypub::processor::{self, ProcessError};
use brolly_identity::db::{self, User};
use brolly_identity::{extract, webid};
use brolly_store::resources::PodRead;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::session_user;

/// Wrap a bare object in the `Create` that publishes it.
///
/// A client may POST either an activity or a plain object; ActivityPub says the
/// server wraps the latter. Doing it here means every downstream stage sees an
/// activity and none of them has to ask.
///
/// **The server chooses embedded object ids.** A client-supplied id could name
/// one of the author's own LDP resources, such as `/~/.acl`. Delivery would then
/// clear and replace it, and a later `Delete` could remove it, all without WAC.
/// So a `Create`'s object gets a freshly minted note id. Any other activity's
/// embedded object becomes its `id` string, because there `object` names
/// something that already exists.
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
        if let Some(object) = activity.get_mut("object").filter(|o| o.is_object()) {
            if kind == "Create" {
                object["id"] = json!(mint_note(base));
                // The author is the outbox's owner, whoever the client named.
                // `attributedTo` is what the Mastodon timelines render a post
                // under, so leaving it to the client lets anyone publish under
                // somebody else's name.
                object["attributedTo"] = json!(actor);
            } else if let Some(named) = object["id"].as_str().map(str::to_string) {
                *object = json!(named);
            }
            // An embedded object with no id is left as it is, and `deliver`
            // refuses it.
        }
        return activity;
    }

    // A bare object: give it its own IRI in the author's pod, then wrap it.
    let mut object = body.clone();
    object["id"] = json!(mint_note(base));
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

/// A fresh note IRI in the author's pod.
///
/// A ULID, not a UUIDv4, and the reason lives one protocol over: ADR 0015
/// builds Mastodon's status ID out of this identifier, and Mastodon clients
/// are permitted to sort IDs lexically. A v4 local part would claim an
/// ordering it does not have.
fn mint_note(base: &str) -> String {
    format!(
        "{base}/~/notes/{}",
        brolly_mastodon::status_id::mint_note_id()
    )
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Why [`deliver`] refused an activity. Each is the caller's fault, so each is
/// a `400`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The activity's id isn't one the server minted under the author's
    /// `/~/activities/`.
    ActivityId,
    /// A `Create`'s embedded object id isn't one the server minted under the
    /// author's `/~/notes/`.
    ObjectId,
    /// An activity other than `Create` still embeds its object.
    EmbeddedObject,
    /// The activity's `actor` isn't the author publishing it.
    Actor,
}

impl Refusal {
    pub fn describe(self) -> &'static str {
        match self {
            Refusal::ActivityId => "The activity id must be one this server minted.",
            Refusal::ObjectId => "A Create's object id must be one this server minted.",
            Refusal::EmbeddedObject => {
                "Only a Create may embed its object. Name it by its id instead."
            }
            Refusal::Actor => "The activity's actor must be the account publishing it.",
        }
    }
}

/// What went wrong publishing.
#[derive(Debug)]
pub enum DeliverError {
    /// Nothing was stored or sent.
    Refused(Refusal),
    /// Storing the author's copy failed.
    Failed,
}

/// Is `iri` exactly one minted segment directly under `prefix`?
///
/// One segment of letters, digits and hyphens. A UUID and a ULID are both that,
/// and `..`, `/` and an empty remainder are not.
fn minted_under(iri: &str, prefix: &str) -> bool {
    iri.strip_prefix(prefix).is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Does this activity name only graphs the server minted for its author?
///
/// `base` is the author's origin, `https://<username>.<base_domain>`. The
/// author's own copy, which `deliver` writes without going through the
/// processor, lands only where this allows: an activity under `/~/activities/`
/// and a note under `/~/notes/`. Both are resources in the author's pod, and
/// none of the author's other resources can be reached this way.
fn authored(activity: &Value, base: &str) -> Result<(), Refusal> {
    let id = activity["id"].as_str().unwrap_or_default();
    if !minted_under(id, &format!("{base}/~/activities/")) {
        return Err(Refusal::ActivityId);
    }
    let embedded = activity.get("object").filter(|o| o.is_object());
    match (activity["type"].as_str(), embedded) {
        (Some("Create"), Some(object)) => {
            let note = object["id"].as_str().unwrap_or_default();
            let minted = note
                .strip_prefix(&format!("{base}/~/notes/"))
                .is_some_and(brolly_mastodon::status_id::is_note_id);
            if minted {
                Ok(())
            } else {
                Err(Refusal::ObjectId)
            }
        }
        (_, None) => Ok(()),
        (_, Some(_)) => Err(Refusal::EmbeddedObject),
    }
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
        Err(DeliverError::Refused(refusal)) => {
            (StatusCode::BAD_REQUEST, refusal.describe()).into_response()
        }
        Err(DeliverError::Failed) => server_error(),
    }
}

/// Publish an activity: store the author's copy, then fan out.
///
/// Exposed to the Mastodon composer so that `POST /api/v1/statuses` goes
/// through the *same* delivery path as `POST /outbox`. The predecessor had a
/// second fan-out for the Mastodon side that queried a table a migration had
/// dropped, and the error was swallowed — so statuses were delivered to nobody,
/// silently. One path, or the second one rots.
///
/// Refuses, before anything is stored, an activity naming a graph the server
/// didn't mint for its author (see [`authored`]). The author's copy is written
/// here directly and not through the processor, so this is the only check it
/// gets.
pub async fn deliver(
    state: &AppState,
    author: &User,
    actor: &str,
    activity: &Value,
) -> Result<(), DeliverError> {
    let base = format!("https://{}.{}", author.username, state.base_domain);
    authored(activity, &base).map_err(DeliverError::Refused)?;
    // Delivery trusts `actor`: the follow bookkeeping records it, and every
    // recipient's processor checks ids against it. Both callers set it, but
    // `deliver` is public, so it is checked rather than assumed.
    if activity["actor"].as_str() != Some(actor) {
        return Err(DeliverError::Refused(Refusal::Actor));
    }

    let received = now();
    let Ok(author_pod) = state.stores.pod(author.id) else {
        return Err(DeliverError::Failed);
    };
    let author_inbox = webid::inbox(&author.username, &state.base_domain);
    let author_outbox = webid::outbox(&author.username, &state.base_domain);

    // The author holds their own post — content lives in exactly one place (D2)
    // and this is it. The note and its activity are resources under the
    // author's `/~/`, listed in `/~/notes/` and `/~/activities/`, and the outbox
    // entry naming the activity lives outside it. One write covers all three,
    // so a failure can't leave a post the outbox doesn't list. A Delete removes
    // rather than stores, in the same single write.
    //
    // `Pod::write` is synchronous, so this write is closed before the recipient
    // loop's first `.await`, and no member's delivery waits on the author's
    // lock.
    let deleting = activity["type"] == "Delete";
    let stored = author_pod.write(|w| {
        if deleting {
            processor::process_member(w, &author_inbox, &author_outbox, activity, &received)
                .map_err(rollback)
        } else {
            brolly_activitypub::inbox::deliver(w, &author_outbox, activity, &received)
                .map(|_| ())
                .map_err(rollback)
        }
    });
    if let Err(e) = stored {
        let what = if deleting { "removing" } else { "storing" };
        tracing::error!(error = %e, "{what} the author's copy failed");
        return Err(DeliverError::Failed);
    }

    // A Follow is also a relationship, not only a notification. Its own write:
    // best effort, and folding it in would let its failure roll back the post.
    if activity["type"] == "Follow"
        && let Some(target) = activity["object"].as_str()
    {
        let _ = author_pod.write(|w| follows::record_following(w, actor, target));
    }

    // Bound before the loop, so no read of the pod is held across its awaits.
    let inboxes = recipients(state, &author_pod.read_store(), actor, activity);
    for inbox in inboxes {
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
    match processor::process_instance(state.stores.instance(), activity) {
        Ok(()) => {}
        Err(e @ ProcessError::ForeignObject) => tracing::warn!(error = %e, "indexing refused"),
        Err(e) => tracing::error!(error = %e, "indexing failed"),
    }

    Ok(())
}

/// The `StoreError` that makes `Pod::write` roll back, keeping the failure's
/// message for the log. A delivery failure isn't a storage error, but the
/// closure has to return one to abort.
fn rollback(e: impl std::fmt::Display) -> brolly_store::StoreError {
    brolly_store::StoreError::Backend(e.to_string())
}

/// Which inboxes this activity is for.
fn recipients(
    state: &AppState,
    author_pod: &impl PodRead,
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
    // which is what delivery reads to resolve recipients next time — *unless*
    // the account is locked, in which case it waits for approval instead.
    //
    // This is the whole of what "locked" means, and the predecessor recorded
    // the follow unconditionally, so the flag did nothing. It did nothing
    // invisibly, too: the profile still rendered the lock.
    //
    // FEDERATION: this writes before `processor::process_member` applies its
    // origin check (stage 0, A1). That is only safe while every activity here
    // came through `outbox::deliver` with an actor the server set. Revisit when
    // federation is enabled (ADR 0016): an inbound Follow's `actor` must be
    // verified before it is recorded as a follower.
    if activity["type"] == "Follow"
        && let Some(target) = activity["object"].as_str()
        && let Some(follower) = activity["actor"].as_str()
    {
        let webid = webid::webid(&user.username, &state.base_domain);
        let document = webid::profile_document(&user.username, &state.base_domain);
        // The lock is read in the same write that records the follow, so the
        // two can't disagree.
        let _ = pod.write(|w| {
            if brolly_solid::profile::read(&*w, &webid, &document).locked {
                follows::record_request(w, follower, target)
            } else {
                follows::record(w, follower, target)
            }
        });
    }

    // A refusal isn't a failure: the activity named a graph its actor doesn't
    // own. Delivery to every other recipient carries on either way.
    let outbox = webid::outbox(&user.username, &state.base_domain);
    match pod
        .write(|w| {
            Ok(processor::process_member(
                w, inbox, &outbox, activity, received,
            ))
        })
        .map_err(ProcessError::from)
        .flatten()
    {
        Ok(()) => {}
        Err(e @ ProcessError::ForeignObject) => {
            tracing::warn!(error = %e, %inbox, "local delivery refused");
        }
        Err(e) => tracing::error!(error = %e, %inbox, "local delivery failed"),
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
    fn a_create_gets_a_minted_object_id_whatever_the_client_claimed() {
        let activity = as_activity(
            &json!({
                "type": "Create",
                "object": {"type": "Note", "id": "https://alice.brolly.test/~/.acl", "content": "hello"},
            }),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        let id = activity["object"]["id"].as_str().expect("an object IRI");
        assert!(
            id.starts_with("https://alice.brolly.test/~/notes/"),
            "the client chose where content lives: {id}"
        );
        assert_eq!(
            activity["object"]["content"], "hello",
            "minting the id must keep the object"
        );
    }

    #[test]
    fn a_create_is_attributed_to_the_outbox_owner() {
        // Mastodon's timelines render a post under its `attributedTo`, so a
        // client-chosen one publishes under somebody else's name.
        let activity = as_activity(
            &json!({
                "type": "Create",
                "object": {
                    "type": "Note",
                    "content": "bob said this",
                    "attributedTo": "https://bob.brolly.test/actor",
                },
            }),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        assert_eq!(activity["object"]["attributedTo"], ACTOR);
    }

    #[test]
    fn a_bare_object_claiming_an_id_gets_a_minted_one() {
        let activity = as_activity(
            &json!({"type": "Note", "id": "https://alice.brolly.test/~/.acl"}),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        let id = activity["object"]["id"].as_str().expect("an object IRI");
        assert!(id.starts_with("https://alice.brolly.test/~/notes/"), "{id}");
    }

    #[test]
    fn any_other_activity_names_an_embedded_object_by_its_id() {
        for kind in ["Delete", "Undo", "Like", "Follow", "Announce"] {
            let activity = as_activity(
                &json!({
                    "type": kind,
                    "object": {"type": "Tombstone", "id": "https://bob.brolly.test/~/notes/1"},
                }),
                ACTOR,
                BASE,
                "2026-08-26T12:00:00Z",
            );
            assert_eq!(
                activity["object"], "https://bob.brolly.test/~/notes/1",
                "{kind} kept its embedded object"
            );
        }
    }

    #[test]
    fn an_embedded_object_with_no_id_is_left_for_deliver_to_refuse() {
        // There's nothing to name it by, so as_activity can't flatten it.
        let activity = as_activity(
            &json!({"type": "Like", "object": {"type": "Note"}}),
            ACTOR,
            BASE,
            "2026-08-26T12:00:00Z",
        );
        assert!(activity["object"].is_object());
    }

    fn activity_id(base: &str) -> String {
        format!("{base}/~/activities/{}", uuid::Uuid::new_v4())
    }

    fn note_id(base: &str) -> String {
        format!(
            "{base}/~/notes/{}",
            brolly_mastodon::status_id::mint_note_id()
        )
    }

    #[test]
    fn what_as_activity_produces_deliver_accepts() {
        for body in [
            json!({"type": "Note", "content": "hello"}),
            json!({"type": "Create", "object": {"type": "Note", "id": "https://alice.brolly.test/~/.acl"}}),
            json!({"type": "Create", "object": "https://alice.brolly.test/~/.acl"}),
            json!({"type": "Delete", "object": {"type": "Tombstone", "id": "https://alice.brolly.test/~/notes/1"}}),
            json!({"type": "Like", "object": "https://bob.brolly.test/~/notes/1"}),
        ] {
            let activity = as_activity(&body, ACTOR, BASE, "2026-08-26T12:00:00Z");
            assert_eq!(authored(&activity, BASE), Ok(()), "{activity}");
        }
    }

    #[test]
    fn deliver_refuses_an_activity_id_it_did_not_mint() {
        for id in [
            "https://alice.brolly.test/~/.acl".to_string(),
            activity_id("https://bob.brolly.test"),
            format!("{BASE}/~/activities/"),
            format!("{BASE}/~/activities/../.acl"),
            format!("{BASE}/~/activities/a/b"),
        ] {
            let activity =
                json!({"type": "Like", "id": id, "object": "https://bob.brolly.test/~/notes/1"});
            assert_eq!(authored(&activity, BASE), Err(Refusal::ActivityId), "{id}");
        }
        assert_eq!(
            authored(&json!({"type": "Like"}), BASE),
            Err(Refusal::ActivityId)
        );
    }

    #[test]
    fn deliver_refuses_a_create_whose_object_id_it_did_not_mint() {
        for object in [
            json!({"type": "Note", "id": "https://alice.brolly.test/~/.acl"}),
            json!({"type": "Note", "id": note_id("https://bob.brolly.test")}),
            json!({"type": "Note", "id": format!("{BASE}/~/notes/not-a-ulid")}),
            json!({"type": "Note"}),
        ] {
            let activity = json!({"type": "Create", "id": activity_id(BASE), "object": object});
            assert_eq!(
                authored(&activity, BASE),
                Err(Refusal::ObjectId),
                "{object}"
            );
        }
    }

    #[test]
    fn deliver_refuses_any_other_activity_that_embeds_its_object() {
        for kind in ["Delete", "Undo", "Like", "Follow", "Announce"] {
            let activity =
                json!({"type": kind, "id": activity_id(BASE), "object": {"id": note_id(BASE)}});
            assert_eq!(
                authored(&activity, BASE),
                Err(Refusal::EmbeddedObject),
                "{kind}"
            );
        }
    }

    #[test]
    fn an_inbox_is_derived_from_an_actor_iri() {
        assert_eq!(
            inbox_for("https://bob.brolly.test/actor"),
            "https://bob.brolly.test/inbox"
        );
    }
}
