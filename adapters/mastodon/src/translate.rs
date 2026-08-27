//! AS2 → Mastodon entities.
//!
//! Pure functions over stored AS2. Nothing here opens a store, and nothing here
//! writes to one — Mastodon is a projection (plan §3 Phase 6), and
//! `server/tests/architecture.rs` enforces it.
//!
//! Two fields in here are the reason this module has its own regression suite.
//! The predecessor hardcoded `media_attachments: []` and accepted-then-ignored
//! `spoiler_text`, so uploads vanished and content warnings published fully
//! exposed. Both failures were invisible to the client: 200, well-formed JSON,
//! wrong. Every field this module touches is asserted in `tests/translate.rs`.

use serde_json::{Value, json};
use uuid::Uuid;

use crate::status_id;

/// The member a status belongs to.
///
/// Passed in rather than read, because resolving it is a database question and
/// this layer stays pure.
#[derive(Debug, Clone)]
pub struct Author {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub bio: String,
    pub locked: bool,
    pub bot: bool,
    pub discoverable: bool,
    pub created_at: String,
}

/// Every spelling of the public collection that can arrive on the wire.
///
/// The predecessor shipped a production bug here: its JSON-LD writer stored the
/// `https://` form while older readers scanned for `http://`, and notification
/// candidates silently stopped matching. Storage canonicalizes now, but an
/// activity still arrives in whatever form the sender chose, and this function
/// runs before that. Both shorthands are permitted by AS2 itself.
fn is_public(value: &str) -> bool {
    matches!(
        value,
        "https://www.w3.org/ns/activitystreams#Public"
            | "http://www.w3.org/ns/activitystreams#Public"
            | "as:Public"
            | "Public"
    )
}

fn addressed_to_public(field: &Value) -> bool {
    match field {
        Value::String(s) => is_public(s),
        Value::Array(items) => items.iter().any(|i| i.as_str().is_some_and(is_public)),
        _ => false,
    }
}

fn is_empty_audience(field: &Value) -> bool {
    match field {
        Value::Array(items) => items.is_empty(),
        Value::Null => true,
        _ => false,
    }
}

/// Mastodon's four visibility levels, recovered from AS2 addressing.
///
/// They are a convention over `to`/`cc`, not a field, so this is a derivation
/// rather than a lookup. Reading it wrong publishes a followers-only post to
/// the public timeline, which is why each case is pinned by a test.
fn visibility(note: &Value) -> &'static str {
    let to = note.get("to").unwrap_or(&Value::Null);
    let cc = note.get("cc").unwrap_or(&Value::Null);

    if addressed_to_public(to) {
        return "public";
    }
    if addressed_to_public(cc) {
        return "unlisted";
    }
    // Followers-only: addressed to a collection rather than to named actors.
    // Anything left is a direct message.
    let followers_addressed = match to {
        Value::String(s) => s.ends_with("/followers"),
        Value::Array(items) => items
            .iter()
            .any(|i| i.as_str().is_some_and(|s| s.ends_with("/followers"))),
        _ => false,
    };
    if followers_addressed {
        return "private";
    }
    if is_empty_audience(to) && is_empty_audience(cc) {
        // Addressed to nobody. Failing open would publish it.
        return "direct";
    }
    "direct"
}

/// `contentMap` is AS2's federated form for language, so it is what we read.
///
/// Returns null rather than a default when absent: clients use `language` to
/// offer translation and to filter, and labelling every undeclared post "en"
/// would be worse than admitting we do not know.
fn language(note: &Value) -> Value {
    note.get("contentMap")
        .and_then(Value::as_object)
        .and_then(|map| map.keys().next())
        .map(|tag| json!(tag))
        .unwrap_or(Value::Null)
}

/// One AS2 `attachment` entry as a Mastodon media attachment.
fn media_attachment(attachment: &Value) -> Value {
    let media_type = attachment["mediaType"].as_str().unwrap_or_default();
    let url = attachment["url"].as_str().unwrap_or_default();

    // Mastodon's coarse kinds. A client uses this to choose a player, so an
    // unknown type is "unknown" rather than a guess at "image".
    let kind = match media_type.split('/').next().unwrap_or_default() {
        "image" => "image",
        "video" => "video",
        "audio" => "audio",
        _ => "unknown",
    };

    json!({
        "id": attachment["id"].as_str().unwrap_or(url),
        "type": kind,
        "url": url,
        // Timelines render `preview_url`; a null one shows a broken box. We
        // serve originals, so it is the same URL rather than absent.
        "preview_url": url,
        "remote_url": Value::Null,
        // The accessibility payload. AS2 carries alt text as `name`.
        "description": attachment["name"].clone(),
        "blurhash": Value::Null,
        "meta": json!({}),
    })
}

fn media_attachments(note: &Value) -> Value {
    match note.get("attachment") {
        Some(Value::Array(items)) => Value::Array(items.iter().map(media_attachment).collect()),
        Some(single @ Value::Object(_)) => json!([media_attachment(single)]),
        _ => json!([]),
    }
}

/// A Mastodon Account.
pub fn account(author: &Author, base_domain: &str) -> Value {
    let username = &author.username;
    json!({
        // Fixed width for the same reason status IDs are: clients sort and
        // paginate on it.
        "id": encode_account_id(author.user_id),
        "username": username,
        // Bare for a local member; `user@host` is the remote form. Clients key
        // mention rendering off this distinction.
        "acct": username,
        "display_name": author.display_name,
        "note": author.bio,
        "url": format!("https://{username}.{base_domain}/"),
        "uri": brolly_identity::webid::actor(username, base_domain),
        "avatar": Value::Null,
        "avatar_static": Value::Null,
        "header": Value::Null,
        "header_static": Value::Null,
        "locked": author.locked,
        "bot": author.bot,
        "discoverable": author.discoverable,
        "group": false,
        "created_at": author.created_at,
        "followers_count": 0,
        "following_count": 0,
        "statuses_count": 0,
        "last_status_at": Value::Null,
        "emojis": [],
        "fields": [],
    })
}

/// Encode a member's UUID as an opaque account id.
pub fn encode_account_id(user_id: Uuid) -> String {
    status_id::encode_uuid(user_id)
}

/// Recover the member behind an account id.
pub fn account_id_to_uuid(account_id: &str) -> Option<Uuid> {
    status_id::decode_uuid(account_id)
}

/// Translate a stored note into a Mastodon Status.
///
/// `None` when the note is not one this instance minted — a remote IRI carries
/// no ULID, and inventing a status id for it would produce something that
/// resolves to the wrong member's pod.
pub fn try_status(note: &Value, author: &Author, base_domain: &str) -> Option<Value> {
    let note_iri = note["id"].as_str()?;
    let note_id = status_id::note_id_from_iri(note_iri)?;
    let id = status_id::encode(note_id, author.user_id)?;

    let spoiler = note["summary"].as_str().unwrap_or_default().to_string();
    // A summary implies sensitive even when the flag is absent — Mastodon's own
    // behaviour, and the safe direction to be wrong in.
    let sensitive = note["sensitive"].as_bool().unwrap_or(false) || !spoiler.is_empty();

    let in_reply_to = note["inReplyTo"]
        .as_str()
        .and_then(status_id::note_id_from_iri)
        .and_then(|parent| status_id::encode(parent, author.user_id));

    Some(json!({
        "id": id,
        "uri": note_iri,
        "url": note_iri,
        "created_at": note["published"].as_str().unwrap_or_default(),
        "edited_at": Value::Null,
        "content": note["content"].as_str().unwrap_or_default(),
        "spoiler_text": spoiler,
        "sensitive": sensitive,
        "language": language(note),
        "visibility": visibility(note),
        "media_attachments": media_attachments(note),
        "in_reply_to_id": in_reply_to.clone().map(Value::String).unwrap_or(Value::Null),
        "in_reply_to_account_id": in_reply_to
            .map(|_| json!(encode_account_id(author.user_id)))
            .unwrap_or(Value::Null),
        "account": account(author, base_domain),
        "replies_count": 0,
        "reblogs_count": 0,
        "favourites_count": 0,
        "favourited": false,
        "reblogged": false,
        "muted": false,
        "bookmarked": false,
        "pinned": false,
        "reblog": Value::Null,
        "application": Value::Null,
        "mentions": [],
        "tags": [],
        "emojis": [],
        "card": Value::Null,
        "poll": Value::Null,
    }))
}

/// Translate a note, panicking-free, for callers that already know it is local.
///
/// Returns an empty object rather than failing, so a single malformed row
/// cannot take down a whole timeline render. Callers that need to distinguish
/// use [`try_status`].
pub fn status(note: &Value, author: &Author, base_domain: &str) -> Value {
    try_status(note, author, base_domain).unwrap_or_else(|| json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_media_type_is_unknown_rather_than_assumed() {
        let attachment = json!({
            "type": "Document",
            "mediaType": "application/pdf",
            "url": "https://alice.brolly.test/~/media/doc",
        });
        assert_eq!(media_attachment(&attachment)["type"], "unknown");
    }

    #[test]
    fn each_media_kind_maps_to_its_player() {
        for (media_type, expected) in [
            ("image/png", "image"),
            ("image/jpeg", "image"),
            ("video/mp4", "video"),
            ("audio/ogg", "audio"),
        ] {
            let attachment = json!({"mediaType": media_type, "url": "https://x/y"});
            assert_eq!(media_attachment(&attachment)["type"], expected);
        }
    }

    #[test]
    fn a_single_attachment_object_is_accepted_as_well_as_an_array() {
        // AS2 permits either, and a sender that emits a bare object should not
        // lose its image.
        let note = json!({
            "attachment": {"mediaType": "image/png", "url": "https://x/y"},
        });
        assert_eq!(media_attachments(&note).as_array().unwrap().len(), 1);
    }
}
