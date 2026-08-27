//! AS2 → Mastodon entity translation.
//!
//! This file is where two of the predecessor's verified P0 defects become
//! regression tests, because both were *silent* — the API accepted the field,
//! returned 200, and dropped it:
//!
//! * **Media attachments.** `to_mastodon_status` hardcoded
//!   `"media_attachments": []` (`translate.rs:109`), so an upload succeeded and
//!   the post published with no image.
//! * **Content warnings.** `sensitive`, `spoiler_text` and `language` were
//!   accepted and ignored (`statuses.rs:24-30`), so a CW'd post published fully
//!   exposed. That is the worst failure mode in the list: the member believed
//!   they had hidden something.
//!
//! Silent data loss cannot be caught by a client, so it is caught here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_mastodon::translate::{self, Author};
use serde_json::{Value, json};
use uuid::Uuid;

const BASE: &str = "brolly.test";
const OWNER: &str = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

fn owner() -> Uuid {
    Uuid::parse_str(OWNER).unwrap()
}

fn author() -> Author {
    Author {
        user_id: owner(),
        username: "alice".into(),
        display_name: "Alice Example".into(),
        bio: "Testing in production".into(),
        locked: false,
        bot: false,
        discoverable: true,
        created_at: "2026-01-01T00:00:00Z".into(),
    }
}

/// A note as it is actually stored — faithful AS2, as the delivery path wrote it.
fn note(id: &str) -> Value {
    json!({
        "type": "Note",
        "id": format!("https://alice.brolly.test/~/notes/{id}"),
        "attributedTo": "https://alice.brolly.test/actor",
        "content": "<p>hello fediverse</p>",
        "published": "2026-08-26T12:00:00Z",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
    })
}

fn a_note_id() -> String {
    brolly_mastodon::status_id::new_note_id(1_724_000_000_000, [7; 10])
}

// --- the two silent-loss regressions ----------------------------------------

#[test]
fn attachments_are_rendered_and_not_hardcoded_empty() {
    // The exact predecessor defect: upload succeeded, post published with no
    // image, nothing anywhere said so.
    let mut note = note(&a_note_id());
    note["attachment"] = json!([{
        "type": "Document",
        "mediaType": "image/png",
        "url": "https://alice.brolly.test/~/media/abc",
        "name": "A photograph of a very small dog",
    }]);

    let status = translate::status(&note, &author(), BASE);
    let media = status["media_attachments"].as_array().expect("an array");

    assert_eq!(media.len(), 1, "the attachment was dropped");
    assert_eq!(media[0]["type"], "image");
    assert_eq!(media[0]["url"], "https://alice.brolly.test/~/media/abc");
    assert_eq!(
        media[0]["description"], "A photograph of a very small dog",
        "alt text must survive — it is the accessibility payload"
    );
    // Clients render `preview_url` in timelines; a null one shows a broken box.
    assert_eq!(media[0]["preview_url"], media[0]["url"]);
}

#[test]
fn a_content_warning_survives_translation() {
    // The worst failure mode in the P0 list: the member believed they had
    // hidden something and had not.
    let mut note = note(&a_note_id());
    note["summary"] = json!("spoilers for a 40 year old film");
    note["sensitive"] = json!(true);

    let status = translate::status(&note, &author(), BASE);

    assert_eq!(status["spoiler_text"], "spoilers for a 40 year old film");
    assert_eq!(status["sensitive"], true);
}

#[test]
fn a_summary_implies_sensitive_even_when_the_flag_is_absent() {
    // Mastodon's own behaviour, and the safe direction to be wrong in.
    let mut note = note(&a_note_id());
    note["summary"] = json!("cw: bees");

    let status = translate::status(&note, &author(), BASE);
    assert_eq!(status["sensitive"], true);
}

#[test]
fn a_note_with_no_warning_is_not_marked_sensitive() {
    let status = translate::status(&note(&a_note_id()), &author(), BASE);
    assert_eq!(status["spoiler_text"], "");
    assert_eq!(status["sensitive"], false);
}

#[test]
fn language_survives_translation() {
    let mut note = note(&a_note_id());
    note["contentMap"] = json!({"pt": "<p>olá</p>"});

    let status = translate::status(&note, &author(), BASE);
    assert_eq!(status["language"], "pt");
}

#[test]
fn a_note_without_a_language_reports_null_rather_than_guessing() {
    // Clients use `language` for translation offers and filtering. Guessing
    // "en" would mislabel every post that did not declare one.
    let status = translate::status(&note(&a_note_id()), &author(), BASE);
    assert!(status["language"].is_null());
}

// --- identity and shape ------------------------------------------------------

#[test]
fn the_status_id_round_trips_to_the_note() {
    let id = a_note_id();
    let status = translate::status(&note(&id), &author(), BASE);

    let rendered = status["id"].as_str().expect("an id");
    let (note_id, user) = brolly_mastodon::status_id::decode(rendered).expect("decode");
    assert_eq!(note_id, id);
    assert_eq!(user, owner());
}

#[test]
fn a_note_this_instance_did_not_mint_has_no_status_id() {
    // A remote note's IRI carries no ULID we can encode. Inventing one would
    // produce an ID that resolves to the wrong pod.
    let mut remote = note(&a_note_id());
    remote["id"] = json!("https://mastodon.social/users/bob/statuses/12345");

    assert!(
        translate::try_status(&remote, &author(), BASE).is_none(),
        "a foreign note must not be given a local status id"
    );
}

#[test]
fn the_account_is_embedded_because_every_client_needs_it() {
    let status = translate::status(&note(&a_note_id()), &author(), BASE);
    let account = &status["account"];

    assert_eq!(account["username"], "alice");
    assert_eq!(
        account["acct"], "alice",
        "a local account's acct is bare — user@host is the remote form"
    );
    assert_eq!(account["display_name"], "Alice Example");
    assert_eq!(account["url"], "https://alice.brolly.test/");
}

#[test]
fn timestamps_are_iso8601_as_clients_expect() {
    let status = translate::status(&note(&a_note_id()), &author(), BASE);
    assert_eq!(status["created_at"], "2026-08-26T12:00:00Z");
}

#[test]
fn a_reply_names_its_parent() {
    let parent = a_note_id();
    let mut child = note(&a_note_id());
    child["inReplyTo"] = json!(format!("https://alice.brolly.test/~/notes/{parent}"));

    let status = translate::status(&child, &author(), BASE);
    let in_reply_to = status["in_reply_to_id"].as_str().expect("a parent id");
    assert_eq!(
        brolly_mastodon::status_id::decode(in_reply_to).unwrap().0,
        parent
    );
}

#[test]
fn a_top_level_post_has_no_parent() {
    let status = translate::status(&note(&a_note_id()), &author(), BASE);
    assert!(status["in_reply_to_id"].is_null());
    assert!(status["in_reply_to_account_id"].is_null());
}

// --- visibility --------------------------------------------------------------

#[test]
fn visibility_is_derived_from_the_audience() {
    // Mastodon's four levels are addressing conventions, not a field. Getting
    // this backwards publishes a followers-only post to the public timeline.
    let public = "https://www.w3.org/ns/activitystreams#Public";
    let followers = "https://alice.brolly.test/followers";
    let bob = "https://bob.brolly.test/actor";

    let cases = [
        (json!([public]), json!([followers]), "public"),
        (json!([followers]), json!([public]), "unlisted"),
        (json!([followers]), json!([]), "private"),
        (json!([bob]), json!([]), "direct"),
    ];

    for (to, cc, expected) in cases {
        let mut note = note(&a_note_id());
        note["to"] = to.clone();
        note["cc"] = cc.clone();

        let status = translate::status(&note, &author(), BASE);
        assert_eq!(
            status["visibility"], expected,
            "to={to} cc={cc} should be {expected}"
        );
    }
}

#[test]
fn an_unaddressed_note_is_direct_rather_than_public() {
    // Failing open here would publish something nobody was addressed on.
    let mut note = note(&a_note_id());
    note.as_object_mut().unwrap().remove("to");

    let status = translate::status(&note, &author(), BASE);
    assert_eq!(status["visibility"], "direct");
}

#[test]
fn the_public_collection_is_recognised_in_both_namespaces() {
    // The AS2 namespace split that shipped a production bug in the predecessor:
    // the writer stored `https://`, older readers scanned `http://`. Storage
    // canonicalizes now, but a note can arrive over the wire either way.
    for public in [
        "https://www.w3.org/ns/activitystreams#Public",
        "http://www.w3.org/ns/activitystreams#Public",
        // The two shorthands the spec also permits.
        "as:Public",
        "Public",
    ] {
        let mut note = note(&a_note_id());
        note["to"] = json!([public]);

        let status = translate::status(&note, &author(), BASE);
        assert_eq!(
            status["visibility"], "public",
            "{public} was not recognised as the public collection"
        );
    }
}

// --- accounts ----------------------------------------------------------------

#[test]
fn an_account_carries_the_flags_that_change_client_behaviour() {
    let mut author = author();
    author.locked = true;
    author.bot = true;
    author.discoverable = false;

    let account = translate::account(&author, BASE);
    assert_eq!(
        account["locked"], true,
        "clients show a lock and a request UI"
    );
    assert_eq!(account["bot"], true);
    assert_eq!(account["discoverable"], false);
}

#[test]
fn an_account_id_resolves_back_to_its_member() {
    let account = translate::account(&author(), BASE);
    let id = account["id"].as_str().expect("an id");
    assert_eq!(translate::account_id_to_uuid(id), Some(owner()));
}

#[test]
fn account_ids_are_fixed_width_too() {
    // Same reasoning as status IDs: clients sort and paginate on them.
    let mut short = author();
    short.username = "jo".into();
    let mut long = author();
    long.username = "a-very-long-member-name-indeed".into();

    assert_eq!(
        translate::account(&short, BASE)["id"]
            .as_str()
            .unwrap()
            .len(),
        translate::account(&long, BASE)["id"]
            .as_str()
            .unwrap()
            .len()
    );
}
