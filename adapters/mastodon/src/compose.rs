//! Turning a Mastodon compose form into an AS2 Note.
//!
//! This is the write half of the two silent-loss defects. `translate` proves a
//! stored note *renders* its media and content warning; this proves the note
//! ever carried them. The predecessor accepted `media_ids`, `sensitive`,
//! `spoiler_text` and `language` and dropped all four on the floor — 200 OK, no
//! image, warning gone.
//!
//! Pure: it takes a form and returns JSON. Publishing is the server's job.

use serde_json::{Value, json};

/// The AS2 public collection.
pub const PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

/// One attachment, already resolved from a media id to something addressable.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub url: String,
    pub media_type: String,
    /// Alt text. The accessibility payload, and the thing most easily lost.
    pub description: Option<String>,
}

/// A compose request, validated.
#[derive(Debug, Clone, Default)]
pub struct Composition {
    pub text: String,
    pub spoiler_text: String,
    pub sensitive: bool,
    pub language: Option<String>,
    pub visibility: String,
    /// The IRI of the note being replied to.
    pub in_reply_to: Option<String>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ComposeError {
    /// Neither text nor media. Mastodon allows either alone, but not neither.
    Empty,
    TooLong {
        limit: usize,
        actual: usize,
    },
    TooManyAttachments {
        limit: usize,
        actual: usize,
    },
    UnknownVisibility(String),
}

impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComposeError::Empty => write!(f, "Validation failed: Text can't be blank"),
            ComposeError::TooLong { limit, actual } => write!(
                f,
                "Validation failed: Text is too long (maximum is {limit} characters, got {actual})"
            ),
            ComposeError::TooManyAttachments { limit, actual } => write!(
                f,
                "Validation failed: Cannot attach more than {limit} files (got {actual})"
            ),
            ComposeError::UnknownVisibility(v) => {
                write!(f, "Validation failed: Visibility {v} is not recognised")
            }
        }
    }
}

/// Check a composition against what the instance advertises it accepts.
///
/// The limits are the same constants `/api/v1/instance` publishes, so a client
/// that respected the advertised configuration cannot trip these.
pub fn validate(composition: &Composition) -> Result<(), ComposeError> {
    const VISIBILITIES: [&str; 4] = ["public", "unlisted", "private", "direct"];

    if !VISIBILITIES.contains(&composition.visibility.as_str()) {
        return Err(ComposeError::UnknownVisibility(
            composition.visibility.clone(),
        ));
    }
    // Media alone is a legitimate post — an image with no caption.
    if composition.text.trim().is_empty() && composition.attachments.is_empty() {
        return Err(ComposeError::Empty);
    }
    // Counted in characters, not bytes: a post of 500 emoji is 500 characters.
    let length = composition.text.chars().count();
    if length > crate::instance::MAX_CHARACTERS {
        return Err(ComposeError::TooLong {
            limit: crate::instance::MAX_CHARACTERS,
            actual: length,
        });
    }
    if composition.attachments.len() > crate::instance::MAX_MEDIA_ATTACHMENTS {
        return Err(ComposeError::TooManyAttachments {
            limit: crate::instance::MAX_MEDIA_ATTACHMENTS,
            actual: composition.attachments.len(),
        });
    }
    Ok(())
}

/// Mastodon's visibility levels as AS2 addressing.
///
/// The inverse of `translate::visibility`, and the pair has to agree or a post
/// composes as one thing and renders as another.
fn audience(visibility: &str, followers: &str) -> (Vec<String>, Vec<String>) {
    match visibility {
        "public" => (vec![PUBLIC.into()], vec![followers.into()]),
        "unlisted" => (vec![followers.into()], vec![PUBLIC.into()]),
        "private" => (vec![followers.into()], vec![]),
        // Direct messages address named actors. Mention parsing is not built,
        // so this addresses nobody — which is strictly safer than addressing
        // more people than intended.
        _ => (vec![], vec![]),
    }
}

fn attachment_json(attachment: &Attachment) -> Value {
    let mut value = json!({
        "type": "Document",
        "mediaType": attachment.media_type,
        "url": attachment.url,
    });
    // AS2 carries alt text as `name`. Absent rather than empty, so a client
    // showing "no description" can tell the difference.
    if let Some(description) = attachment
        .description
        .as_deref()
        .filter(|d| !d.trim().is_empty())
    {
        value["name"] = json!(description);
    }
    value
}

/// Build the AS2 Note a composition publishes.
///
/// The `id` is left for the publisher to mint, since that is where the note's
/// IRI is decided.
pub fn note(composition: &Composition, actor: &str, followers: &str, published: &str) -> Value {
    let (to, cc) = audience(&composition.visibility, followers);

    let mut note = json!({
        "type": "Note",
        "attributedTo": actor,
        "content": composition.text,
        "published": published,
        "to": to,
        "cc": cc,
    });

    // A content warning is AS2 `summary` — exactly Mastodon's own mapping, so
    // it federates without translation.
    if !composition.spoiler_text.trim().is_empty() {
        note["summary"] = json!(composition.spoiler_text);
        // A warning implies sensitive, matching Mastodon.
        note["sensitive"] = json!(true);
    } else if composition.sensitive {
        note["sensitive"] = json!(true);
    }

    if let Some(language) = composition.language.as_deref().filter(|l| !l.is_empty()) {
        // `contentMap` is the federated form. The predecessor stored a private
        // predicate because federation was off; it is on now.
        note["contentMap"] = json!({language: composition.text});
    }

    if let Some(parent) = composition.in_reply_to.as_deref() {
        note["inReplyTo"] = json!(parent);
    }

    if !composition.attachments.is_empty() {
        note["attachment"] = Value::Array(
            composition
                .attachments
                .iter()
                .map(attachment_json)
                .collect(),
        );
    }

    note
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_composition() -> Composition {
        Composition {
            text: "hello".into(),
            visibility: "public".into(),
            ..Default::default()
        }
    }

    const FOLLOWERS: &str = "https://alice.brolly.test/followers";
    const ACTOR: &str = "https://alice.brolly.test/actor";

    #[test]
    fn a_content_warning_becomes_as2_summary_and_implies_sensitive() {
        // The predecessor accepted both and stored neither, so a warned post
        // published fully exposed.
        let mut composition = a_composition();
        composition.spoiler_text = "spoilers".into();

        let note = note(&composition, ACTOR, FOLLOWERS, "2026-08-26T12:00:00Z");
        assert_eq!(note["summary"], "spoilers");
        assert_eq!(note["sensitive"], true);
    }

    #[test]
    fn sensitive_alone_is_carried_without_inventing_a_warning() {
        let mut composition = a_composition();
        composition.sensitive = true;

        let note = note(&composition, ACTOR, FOLLOWERS, "2026-08-26T12:00:00Z");
        assert_eq!(note["sensitive"], true);
        assert!(
            note.get("summary").is_none(),
            "an empty summary renders as a blank warning bar"
        );
    }

    #[test]
    fn attachments_carry_their_alt_text() {
        let mut composition = a_composition();
        composition.attachments = vec![Attachment {
            url: "https://alice.brolly.test/~/media/1".into(),
            media_type: "image/png".into(),
            description: Some("a small dog".into()),
        }];

        let note = note(&composition, ACTOR, FOLLOWERS, "2026-08-26T12:00:00Z");
        let attachment = &note["attachment"][0];
        assert_eq!(attachment["mediaType"], "image/png");
        assert_eq!(attachment["url"], "https://alice.brolly.test/~/media/1");
        assert_eq!(attachment["name"], "a small dog");
    }

    #[test]
    fn an_attachment_without_alt_text_omits_the_field() {
        let mut composition = a_composition();
        composition.attachments = vec![Attachment {
            url: "https://alice.brolly.test/~/media/1".into(),
            media_type: "image/png".into(),
            description: None,
        }];

        let note = note(&composition, ACTOR, FOLLOWERS, "2026-08-26T12:00:00Z");
        assert!(note["attachment"][0].get("name").is_none());
    }

    #[test]
    fn language_is_carried_as_content_map() {
        let mut composition = a_composition();
        composition.language = Some("pt".into());

        let note = note(&composition, ACTOR, FOLLOWERS, "2026-08-26T12:00:00Z");
        assert_eq!(note["contentMap"]["pt"], "hello");
    }

    #[test]
    fn visibility_round_trips_through_translation() {
        // Compose and render must agree, or a post is composed as one thing and
        // displayed as another.
        for visibility in ["public", "unlisted", "private"] {
            let mut composition = a_composition();
            composition.visibility = visibility.into();

            let mut note = note(&composition, ACTOR, FOLLOWERS, "2026-08-26T12:00:00Z");
            note["id"] = json!(format!(
                "https://alice.brolly.test/~/notes/{}",
                crate::status_id::new_note_id(1_724_000_000_000, [1; 10])
            ));

            let author = crate::translate::Author {
                user_id: uuid::Uuid::nil(),
                username: "alice".into(),
                display_name: String::new(),
                bio: String::new(),
                locked: false,
                bot: false,
                discoverable: true,
                created_at: String::new(),
            };
            let status = crate::translate::status(&note, &author, "brolly.test");
            assert_eq!(
                status["visibility"], visibility,
                "{visibility} did not survive the round trip"
            );
        }
    }

    #[test]
    fn a_post_with_only_media_is_allowed() {
        // An image with no caption is a legitimate post.
        let mut composition = a_composition();
        composition.text = String::new();
        composition.attachments = vec![Attachment {
            url: "https://alice.brolly.test/~/media/1".into(),
            media_type: "image/png".into(),
            description: None,
        }];
        assert_eq!(validate(&composition), Ok(()));
    }

    #[test]
    fn a_post_with_neither_text_nor_media_is_refused() {
        let mut composition = a_composition();
        composition.text = "   ".into();
        assert_eq!(validate(&composition), Err(ComposeError::Empty));
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        // 500 emoji is 500 characters and about 2000 bytes. Counting bytes
        // would refuse a post the instance advertised as acceptable.
        let mut composition = a_composition();
        composition.text = "🌱".repeat(crate::instance::MAX_CHARACTERS);
        assert_eq!(validate(&composition), Ok(()));

        composition.text = "🌱".repeat(crate::instance::MAX_CHARACTERS + 1);
        assert!(matches!(
            validate(&composition),
            Err(ComposeError::TooLong { .. })
        ));
    }

    #[test]
    fn too_many_attachments_is_refused_with_the_advertised_limit() {
        let mut composition = a_composition();
        composition.attachments = (0..5)
            .map(|n| Attachment {
                url: format!("https://alice.brolly.test/~/media/{n}"),
                media_type: "image/png".into(),
                description: None,
            })
            .collect();

        assert_eq!(
            validate(&composition),
            Err(ComposeError::TooManyAttachments {
                limit: crate::instance::MAX_MEDIA_ATTACHMENTS,
                actual: 5
            })
        );
    }

    #[test]
    fn an_unknown_visibility_is_refused_rather_than_defaulted() {
        // Defaulting to public would publish something the client asked to keep
        // private.
        let mut composition = a_composition();
        composition.visibility = "sekrit".into();
        assert!(matches!(
            validate(&composition),
            Err(ComposeError::UnknownVisibility(_))
        ));
    }

    #[test]
    fn a_direct_post_addresses_nobody_rather_than_everybody() {
        let mut composition = a_composition();
        composition.visibility = "direct".into();

        let note = note(&composition, ACTOR, FOLLOWERS, "2026-08-26T12:00:00Z");
        assert_eq!(note["to"], json!([]));
        assert_eq!(note["cc"], json!([]));
    }
}
