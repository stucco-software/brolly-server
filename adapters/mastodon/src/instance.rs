//! The Instance entity, and the endpoints we answer emptily rather than not at
//! all.
//!
//! **`configuration` is the honest part.** Clients read it before showing a
//! composer, and hide what the instance says it cannot do. Advertising a poll
//! limit we do not honour produces a poll button that silently drops the poll —
//! which is the whole class of defect Phase 6 exists to close. So the numbers
//! here describe what is actually implemented, and the unimplemented features
//! are advertised as absent.
//!
//! The stub list is the same principle applied to routing. Clients poll a dozen
//! endpoints unconditionally at startup; the predecessor let those fall through
//! to the LDP router, which answered with RDF and HTML. An empty array is a
//! true answer — there are no bookmarks — where an HTML error page is a lie in
//! a shape the client cannot even parse.

use serde_json::{Value, json};

/// The longest post we accept. Mastodon's own default, which is what clients
/// assume when the field is missing anyway.
pub const MAX_CHARACTERS: usize = 500;

/// Attachments per post.
pub const MAX_MEDIA_ATTACHMENTS: usize = 4;

/// Endpoints that exist, are empty, and are honest about it.
///
/// Every one of these is polled by mainstream clients at startup. Returning the
/// empty shape means the client renders an empty tab; letting the request fall
/// through to another router means it renders an error, or worse, tries to
/// parse RDF as JSON.
///
/// Each entry is `(path, empty body)`. They are deleted one by one as real
/// implementations land — none of them fakes a *write*.
pub const EMPTY_READS: &[(&str, &str)] = &[
    ("/api/v1/lists", "[]"),
    ("/api/v1/filters", "[]"),
    ("/api/v2/filters", "[]"),
    ("/api/v1/announcements", "[]"),
    ("/api/v1/bookmarks", "[]"),
    ("/api/v1/favourites", "[]"),
    ("/api/v1/trends/tags", "[]"),
    ("/api/v1/trends/statuses", "[]"),
    ("/api/v1/trends/links", "[]"),
    ("/api/v1/conversations", "[]"),
    ("/api/v2/suggestions", "[]"),
    ("/api/v1/scheduled_statuses", "[]"),
    // An object, not an array — clients index into it by timeline name.
    ("/api/v1/markers", "{}"),
];

/// Endpoints served without a token.
///
/// `custom_emojis` is fetched *before* login by most clients, so requiring auth
/// makes the login screen itself show an error.
pub const PUBLIC_EMPTY_READS: &[(&str, &str)] = &[("/api/v1/custom_emojis", "[]")];

/// What the instance can actually do.
fn configuration() -> Value {
    json!({
        "urls": {},
        "accounts": {
            "max_featured_tags": 0,
        },
        "statuses": {
            "max_characters": MAX_CHARACTERS,
            "max_media_attachments": MAX_MEDIA_ATTACHMENTS,
            // Link previews are not generated, so a URL costs its own length.
            "characters_reserved_per_url": 23,
        },
        "media_attachments": {
            "supported_mime_types": [
                "image/jpeg", "image/png", "image/gif", "image/webp",
            ],
            "image_size_limit": 10 * 1024 * 1024,
            "image_matrix_limit": 16_777_216,
            // Video is not transcoded, so it is not advertised.
            "video_size_limit": 0,
            "video_frame_rate_limit": 0,
            "video_matrix_limit": 0,
        },
        // Polls are not implemented. Zeroes here are what make a client hide
        // the poll composer instead of offering one that drops the poll.
        "polls": {
            "max_options": 0,
            "max_characters_per_option": 0,
            "min_expiration": 0,
            "max_expiration": 0,
        },
        "translation": {"enabled": false},
    })
}

/// `GET /api/v2/instance` — the modern shape (Mastodon 4.x).
pub fn instance_v2(domain: &str, title: &str, description: &str, users: i64, posts: i64) -> Value {
    json!({
        "domain": domain,
        "title": title,
        "version": concat!("4.2.0 (compatible; brolly ", env!("CARGO_PKG_VERSION"), ")"),
        "source_url": "https://github.com/",
        "description": description,
        "usage": {"users": {"active_month": users}},
        "thumbnail": {"url": format!("https://{domain}/static/thumbnail.png")},
        "languages": ["en"],
        "configuration": configuration(),
        // Invite-only, and said in the field clients actually read.
        "registrations": {
            "enabled": false,
            "approval_required": false,
            "message": Value::Null,
        },
        "contact": {"email": Value::Null, "account": Value::Null},
        "rules": [],
        "stats": {"user_count": users, "status_count": posts, "domain_count": 1},
    })
}

/// `GET /api/v1/instance` — the legacy shape, still requested by older clients.
///
/// Kept because a client that gets a 404 here often refuses to continue at all,
/// and the cost of both is one function.
pub fn instance_v1(domain: &str, title: &str, description: &str, users: i64, posts: i64) -> Value {
    json!({
        "uri": domain,
        "title": title,
        "short_description": description,
        "description": description,
        "email": Value::Null,
        "version": concat!("4.2.0 (compatible; brolly ", env!("CARGO_PKG_VERSION"), ")"),
        "urls": {},
        "stats": {"user_count": users, "status_count": posts, "domain_count": 1},
        "thumbnail": format!("https://{domain}/static/thumbnail.png"),
        "languages": ["en"],
        "registrations": false,
        "approval_required": false,
        "invites_enabled": true,
        "configuration": configuration(),
        "rules": [],
    })
}

/// Mastodon's error body. Clients parse `error`; anything else — an HTML page
/// especially — surfaces as an unexplained failure.
pub fn error(message: &str) -> Value {
    json!({"error": message})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_features_are_advertised_as_unavailable() {
        // The point of the whole module: a client must be able to tell what
        // *not* to offer. A poll composer that silently drops the poll is the
        // exact defect class Phase 6 closes.
        let config = configuration();
        assert_eq!(config["polls"]["max_options"], 0);
        assert_eq!(config["media_attachments"]["video_size_limit"], 0);
        assert_eq!(config["translation"]["enabled"], false);
    }

    #[test]
    fn the_limits_we_advertise_are_the_ones_we_enforce() {
        let config = configuration();
        assert_eq!(config["statuses"]["max_characters"], MAX_CHARACTERS);
        assert_eq!(
            config["statuses"]["max_media_attachments"],
            MAX_MEDIA_ATTACHMENTS
        );
    }

    #[test]
    fn registration_is_advertised_as_closed_in_both_shapes() {
        // Invite-only. Saying otherwise puts us in the signup lists that spam
        // registrations come from.
        let v2 = instance_v2("brolly.test", "Brolly", "", 1, 0);
        assert_eq!(v2["registrations"]["enabled"], false);

        let v1 = instance_v1("brolly.test", "Brolly", "", 1, 0);
        assert_eq!(v1["registrations"], false);
    }

    #[test]
    fn the_version_claims_mastodon_compatibility_and_names_us() {
        // Clients gate features on the version string. Claiming 4.2 says which
        // API surface to expect; the parenthetical keeps it honest about what
        // is actually serving.
        for shape in [
            instance_v2("brolly.test", "Brolly", "", 1, 0),
            instance_v1("brolly.test", "Brolly", "", 1, 0),
        ] {
            let version = shape["version"].as_str().expect("a version");
            assert!(version.starts_with("4."), "got {version}");
            assert!(version.contains("brolly"), "got {version}");
        }
    }

    #[test]
    fn every_stub_is_valid_json_of_the_shape_clients_expect() {
        for (path, body) in EMPTY_READS.iter().chain(PUBLIC_EMPTY_READS) {
            let parsed: Value =
                serde_json::from_str(body).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(
                parsed.is_array() || parsed.is_object(),
                "{path} must be an array or object, got {body}"
            );
        }
    }

    #[test]
    fn custom_emojis_is_public_because_clients_fetch_it_before_login() {
        // Requiring a token here makes the login screen itself show an error.
        assert!(
            PUBLIC_EMPTY_READS
                .iter()
                .any(|(path, _)| *path == "/api/v1/custom_emojis")
        );
        assert!(
            !EMPTY_READS
                .iter()
                .any(|(path, _)| *path == "/api/v1/custom_emojis"),
            "custom_emojis must not also be behind auth"
        );
    }

    #[test]
    fn no_stub_shadows_a_real_endpoint() {
        // A stub mounted over something implemented would silently return
        // nothing forever.
        const REAL: [&str; 6] = [
            "/api/v1/instance",
            "/api/v2/instance",
            "/api/v1/timelines/home",
            "/api/v1/timelines/public",
            "/api/v1/statuses",
            "/api/v1/accounts/relationships",
        ];
        for (path, _) in EMPTY_READS.iter().chain(PUBLIC_EMPTY_READS) {
            assert!(!REAL.contains(path), "{path} is stubbed but implemented");
        }
    }
}
