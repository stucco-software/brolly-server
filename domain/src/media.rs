//! The media gate: what this server stores, and how much of it (spec 4).
//!
//! One allow-list and one size limit, both enforced at the single choke point
//! every protocol's binary already passes through (`ldp::prepare`) and both
//! advertised by the Mastodon instance configuration — the stage's premise is
//! that an advertised contract nothing keeps is a bug, and the two tests here
//! and in `brolly-mastodon`'s instance module are what keep the three from
//! drifting apart silently.

/// The content types this server stores as media (spec 4, H2).
///
/// A binary is stored only if its content type — parameters stripped, as
/// [`crate::syntax::media_type_of`] produces — is on this list. Anything else
/// is a 415 with this list in the body: the type is syntactically fine, this
/// server just doesn't store it as media. Before the list, a member-typed
/// `text/html` on the member's own origin was stored XSS: the bytes were
/// served back with the type the uploader chose, on the origin that holds the
/// member's session.
///
/// **`image/svg+xml` is deliberately absent.** SVG is script; a member-hosted
/// SVG on the member's origin, rendered by any browser that follows the type,
/// is stored XSS with the pod's cookies in scope. When SVG is wanted, it wants
/// its own serving rules (`Content-Disposition`, CSP), and that is a recorded
/// decision to reopen, not a default to slip in.
///
/// The six RDF syntaxes and ADR 0007's `rdf+xml` refusal are upstream of this
/// list and unchanged: a parseable RDF type never reaches the binary branch,
/// and `rdf+xml` is refused outright rather than stored as a blob.
///
/// `text/plain` and friends are here, not in the graph store: they are not RDF
/// syntaxes, and plain text is not script.
pub const ALLOWED_MEDIA_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/avif",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/flac",
    "audio/webm",
    "video/mp4",
    "video/webm",
    "application/pdf",
    "application/zip",
    "text/plain",
    "text/markdown",
    "text/csv",
    "application/octet-stream",
];

/// The upload limit this server enforces, and the one it advertises (spec 4,
/// H3).
///
/// `DefaultBodyLimit` on the pod and media routes, overridable with
/// `BROLLY_MAX_UPLOAD_BYTES`; the Mastodon instance configuration's
/// `image_size_limit` is this same constant, with a test asserting the two are
/// equal — an advertised limit and an enforced limit that differ is the bug
/// this stage closes. The limit is bytes-on-the-wire: a multipart file at
/// exactly this number 413s, because its framing counts too. Accepted — the
/// one constant is worth more than a fudge factor.
pub const MAX_UPLOAD_BYTES: usize = 10 * 1024 * 1024;

/// True when `media_type` — a bare, parameter-stripped type — is one this
/// server stores as media. The stripping is the caller's
/// ([`crate::syntax::media_type_of`]): `image/png; charset=utf-8` is
/// `image/png`.
pub fn is_allowed_media_type(media_type: &str) -> bool {
    ALLOWED_MEDIA_TYPES.contains(&media_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_what_the_spec_names() {
        // The spec's own block, in its order, so a diff against the spec is
        // readable. `application/octet-stream` last, as the catch-all a
        // type-less client gets.
        assert_eq!(
            ALLOWED_MEDIA_TYPES,
            &[
                "image/jpeg",
                "image/png",
                "image/gif",
                "image/webp",
                "image/avif",
                "audio/mpeg",
                "audio/ogg",
                "audio/wav",
                "audio/flac",
                "audio/webm",
                "video/mp4",
                "video/webm",
                "application/pdf",
                "application/zip",
                "text/plain",
                "text/markdown",
                "text/csv",
                "application/octet-stream",
            ]
        );
    }

    #[test]
    fn svg_is_absent_and_stays_absent() {
        // The one absence that is a decision rather than an omission (spec 4,
        // H2): SVG is script, and a member-hosted SVG on the member's origin
        // is stored XSS. Reopening it wants serving rules, not a list edit.
        assert!(!is_allowed_media_type("image/svg+xml"));
        assert!(is_allowed_media_type("image/png"));
        assert!(!is_allowed_media_type("text/html"));
    }
}
