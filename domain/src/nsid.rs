//! ATProtocol NSID → predicate namespace.
//!
//! The predecessor flattened every lexicon into one namespace:
//! `urn:atproto:field:text`. That collides — `app.bsky.feed.post#text` and
//! `site.standard.doc#text` became the same predicate, so two unrelated
//! lexicons' fields silently merged in the pod.
//!
//! Deriving the namespace from the record's `$type` keeps every lexicon in its
//! own term space, which is what lets **any** lexicon ingest faithfully with no
//! mapping table (decision D7's faithful layer).

/// Namespace for a lexicon: `app.bsky.feed.post` → `at://app.bsky.feed.post#`.
pub fn namespace(nsid: &str) -> String {
    format!("at://{nsid}#")
}

/// Predicate for one field of one lexicon.
pub fn predicate(nsid: &str, field: &str) -> String {
    format!("at://{nsid}#{field}")
}

/// Inverse of [`predicate`]: recover `(nsid, field)`.
pub fn split(iri: &str) -> Option<(&str, &str)> {
    iri.strip_prefix("at://")?.split_once('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_lexicons_do_not_collide() {
        let bsky = predicate("app.bsky.feed.post", "text");
        let other = predicate("site.standard.doc", "text");
        assert_ne!(
            bsky, other,
            "the predecessor's flat urn:atproto:field: namespace merged these"
        );
    }

    #[test]
    fn predicate_round_trips() {
        let p = predicate("app.bsky.feed.post", "createdAt");
        assert_eq!(split(&p), Some(("app.bsky.feed.post", "createdAt")));
    }

    #[test]
    fn namespace_is_the_predicate_prefix() {
        assert!(predicate("a.b.c", "d").starts_with(&namespace("a.b.c")));
    }
}
