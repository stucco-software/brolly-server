//! The canonical layer: additional assertions for entities that genuinely are
//! the same thing across protocols.
//!
//! The faithful layer ([`crate::faithful`]) is always emitted and is lossless.
//! This layer is *additive* — it asserts standard-vocabulary triples **onto the
//! same subject IRI** so a Solid reader, an AS2 reader, and a Mastodon
//! projection all see one node.
//!
//! Harmonization is agreement on the **subject**, not just the predicate. The
//! Solid profile writer, the AP actor builder, and the ATProto profile adapter
//! all assert `foaf:name` onto `…/profile#me`. There is nothing to join, and no
//! `owl:sameAs` reasoning is required.
//!
//! **Profile only, for now.** A second entity earns its way in when there is a
//! concrete reader for it. An unmapped lexicon is still stored, still exported,
//! and still round-trips — it is simply not cross-visible. Graceful
//! degradation, no gate on ingest.

use oxrdf::{GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::Value;

use crate::vocab;

/// One field mapping: a source field in some protocol's record, and the
/// canonical predicate it also asserts.
struct FieldMap {
    /// Field name in the source record.
    source: &'static str,
    /// Canonical predicate asserted onto the shared subject.
    predicate: &'static str,
}

/// `app.bsky.actor.profile` → the WebID.
const BSKY_PROFILE: &[FieldMap] = &[
    FieldMap {
        source: "displayName",
        predicate: vocab::FOAF_NAME,
    },
    FieldMap {
        source: "description",
        predicate: vocab::VCARD_NOTE,
    },
];

/// AS2 `Person` → the WebID.
const AS2_PERSON: &[FieldMap] = &[
    FieldMap {
        source: "name",
        predicate: vocab::FOAF_NAME,
    },
    FieldMap {
        source: "summary",
        predicate: vocab::VCARD_NOTE,
    },
];

/// The whole mapping table. Keyed by the record's `$type` / AS2 `type`.
fn mapping_for(record_type: &str) -> Option<&'static [FieldMap]> {
    match record_type {
        "app.bsky.actor.profile" => Some(BSKY_PROFILE),
        "Person" | "https://www.w3.org/ns/activitystreams#Person" => Some(AS2_PERSON),
        _ => None,
    }
}

/// True if this record type contributes to the canonical layer at all.
pub fn is_mapped(record_type: &str) -> bool {
    mapping_for(record_type).is_some()
}

/// Emit canonical triples for `record`, asserted onto `subject`.
///
/// Returns an empty vec for unmapped types — that is the normal case and not an
/// error. `subject` is the *shared* node (a WebID), not the record's own IRI.
pub fn assert_onto(
    record: &Value,
    record_type: &str,
    subject: &NamedNode,
    graph: &NamedNode,
) -> Vec<Quad> {
    let Some(mapping) = mapping_for(record_type) else {
        return Vec::new();
    };
    let graph_name = GraphName::NamedNode(graph.clone());

    mapping
        .iter()
        .filter_map(|field| {
            let value = record.get(field.source)?.as_str()?;
            Some(Quad::new(
                NamedOrBlankNode::NamedNode(subject.clone()),
                NamedNode::new_unchecked(field.predicate),
                Term::Literal(Literal::new_simple_literal(value)),
                graph_name.clone(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(s: &str) -> NamedNode {
        NamedNode::new_unchecked(s)
    }

    #[test]
    fn bsky_and_as2_profiles_land_on_the_same_subject_and_predicate() {
        let webid = node("https://alice.brolly.id/profile#me");
        let graph = node("https://alice.brolly.id/profile");

        let from_bsky = assert_onto(
            &json!({"$type": "app.bsky.actor.profile", "displayName": "Alice"}),
            "app.bsky.actor.profile",
            &webid,
            &graph,
        );
        let from_as2 = assert_onto(
            &json!({"type": "Person", "name": "Alice"}),
            "Person",
            &webid,
            &graph,
        );

        assert_eq!(
            from_bsky, from_as2,
            "harmonization is subject + predicate agreement"
        );
        assert_eq!(from_bsky.len(), 1);
        assert_eq!(from_bsky[0].predicate.as_str(), vocab::FOAF_NAME);
    }

    #[test]
    fn unmapped_lexicons_are_not_an_error() {
        let quads = assert_onto(
            &json!({"$type": "site.standard.doc", "text": "hi"}),
            "site.standard.doc",
            &node("https://alice.brolly.id/profile#me"),
            &node("https://alice.brolly.id/doc"),
        );
        assert!(quads.is_empty(), "unmapped types degrade gracefully");
        assert!(!is_mapped("site.standard.doc"));
    }

    #[test]
    fn missing_fields_are_skipped_not_defaulted() {
        let quads = assert_onto(
            &json!({"$type": "app.bsky.actor.profile"}),
            "app.bsky.actor.profile",
            &node("https://alice.brolly.id/profile#me"),
            &node("https://alice.brolly.id/profile"),
        );
        assert!(quads.is_empty());
    }
}
