//! Records into the pod: faithful always, canonical where the type is mapped.
//!
//! This is D7's two layers at the ATProtocol edge, and the reason **any**
//! lexicon can be ingested without anyone writing a mapping first.
//!
//! * **Faithful** quads use predicates derived from the record's own `$type`
//!   (`at://app.bsky.feed.post#text`), so every lexicon gets its own term
//!   space. The predecessor flattened all of them into
//!   `urn:atproto:field:text`, which silently merged `app.bsky.feed.post#text`
//!   with `site.standard.doc#text` — two unrelated lexicons writing over each
//!   other in one pod.
//! * **Canonical** triples are asserted onto the member's WebID for the handful
//!   of types in the mapping table (D8), so a profile written through
//!   ATProtocol lands on the same node the Solid and ActivityPub writers use.
//!
//! Unmapped is the normal case, not an error. Most of the network is lexicons
//! we have never seen, and the point of the faithful layer is that they cost
//! nothing to accept.

use brolly_domain::{canonical, faithful};
use brolly_store::Store;
use brolly_store::write::{WriteError, insert_quads};
use oxigraph::model::NamedNode;
use serde_json::Value;

#[derive(Debug)]
pub enum IngestError {
    /// A record with no `$type` cannot name its own term space, so its fields
    /// have nowhere to land that would not collide with another lexicon's.
    NoType,
    Encode(faithful::FaithfulError),
    Store(WriteError),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::NoType => write!(f, "record has no $type"),
            IngestError::Encode(e) => write!(f, "encode: {e}"),
            IngestError::Store(e) => write!(f, "store: {e}"),
        }
    }
}

impl std::error::Error for IngestError {}

impl From<faithful::FaithfulError> for IngestError {
    fn from(e: faithful::FaithfulError) -> Self {
        IngestError::Encode(e)
    }
}

impl From<WriteError> for IngestError {
    fn from(e: WriteError) -> Self {
        IngestError::Store(e)
    }
}

/// The AT-URI naming a record: `at://<did>/<collection>/<rkey>`.
///
/// **The DID, not the handle** (D11): handles are rented and change, and an
/// AT-URI built on one stops resolving the moment its owner renames. Every wire
/// format gets `did:plc:` from the first commit so there is no migration later.
pub fn at_uri(did: &str, collection: &str, rkey: &str) -> String {
    format!("at://{did}/{collection}/{rkey}")
}

/// The record type, which is also its term space.
pub fn record_type(record: &Value) -> Option<&str> {
    record.get("$type")?.as_str()
}

/// Write a record into the pod.
///
/// Returns the number of quads stored.
///
/// The two layers land in **different graphs**, and that separation is the
/// whole of D8 working:
///
/// * Faithful quads go in the record's own graph, so a delete clears exactly
///   one record and an export can name it.
/// * Canonical quads go in the member's **profile document** graph, asserted
///   onto their WebID — because that is where `profile::read` looks, and
///   `profile::read` is what the ActivityPub actor builder and the Mastodon
///   account projection both call. Writing them into the record's graph
///   instead would be tidy, correct-looking, and invisible to every reader
///   that matters.
pub fn ingest(
    store: &Store,
    record: &Value,
    at_uri: &str,
    webid: &str,
    profile_document: &str,
) -> Result<usize, IngestError> {
    let lexicon = record_type(record).ok_or(IngestError::NoType)?.to_string();

    let subject = NamedNode::new_unchecked(at_uri);
    let graph = NamedNode::new_unchecked(at_uri);

    // Faithful: always, whatever the lexicon.
    let mut quads = faithful::encode(record, &subject, &graph, &lexicon)?;

    // Canonical: only for mapped types, onto the WebID, in the profile
    // document — a *shared* node in the graph every protocol already reads.
    quads.extend(canonical::assert_onto(
        record,
        &lexicon,
        &NamedNode::new_unchecked(webid),
        &NamedNode::new_unchecked(profile_document),
    ));

    Ok(insert_quads(store, &quads)?)
}

/// Read a record back out of the pod, as the wire format it arrived in.
pub fn read(store: &Store, at_uri: &str) -> Option<Value> {
    brolly_store::collection::read_record(store, at_uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const WEBID: &str = "https://alice.brolly.test/profile#me";
    const PROFILE: &str = "https://alice.brolly.test/profile";

    fn store() -> (tempfile::TempDir, std::sync::Arc<Store>) {
        let dir = tempfile::tempdir().unwrap();
        let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
        let store = manager.pod(uuid::Uuid::new_v4()).unwrap();
        (dir, store)
    }

    #[test]
    fn an_unmapped_lexicon_ingests_without_a_mapping() {
        // The whole point. Most of the network is lexicons we have never seen,
        // and they must cost nothing to accept.
        let (_dir, store) = store();
        let record = json!({
            "$type": "site.standard.doc",
            "text": "from a lexicon nobody mapped",
            "createdAt": "2026-08-26T12:00:00Z",
        });
        let uri = at_uri(DID, "site.standard.doc", "3kaaa");

        let written = ingest(&store, &record, &uri, WEBID, PROFILE).expect("ingest");
        assert!(written > 0);
        assert_eq!(read(&store, &uri), Some(record));
    }

    #[test]
    fn two_lexicons_sharing_a_field_name_do_not_collide() {
        // The predecessor's actual bug: both became `urn:atproto:field:text`
        // and one silently overwrote the other.
        let (_dir, store) = store();

        let bsky_uri = at_uri(DID, "app.bsky.feed.post", "3kaaa");
        let doc_uri = at_uri(DID, "site.standard.doc", "3kbbb");

        ingest(
            &store,
            &json!({"$type": "app.bsky.feed.post", "text": "the bsky one"}),
            &bsky_uri,
            WEBID,
            PROFILE,
        )
        .unwrap();
        ingest(
            &store,
            &json!({"$type": "site.standard.doc", "text": "the other one"}),
            &doc_uri,
            WEBID,
            PROFILE,
        )
        .unwrap();

        assert_eq!(read(&store, &bsky_uri).unwrap()["text"], "the bsky one");
        assert_eq!(read(&store, &doc_uri).unwrap()["text"], "the other one");
    }

    #[test]
    fn the_predicates_carry_their_own_lexicon() {
        // What actually prevents the collision above, asserted directly rather
        // than inferred from the records surviving.
        let bsky = brolly_domain::nsid::predicate("app.bsky.feed.post", "text");
        let doc = brolly_domain::nsid::predicate("site.standard.doc", "text");
        assert_ne!(bsky, doc);
        assert!(bsky.contains("app.bsky.feed.post"));
    }

    #[test]
    fn nested_structure_survives_verbatim() {
        // A faithful layer that flattens is not faithful. This is also what
        // makes `rawJson` unnecessary.
        let (_dir, store) = store();
        let record = json!({
            "$type": "site.standard.doc",
            "nested": {"depth": 2, "list": [1, 2, 3], "inner": {"flag": true}},
            "empty_object": {},
            "empty_list": [],
            "null_field": null,
        });
        let uri = at_uri(DID, "site.standard.doc", "3kaaa");

        ingest(&store, &record, &uri, WEBID, PROFILE).unwrap();
        assert_eq!(read(&store, &uri), Some(record));
    }

    #[test]
    fn a_record_without_a_type_is_refused() {
        // With no `$type` there is no term space, so its fields would have to
        // land somewhere shared — which is the collision this design exists to
        // prevent.
        let (_dir, store) = store();
        let uri = at_uri(DID, "site.standard.doc", "3kaaa");
        assert!(matches!(
            ingest(&store, &json!({"text": "orphan"}), &uri, WEBID, PROFILE),
            Err(IngestError::NoType)
        ));
    }

    #[test]
    fn a_mapped_type_also_asserts_onto_the_webid() {
        // D8: the ATProtocol profile writer lands on the same node the Solid
        // and ActivityPub writers use, so there is nothing to join.
        let (_dir, store) = store();
        let record = json!({
            "$type": "app.bsky.actor.profile",
            "displayName": "Alice Example",
        });
        let uri = at_uri(DID, "app.bsky.actor.profile", "self");

        ingest(&store, &record, &uri, WEBID, PROFILE).unwrap();

        // Read the way `profile::read` does — subject WebID, graph profile
        // document — so this asserts the integration and not just that some
        // triple exists somewhere.
        let name = brolly_store::collection::literal_in(
            &store,
            WEBID,
            brolly_domain::vocab::FOAF_NAME,
            PROFILE,
        );
        assert_eq!(
            name.as_deref(),
            Some("Alice Example"),
            "a mapped profile must assert onto the shared WebID node"
        );
    }

    #[test]
    fn an_unmapped_type_asserts_nothing_canonical_and_that_is_fine() {
        let (_dir, store) = store();
        let uri = at_uri(DID, "site.standard.doc", "3kaaa");
        ingest(
            &store,
            &json!({"$type": "site.standard.doc", "displayName": "not a profile"}),
            &uri,
            WEBID,
            PROFILE,
        )
        .expect("unmapped is the normal case, not an error");

        assert_eq!(
            brolly_store::collection::literal_in(
                &store,
                WEBID,
                brolly_domain::vocab::FOAF_NAME,
                PROFILE
            ),
            None,
            "an unmapped lexicon must not write onto the WebID"
        );
    }

    #[test]
    fn an_at_uri_names_the_did_not_the_handle() {
        // D11. A handle is rented; an AT-URI built on one stops resolving the
        // moment its owner renames.
        let uri = at_uri(DID, "app.bsky.feed.post", "3kaaa");
        assert_eq!(
            uri,
            "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kaaa"
        );
        assert!(uri.starts_with("at://did:"));
    }

    #[test]
    fn each_record_lands_in_its_own_graph() {
        // So a delete clears exactly one record, and an export can name it.
        let (_dir, store) = store();
        let first = at_uri(DID, "app.bsky.feed.post", "3kaaa");
        let second = at_uri(DID, "app.bsky.feed.post", "3kbbb");

        ingest(
            &store,
            &json!({"$type": "app.bsky.feed.post", "text": "one"}),
            &first,
            WEBID,
            PROFILE,
        )
        .unwrap();
        ingest(
            &store,
            &json!({"$type": "app.bsky.feed.post", "text": "two"}),
            &second,
            WEBID,
            PROFILE,
        )
        .unwrap();

        assert_eq!(read(&store, &first).unwrap()["text"], "one");
        assert_eq!(read(&store, &second).unwrap()["text"], "two");
    }
}
