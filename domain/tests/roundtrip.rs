//! The property that makes `rawJson` unnecessary.
//!
//! The predecessor stashed the original JSON in a `mycorriza:rawJson` literal
//! beside every stored activity, because nothing guaranteed the triples could
//! reconstruct the wire format — and with no round-trip test, nobody could ever
//! delete it. This file is that guarantee.
//!
//! Phase 1 exit criterion: `wire → quads → wire` holds for AS2 and for two
//! unrelated ATProtocol lexicons.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_domain::faithful::{decode, encode};
use brolly_domain::iri::canonicalize_quad;
use oxrdf::NamedNode;
use proptest::prelude::*;
use serde_json::{Map, Value, json};

fn node(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// Encode then decode, exactly as storage would.
fn round_trip(record: &Value, lexicon: &str) -> Value {
    let subject = node("https://alice.brolly.id/records/1");
    let graph = node("https://alice.brolly.id/records/1");
    let quads = encode(record, &subject, &graph, lexicon).expect("encode");
    // Storage canonicalizes on the way in; the round trip must survive it.
    let quads: Vec<_> = quads.iter().map(canonicalize_quad).collect();
    decode(&quads, &subject).expect("decode")
}

#[test]
fn as2_note_round_trips() {
    let note = json!({
        "type": "Note",
        "id": "https://alice.brolly.id/notes/01H",
        "attributedTo": "https://alice.brolly.id/actor",
        "content": "<p>hello fediverse</p>",
        "published": "2026-08-18T12:00:00Z",
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "cc": [],
        "sensitive": false,
        "tag": [{"type": "Hashtag", "name": "#rdf", "href": "https://brolly.id/tags/rdf"}]
    });
    assert_eq!(round_trip(&note, "as2"), note);
}

#[test]
fn bsky_post_round_trips() {
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "written by brolly",
        "createdAt": "2026-08-18T12:00:00Z",
        "langs": ["en", "no"],
        "reply": {
            "root": {"uri": "at://did:plc:x/app.bsky.feed.post/1", "cid": "bafy1"},
            "parent": {"uri": "at://did:plc:x/app.bsky.feed.post/2", "cid": "bafy2"}
        }
    });
    assert_eq!(round_trip(&post, "app.bsky.feed.post"), post);
}

#[test]
fn an_unrelated_third_party_lexicon_round_trips() {
    // Nobody wrote a mapping for this, and it still survives export intact.
    let doc = json!({
        "$type": "site.standard.doc",
        "text": "a different lexicon that reuses the field name 'text'",
        "blocks": [{"kind": "para", "depth": 0}, {"kind": "list", "depth": 2}],
        "wordCount": 12,
        "ratio": 1.5,
        "draft": true,
        "publishedAt": null
    });
    assert_eq!(round_trip(&doc, "site.standard.doc"), doc);
}

#[test]
fn same_field_name_in_two_lexicons_stays_distinct() {
    let subject = node("https://alice.brolly.id/records/1");
    let graph = node("https://alice.brolly.id/records/1");

    let a = encode(
        &json!({"text": "one"}),
        &subject,
        &graph,
        "app.bsky.feed.post",
    )
    .unwrap();
    let b = encode(
        &json!({"text": "two"}),
        &subject,
        &graph,
        "site.standard.doc",
    )
    .unwrap();

    let text_a: Vec<_> = a
        .iter()
        .filter(|q| q.predicate.as_str().ends_with("#text"))
        .map(|q| q.predicate.as_str().to_string())
        .collect();
    let text_b: Vec<_> = b
        .iter()
        .filter(|q| q.predicate.as_str().ends_with("#text"))
        .map(|q| q.predicate.as_str().to_string())
        .collect();

    assert_eq!(text_a.len(), 1);
    assert_eq!(text_b.len(), 1);
    assert_ne!(
        text_a[0], text_b[0],
        "the predecessor's flat urn:atproto:field: namespace merged these"
    );
}

#[test]
fn empty_containers_survive() {
    let record = json!({"emptyList": [], "emptyObject": {}, "nested": {"alsoEmpty": {}}});
    assert_eq!(round_trip(&record, "test.empty"), record);
}

#[test]
fn number_kinds_are_preserved() {
    // 1 and 1.0 are different JSON values; the datatype has to carry that.
    let record = json!({"int": 1, "float": 1.0, "neg": -7});
    let out = round_trip(&record, "test.numbers");
    assert_eq!(out, record);
    assert!(out["int"].is_i64());
    assert!(out["float"].is_f64());
}

#[test]
fn array_order_is_preserved() {
    let record = json!({"items": ["a", "b", "c", "d", "e"]});
    assert_eq!(round_trip(&record, "test.order"), record);
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|i| Value::from(i as i64)),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::from),
        "[a-zA-Z0-9 _-]{0,24}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::hash_map("[a-z][a-zA-Z0-9]{0,8}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn any_json_object_round_trips(fields in prop::collection::hash_map(
        "[a-z][a-zA-Z0-9]{0,8}", arb_json(), 0..6
    )) {
        let record = Value::Object(fields.into_iter().collect::<Map<_, _>>());
        prop_assert_eq!(round_trip(&record, "test.property"), record);
    }
}
