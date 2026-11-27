//! The lexicon validator against its three bars (stage 4a, H4): our corpus,
//! the atproto-interop-tests lexicon suite, and its syntax vectors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use brolly_atproto::lexicon::{self, Registry};
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|e| panic!("{path:?}: {e}"))
}

/// Every `.json` under `dir`, recursively.
fn documents(dir: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "json") {
                out.push(json(&path));
            }
        }
    }
    out
}

fn vendored_docs() -> Vec<Value> {
    documents(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/lexicons"))
}

/// The vendored tree plus extra documents — the registry the tests validate against.
fn registry_with(extra: &Path) -> Registry {
    let mut docs = vendored_docs();
    docs.extend(documents(extra));
    Registry::from_docs(docs).unwrap()
}

#[test]
fn the_vendored_tree_loads_and_every_record_ref_resolves() {
    let registry = lexicon::vendored().unwrap();
    for nsid in [
        "app.bsky.feed.post",
        "app.bsky.actor.profile",
        "app.bsky.graph.follow",
    ] {
        assert!(registry.is_record(nsid), "{nsid}");
    }
    assert!(!registry.is_record("app.bsky.feed.getTimeline"));
}

#[test]
fn the_interop_valid_lexicons_load() {
    for case in json(&fixtures().join("interop/lexicon/lexicon-valid.json"))
        .as_array()
        .unwrap()
    {
        let mut docs = vendored_docs();
        docs.push(case["lexicon"].clone());
        Registry::from_docs(docs).unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
    }
}

#[test]
fn the_interop_invalid_lexicons_are_refused() {
    for case in json(&fixtures().join("interop/lexicon/lexicon-invalid.json"))
        .as_array()
        .unwrap()
    {
        let mut docs = vendored_docs();
        docs.push(case["lexicon"].clone());
        assert!(Registry::from_docs(docs).is_err(), "{}", case["name"]);
    }
}

#[test]
fn a_dangling_ref_from_a_record_fails_the_load() {
    let mut docs = vendored_docs();
    docs.push(serde_json::json!({
        "lexicon": 1, "id": "com.example.dangling",
        "defs": {"main": {"type": "record", "key": "any", "record": {"type": "object",
            "properties": {"x": {"type": "ref", "ref": "com.example.nowhere#thing"}}}}}
    }));
    let err = Registry::from_docs(docs).unwrap_err();
    assert!(
        err.to_string().contains("com.example.nowhere#thing"),
        "{err}"
    );
}

#[test]
fn a_duplicate_id_fails_the_load() {
    let mut docs = vendored_docs();
    docs.push(docs[0].clone());
    assert!(Registry::from_docs(docs).is_err());
}

fn lines(file: &str) -> Vec<String> {
    std::fs::read_to_string(fixtures().join("interop/syntax").join(file))
        .unwrap()
        .lines()
        .map(|l| l.trim_end_matches('\r').to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[test]
fn every_format_holds_to_the_interop_syntax_vectors() {
    let table: [(&str, &str, &[&str]); 11] = [
        (
            "at-identifier",
            "atidentifier_syntax_valid.txt",
            &["atidentifier_syntax_invalid.txt"],
        ),
        (
            "at-uri",
            "aturi_syntax_valid.txt",
            &["aturi_syntax_invalid.txt"],
        ),
        ("cid", "cid_syntax_valid.txt", &["cid_syntax_invalid.txt"]),
        (
            "datetime",
            "datetime_syntax_valid.txt",
            &["datetime_syntax_invalid.txt", "datetime_parse_invalid.txt"],
        ),
        ("did", "did_syntax_valid.txt", &["did_syntax_invalid.txt"]),
        (
            "handle",
            "handle_syntax_valid.txt",
            &["handle_syntax_invalid.txt"],
        ),
        (
            "language",
            "language_syntax_valid.txt",
            &["language_syntax_invalid.txt"],
        ),
        (
            "nsid",
            "nsid_syntax_valid.txt",
            &["nsid_syntax_invalid.txt"],
        ),
        (
            "record-key",
            "recordkey_syntax_valid.txt",
            &["recordkey_syntax_invalid.txt"],
        ),
        ("tid", "tid_syntax_valid.txt", &["tid_syntax_invalid.txt"]),
        ("uri", "uri_syntax_valid.txt", &["uri_syntax_invalid.txt"]),
    ];
    let mut wrong = Vec::new();
    for (format, valid, invalids) in table {
        for v in lines(valid) {
            if !lexicon::formats::check_syntax(format, &v) {
                wrong.push(format!("{format}: refused valid {v:?}"));
            }
        }
        for file in invalids {
            for v in lines(file) {
                if lexicon::formats::check_syntax(format, &v) {
                    wrong.push(format!("{format}: accepted invalid {v:?}"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} disagreements:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn an_unknown_format_is_accepted() {
    // The evolution rules let a newer lexicon name a format this pin does not
    // know; the field is still a string.
    assert!(lexicon::formats::check("some-future-format", "anything"));
}

use brolly_atproto::data_model;
use brolly_atproto::lexicon::{Refusal, Status};

/// What the whole pre-commit path says about one record: the data model,
/// then the lexicon. A data-model refusal is a refusal.
fn verdict(
    registry: &Registry,
    collection: &str,
    rkey: &str,
    record: &Value,
) -> Result<Status, String> {
    let ipld = data_model::record_from_json(record).map_err(|e| e.to_string())?;
    registry
        .validate(collection, Some(rkey), &data_model::to_json(&ipld))
        .map_err(|e| e.to_string())
}

#[test]
fn the_corpus_holds() {
    let corpus = fixtures().join("lexicon-corpus");
    let registry = registry_with(&corpus.join("lexicons"));
    let mut wrong = Vec::new();
    for case in json(&corpus.join("cases.json")).as_array().unwrap() {
        let got = verdict(
            &registry,
            case["collection"].as_str().unwrap(),
            case["rkey"].as_str().unwrap(),
            &case["record"],
        );
        let got_word = match &got {
            Ok(Status::Valid) => "valid",
            Ok(Status::Unknown) => "unknown",
            Err(_) => "invalid",
        };
        if got_word != case["expect"].as_str().unwrap() {
            wrong.push(format!(
                "{}: expected {}, got {got:?}",
                case["name"], case["expect"]
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of the corpus disagree:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_interop_record_suite_holds() {
    let dir = fixtures().join("interop/lexicon");
    let registry = registry_with(&dir.join("catalog"));
    let mut wrong = Vec::new();
    for (file, want_valid) in [
        ("record-data-valid.json", true),
        ("record-data-invalid.json", false),
    ] {
        for case in json(&dir.join(file)).as_array().unwrap() {
            let data = &case["data"];
            let collection = data["$type"].as_str().unwrap();
            // The lexicon alone, on the vector as written: these vectors test
            // the lexicon, not H1, and their blob refs are dag-cbor CIDs and
            // one `$bytes` has non-zero trailing bits — both of which H1
            // refuses on purpose (spec H1, `data_model.rs`). They are already
            // in normalised form.
            let got = registry.validate(collection, Some(case["rkey"].as_str().unwrap()), data);
            if matches!(got, Ok(Status::Valid)) != want_valid {
                wrong.push(format!("{file} {}: got {got:?}", case["name"]));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} disagree:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn a_refusal_names_its_path_in_the_references_shape() {
    let registry = lexicon::vendored().unwrap();
    let post = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "x".repeat(301),
        "createdAt": "2026-11-27T00:00:00.000Z",
    });
    assert_eq!(
        registry.validate("app.bsky.feed.post", None, &post),
        Err(Refusal::Record(
            "record/text must not be longer than 300 graphemes".to_string()
        ))
    );
    let no_date = serde_json::json!({"$type": "app.bsky.feed.post", "text": "hi"});
    assert_eq!(
        registry.validate("app.bsky.feed.post", None, &no_date),
        Err(Refusal::Record(
            "record must have the property \"createdAt\"".to_string()
        ))
    );
}

#[test]
fn a_collection_that_is_not_a_record_type_is_refused() {
    let registry = lexicon::vendored().unwrap();
    let err = registry
        .validate("app.bsky.feed.getTimeline", None, &serde_json::json!({}))
        .unwrap_err();
    assert_eq!(
        err,
        Refusal::NotARecord("app.bsky.feed.getTimeline".to_string())
    );
    assert_eq!(
        err.to_string(),
        "app.bsky.feed.getTimeline is not a record type"
    );
}

#[test]
fn key_types_hold() {
    let registry = lexicon::vendored().unwrap();
    assert!(registry.check_key("app.bsky.actor.profile", "self").is_ok());
    assert!(
        registry
            .check_key("app.bsky.actor.profile", "3kaaaaaaaaaab")
            .is_err()
    );
    assert!(
        registry
            .check_key("app.bsky.feed.post", "3kaaaaaaaaaab")
            .is_ok()
    );
    assert_eq!(
        registry.check_key("app.bsky.feed.post", "nottid"),
        Err(Refusal::Key("record key nottid is not a TID".to_string()))
    );
    assert!(registry.check_key("com.example.nobody", "anything").is_ok());
}

#[test]
fn a_deep_record_is_refused_not_overflowed() {
    // An `unknown` is not descended, but a recursive object lexicon is; the
    // walk is bounded either way.
    let mut docs = vendored_docs();
    docs.push(serde_json::json!({
        "lexicon": 1, "id": "com.example.deep",
        "defs": {
            "main": {"type": "record", "key": "any", "record": {"type": "ref", "ref": "#node"}},
            "node": {"type": "object", "properties": {"next": {"type": "ref", "ref": "#node"}}}
        }
    }));
    // A record schema must be an object, so the ref-as-record form is
    // refused at load; build the same recursion through a property instead.
    assert!(Registry::from_docs(docs.clone()).is_err());
    docs.pop();
    docs.push(serde_json::json!({
        "lexicon": 1, "id": "com.example.deep",
        "defs": {
            "main": {"type": "record", "key": "any", "record": {"type": "object",
                "properties": {"next": {"type": "ref", "ref": "#node"}}}},
            "node": {"type": "object", "properties": {"next": {"type": "ref", "ref": "#node"}}}
        }
    }));
    let registry = Registry::from_docs(docs).unwrap();
    let mut value = serde_json::json!({});
    for _ in 0..100 {
        value = serde_json::json!({"next": value});
    }
    value["$type"] = "com.example.deep".into();
    let err = registry
        .validate("com.example.deep", None, &value)
        .unwrap_err();
    assert!(matches!(err, Refusal::Record(_)), "{err:?}");
    assert!(err.to_string().contains("nested too deeply"), "{err}");
}

/// The vendored tree plus one more document.
fn with_doc(doc: Value) -> Result<Registry, lexicon::LoadError> {
    let mut docs = vendored_docs();
    docs.push(doc);
    Registry::from_docs(docs)
}

/// A record lexicon `com.example.t` whose record has `properties`.
fn record_doc(key: &str, properties: Value) -> Value {
    serde_json::json!({
        "lexicon": 1, "id": "com.example.t",
        "defs": {"main": {"type": "record", "key": key,
            "record": {"type": "object", "properties": properties}}}
    })
}

#[test]
fn an_unsupported_key_type_is_refused_by_name() {
    for key in ["foo", "literal:"] {
        let registry = with_doc(record_doc(key, serde_json::json!({}))).unwrap();
        assert_eq!(
            registry.check_key("com.example.t", "x"),
            Err(Refusal::Key(format!(
                "record key x is not allowed: unsupported key type {key}"
            ))),
            "{key}"
        );
    }
}

#[test]
fn a_union_type_must_be_an_nsid_with_at_most_one_fragment() {
    let registry = lexicon::vendored().unwrap();
    for t in [
        "#image",
        "app.bsky.embed.images#main#x",
        "app.bsky.embed.images#",
        "not an nsid",
    ] {
        let post = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hi",
            "createdAt": "2026-11-27T00:00:00.000Z",
            "embed": {"$type": t},
        });
        assert_eq!(
            registry.validate("app.bsky.feed.post", None, &post),
            Err(Refusal::Record(
                "record/embed $type must be an NSID, optionally with a #fragment".to_string()
            )),
            "{t}"
        );
    }
    // An open union still takes a well-formed type it does not know.
    let post = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "hi",
        "createdAt": "2026-11-27T00:00:00.000Z",
        "embed": {"$type": "com.example.embed#thing"},
    });
    assert_eq!(
        registry.validate("app.bsky.feed.post", None, &post),
        Ok(Status::Valid)
    );
}

#[test]
fn graphemes_are_counted_against_both_bounds() {
    let registry = with_doc(record_doc(
        "any",
        serde_json::json!({
            "s": {"type": "string", "maxGraphemes": 3, "minGraphemes": 2}
        }),
    ))
    .unwrap();
    let check = |s: &str| registry.validate("com.example.t", None, &serde_json::json!({"s": s}));
    // "é" written as e + combining acute: two code points, one grapheme.
    let e = "e\u{301}";
    assert_eq!(check(&e.repeat(3)), Ok(Status::Valid));
    assert_eq!(
        check(&e.repeat(4)),
        Err(Refusal::Record(
            "record/s must not be longer than 3 graphemes".to_string()
        ))
    );
    assert_eq!(
        check(e),
        Err(Refusal::Record(
            "record/s must not be shorter than 2 graphemes".to_string()
        ))
    );
    assert_eq!(
        check("a"),
        Err(Refusal::Record(
            "record/s must not be shorter than 2 graphemes".to_string()
        ))
    );
    assert_eq!(check("ab"), Ok(Status::Valid));
}

#[test]
fn an_inline_token_field_is_the_lexicons_fault() {
    let registry = with_doc(record_doc(
        "any",
        serde_json::json!({"t": {"type": "token"}}),
    ))
    .unwrap();
    let err = registry
        .validate("com.example.t", None, &serde_json::json!({"t": "x"}))
        .unwrap_err();
    assert!(matches!(err, Refusal::Lexicon(_)), "{err:?}");
}

#[test]
fn a_constraint_of_the_wrong_type_fails_the_load() {
    for props in [
        serde_json::json!({"s": {"type": "string", "maxLength": "300"}}),
        serde_json::json!({"s": {"type": "string", "maxGraphemes": -1}}),
        serde_json::json!({"s": {"type": "string", "enum": ["a", 1]}}),
        serde_json::json!({"s": {"type": "string", "const": 1}}),
        serde_json::json!({"n": {"type": "integer", "maximum": 1.5}}),
        serde_json::json!({"n": {"type": "integer", "enum": ["a"]}}),
        serde_json::json!({"b": {"type": "boolean", "const": "true"}}),
        serde_json::json!({"a": {"type": "array", "items": {"type": "string"}, "maxLength": "3"}}),
        serde_json::json!({"b": {"type": "blob", "accept": "image/*"}}),
        serde_json::json!({"b": {"type": "blob", "maxSize": "1000"}}),
        serde_json::json!({"y": {"type": "bytes", "minLength": -2}}),
        serde_json::json!({"u": {"type": "union", "refs": [], "closed": "yes"}}),
    ] {
        assert!(
            with_doc(record_doc("any", props.clone())).is_err(),
            "{props}"
        );
    }
}

#[test]
fn required_and_nullable_must_name_properties() {
    for (list, name) in [("required", "missing"), ("nullable", "missing")] {
        let doc = serde_json::json!({
            "lexicon": 1, "id": "com.example.t",
            "defs": {"main": {"type": "record", "key": "any",
                "record": {"type": "object", list: [name],
                    "properties": {"here": {"type": "string"}}}}}
        });
        let err = with_doc(doc).unwrap_err();
        assert!(err.to_string().contains(name), "{list}: {err}");
    }
}

#[test]
fn a_ref_to_a_record_fails_the_load() {
    let err = with_doc(record_doc(
        "any",
        serde_json::json!({"p": {"type": "ref", "ref": "app.bsky.feed.post"}}),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("app.bsky.feed.post#main"), "{err}");
}

#[test]
fn a_token_as_a_union_member_fails_the_load() {
    let doc = serde_json::json!({
        "lexicon": 1, "id": "com.example.t",
        "defs": {
            "main": {"type": "record", "key": "any", "record": {"type": "object",
                "properties": {"u": {"type": "union", "refs": ["#tok"]}}}},
            "tok": {"type": "token"}
        }
    });
    let err = with_doc(doc).unwrap_err();
    assert!(err.to_string().contains("com.example.t#tok"), "{err}");
    // Through a ref, a token is a value, and loads.
    let doc = serde_json::json!({
        "lexicon": 1, "id": "com.example.t",
        "defs": {
            "main": {"type": "record", "key": "any", "record": {"type": "object",
                "properties": {"r": {"type": "ref", "ref": "#tok"}}}},
            "tok": {"type": "token"}
        }
    });
    assert!(with_doc(doc).is_ok());
}
