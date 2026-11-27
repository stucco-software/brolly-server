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
