//! Run each lexicon-validation candidate against the corpus (stage 4a, H4).
//!
//! `cargo run -- <candidate>` prints one line per case and a summary; the
//! exit code is non-zero if any case disagrees with its `expect`.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::Value;

/// What a candidate says about one record.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    Invalid(String),
    /// The lexicon is not in the registry: accepted unvalidated.
    Unknown,
}

/// A candidate validator, loaded from a set of lexicon documents.
pub trait Candidate {
    fn name(&self) -> &'static str;
    fn check(&self, collection: &str, rkey: &str, record: &Value) -> Verdict;
}

mod candidates;

/// The rkey against a record lexicon's `key` (spec H4: this check is ours,
/// whichever validator is adopted). An unrecognised `key` refuses.
pub fn key_ok(key: &str, rkey: &str) -> bool {
    const TID_CHARS: &str = "234567abcdefghijklmnopqrstuvwxyz";
    const TID_FIRST: &str = "234567abcdefghij";
    match key {
        "any" => true,
        "tid" => {
            rkey.len() == 13
                && rkey.chars().all(|c| TID_CHARS.contains(c))
                && rkey.chars().next().is_some_and(|c| TID_FIRST.contains(c))
        }
        "nsid" => rkey.split('.').count() >= 3 && rkey.split('.').all(|s| !s.is_empty()),
        other => match other.strip_prefix("literal:") {
            Some(want) => rkey == want,
            None => false,
        },
    }
}

/// The `key` of `nsid`'s `main` def, if it is a record in `docs`.
pub fn key_of(docs: &[Value], nsid: &str) -> Option<String> {
    docs.iter()
        .find(|d| d["id"].as_str() == Some(nsid))
        .and_then(|d| d["defs"]["main"]["key"].as_str())
        .map(str::to_owned)
}

fn lexicon_files(dirs: &[PathBuf]) -> anyhow::Result<Vec<Value>> {
    let mut docs = Vec::new();
    for dir in dirs {
        let mut stack = vec![dir.clone()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).with_context(|| format!("{d:?}"))? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "json") {
                    docs.push(serde_json::from_str(&std::fs::read_to_string(&path)?)?);
                }
            }
        }
    }
    Ok(docs)
}

fn main() -> anyhow::Result<()> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus = here.join("../../adapters/atproto/tests/fixtures/lexicon-corpus");
    let docs = lexicon_files(&[here.join("../../vendor/lexicons"), corpus.join("lexicons")])?;
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(corpus.join("cases.json"))?)?;

    let which = std::env::args().nth(1).context("usage: <candidate>")?;
    let candidate = candidates::load(&which, &docs)?;

    let mut wrong = 0;
    for case in &cases {
        let name = case["name"].as_str().unwrap_or("?");
        let expect = case["expect"].as_str().unwrap_or("?");
        let verdict = candidate.check(
            case["collection"].as_str().unwrap_or_default(),
            case["rkey"].as_str().unwrap_or_default(),
            &case["record"],
        );
        let got = match &verdict {
            Verdict::Valid => "valid",
            Verdict::Invalid(_) => "invalid",
            Verdict::Unknown => "unknown",
        };
        let ok = got == expect;
        if !ok {
            wrong += 1;
        }
        let detail = match &verdict {
            Verdict::Invalid(why) => why.as_str(),
            _ => "",
        };
        println!(
            "{} {name:28} expect {expect:8} got {got:8} {detail}",
            if ok { "ok  " } else { "FAIL" }
        );
    }
    println!(
        "{}: {} of {} agree",
        candidate.name(),
        cases.len() - wrong,
        cases.len()
    );
    if wrong > 0 {
        std::process::exit(1);
    }
    Ok(())
}
