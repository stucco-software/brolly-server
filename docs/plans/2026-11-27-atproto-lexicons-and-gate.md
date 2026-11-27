# Stage 4a — The Data Model, Held: Implementation Plan (chunks 3–4)

<!-- doc-paths: skip -->
<!-- The plan names files it creates (the lexicon module, the moved corpus,
     the new interop fixtures), so not every path it cites resolves until it
     lands. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate every record against its vendored lexicon with a validator we write (chunk 3), then put that validator in front of every write as one gate, with `validate`/`validationStatus` on the wire and `applyWrites` answering in its lexicon's union (chunk 4).

**Architecture:** A new `adapters/atproto/src/lexicon/` module owns the lexicons: `registry.rs` loads and structurally checks lexicon documents (the vendored tree is embedded with `include_dir` and parsed once, behind a `LazyLock`), `formats.rs` checks string formats, `validate.rs` walks a record against its schema. The validator reads the record's **normalised** JSON — `data_model::to_json` of the IPLD that will be committed — so what is validated is exactly what is signed (Decision F). `record.rs`'s `prepare` becomes `check_record` (envelope → data model → lexicon) and `check_key`; `PlannedWrite`'s constructors call it with a `Validate`, and the `Status` rides `AppliedOp` to the handlers.

**Tech Stack:** Rust 2024, `serde_json`, `include_dir` 0.7 (MIT/Apache-2.0), `unicode-segmentation` 1.13 (MIT/Apache-2.0, already in the lockfile), `regex` 1 (already in the lockfile), atrium-api's string types (`Did`, `Handle`, `Nsid`, `Tid`, `RecordKey`, `Language`, `Datetime`), axum 0.8.

**Spec:** `docs/specs/2026-11-26-atproto-data-model-and-lexicons.md` — read H3–H6, Testing, and Decisions D–G first. ADR 0022 is the principle behind it. Chunks 1–2 are in `docs/plans/2026-11-26-atproto-data-model.md` (done: `b26a45f`, `923f69a`).

**What chunk 1 already did that the spec lists under chunk 3:** the vendored tree (`vendor/lexicons/`, 274 files) and `tools/refresh-lexicons.sh` landed in `590bddf`. Chunk 3 here embeds and validates against them.

**One addition over the spec, found while planning:** the atproto-interop-tests pin we already vendor (`056e5741…`, `adapters/atproto/tests/fixtures/interop/SOURCE.md`) carries a lexicon suite (`lexicon/`: 50 invalid and 3 valid records against a catalog, and 7 invalid lexicon documents) and syntax vectors for every string format (`syntax/`). They join the corpus as acceptance tests (Task 3.1). The corpus is ours; these are the network's.

**House rules that bite here:**
- Library crates deny `unwrap`/`expect`/`panic`/`println!`/indexing panics by workspace clippy lints. Integration test files carry `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` at the top; a library crate's in-file `mod tests` is covered by the crate-level `#![cfg_attr(test, allow(…))]` in `adapters/atproto/src/lib.rs:7` — do not add a second attribute. `test-support` is a library crate: its helpers must not `unwrap` either.
- Trunk-based: commit straight to `main`, **push after every commit** (`git push`), every commit green and deployable. No branches, no PRs.
- Pre-commit (lefthook) runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `./tools/check-doc-paths.sh`. Run them yourself before `git commit`.
- **Database tests need OrbStack's socket.** Prefix every `cargo test` that touches Postgres with `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock`. Run the full suite with `--no-fail-fast`. Known flakes, not regressions: `connect to test postgres: PoolTimedOut` in a random test, and `store/tests/blobs.rs::blob_bytes_count_towards_the_pod_quota`. Re-run the single test before treating either as real.
- Gate shell chains on cargo's own exit status: `cargo test … > /tmp/x.log 2>&1; echo exit=$?`, never `cargo test … | grep …` as a pass/fail signal.
- Stage only the files each task names. Never `git add -A` / `git add .`.
- Commit messages: a conventional prefix, a body that says why, and the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

**Message shapes (used throughout):** a refusal is `Invalid {collection} record: {path} {problem}`, where `{path}` starts at `record` and is `/`-joined (`record/reply/root/cid`), the same root `data_model` errors use. Problems, after the reference's `@atproto/lexicon` wording:

| Rule | Problem |
|---|---|
| required | `must have the property "{key}"` |
| wrong type | `must be a string` / `an integer` / `a boolean` / `an object` / `an array` / `null` / `a byte array` / `a CID` / `a blob ref` |
| string length (UTF-8 bytes) | `must not be longer than {n} characters` / `must not be shorter than {n} characters` |
| graphemes | `must not be longer than {n} graphemes` / `must not be shorter than {n} graphemes` |
| enum | `must be one of ({a}\|{b})` |
| const | `must be {value}` |
| integer range | `can not be greater than {n}` / `can not be less than {n}` |
| array length | `must not have more than {n} elements` / `must not have fewer than {n} elements` |
| bytes length | `must not be larger than {n} bytes` / `must not be smaller than {n} bytes` |
| format | `must be a valid {format}` |
| union | `must be an object which includes the "$type" property` / `$type must be one of {refs}` |
| blob | `mimeType {m} is not accepted ({accept})` / `is {size} bytes, over maxSize {n}` |
| key | `record key {rkey} is not {what}` (`self`, `a TID`, `an NSID`) |
| unknown lexicon, `validate: true` | the whole message is `Unknown lexicon type: {collection}` |

---

## Chunk 3: The registry and the validator (H3, H4)

Ends with `brolly_atproto::lexicon` able to say, for any vendored collection, whether a record is valid — proven by our 107-case corpus, the interop lexicon suite, and the interop syntax vectors — and with the server refusing to boot if the vendored tree does not load. **No write path calls it yet**; behaviour on the wire is unchanged at the end of this chunk.

### Task 3.1: Move the corpus, vendor the interop lexicon and syntax vectors

**Files:**
- Move: `spikes/lexicon-validation/corpus/` → `adapters/atproto/tests/fixtures/lexicon-corpus/`
- Modify: `spikes/lexicon-validation/src/main.rs` (corpus path), `spikes/lexicon-validation/RESULT.md` (corpus path)
- Create: `adapters/atproto/tests/fixtures/interop/lexicon/` and `adapters/atproto/tests/fixtures/interop/syntax/` (copied verbatim)
- Modify: `adapters/atproto/tests/fixtures/interop/SOURCE.md`

- [ ] **Step 1: Move the corpus**

```bash
git mv spikes/lexicon-validation/corpus adapters/atproto/tests/fixtures/lexicon-corpus
```

In `spikes/lexicon-validation/src/main.rs`, `main()` reads `corpus/lexicons` and `corpus/cases.json` relative to the spike. Point both at the new home so the spike stays runnable (Decision D says `proto-blue-lexicon` is the one to re-check):

```rust
    let corpus = here.join("../../adapters/atproto/tests/fixtures/lexicon-corpus");
    let docs = lexicon_files(&[here.join("../../vendor/lexicons"), corpus.join("lexicons")])?;
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(corpus.join("cases.json"))?)?;
```

In `RESULT.md`, replace each `corpus/cases.json` with `adapters/atproto/tests/fixtures/lexicon-corpus/cases.json` and add one line under the first paragraph: `The corpus moved to the adapter's tests in stage 4a chunk 3; the spike reads it from there.`

- [ ] **Step 2: Verify the spike still runs**

Run: `cd spikes/lexicon-validation && cargo run -q -- proto-blue-lexicon > /tmp/spike.log 2>&1; echo exit=$?; tail -1 /tmp/spike.log; cd ../..`
Expected: `exit=1` and `proto-blue-lexicon: 24 of 107 agree` (the recorded result; non-zero because cases disagree).

- [ ] **Step 3: Vendor the interop vectors at the existing pin**

```bash
d=$(mktemp -d) && curl -sL https://codeload.github.com/bluesky-social/atproto-interop-tests/tar.gz/056e5741bb330757205d6b16db5266fffcae937b | tar xz -C "$d" \
  && src="$d/atproto-interop-tests-056e5741bb330757205d6b16db5266fffcae937b" \
  && cp -R "$src/lexicon" adapters/atproto/tests/fixtures/interop/lexicon \
  && cp -R "$src/syntax" adapters/atproto/tests/fixtures/interop/syntax \
  && ls adapters/atproto/tests/fixtures/interop/lexicon adapters/atproto/tests/fixtures/interop/syntax
```

Expected: `lexicon/` holds `catalog/` (`permission-set.json procedure.json query.json record.json subscription.json`), `lexicon-invalid.json`, `lexicon-valid.json`, `record-data-invalid.json`, `record-data-valid.json`; `syntax/` holds 24 `*.txt` files.

Rewrite `SOURCE.md` to:

```markdown
# atproto-interop-tests vectors

From https://github.com/bluesky-social/atproto-interop-tests at
`056e5741bb330757205d6b16db5266fffcae937b`. CC0-1.0. Copied verbatim.

| Directory | Used by |
|---|---|
| `data-model/` | `adapters/atproto/tests/data_model_vectors.rs` (stage 4a, H1) |
| `lexicon/` | `adapters/atproto/tests/lexicon_vectors.rs` (stage 4a, H4) |
| `syntax/` | `adapters/atproto/tests/lexicon_vectors.rs` (stage 4a, H4: string formats) |
```

- [ ] **Step 4: Commit**

```bash
git add spikes/lexicon-validation/src/main.rs spikes/lexicon-validation/RESULT.md \
  adapters/atproto/tests/fixtures/lexicon-corpus adapters/atproto/tests/fixtures/interop
git status --short   # the old spikes/lexicon-validation/corpus paths show as renames
git commit -m "test(atproto): the lexicon corpus moves to the adapter; interop lexicon and syntax vectors

The corpus written for the spike is the validator's acceptance test from
here on (stage 4a, H4), so it lives with the adapter's tests; the spike
reads it from there and still runs. The atproto-interop-tests pin we
already vendor also carries the network's own lexicon suite and syntax
vectors for every string format — the bar beside ours.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

### Task 3.2: Dependencies and the module skeleton

**Files:**
- Modify: `adapters/atproto/Cargo.toml`
- Create: `adapters/atproto/src/lexicon/mod.rs`, `adapters/atproto/src/lexicon/registry.rs`, `adapters/atproto/src/lexicon/formats.rs`, `adapters/atproto/src/lexicon/validate.rs`
- Modify: `adapters/atproto/src/lib.rs`

- [ ] **Step 1: Add the dependencies**

In `adapters/atproto/Cargo.toml` `[dependencies]`, after the `base64` line:

```toml
# The vendored lexicons, embedded in the binary (stage 4a, H3, Decision C):
# no build script, no runtime fetch. On stable Rust a change under
# vendor/lexicons/ does not by itself trigger a rebuild, so
# tools/refresh-lexicons.sh touches lexicon/mod.rs.
include_dir = "0.7.4"
# Grapheme clusters (UAX #29, extended) for maxGraphemes/minGraphemes (H4).
unicode-segmentation = "1.13.3"
# The datetime, uri and at-uri formats, after the reference's own patterns.
regex = "1"
```

and on the existing `time = "0.3.55"` line, add the `parsing` feature (the `datetime` format parses RFC 3339 with it): `time = { version = "0.3.55", features = ["parsing"] }`. Keep whatever features the line already has.

Run: `cargo tree -p brolly-atproto -i regex --depth 0 > /dev/null 2>&1; echo exit=$?` — expect `exit=0`. Check `regex`'s resolved version in `Cargo.lock` matches what atrium already uses (one copy, not two): `grep -c '^name = "regex"$' Cargo.lock` — expect `1`.

- [ ] **Step 2: Touch the registry from the refresh tool**

At the end of `tools/refresh-lexicons.sh` (before any final `echo`; read the script first — if it already holds the repo root in a variable, use that), add:

```bash
# include_dir cannot tell cargo the tree changed on stable Rust; touching the
# module that embeds it forces the rebuild.
touch "$(git rev-parse --show-toplevel)/adapters/atproto/src/lexicon/mod.rs"
```

- [ ] **Step 3: The module skeleton**

`adapters/atproto/src/lexicon/mod.rs`:

```rust
//! Lexicons (stage 4a, H3, H4): the vendored documents, embedded and loaded
//! once, and the validator that holds a record to its collection's lexicon.
//!
//! Written, not adopted (Decision D): neither candidate crate passed the
//! corpus. The validator reads a record's **normalised** JSON — the
//! `data_model::to_json` of the IPLD that will be committed — so what is
//! validated is exactly what is signed (Decision F).

pub mod formats;
mod registry;
mod validate;

use std::sync::LazyLock;

pub use registry::{LoadError, Registry};

/// What validation said about a record that was not refused: the
/// `validationStatus` a write answers with (H6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Its lexicon is vendored and the record holds to it.
    Valid,
    /// Its collection has no vendored lexicon; accepted unvalidated.
    Unknown,
}

impl Status {
    /// The lexicon's `validationStatus` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Unknown => "unknown",
        }
    }
}

static TREE: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../vendor/lexicons");

static VENDORED: LazyLock<Result<Registry, LoadError>> =
    LazyLock::new(|| Registry::from_docs(registry::documents(&TREE)?));

/// The vendored lexicons, parsed on first use. The server calls this at
/// startup, so a tree that does not load stops the boot rather than the
/// first write (Decision C).
pub fn vendored() -> Result<&'static Registry, LoadError> {
    VENDORED.as_ref().map_err(Clone::clone)
}
```

`registry.rs`, `formats.rs`, `validate.rs`: create each with a one-line `//!` doc for now (filled by Tasks 3.3–3.5). In `lib.rs`, add `pub mod lexicon;` in alphabetical order (after `pub mod legacy;`).

Note: `Registry::from_docs(registry::documents(&TREE)?)` — the `?` inside the closure works because the closure returns `Result<Registry, LoadError>`.

This step does not compile until Task 3.3 defines `Registry`, `LoadError` and `documents`; do not run anything yet.

### Task 3.3: The registry — load, check, resolve

**Files:**
- Modify: `adapters/atproto/src/lexicon/registry.rs`
- Test: `adapters/atproto/tests/lexicon_vectors.rs` (create)

What the loader enforces (the interop `lexicon-invalid.json` cases, plus what the validator relies on so it never meets a malformed schema it must guess about):

- a document is an object with `"lexicon": 1`, a string `id` that is a valid NSID, and an object `defs`; ids are unique;
- every def is an object with a string `type`;
- `record`, `query`, `procedure`, `subscription` and `permission-set` may only be `main`;
- `ref`, `union` and `unknown` may not be defs of their own (they are field types);
- a `record` has a string `key` and a `record` whose `type` is `object`;
- **closure**: from every record's `main`, every schema reachable through `properties`, `items`, `record`, `ref` and `refs` has a known field type, and every `ref`/`refs` entry resolves to a def that exists. A dangling ref fails the load (H3: "a dangling one fails CI").

- [ ] **Step 1: Write the failing tests**

`adapters/atproto/tests/lexicon_vectors.rs`:

```rust
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
    for nsid in ["app.bsky.feed.post", "app.bsky.actor.profile", "app.bsky.graph.follow"] {
        assert!(registry.is_record(nsid), "{nsid}");
    }
    assert!(!registry.is_record("app.bsky.feed.getTimeline"));
}

#[test]
fn the_interop_valid_lexicons_load() {
    for case in json(&fixtures().join("interop/lexicon/lexicon-valid.json")).as_array().unwrap() {
        let mut docs = vendored_docs();
        docs.push(case["lexicon"].clone());
        Registry::from_docs(docs).unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
    }
}

#[test]
fn the_interop_invalid_lexicons_are_refused() {
    for case in json(&fixtures().join("interop/lexicon/lexicon-invalid.json")).as_array().unwrap() {
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
    assert!(err.to_string().contains("com.example.nowhere#thing"), "{err}");
}

#[test]
fn a_duplicate_id_fails_the_load() {
    let mut docs = vendored_docs();
    docs.push(docs[0].clone());
    assert!(Registry::from_docs(docs).is_err());
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-atproto --test lexicon_vectors > /tmp/t.log 2>&1; echo exit=$?; grep -E "^error" /tmp/t.log | head`
Expected: `exit=101`, compile errors (`Registry`, `LoadError`, `is_record` not found).

- [ ] **Step 3: Implement the registry**

`adapters/atproto/src/lexicon/registry.rs`:

```rust
//! Loading lexicon documents and resolving references between them (H3).

use std::collections::{BTreeMap, BTreeSet};

use atrium_api::types::string::Nsid;
use serde_json::{Map, Value};

/// Why a set of lexicon documents did not load. The message names the
/// document and the def.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lexicons: {}", self.0)
    }
}

impl std::error::Error for LoadError {}

fn fail(what: impl Into<String>) -> LoadError {
    LoadError(what.into())
}

/// Def types that are a document's primary type, and so may only be `main`.
const PRIMARY: [&str; 5] = ["record", "query", "procedure", "subscription", "permission-set"];
/// Field types that may not stand as a def of their own.
const FIELD_ONLY: [&str; 3] = ["ref", "union", "unknown"];
/// The types a record's schema may contain, wherever it nests.
const FIELD_TYPES: [&str; 13] = [
    "null", "boolean", "integer", "string", "bytes", "cid-link", "blob", "array", "object",
    "ref", "union", "unknown", "token",
];

/// A set of loaded lexicons: each document's `defs`, by NSID.
#[derive(Debug)]
pub struct Registry {
    docs: BTreeMap<String, Map<String, Value>>,
}

/// `r` as `(nsid, def)`, relative to the document `base` it appears in:
/// `#def` is local, `nsid#def` is remote, a bare `nsid` is its `main`.
pub(crate) fn resolve<'a>(base: &'a str, r: &'a str) -> (&'a str, &'a str) {
    if let Some(def) = r.strip_prefix('#') {
        return (base, def);
    }
    match r.split_once('#') {
        Some((nsid, def)) => (nsid, def),
        None => (r, "main"),
    }
}

/// Every `.json` file in an embedded tree, parsed.
pub(crate) fn documents(dir: &include_dir::Dir<'_>) -> Result<Vec<Value>, LoadError> {
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        stack.extend(d.dirs());
        for file in d.files() {
            if file.path().extension().is_some_and(|e| e == "json") {
                let doc = serde_json::from_slice(file.contents())
                    .map_err(|e| fail(format!("{}: {e}", file.path().display())))?;
                out.push(doc);
            }
        }
    }
    Ok(out)
}

impl Registry {
    /// Load `docs`, checking each document's structure and that every ref
    /// reachable from a record resolves.
    pub fn from_docs(docs: Vec<Value>) -> Result<Self, LoadError> {
        let mut map = BTreeMap::new();
        for doc in docs {
            let (id, defs) = check_doc(doc)?;
            if map.contains_key(&id) {
                return Err(fail(format!("{id}: defined twice")));
            }
            map.insert(id, defs);
        }
        let registry = Registry { docs: map };
        let mut seen = BTreeSet::new();
        for (id, defs) in &registry.docs {
            if let Some(main) = defs.get("main").filter(|m| type_of(m) == Some("record")) {
                registry.walk(id, main, &mut seen)?;
            }
        }
        Ok(registry)
    }

    /// The def `nsid#name`, if loaded.
    pub(crate) fn def(&self, nsid: &str, name: &str) -> Option<&Value> {
        self.docs.get(nsid)?.get(name)
    }

    /// Whether `nsid` names a loaded document at all.
    pub fn knows(&self, nsid: &str) -> bool {
        self.docs.contains_key(nsid)
    }

    /// Whether `nsid`'s `main` is a record lexicon.
    pub fn is_record(&self, nsid: &str) -> bool {
        self.record(nsid).is_some()
    }

    /// `nsid`'s `main` def, when it is a record.
    pub(crate) fn record(&self, nsid: &str) -> Option<&Value> {
        self.def(nsid, "main").filter(|m| type_of(m) == Some("record"))
    }

    /// The closure walk: `schema` (in document `base`) and everything it
    /// reaches has a known type, and every ref resolves.
    fn walk(&self, base: &str, schema: &Value, seen: &mut BTreeSet<String>) -> Result<(), LoadError> {
        let ty = type_of(schema).ok_or_else(|| fail(format!("{base}: a schema has no type")))?;
        match ty {
            "record" => {
                let record = schema.get("record").unwrap_or(&Value::Null);
                self.walk(base, record, seen)
            }
            "object" => {
                if let Some(props) = schema.get("properties") {
                    let props = props
                        .as_object()
                        .ok_or_else(|| fail(format!("{base}: properties must be an object")))?;
                    for prop in props.values() {
                        self.walk(base, prop, seen)?;
                    }
                }
                for list in ["required", "nullable"] {
                    if let Some(names) = schema.get(list)
                        && !names.as_array().is_some_and(|a| a.iter().all(Value::is_string))
                    {
                        return Err(fail(format!("{base}: {list} must be a list of names")));
                    }
                }
                Ok(())
            }
            "array" => {
                let items = schema
                    .get("items")
                    .ok_or_else(|| fail(format!("{base}: an array has no items")))?;
                self.walk(base, items, seen)
            }
            "ref" => {
                let r = schema
                    .get("ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fail(format!("{base}: a ref has no ref")))?;
                self.follow(base, r, seen)
            }
            "union" => {
                let refs = schema
                    .get("refs")
                    .and_then(Value::as_array)
                    .ok_or_else(|| fail(format!("{base}: a union has no refs")))?;
                for r in refs {
                    let r = r
                        .as_str()
                        .ok_or_else(|| fail(format!("{base}: a union ref is not a string")))?;
                    self.follow(base, r, seen)?;
                }
                Ok(())
            }
            t if FIELD_TYPES.contains(&t) => Ok(()),
            other => Err(fail(format!("{base}: no such field type {other:?}"))),
        }
    }

    fn follow(&self, base: &str, r: &str, seen: &mut BTreeSet<String>) -> Result<(), LoadError> {
        let (nsid, name) = resolve(base, r);
        if !seen.insert(format!("{nsid}#{name}")) {
            return Ok(());
        }
        let def = self
            .def(nsid, name)
            .ok_or_else(|| fail(format!("{base}: {nsid}#{name} does not resolve")))?;
        self.walk(nsid, def, seen)
    }
}

fn type_of(schema: &Value) -> Option<&str> {
    schema.get("type").and_then(Value::as_str)
}

/// One document's structure; its id and defs.
fn check_doc(doc: Value) -> Result<(String, Map<String, Value>), LoadError> {
    let Value::Object(mut doc) = doc else {
        return Err(fail("a document is not an object"));
    };
    if doc.get("lexicon").and_then(Value::as_u64) != Some(1) {
        return Err(fail(format!("{:?}: lexicon must be 1", doc.get("id"))));
    }
    let id = match doc.get("id").and_then(Value::as_str) {
        Some(id) if Nsid::new(id.to_string()).is_ok() => id.to_string(),
        other => return Err(fail(format!("{other:?}: id must be an NSID"))),
    };
    let Some(Value::Object(defs)) = doc.remove("defs") else {
        return Err(fail(format!("{id}: defs must be an object")));
    };
    for (name, def) in &defs {
        let ty = type_of(def).ok_or_else(|| fail(format!("{id}#{name}: no type")))?;
        if PRIMARY.contains(&ty) && name != "main" {
            return Err(fail(format!("{id}#{name}: a {ty} must be main")));
        }
        if FIELD_ONLY.contains(&ty) {
            return Err(fail(format!("{id}#{name}: a {ty} cannot be a def of its own")));
        }
        if ty == "record" {
            if def.get("key").and_then(Value::as_str).is_none() {
                return Err(fail(format!("{id}#{name}: a record needs a key")));
            }
            if def.get("record").and_then(type_of) != Some("object") {
                return Err(fail(format!("{id}#{name}: a record's record must be an object")));
            }
        }
    }
    Ok((id, defs))
}
```

Note the `seen` set spans all records: a def reached once is checked once, and a recursive ref cannot loop.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p brolly-atproto --test lexicon_vectors > /tmp/t.log 2>&1; echo exit=$?; grep -E "^test |test result" /tmp/t.log`
Expected: `exit=0`, 5 passed. If `the_vendored_tree_loads…` fails, the message names the def — read it before changing a rule: a vendored lexicon that trips the loader is either a loader bug or a real dangling ref (in which case the refresh tool's closure is wrong; fix the tool, not the check).

If `the_interop_valid_lexicons_load` fails because a catalog document's type is unfamiliar (e.g. `permission-set` internals), the loader only walks records, so the failure is in `check_doc`; widen only what the vector shows.

- [ ] **Step 5: Commit** (after fmt, clippy, doc-paths)

```bash
git add adapters/atproto/Cargo.toml Cargo.lock tools/refresh-lexicons.sh adapters/atproto/src/lib.rs \
  adapters/atproto/src/lexicon adapters/atproto/tests/lexicon_vectors.rs
git commit -m "feat(atproto): the lexicon registry, embedded and checked on load

The vendored lexicons are embedded with include_dir and parsed once
(stage 4a, H3, Decision C). The loader holds each document to the
lexicon language's structure — the interop suite's invalid documents are
refused — and walks every record's closure so a dangling ref fails the
load, not a write. Nothing validates against it yet.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

(`formats.rs` and `validate.rs` are still one-line stubs; that is fine — they are private modules with no items.)

### Task 3.4: String formats

**Files:**
- Modify: `adapters/atproto/src/lexicon/formats.rs`
- Test: `adapters/atproto/tests/lexicon_vectors.rs`

The bar is the interop syntax vectors. Each file is one value per line; skip blank lines and lines starting with `#`; do **not** trim (some invalid values are whitespace-sensitive). Which files hold for which format:

| Format | Must pass | Must fail |
|---|---|---|
| `at-identifier` | `atidentifier_syntax_valid.txt` | `atidentifier_syntax_invalid.txt` |
| `at-uri` | `aturi_syntax_valid.txt` | `aturi_syntax_invalid.txt` |
| `cid` | `cid_syntax_valid.txt` | `cid_syntax_invalid.txt` |
| `datetime` | `datetime_syntax_valid.txt` | `datetime_syntax_invalid.txt`, `datetime_parse_invalid.txt` |
| `did` | `did_syntax_valid.txt` | `did_syntax_invalid.txt` |
| `handle` | `handle_syntax_valid.txt` | `handle_syntax_invalid.txt` |
| `language` | `language_syntax_valid.txt` | `language_syntax_invalid.txt` |
| `nsid` | `nsid_syntax_valid.txt` | `nsid_syntax_invalid.txt` |
| `record-key` | `recordkey_syntax_valid.txt` | `recordkey_syntax_invalid.txt` |
| `tid` | `tid_syntax_valid.txt` | `tid_syntax_invalid.txt` |
| `uri` | `uri_syntax_valid.txt` | `uri_syntax_invalid.txt` |

`language_parse_invalid.txt` is **not** a bar: the lexicon `language` format is BCP 47 *well-formedness* (H4), and those values are well-formed but not "valid" (repeated subtags).

- [ ] **Step 1: Write the failing test**

Append to `adapters/atproto/tests/lexicon_vectors.rs`:

```rust
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
        ("at-identifier", "atidentifier_syntax_valid.txt", &["atidentifier_syntax_invalid.txt"]),
        ("at-uri", "aturi_syntax_valid.txt", &["aturi_syntax_invalid.txt"]),
        ("cid", "cid_syntax_valid.txt", &["cid_syntax_invalid.txt"]),
        ("datetime", "datetime_syntax_valid.txt", &["datetime_syntax_invalid.txt", "datetime_parse_invalid.txt"]),
        ("did", "did_syntax_valid.txt", &["did_syntax_invalid.txt"]),
        ("handle", "handle_syntax_valid.txt", &["handle_syntax_invalid.txt"]),
        ("language", "language_syntax_valid.txt", &["language_syntax_invalid.txt"]),
        ("nsid", "nsid_syntax_valid.txt", &["nsid_syntax_invalid.txt"]),
        ("record-key", "recordkey_syntax_valid.txt", &["recordkey_syntax_invalid.txt"]),
        ("tid", "tid_syntax_valid.txt", &["tid_syntax_invalid.txt"]),
        ("uri", "uri_syntax_valid.txt", &["uri_syntax_invalid.txt"]),
    ];
    let mut wrong = Vec::new();
    for (format, valid, invalids) in table {
        for v in lines(valid) {
            if !lexicon::formats::check(format, &v) {
                wrong.push(format!("{format}: refused valid {v:?}"));
            }
        }
        for file in invalids {
            for v in lines(file) {
                if lexicon::formats::check(format, &v) {
                    wrong.push(format!("{format}: accepted invalid {v:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{} disagreements:\n{}", wrong.len(), wrong.join("\n"));
}

#[test]
fn an_unknown_format_is_accepted() {
    // The evolution rules let a newer lexicon name a format this pin does not
    // know; the field is still a string.
    assert!(lexicon::formats::check("some-future-format", "anything"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p brolly-atproto --test lexicon_vectors format > /tmp/t.log 2>&1; echo exit=$?`
Expected: `exit=101`, `formats::check` not found. (The filter is `format`, which matches both tests; check `grep "running" /tmp/t.log` shows 2 tests once it compiles — a filter that matches nothing passes vacuously.)

- [ ] **Step 3: Implement**

`adapters/atproto/src/lexicon/formats.rs`:

```rust
//! String formats (stage 4a, H4). Identifier formats accept the most
//! expansive syntax; the interop syntax vectors are the bar.
//!
//! atrium's identifier types (`Did`, `Handle`, `Nsid`, `Tid`, `RecordKey`)
//! agree with the vectors and are reused. Three formats leave atrium:
//! `datetime` (atrium's `Datetime` refuses every negative offset but
//! `-0X:00`-style ones, so a `-10:00` `createdAt` would be refused, and it
//! accepts year-zero instants the reference refuses), `language` (`langtag`
//! accepts primary subtags like `jaja` and `JA` the reference refuses), and
//! `uri`/`at-uri`, which follow the reference's own patterns
//! (`@atproto/syntax`, `@atproto/lexicon`'s `formats.ts`). `cid` is checked
//! for syntax only, as the reference's lexicon does.

use std::sync::LazyLock;

use atrium_api::types::string::{Did, Handle, Language, Nsid, RecordKey, Tid};
use regex::Regex;

/// RFC 3339 ∩ ISO 8601 as the data model has it: uppercase `T`, seconds
/// required, any number of fractional digits, `Z` or a numeric offset.
static DATETIME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^[0-9]{4}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-6][0-9]:[0-6][0-9](\.[0-9]{1,20})?(Z|[+-][0-2][0-9]:[0-5][0-9])$",
    )
    .ok()
});

/// 0000-01-01T00:00:00Z: the reference refuses an instant before year zero.
const YEAR_ZERO: i64 = -62_167_219_200;

/// A BCP 47 primary language subtag as the reference reads it: two or three
/// lowercase letters, or the `i`/`x` singletons.
static LANGUAGE_PRIMARY: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(i|x|X|[a-z]{2,3})(-|$)").ok());

/// A URI scheme (RFC 3986: a letter, then letters, digits, `+`, `.`, `-`)
/// and a non-empty, whitespace-free rest.
static URI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$").ok());

/// The reference's AT-URI pattern: authority, optional collection,
/// optional rkey, optional `#/…` fragment.
static AT_URI: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^at://([a-zA-Z0-9._:%-]+)(/([a-zA-Z0-9.-]+)(/([a-zA-Z0-9._~:@!$&%')(*+,;=-]+))?)?(#(/[a-zA-Z0-9._~:@!$&%')(*+,;=\-\[\]/\\]*))?$",
    )
    .ok()
});

fn matches(re: &LazyLock<Option<Regex>>, s: &str) -> bool {
    re.as_ref().is_some_and(|re| re.is_match(s))
}

/// Whether `s` is a valid `format`. A format this pin does not know is
/// accepted: the field is still a string, and the evolution rules let a
/// newer lexicon add one.
pub fn check(format: &str, s: &str) -> bool {
    match format {
        "at-identifier" => at_identifier(s),
        "at-uri" => at_uri(s),
        "cid" => cid(s),
        "datetime" => datetime(s),
        "did" => Did::new(s.to_string()).is_ok(),
        "handle" => Handle::new(s.to_string()).is_ok(),
        "language" => matches(&LANGUAGE_PRIMARY, s) && Language::new(s.to_string()).is_ok(),
        "nsid" => Nsid::new(s.to_string()).is_ok(),
        "record-key" => RecordKey::new(s.to_string()).is_ok(),
        "tid" => Tid::new(s.to_string()).is_ok(),
        "uri" => s.len() <= 8192 && matches(&URI, s),
        _ => true,
    }
}

fn at_identifier(s: &str) -> bool {
    if s.starts_with("did:") {
        Did::new(s.to_string()).is_ok()
    } else {
        Handle::new(s.to_string()).is_ok()
    }
}

fn at_uri(s: &str) -> bool {
    if s.len() > 8192 {
        return false;
    }
    let Some(caps) = AT_URI.as_ref().and_then(|re| re.captures(s)) else {
        return false;
    };
    let authority_ok = caps.get(1).is_some_and(|a| at_identifier(a.as_str()));
    let collection_ok = caps
        .get(3)
        .is_none_or(|c| Nsid::new(c.as_str().to_string()).is_ok());
    let rkey_ok = caps
        .get(5)
        .is_none_or(|r| RecordKey::new(r.as_str().to_string()).is_ok());
    authority_ok && collection_ok && rkey_ok
}

/// Syntax only, as the reference's lexicon checks it; a CIDv0 (`Qmb…`) is
/// not a CID string the network writes.
fn cid(s: &str) -> bool {
    (8..=256).contains(&s.len())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '=')
        && !s.starts_with("Qmb")
}

fn datetime(s: &str) -> bool {
    s.len() <= 64
        && !s.ends_with("-00:00")
        && matches(&DATETIME, s)
        // The calendar (month 13, hour 25 pass the pattern) and year zero.
        && time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .is_ok_and(|d| d.unix_timestamp() >= YEAR_ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        for re in [&DATETIME, &LANGUAGE_PRIMARY, &URI, &AT_URI] {
            assert!(re.is_some());
        }
    }

    #[test]
    fn a_negative_offset_is_a_datetime() {
        // Not in the interop vectors; atrium's `Datetime` refuses it.
        assert!(datetime("1985-04-12T23:20:50.123-10:00"));
        assert!(datetime("2026-11-27T00:00:00.123456789012Z"));
    }
}
```

- [ ] **Step 4: Run and close the gaps the vectors show**

Run: `cargo test -p brolly-atproto --test lexicon_vectors format > /tmp/t.log 2>&1; echo exit=$?; grep running /tmp/t.log; sed -n '/disagreements/,/^$/p' /tmp/t.log | head -40`

Expected: `exit=0` and `running 2 tests` — the code above was checked against every vector during plan review (0 disagreements). If a disagreement appears anyway, **the vector wins**: open the reference rule in `bluesky-social/atproto` at `665c90c8` (`packages/syntax/src/{did,handle,nsid,tid,recordkey,aturi_validation,datetime,language}.ts`) and replace that arm of `check` with the reference's rule as a private function, with a one-line comment saying why atrium's type was not enough. Do not loosen a vector or skip a line. Re-run until `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add adapters/atproto/src/lexicon/formats.rs adapters/atproto/tests/lexicon_vectors.rs
git commit -m "feat(atproto): lexicon string formats, held to the interop syntax vectors

Every format the vendored lexicons name (stage 4a, H4), checked against
atproto-interop-tests' syntax vectors: atrium's identifier types where
they agree with the network, the reference's own rules where they do
not. datetime leaves atrium, whose Datetime refuses a -10:00 offset;
language leaves langtag, which accepts primary subtags like "jaja"; uri
and at-uri follow the reference's patterns; cid is syntax only.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

### Task 3.5: The validator

**Files:**
- Modify: `adapters/atproto/src/lexicon/validate.rs`, `adapters/atproto/src/lexicon/registry.rs` (the public entry points)
- Test: `adapters/atproto/tests/lexicon_vectors.rs`

The public surface, on `Registry`:

```rust
/// `record` — **normalised** JSON (`data_model::to_json` of the IPLD to be
/// committed) — against `collection`'s record lexicon, and `rkey` (when
/// known) against its `key`. `Ok(Status::Unknown)` when the collection has
/// no lexicon here; `Err(problem)` with the path-first message otherwise.
pub fn validate(&self, collection: &str, rkey: Option<&str>, record: &Value) -> Result<Status, String>;

/// `rkey` against `collection`'s record `key`. Unknown collections pass.
pub fn check_key(&self, collection: &str, rkey: &str) -> Result<(), String>;
```

A collection whose NSID is loaded but whose `main` is not a record (`app.bsky.feed.getTimeline`) is refused: `{collection} is not a record type`.

Normalised JSON means the special forms are unambiguous: an object with a single `$link` key is a link, a single `$bytes` key is bytes, an object with `"$type": "blob"` is a blob (the data model has already refused malformed ones). Integers are `i64`s (`1.0` arrived as `1`).

- [ ] **Step 1: Write the failing tests — the corpus and the interop record suite**

Append to `adapters/atproto/tests/lexicon_vectors.rs`:

```rust
use brolly_atproto::data_model;
use brolly_atproto::lexicon::Status;

/// What the whole pre-commit path says about one record: the data model,
/// then the lexicon. A data-model refusal is a refusal.
fn verdict(registry: &Registry, collection: &str, rkey: &str, record: &Value) -> Result<Status, String> {
    let ipld = data_model::record_from_json(record).map_err(|e| e.to_string())?;
    registry.validate(collection, Some(rkey), &data_model::to_json(&ipld))
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
            wrong.push(format!("{}: expected {}, got {got:?}", case["name"], case["expect"]));
        }
    }
    assert!(wrong.is_empty(), "{} of the corpus disagree:\n{}", wrong.len(), wrong.join("\n"));
}

#[test]
fn the_interop_record_suite_holds() {
    let dir = fixtures().join("interop/lexicon");
    let registry = registry_with(&dir.join("catalog"));
    let mut wrong = Vec::new();
    for (file, want_valid) in [("record-data-valid.json", true), ("record-data-invalid.json", false)] {
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
    assert!(wrong.is_empty(), "{} disagree:\n{}", wrong.len(), wrong.join("\n"));
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
        Err("record/text must not be longer than 300 graphemes".to_string())
    );
    let no_date = serde_json::json!({"$type": "app.bsky.feed.post", "text": "hi"});
    assert_eq!(
        registry.validate("app.bsky.feed.post", None, &no_date),
        Err("record must have the property \"createdAt\"".to_string())
    );
}

#[test]
fn a_collection_that_is_not_a_record_type_is_refused() {
    let registry = lexicon::vendored().unwrap();
    let err = registry
        .validate("app.bsky.feed.getTimeline", None, &serde_json::json!({}))
        .unwrap_err();
    assert_eq!(err, "app.bsky.feed.getTimeline is not a record type");
}

#[test]
fn key_types_hold() {
    let registry = lexicon::vendored().unwrap();
    assert!(registry.check_key("app.bsky.actor.profile", "self").is_ok());
    assert!(registry.check_key("app.bsky.actor.profile", "3kaaaaaaaaaab").is_err());
    assert!(registry.check_key("app.bsky.feed.post", "3kaaaaaaaaaab").is_ok());
    assert!(registry.check_key("app.bsky.feed.post", "nottid").is_err());
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
    let err = registry.validate("com.example.deep", None, &value).unwrap_err();
    assert!(err.contains("nested too deeply"), "{err}");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p brolly-atproto --test lexicon_vectors > /tmp/t.log 2>&1; echo exit=$?`
Expected: `exit=101`, `validate`/`check_key` not found.

- [ ] **Step 3: Implement the entry points**

Append to the `impl Registry` block in `registry.rs`:

```rust
    /// `record` — normalised JSON — against `collection`'s record lexicon,
    /// and `rkey` (when known) against its `key` (H4, H5).
    pub fn validate(
        &self,
        collection: &str,
        rkey: Option<&str>,
        record: &Value,
    ) -> Result<super::Status, String> {
        if !self.knows(collection) {
            return Ok(super::Status::Unknown);
        }
        let main = self
            .record(collection)
            .ok_or_else(|| format!("{collection} is not a record type"))?;
        if let Some(rkey) = rkey {
            self.check_key(collection, rkey)?;
        }
        let schema = main.get("record").unwrap_or(&Value::Null);
        self.check(collection, schema, record, "record", 0)?;
        Ok(super::Status::Valid)
    }

    /// `rkey` against `collection`'s record `key`. Unknown collections pass;
    /// the rkey's own grammar is checked where it is parsed.
    pub fn check_key(&self, collection: &str, rkey: &str) -> Result<(), String> {
        if !self.knows(collection) {
            return Ok(());
        }
        let key = self
            .record(collection)
            .ok_or_else(|| format!("{collection} is not a record type"))?
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or("");
        let (ok, what) = match key {
            "any" => (true, "any"),
            "tid" => (Tid::new(rkey.to_string()).is_ok(), "a TID"),
            "nsid" => (Nsid::new(rkey.to_string()).is_ok(), "an NSID"),
            other => match other.strip_prefix("literal:") {
                Some(want) => (rkey == want, want),
                None => (false, other),
            },
        };
        if ok {
            Ok(())
        } else {
            Err(format!("record key {rkey} is not {what}"))
        }
    }
```

and add `Tid` to the `atrium_api::types::string` import.

- [ ] **Step 4: Implement the walk**

`adapters/atproto/src/lexicon/validate.rs`:

```rust
//! The validator (stage 4a, H4; Decision D): a record's normalised JSON
//! against its schema. Unexpected fields are ignored, as the lexicon
//! evolution rules require; only declared properties are descended, so a
//! path is built from schema names and indices, never from a client's keys.

use serde_json::{Map, Value};
use unicode_segmentation::UnicodeSegmentation;

use super::formats;
use super::registry::{Registry, resolve};

/// How deep the walk may go through nesting and refs. Recursive lexicons
/// exist; this bounds the walk whatever the record.
const MAX_DEPTH: usize = 64;

type Check = Result<(), String>;

fn is_link(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == 1 && o.get("$link").is_some_and(Value::is_string))
}

fn bytes_b64(v: &Value) -> Option<&str> {
    v.as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.get("$bytes"))
        .and_then(Value::as_str)
}

fn is_blob(v: &Value) -> bool {
    v.get("$type").and_then(Value::as_str) == Some("blob")
}

/// An object that is not one of the data model's special forms.
fn plain_object(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
        .filter(|_| !is_link(v) && bytes_b64(v).is_none())
}

fn uint(schema: &Value, field: &str) -> Option<u64> {
    schema.get(field).and_then(Value::as_u64)
}

fn names<'a>(schema: &'a Value, field: &str) -> Vec<&'a str> {
    schema
        .get(field)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

impl Registry {
    pub(crate) fn check(
        &self,
        base: &str,
        schema: &Value,
        value: &Value,
        path: &str,
        depth: usize,
    ) -> Check {
        if depth > MAX_DEPTH {
            return Err(format!("{path} is nested too deeply"));
        }
        match schema.get("type").and_then(Value::as_str).unwrap_or("") {
            "null" if value.is_null() => Ok(()),
            "null" => Err(format!("{path} must be null")),
            "boolean" => boolean(schema, value, path),
            "integer" => integer(schema, value, path),
            "string" => string(schema, value, path),
            "bytes" => bytes(schema, value, path),
            "cid-link" if is_link(value) => Ok(()),
            "cid-link" => Err(format!("{path} must be a CID")),
            "blob" => blob(schema, value, path),
            "unknown" => match plain_object(value) {
                Some(_) if !is_blob(value) => Ok(()),
                _ => Err(format!("{path} must be an object")),
            },
            "array" => self.array(base, schema, value, path, depth),
            "object" => self.object(base, schema, value, path, depth),
            "ref" => self.reference(base, schema, value, path, depth),
            "union" => self.union(base, schema, value, path, depth),
            // A token is a value reached through a `ref` (`reference`
            // handles it); written inline as a field it can hold nothing.
            "token" => Err(format!("{path}: a token is a value, not a field")),
            other => Err(format!("{path}: the lexicon has no rule for {other:?}")),
        }
    }

    fn object(&self, base: &str, schema: &Value, value: &Value, path: &str, depth: usize) -> Check {
        let Some(fields) = plain_object(value) else {
            return Err(format!("{path} must be an object"));
        };
        for key in names(schema, "required") {
            if !fields.contains_key(key) {
                return Err(format!("{path} must have the property \"{key}\""));
            }
        }
        let nullable = names(schema, "nullable");
        let Some(props) = schema.get("properties").and_then(Value::as_object) else {
            return Ok(());
        };
        for (key, prop) in props {
            match fields.get(key) {
                None => {}
                Some(Value::Null) if nullable.contains(&key.as_str()) => {}
                Some(v) => self.check(base, prop, v, &format!("{path}/{key}"), depth + 1)?,
            }
        }
        Ok(())
    }

    fn array(&self, base: &str, schema: &Value, value: &Value, path: &str, depth: usize) -> Check {
        let Some(items) = value.as_array() else {
            return Err(format!("{path} must be an array"));
        };
        let len = items.len() as u64;
        if let Some(max) = uint(schema, "maxLength")
            && len > max
        {
            return Err(format!("{path} must not have more than {max} elements"));
        }
        if let Some(min) = uint(schema, "minLength")
            && len < min
        {
            return Err(format!("{path} must not have fewer than {min} elements"));
        }
        let Some(item_schema) = schema.get("items") else {
            return Ok(());
        };
        for (i, item) in items.iter().enumerate() {
            self.check(base, item_schema, item, &format!("{path}/{i}"), depth + 1)?;
        }
        Ok(())
    }

    fn reference(&self, base: &str, schema: &Value, value: &Value, path: &str, depth: usize) -> Check {
        let r = schema.get("ref").and_then(Value::as_str).unwrap_or("");
        let (nsid, name) = resolve(base, r);
        let Some(def) = self.def(nsid, name) else {
            return Err(format!("{path}: the lexicon refers to {nsid}#{name}, which is not loaded"));
        };
        if def.get("type").and_then(Value::as_str) == Some("token") {
            let token = format!("{nsid}#{name}");
            return match value.as_str() {
                Some(s) if s == token => Ok(()),
                _ => Err(format!("{path} must be {token}")),
            };
        }
        self.check(nsid, def, value, path, depth + 1)
    }

    fn union(&self, base: &str, schema: &Value, value: &Value, path: &str, depth: usize) -> Check {
        let Some(t) = plain_object(value)
            .and_then(|o| o.get("$type"))
            .and_then(Value::as_str)
        else {
            return Err(format!(
                "{path} must be an object which includes the \"$type\" property"
            ));
        };
        let want = if t.contains('#') { t.to_string() } else { format!("{t}#main") };
        let refs = names(schema, "refs");
        for r in &refs {
            let (nsid, name) = resolve(base, r);
            if format!("{nsid}#{name}") == want {
                let Some(def) = self.def(nsid, name) else {
                    return Err(format!("{path}: the lexicon refers to {want}, which is not loaded"));
                };
                return self.check(nsid, def, value, path, depth + 1);
            }
        }
        if schema.get("closed").and_then(Value::as_bool) == Some(true) {
            let all: Vec<String> = refs
                .iter()
                .map(|r| {
                    let (nsid, name) = resolve(base, r);
                    format!("{nsid}#{name}")
                })
                .collect();
            return Err(format!("{path} $type must be one of {}", all.join(", ")));
        }
        // An open union accepts a type it does not know, unvalidated.
        Ok(())
    }
}

fn boolean(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(b) = value.as_bool() else {
        return Err(format!("{path} must be a boolean"));
    };
    match schema.get("const").and_then(Value::as_bool) {
        Some(c) if c != b => Err(format!("{path} must be {c}")),
        _ => Ok(()),
    }
}

fn integer(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(n) = value.as_i64() else {
        return Err(format!("{path} must be an integer"));
    };
    if let Some(c) = schema.get("const").and_then(Value::as_i64)
        && c != n
    {
        return Err(format!("{path} must be {c}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.iter().any(|a| a.as_i64() == Some(n))
    {
        let list: Vec<String> = allowed.iter().map(Value::to_string).collect();
        return Err(format!("{path} must be one of ({})", list.join("|")));
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_i64)
        && n > max
    {
        return Err(format!("{path} can not be greater than {max}"));
    }
    if let Some(min) = schema.get("minimum").and_then(Value::as_i64)
        && n < min
    {
        return Err(format!("{path} can not be less than {min}"));
    }
    Ok(())
}

fn string(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(s) = value.as_str() else {
        return Err(format!("{path} must be a string"));
    };
    if let Some(c) = schema.get("const").and_then(Value::as_str)
        && c != s
    {
        return Err(format!("{path} must be {c}"));
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.iter().any(|a| a.as_str() == Some(s))
    {
        let list: Vec<&str> = allowed.iter().filter_map(Value::as_str).collect();
        return Err(format!("{path} must be one of ({})", list.join("|")));
    }
    let bytes = s.len() as u64;
    if let Some(max) = uint(schema, "maxLength")
        && bytes > max
    {
        return Err(format!("{path} must not be longer than {max} characters"));
    }
    if let Some(min) = uint(schema, "minLength")
        && bytes < min
    {
        return Err(format!("{path} must not be shorter than {min} characters"));
    }
    // A string has no more graphemes than bytes, so a short one is never
    // counted for a maximum.
    let mut counted = None;
    let mut graphemes = || *counted.get_or_insert_with(|| s.graphemes(true).count() as u64);
    if let Some(max) = uint(schema, "maxGraphemes")
        && bytes > max
        && graphemes() > max
    {
        return Err(format!("{path} must not be longer than {max} graphemes"));
    }
    if let Some(min) = uint(schema, "minGraphemes")
        && graphemes() < min
    {
        return Err(format!("{path} must not be shorter than {min} graphemes"));
    }
    if let Some(format) = schema.get("format").and_then(Value::as_str)
        && !formats::check(format, s)
    {
        return Err(format!("{path} must be a valid {format}"));
    }
    Ok(())
}

fn bytes(schema: &Value, value: &Value, path: &str) -> Check {
    let Some(b64) = bytes_b64(value) else {
        return Err(format!("{path} must be a byte array"));
    };
    // The data model has already decoded it once; its length follows from
    // the unpadded length without decoding again.
    let len = (b64.trim_end_matches('=').len() * 3 / 4) as u64;
    if let Some(max) = uint(schema, "maxLength")
        && len > max
    {
        return Err(format!("{path} must not be larger than {max} bytes"));
    }
    if let Some(min) = uint(schema, "minLength")
        && len < min
    {
        return Err(format!("{path} must not be smaller than {min} bytes"));
    }
    Ok(())
}

/// `accept` as the lexicon defines it: exact types, `type/*`, and `*/*`.
/// Nothing else is a glob.
fn accepts(pattern: &str, mime: &str) -> bool {
    if pattern == "*/*" {
        return true;
    }
    match pattern.strip_suffix("/*") {
        Some(top) => mime.split_once('/').is_some_and(|(t, _)| t == top),
        None => pattern == mime,
    }
}

fn blob(schema: &Value, value: &Value, path: &str) -> Check {
    if !is_blob(value) {
        return Err(format!("{path} must be a blob ref"));
    }
    let mime = value.get("mimeType").and_then(Value::as_str).unwrap_or("");
    let size = value.get("size").and_then(Value::as_u64).unwrap_or(u64::MAX);
    if let Some(accept) = schema.get("accept").and_then(Value::as_array) {
        let list: Vec<&str> = accept.iter().filter_map(Value::as_str).collect();
        if !list.iter().any(|p| accepts(p, mime)) {
            return Err(format!("{path} mimeType {mime} is not accepted ({})", list.join(", ")));
        }
    }
    if let Some(max) = uint(schema, "maxSize")
        && size > max
    {
        return Err(format!("{path} is {size} bytes, over maxSize {max}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_is_exact_or_a_whole_top_level_type() {
        assert!(accepts("*/*", "video/mp4"));
        assert!(accepts("image/*", "image/png"));
        assert!(!accepts("image/*", "imagey/png"));
        assert!(accepts("image/png", "image/png"));
        assert!(!accepts("image/pn*", "image/png"));
    }

    #[test]
    fn a_byte_length_follows_from_padded_and_unpadded_base64() {
        for (b64, len) in [("", 0), ("AQ", 1), ("AQ==", 1), ("AQI", 2), ("AQID", 3), ("AQIDBA", 4)] {
            assert_eq!((b64.trim_end_matches('=').len() * 3 / 4), len, "{b64}");
        }
    }
}
```

Notes for the implementer:
- `bytes` length arithmetic: unpadded base64 of n bytes has `ceil(4n/3)` characters, and `floor(chars·3/4)` recovers n for every remainder (0, 2, 3). The unit test pins it.
- The `graphemes` closure borrows `counted` mutably; if the borrow checker objects to calling it in two `if let … &&` chains, compute `let mut count = || …` as a plain `Option<u64>` and fill it explicitly. Behaviour, not shape, is the requirement: count graphemes at most once, and not at all when `bytes <= maxGraphemes` and there is no `minGraphemes`.
- Do not descend `unknown`. Do not validate an open union's unknown member.

- [ ] **Step 5: Run, and close each disagreement against the reference**

Run: `cargo test -p brolly-atproto --test lexicon_vectors > /tmp/t.log 2>&1; echo exit=$?; grep -E "disagree|^test .*FAILED" -A30 /tmp/t.log | head -60`

Expected: `exit=0` — all corpus and interop cases agree. If any disagree, each is a rule this walk gets wrong; read the case, find the rule in the spec (H4) or the reference's `packages/lexicon/src/validators/*.ts` at `665c90c8`, fix the walk. Never edit a vector or the corpus to agree with the code — a corpus case is only changed if it is shown to be wrong against the lexicon spec, and then the commit says so.

Also run the crate's unit tests: `cargo test -p brolly-atproto --lib lexicon > /tmp/u.log 2>&1; echo exit=$?` — expect `exit=0`.

- [ ] **Step 6: Commit**

```bash
git add adapters/atproto/src/lexicon adapters/atproto/tests/lexicon_vectors.rs
git commit -m "feat(atproto): the lexicon validator, written (Decision D)

Records are walked against their vendored lexicon in normalised JSON —
what will be committed, not what was sent (Decision F). Every rule in H4:
null and nullable, required, UTF-8 and grapheme lengths, enum/const,
integer ranges, bytes, cid-links, blobs with accept and maxSize, open and
closed unions, unknown, local and remote refs, tokens, and the rkey
against the record's key. It agrees with all 107 corpus cases and the
whole atproto-interop-tests lexicon suite. The walk is depth-bounded and
builds paths only from schema names, so hostile records cost what their
size costs. No write calls it yet.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

### Task 3.6: Force the load at startup

**Files:**
- Modify: `server/src/main.rs`

- [ ] **Step 1: Load the lexicons before the database**

In `main()`, directly after the `tracing_subscriber` block and before `plc_client`:

```rust
    // The vendored lexicons are parsed here, before anything else is
    // opened, so a tree that does not load stops the boot with a clear
    // error rather than refusing the first write (stage 4a, Decision C).
    if let Err(e) = brolly_atproto::lexicon::vendored() {
        tracing::error!(error = %e, "the vendored lexicons did not load");
        return Err(e.into());
    }
```

Check `server/Cargo.toml` already depends on `brolly-atproto` (it does: `xrpc.rs` uses it). No test: `main` is not exercised by the suite; the load itself is tested by `the_vendored_tree_loads_and_every_record_ref_resolves`.

- [ ] **Step 2: Build and boot-check**

Run: `cargo build -p brolly-server > /tmp/b.log 2>&1; echo exit=$?` — expect `exit=0`.

- [ ] **Step 3: The whole suite, then commit**

Run: `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test --workspace --no-fail-fast > /tmp/full.log 2>&1; echo exit=$?; grep -E "^test result|FAILED|panicked" /tmp/full.log | sort | uniq -c | head -40`
Expected: `exit=0` (or only the known flakes, each confirmed by a single re-run). Behaviour is unchanged: nothing calls the validator on a write yet.

```bash
git add server/src/main.rs
git commit -m "feat(server): the vendored lexicons load at boot, or the boot stops

Decision C: a malformed or dangling vendored lexicon is a deploy that
should not start, not a write that fails later.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

## Chunk 4: The gate and the wire (H5, H6)

Ends with every write — `createRecord`, `putRecord`, `applyWrites`, `swapRecord`, `swapCommit` — validated against its lexicon through one gate, `validate` honoured per Decision E's table, `validationStatus` in every answer, and `applyWrites` results in their lexicon union. The test fixtures that wrote invalid posts are fixed in the same commit that turns validation on, so every commit stays green.

### Task 4.1: The gate — `check_record`, `check_key`, `Validate`

**Files:**
- Modify: `adapters/atproto/src/record.rs`

`prepare` becomes `check_record`; its tests move with it. **Nothing calls `check_record` yet** — `PlannedWrite` still calls `prepare` until Task 4.2, so keep `prepare` as a thin wrapper for one commit:

- [ ] **Step 1: Write the failing tests**

Replace `record.rs`'s `mod tests` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nsid(s: &str) -> Nsid {
        Nsid::new(s.into()).unwrap()
    }

    fn rkey(s: &str) -> RecordKey {
        RecordKey::new(s.into()).unwrap()
    }

    const CREATED: &str = "2026-11-27T00:00:00.000Z";

    fn a_post() -> Value {
        json!({"$type": "app.bsky.feed.post", "text": "hi", "createdAt": CREATED})
    }

    fn a_bad_post() -> Value {
        json!({"$type": "app.bsky.feed.post", "text": "hi"})
    }

    #[test]
    fn a_record_that_is_not_an_object_is_refused_not_panicked() {
        for value in [json!("blah"), json!(1), json!([1]), json!(null), json!(true)] {
            assert!(
                check_record(&nsid("app.bsky.feed.post"), None, &value, Validate::Optimistic).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn a_missing_type_is_filled_with_the_collection() {
        let (ipld, status) =
            check_record(&nsid("com.example.thing"), None, &json!({"text": "hi"}), Validate::Optimistic)
                .unwrap();
        assert_eq!(crate::data_model::to_json(&ipld)["$type"], "com.example.thing");
        assert_eq!(status, Status::Unknown);
    }

    #[test]
    fn a_different_type_is_refused_under_every_validate() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            let err = check_record(
                &nsid("app.bsky.feed.post"),
                None,
                &json!({"$type": "app.bsky.feed.like"}),
                validate,
            )
            .unwrap_err();
            assert_eq!(
                err.to_string(),
                "Invalid $type: expected app.bsky.feed.post, got app.bsky.feed.like"
            );
        }
    }

    #[test]
    fn a_type_that_is_not_a_string_is_refused() {
        let err = check_record(&nsid("com.example.thing"), None, &json!({"$type": 1}), Validate::Optimistic)
            .unwrap_err();
        assert_eq!(err.to_string(), "record/$type: $type must be a non-empty string");
    }

    #[test]
    fn the_data_model_applies_inside_under_every_validate() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            assert!(check_record(&nsid("com.example.thing"), None, &json!({"n": 1.5}), validate).is_err());
        }
    }

    // Decision E's table, cell by cell.

    #[test]
    fn known_and_valid_is_valid_under_every_validate() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            let (_, status) = check_record(&nsid("app.bsky.feed.post"), None, &a_post(), validate).unwrap();
            assert_eq!(status, Status::Valid);
        }
    }

    #[test]
    fn known_and_invalid_is_refused_under_every_validate_even_false() {
        for validate in [Validate::Required, Validate::Skip, Validate::Optimistic] {
            let err = check_record(&nsid("app.bsky.feed.post"), None, &a_bad_post(), validate).unwrap_err();
            assert_eq!(
                err.to_string(),
                "Invalid app.bsky.feed.post record: record must have the property \"createdAt\""
            );
        }
    }

    #[test]
    fn unknown_is_accepted_unless_validation_is_required() {
        let thing = json!({"$type": "com.example.thing", "x": 1});
        for validate in [Validate::Skip, Validate::Optimistic] {
            let (_, status) = check_record(&nsid("com.example.thing"), None, &thing, validate).unwrap();
            assert_eq!(status, Status::Unknown);
        }
        let err = check_record(&nsid("com.example.thing"), None, &thing, Validate::Required).unwrap_err();
        assert_eq!(err.to_string(), "Unknown lexicon type: com.example.thing");
    }

    #[test]
    fn the_validate_parameter_maps_to_the_table() {
        assert_eq!(Validate::from_param(Some(true)), Validate::Required);
        assert_eq!(Validate::from_param(Some(false)), Validate::Skip);
        assert_eq!(Validate::from_param(None), Validate::Optimistic);
    }

    #[test]
    fn a_known_rkey_is_held_to_the_key_type() {
        let profile = json!({"$type": "app.bsky.actor.profile"});
        let collection = nsid("app.bsky.actor.profile");
        assert!(check_record(&collection, Some(&rkey("self")), &profile, Validate::Optimistic).is_ok());
        let err = check_record(&collection, Some(&rkey("3kaaaaaaaaaab")), &profile, Validate::Optimistic)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid app.bsky.actor.profile record: record key 3kaaaaaaaaaab is not self"
        );
        assert!(check_key(&collection, &rkey("3kaaaaaaaaaab")).is_err());
        assert!(check_key(&collection, &rkey("self")).is_ok());
    }

    #[test]
    fn a_valid_like_with_a_strong_ref_passes_validate_true() {
        let like = json!({
            "$type": "app.bsky.feed.like",
            "subject": {"uri": "at://did:plc:abc/app.bsky.feed.post/3kaaaaaaaaaab",
                        "cid": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"},
            "createdAt": CREATED,
        });
        assert!(check_record(&nsid("app.bsky.feed.like"), None, &like, Validate::Required).is_ok());
    }
}
```


- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p brolly-atproto --lib record:: > /tmp/t.log 2>&1; echo exit=$?`
Expected: `exit=101`, `check_record`/`Validate` not found.

- [ ] **Step 3: Implement**

Replace the body of `record.rs` above `mod tests` with:

```rust
//! The gate (stage 4a, H2, H5): what every write's record passes through
//! before a block is made of it.
//!
//! In order: the record is an object; `$type` is filled with the collection
//! when missing and refused when it names another (the reference's rule,
//! under any `validate`); the data model (`data_model`); then the record's
//! lexicon (`lexicon`), against the **normalised** value, so what is
//! validated is what is committed (Decision F). This is the only place a
//! `$type` is filled. A record must name its own type because the pod's
//! faithful layer keys every field under it.
//!
//! Part c (ADR 0022) wraps this behind a protocol-neutral container hook;
//! nothing ATProto-typed crosses into the core.

use atrium_api::types::string::{Nsid, RecordKey};
use ipld_core::ipld::Ipld;
use serde_json::Value;

use crate::data_model;
use crate::lexicon::{self, Status};
use crate::repo::RepoError;

/// What a write asked for, as the lexicons define `validate` (H5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validate {
    /// `validate: true` — an unknown lexicon is refused.
    Required,
    /// `validate: false` — the reference skips validation; brolly still
    /// validates a known lexicon (Decision E), so this differs from
    /// `Optimistic` only in name.
    Skip,
    /// `validate` absent — known lexicons validated, unknown accepted.
    Optimistic,
}

impl Validate {
    /// The wire's optional boolean.
    pub fn from_param(validate: Option<bool>) -> Self {
        match validate {
            Some(true) => Validate::Required,
            Some(false) => Validate::Skip,
            None => Validate::Optimistic,
        }
    }
}

fn lexicons() -> Result<&'static lexicon::Registry, RepoError> {
    // Forced at startup, so this does not fail in a running server.
    lexicon::vendored().map_err(|e| RepoError::Repo(e.to_string()))
}

/// H2 and H5: envelope, data model, lexicon. The IPLD to commit and the
/// status to answer with. `rkey` is `None` for a create that has not
/// minted one; `apply` runs [`check_key`] once it has.
pub fn check_record(
    collection: &Nsid,
    rkey: Option<&RecordKey>,
    record: &Value,
    validate: Validate,
) -> Result<(Ipld, Status), RepoError> {
    let ipld = envelope(collection, record)?;
    let normalised = data_model::to_json(&ipld);
    let status = lexicons()?
        .validate(collection.as_str(), rkey.map(|r| r.as_str()), &normalised)
        .map_err(|why| invalid(collection, &why))?;
    if status == Status::Unknown && validate == Validate::Required {
        return Err(RepoError::InvalidRecord(format!(
            "Unknown lexicon type: {}",
            collection.as_str()
        )));
    }
    Ok((ipld, status))
}

/// The lexicon's `key` type against an rkey (H5).
pub fn check_key(collection: &Nsid, rkey: &RecordKey) -> Result<(), RepoError> {
    lexicons()?
        .check_key(collection.as_str(), rkey.as_str())
        .map_err(|why| invalid(collection, &why))
}

fn invalid(collection: &Nsid, why: &str) -> RepoError {
    RepoError::InvalidRecord(format!("Invalid {} record: {why}", collection.as_str()))
}

/// The envelope and the data model (H1, H2): what `prepare` was.
fn envelope(collection: &Nsid, record: &Value) -> Result<Ipld, RepoError> {
    // (the existing body of `prepare`, unchanged)
}

/// Until `PlannedWrite` moves to [`check_record`] (the next task).
pub fn prepare(collection: &Nsid, record: &Value) -> Result<Ipld, RepoError> {
    envelope(collection, record)
}
```

Move `prepare`'s current body verbatim into `envelope`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p brolly-atproto --lib record:: > /tmp/t.log 2>&1; echo exit=$?; grep "test result" /tmp/t.log`
Expected: `exit=0`.

- [ ] **Step 5: Commit**

```bash
git add adapters/atproto/src/record.rs
git commit -m "feat(atproto): the gate — check_record and check_key (H5)

Envelope, data model, then the lexicon against the normalised value, in
one function, with validate as the lexicons define it and Decision E
held: validate:false cannot skip a known lexicon. Not yet called by the
write path.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

### Task 4.2: Every write through the gate, and the fixtures that wrote invalid records

This is the commit that turns validation on. Every test that wrote an invalid record breaks in it and is fixed in it.

**Files:**
- Modify: `adapters/atproto/src/repo.rs` (constructors, `PlannedWrite`, `apply`, `AppliedOp`, tests)
- Modify: `adapters/atproto/src/record.rs` (delete `prepare`)
- Modify: `server/src/xrpc.rs` (six constructor calls)
- Modify: `test-support/Cargo.toml`, `test-support/src/lib.rs`; create `test-support/src/atproto.rs`
- Modify (fixtures): `adapters/atproto/tests/firehose.rs`, `adapters/atproto/tests/car_export.rs`, `server/tests/xrpc.rs`, and any other test the suite run names

- [ ] **Step 1: The fixture helpers**

`test-support/Cargo.toml` `[dependencies]`: add `serde_json = "1"` (check the version spelled elsewhere in the workspace and match it).

`test-support/src/atproto.rs`:

```rust
//! Fixtures for ATProto writes that hold to their lexicons (stage 4a, H5).

use serde_json::{Value, json};

/// A fixed, valid `createdAt`.
pub const CREATED_AT: &str = "2026-01-01T00:00:00.000Z";

/// A valid `app.bsky.feed.post` with `text` (≤ 300 graphemes).
pub fn post(text: &str) -> Value {
    json!({"$type": "app.bsky.feed.post", "text": text, "createdAt": CREATED_AT})
}

/// The `n`th of a deterministic sequence of valid, increasing TIDs:
/// 13 base32-sortable characters, the first in `2–7a–j`.
pub fn tid(n: u64) -> String {
    const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut out = [b'2'; 13];
    out[0] = b'3';
    let mut rest = n;
    for slot in out[1..].iter_mut().rev() {
        *slot = ALPHABET[(rest % 32) as usize];
        rest /= 32;
    }
    out.iter().map(|&b| b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tids_are_valid_and_increase() {
        let a = tid(0);
        let b = tid(1);
        let c = tid(1_000_000);
        assert_eq!(a, "3222222222222");
        assert!(a < b && b < c);
        for t in [a, b, c] {
            assert!(atrium_like_tid(&t), "{t}");
        }
    }

    fn atrium_like_tid(t: &str) -> bool {
        t.len() == 13
            && "234567abcdefghij".contains(&t[..1])
            && t.chars().all(|c| "234567abcdefghijklmnopqrstuvwxyz".contains(c))
    }
}
```

If the workspace's indexing lint (`clippy::indexing_slicing`) is on for library crates, replace `out[0]`/`out[1..]`/`ALPHABET[…]` with `get`/`get_mut` forms that cannot panic (e.g. `if let Some(first) = out.first_mut() { *first = b'3'; }`, `out.iter_mut().skip(1).rev()`, `ALPHABET.get(i).copied().unwrap_or(b'2')`). Run clippy to find out.

In `test-support/src/lib.rs` add `pub mod atproto;`. Check `adapters/atproto/Cargo.toml` and `server/Cargo.toml` both list `brolly-test-support` as a dev-dependency (both do).

- [ ] **Step 2: `PlannedWrite` through the gate**

In `adapters/atproto/src/repo.rs`:

1. Imports: `use crate::lexicon::Status;` and `use crate::record::{self, Validate};` (keep the existing ones).
2. `PlannedWrite` gains `status: Option<Status>` (`None` for a delete).
3. The constructors take `validate: Validate` as their **last** argument and call the gate:

```rust
    pub fn create(
        collection: &str,
        rkey: Option<&str>,
        record: &Value,
        validate: Validate,
    ) -> Result<Self, RepoError> {
        let collection = parse_nsid(collection)?;
        let rkey = parse_rkey(rkey)?;
        let (record, status) = record::check_record(&collection, rkey.as_ref(), record, validate)?;
        Ok(PlannedWrite {
            action: WriteAction::Create,
            collection,
            rkey,
            record: Some(record),
            status: Some(status),
            swap: RecordSwap::Any,
        })
    }
```

`put(collection, rkey, record, swap, validate)` and `update(collection, rkey, record, validate)` likewise (both pass `rkey.as_ref()`). `delete` sets `status: None`. Update the type's doc comment: "…the record is held to the gate (`record::check_record`, stage 4a: envelope, data model, lexicon)…".

4. In `apply`, right after a minted rkey is stored:

```rust
            write.rkey = parse_rkey(Some(minted.as_str()))?;
            // A minted TID against the lexicon's key type: a create into a
            // `literal:self` collection with no rkey is refused, not
            // committed under a TID (H5).
            if let Some(rkey) = &write.rkey {
                record::check_key(&write.collection, rkey)?;
            }
```

5. `AppliedOp` gains:

```rust
    /// What validation said — the `validationStatus` the write answers
    /// with (H6); absent for a delete.
    pub status: Option<Status>,
```

and the `ops.push(AppliedOp { … })` sets `status: write.status`.

6. Delete `prepare` from `record.rs` (and its "Until…" comment).

- [ ] **Step 3: Every caller passes a `Validate`**

`server/src/xrpc.rs`: the six constructor calls (`create_record`, `put_record`, `swap_record`, `swap_commit`, and `apply_writes`' create and update arms) pass `brolly_atproto::record::Validate::Optimistic` **for now** — Task 4.3 wires the parameter. Behaviour of an absent `validate` is exactly Optimistic, so the wire is already right for every client that does not send it.

Tests: every `PlannedWrite::{create,put,update}(…)` call gains `Validate::Optimistic` as its last argument (18 in `repo.rs`, 7 in `adapters/atproto/tests/firehose.rs`, 1 in `car_export.rs`; `server/tests/xrpc.rs` has none — its writes go through XRPC). `rg -n 'PlannedWrite::(create|put|update)\(' --type rust` lists them.

Run: `cargo build --workspace --all-targets > /tmp/b.log 2>&1; echo exit=$?` — expect `exit=0` before touching any fixture.

- [ ] **Step 4: Write the new behaviour tests (they pass once the gate is on)**

In `repo.rs`'s `mod tests`:

```rust
    #[tokio::test]
    async fn a_create_with_no_rkey_into_a_self_keyed_collection_is_refused() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, rev) = create(blocks(&manager, user), DID, &key).await.unwrap();
        let write = PlannedWrite::create(
            "app.bsky.actor.profile",
            None,
            &json!({"$type": "app.bsky.actor.profile", "displayName": "a"}),
            Validate::Optimistic,
        )
        .unwrap();
        let err = apply(blocks(&manager, user), root, &key, vec![write], &rev)
            .await
            .unwrap_err();
        assert!(matches!(err, RepoError::InvalidRecord(_)), "{err}");
        assert!(err.to_string().contains("is not self"), "{err}");
    }

    #[tokio::test]
    async fn a_write_carries_its_validation_status_to_the_applied_op() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, rev) = create(blocks(&manager, user), DID, &key).await.unwrap();
        let writes = vec![
            PlannedWrite::create("app.bsky.feed.post", None, &brolly_test_support::atproto::post("hi"), Validate::Optimistic).unwrap(),
            PlannedWrite::create("com.example.thing", None, &json!({"x": 1}), Validate::Optimistic).unwrap(),
        ];
        let applied = apply(blocks(&manager, user), root, &key, writes, &rev).await.unwrap();
        assert_eq!(applied.ops[0].status, Some(Status::Valid));
        assert_eq!(applied.ops[1].status, Some(Status::Unknown));
    }
```

(Match `fixture()`, `blocks()`, `create()` and `DID` to the helpers that already exist in that module — read the top of `mod tests` first; if `create` returns a different shape, follow it.)

- [ ] **Step 5: Run the suite and fix the fixtures**

Run: `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test --workspace --no-fail-fast > /tmp/full.log 2>&1; echo exit=$?; grep -E "^test .* FAILED|^    [a-z_:]+$" /tmp/full.log | sort -u | head -80`

Expect failures, each in one of the four categories the spec names (Testing → "Existing tests this part changes"). Fix each by its category, never by weakening the gate:

1. **A post without `createdAt`** (most of them, `Invalid app.bsky.feed.post record: record must have the property "createdAt"`): replace the literal with `brolly_test_support::atproto::post("…")` (import it as `use brolly_test_support::atproto::post;` at the top of the test file; in `json!` it interpolates: `"record": post("in both places")`). For `repo.rs`'s `a_put` helper (`repo.rs:1215`), add `"createdAt": brolly_test_support::atproto::CREATED_AT` to the record it builds — harmless for `com.example.*` collections. A post literal that also carries `reply`/`embed`/`facets`, build it from `post(…)` and add the fields, or add `createdAt` inline.

   A mechanical first pass for `server/tests/xrpc.rs` (review the diff; it handles only the simple literal):
   ```bash
   perl -0pi -e 's/\{"\$type": "app\.bsky\.feed\.post", "text": ("[^"]*")\}/post($1)/g' server/tests/xrpc.rs
   git diff --stat server/tests/xrpc.rs
   ```
2. **A post under a non-TID rkey** (`record key … is not a TID`): use `brolly_test_support::atproto::tid(n)` for generated rkeys (`a_long_historys_commits_each_invert` in `adapters/atproto/tests/firehose.rs`, the batch-cap test in `repo.rs`, and the `server/tests/xrpc.rs` loops the spec lists), or move the test to `com.example.*` when it is not about posts.
3. **A size test now refused by `maxGraphemes`** (`a_record_over_a_megabyte_is_refused` and `a_commit_whose_diff_would_exceed_two_megabytes_is_refused` in `repo.rs`, and `a_record_over_a_megabyte_is_refused` in `server/tests/xrpc.rs`): move the oversized record to collection `com.example.big`, so it still reaches the size cap. Assert the same `TooLarge`/413 as before.
4. **A test that sent an unknown-to-the-data-model shape on purpose**: already fixed in chunk 2; if one appears, it is a real finding — stop and report it.

A failure that fits none of these is a finding about the gate, not a fixture: stop, write down the test and the message, and report it rather than editing the test.

Re-run until `exit=0` (known flakes aside, each confirmed by a single re-run).

- [ ] **Step 6: fmt, clippy, doc-paths, commit**

```bash
git add adapters/atproto/src/repo.rs adapters/atproto/src/record.rs server/src/xrpc.rs \
  test-support/Cargo.toml test-support/src/lib.rs test-support/src/atproto.rs Cargo.lock \
  adapters/atproto/tests/firehose.rs adapters/atproto/tests/car_export.rs server/tests/xrpc.rs
git status --short   # anything else modified is a test the run named — add it by name
git commit -m "feat(atproto): every write through the lexicon gate (H5)

PlannedWrite's constructors take a Validate and call check_record, so
envelope, data model and lexicon happen once, in one place, before any
block is written; a minted TID is held to the collection's key type, so
an rkey-less create into app.bsky.actor.profile is refused rather than
committed under a TID. The status rides AppliedOp. The handlers pass
Optimistic until the next commit wires the parameter.

The fixtures that wrote invalid records move to a valid-post helper and
a deterministic TID sequence; the size tests move to com.example.big so
they still test the size cap, not maxGraphemes.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

### Task 4.3: The wire — `validate`, `validationStatus`, the `applyWrites` union (H6)

**Files:**
- Modify: `server/src/xrpc.rs`
- Test: `server/tests/xrpc.rs`

- [ ] **Step 1: Write the failing tests**

Append to `server/tests/xrpc.rs` (use the file's existing `harness`, `a_member`, `post_json`, `BASE` helpers; match their signatures — `a_member` returns `(id, cookie)`; read one existing write test, e.g. `apply_writes_applies_a_batch_as_one_commit`, and follow its shape exactly):

```rust
async fn write(h: &Harness, cookie: &str, verb: &str, body: serde_json::Value) -> Reply {
    post_json(h, &format!("/xrpc/com.atproto.repo.{verb}"), body, Some(cookie)).await
}

#[tokio::test]
async fn validation_status_answers_on_every_write_verb() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let repo = format!("alice.{BASE}");

    let r = write(&h, &cookie, "createRecord", json!({
        "repo": repo, "collection": "app.bsky.feed.post", "record": post("hi"),
    })).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.json()["validationStatus"], "valid");

    let r = write(&h, &cookie, "createRecord", json!({
        "repo": repo, "collection": "com.example.thing", "record": {"x": 1},
    })).await;
    assert_eq!(r.json()["validationStatus"], "unknown");

    let r = write(&h, &cookie, "putRecord", json!({
        "repo": repo, "collection": "app.bsky.feed.post", "rkey": tid(1), "record": post("put"),
    })).await;
    assert_eq!(r.json()["validationStatus"], "valid");
    let head = r.json()["commit"]["cid"].as_str().unwrap().to_string();
    let cid = r.json()["cid"].as_str().unwrap().to_string();

    let r = write(&h, &cookie, "swapRecord", json!({
        "repo": repo, "collection": "app.bsky.feed.post", "rkey": tid(1), "record": post("swap"),
        "swapRecord": cid, "swapCommit": head,
    })).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.json()["validationStatus"], "valid");
    let head = r.json()["commit"]["cid"].as_str().unwrap().to_string();

    let r = write(&h, &cookie, "swapCommit", json!({
        "repo": repo, "collection": "app.bsky.feed.post", "rkey": tid(2), "record": post("sc"),
        "commitCid": head,
    })).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.json()["validationStatus"], "valid");
}

#[tokio::test]
async fn validate_follows_decision_es_table_on_create_record() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let repo = format!("alice.{BASE}");
    let bad = json!({"$type": "app.bsky.feed.post", "text": "no date"});

    // Known and invalid: refused whatever validate says — false included.
    for validate in [json!(null), json!(true), json!(false)] {
        let mut body = json!({"repo": repo, "collection": "app.bsky.feed.post", "record": bad});
        if !validate.is_null() {
            body["validate"] = validate.clone();
        }
        let r = write(&h, &cookie, "createRecord", body).await;
        assert_eq!(r.status, 400, "validate {validate}");
        assert_eq!(r.json()["error"], "InvalidRequest");
        assert_eq!(
            r.json()["message"],
            "Invalid app.bsky.feed.post record: record must have the property \"createdAt\""
        );
    }

    // Unknown: accepted unless validate is true.
    let r = write(&h, &cookie, "createRecord", json!({
        "repo": repo, "collection": "com.example.thing", "record": {"x": 1}, "validate": true,
    })).await;
    assert_eq!(r.status, 400);
    assert_eq!(r.json()["message"], "Unknown lexicon type: com.example.thing");
    let r = write(&h, &cookie, "createRecord", json!({
        "repo": repo, "collection": "com.example.thing", "record": {"x": 1}, "validate": false,
    })).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["validationStatus"], "unknown");
}

#[tokio::test]
async fn a_profile_needs_its_self_key() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let repo = format!("alice.{BASE}");
    let profile = json!({"$type": "app.bsky.actor.profile", "displayName": "Alice"});

    let r = write(&h, &cookie, "createRecord", json!({
        "repo": repo, "collection": "app.bsky.actor.profile", "record": profile,
    })).await;
    assert_eq!(r.status, 400, "an rkey-less profile must not land under a TID");

    let r = write(&h, &cookie, "createRecord", json!({
        "repo": repo, "collection": "app.bsky.actor.profile", "rkey": "self", "record": profile,
    })).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
}

#[tokio::test]
async fn apply_writes_results_carry_their_union_type() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let repo = format!("alice.{BASE}");
    for (n, text) in [(1, "old"), (2, "doomed")] {
        write(&h, &cookie, "createRecord", json!({
            "repo": repo, "collection": "app.bsky.feed.post", "rkey": tid(n), "record": post(text),
        })).await;
    }

    let r = write(&h, &cookie, "applyWrites", json!({
        "repo": repo,
        "writes": [
            {"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "rkey": tid(3), "value": post("new")},
            {"$type": "com.atproto.repo.applyWrites#update", "collection": "app.bsky.feed.post", "rkey": tid(1), "value": post("changed")},
            {"$type": "com.atproto.repo.applyWrites#create", "collection": "com.example.thing", "value": {"x": 1}},
            {"$type": "com.atproto.repo.applyWrites#delete", "collection": "app.bsky.feed.post", "rkey": tid(2)},
        ],
    })).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    let results = r.json()["results"].as_array().unwrap().clone();
    assert_eq!(results[0]["$type"], "com.atproto.repo.applyWrites#createResult");
    assert_eq!(results[0]["validationStatus"], "valid");
    assert!(results[0]["uri"].is_string() && results[0]["cid"].is_string());
    assert_eq!(results[1]["$type"], "com.atproto.repo.applyWrites#updateResult");
    assert_eq!(results[1]["validationStatus"], "valid");
    assert_eq!(results[2]["validationStatus"], "unknown");
    assert_eq!(results[3], json!({"$type": "com.atproto.repo.applyWrites#deleteResult"}));
}

#[tokio::test]
async fn one_invalid_write_refuses_its_batch_even_with_validate_false() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let repo = format!("alice.{BASE}");
    let before = commits(&h.db.pool).await.len();
    let r = write(&h, &cookie, "applyWrites", json!({
        "repo": repo,
        "validate": false,
        "writes": [
            {"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": post("fine")},
            {"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": {"text": "no date"}},
        ],
    })).await;
    assert_eq!(r.status, 400);
    assert_eq!(commits(&h.db.pool).await.len(), before, "nothing committed");
}

#[tokio::test]
async fn apply_writes_follows_decision_es_table_for_unknown_lexicons() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let repo = format!("alice.{BASE}");
    let batch = |validate: bool| json!({
        "repo": repo,
        "validate": validate,
        "writes": [{"$type": "com.atproto.repo.applyWrites#create", "collection": "com.example.thing", "value": {"x": 1}}],
    });
    let r = write(&h, &cookie, "applyWrites", batch(true)).await;
    assert_eq!(r.status, 400);
    assert_eq!(r.json()["message"], "Unknown lexicon type: com.example.thing");
    let r = write(&h, &cookie, "applyWrites", batch(false)).await;
    assert_eq!(r.status, 200, "{:?}", r.body);
    assert_eq!(r.json()["results"][0]["validationStatus"], "unknown");
}
```

Adapt the helper names to the file (`Reply`'s fields, whether `post_json` takes `&str` or `Option<&str>` for the cookie, `h.db.pool`, `r.json()` vs `r.body`). The `post` and `tid` imports come from `brolly_test_support::atproto` (added to this file in Task 4.2). Note the first `createRecord` above has a minted rkey and later ones use `tid(n)` — `tid(1)` and `tid(2)` are far below any minted TID, so they never collide.

- [ ] **Step 2: Run to verify they fail**

Run: `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test -p brolly-server --test xrpc -- validation_status validate_follows a_profile_needs apply_writes_ one_invalid_write > /tmp/t.log 2>&1; echo exit=$?; grep -E "^test " /tmp/t.log`
Expected: failures on `validationStatus` missing, `validate: true` with an unknown lexicon accepted (200, not 400), and the results' missing `$type`. `a_profile_needs_its_self_key` and `one_invalid_write…` already pass (Task 4.2 did that) — that is fine; they pin it.

- [ ] **Step 3: Read `validate` on the five verbs**

Add `validate: Option<bool>` to `CreateRecord`, `PutRecord`, `SwapRecord`, `SwapCommit` and `ApplyWrites` (top level — the lexicon's `validate` applies to the whole batch). Replace each `Validate::Optimistic` placed in Task 4.2 with `brolly_atproto::record::Validate::from_param(input.validate)`.

- [ ] **Step 4: Answer `validationStatus`**

In `write_response`, after `"cid"`:

```rust
        "validationStatus": op.status.map(|s| s.as_str()),
```

(`createRecord`, `putRecord`, `swapRecord` and `swapCommit` all answer through it; a create/put op always carries a status, so the field is never `null` in practice.)

- [ ] **Step 5: The `applyWrites` union**

Replace the `results` mapping in `apply_writes`:

```rust
    // One result per write, in order, in the lexicon's union (H6, Decision G).
    let did = did_of(&user, &state);
    let results: Vec<Value> = landed
        .applied
        .ops
        .iter()
        .map(|op| {
            let kind = match op.action {
                brolly_atproto::firehose::Action::Create => "createResult",
                brolly_atproto::firehose::Action::Update => "updateResult",
                brolly_atproto::firehose::Action::Delete => {
                    return json!({"$type": "com.atproto.repo.applyWrites#deleteResult"});
                }
            };
            let uri = op
                .path
                .split_once('/')
                .map(|(collection, rkey)| ingest::at_uri(&did, collection, rkey));
            json!({
                "$type": format!("com.atproto.repo.applyWrites#{kind}"),
                "uri": uri,
                "cid": op.record_cid.map(|cid| cid.to_string()),
                "validationStatus": op.status.map(|s| s.as_str()),
            })
        })
        .collect();
```

Check the existing test `apply_writes_applies_a_batch_as_one_commit` still passes; if it asserted the old result shape (`{"uri", "cid"}` with no `$type`), update its assertion to the union shape — that is the point of this task.

- [ ] **Step 6: Run the server tests, then the whole suite**

Run: `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test --workspace --no-fail-fast > /tmp/full.log 2>&1; echo exit=$?; grep -E "^test .* FAILED" /tmp/full.log | sort -u`
Expected: `exit=0` (known flakes aside, each re-run).

- [ ] **Step 7: Commit**

```bash
git add server/src/xrpc.rs server/tests/xrpc.rs
git commit -m "feat(xrpc): validate and validationStatus on every write; applyWrites answers in its union (H6)

createRecord, putRecord, applyWrites and brolly's swapRecord and
swapCommit read validate and answer validationStatus. validate:true
refuses a collection with no lexicon; validate:false still validates a
known one (Decision E). applyWrites results carry their union \$type —
createResult and updateResult with uri, cid and validationStatus, and a
deleteResult with nothing else — so a client can tell which it holds
(Decision G).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

### Task 4.4: Close the part

**Files:**
- Modify: `docs/specs/2026-11-26-atproto-data-model-and-lexicons.md` (Status)
- Modify: `docs/specs/2026-09-17-interop-roadmap.md` (stage 4, part a)
- Modify: `docs/plans/2026-11-26-atproto-data-model.md` (one line pointing here)

- [ ] **Step 1: The spec's Status**

Extend the `**Status:**` paragraph: `Chunks 3 and 4 landed {date}: the lexicon registry and a written validator (held to the corpus and to atproto-interop-tests' lexicon suite and syntax vectors), and the gate on every write with validate/validationStatus and the applyWrites union. Part a is done.` Add to the spec's Rollout list of deliberate strictness: a collection whose NSID is a vendored lexicon but whose `main` is not a record (e.g. `com.atproto.repo.strongRef`) is refused under any `validate`. Add any divergence from this plan the execution found (a vector that forced a rule away from atrium's type, a message that changed) as one sentence each.

- [ ] **Step 2: The roadmap**

In `docs/specs/2026-09-17-interop-roadmap.md`, mark stage 4's ATProto part a as implemented, in the same style the file uses for stage 3 (read how stage 3 was marked first; `grep -n "Implemented\|implemented" docs/specs/2026-09-17-interop-roadmap.md`). Name part b (records as `/~/{collection}/{rkey}` resources) as next.

- [ ] **Step 3: Point the first plan here**

In `docs/plans/2026-11-26-atproto-data-model.md`'s **Scope of this plan** paragraph, append: `Chunks 3–4 are planned in docs/plans/2026-11-27-atproto-lexicons-and-gate.md.`

- [ ] **Step 4: Checks and commit**

Run: `./tools/check-doc-paths.sh; echo exit=$?` — expect `exit=0`.

```bash
git add docs/specs/2026-11-26-atproto-data-model-and-lexicons.md docs/specs/2026-09-17-interop-roadmap.md docs/plans/2026-11-26-atproto-data-model.md
git commit -m "docs: stage 4a is done — the data model, held

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
