//! Mechanical enforcement of the crate-graph rules.
//!
//! These are the invariants that decayed last time: `app()` migrated into a
//! shared crate, adapters grew dependencies on each other, and the "core"
//! crate ended up depending on every protocol. Intention was not enough, so
//! they are tests.
//!
//! See `docs/greenfield-implementation-plan.md` §2.1 and §5.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const ADAPTERS: [&str; 4] = [
    "brolly-solid",
    "brolly-atproto",
    "brolly-activitypub",
    "brolly-mastodon",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Map every workspace member to the set of `brolly-*` crates it depends on.
fn internal_deps() -> BTreeMap<String, Vec<String>> {
    let root = workspace_root();
    let ws: toml::Value = toml::from_str(
        &std::fs::read_to_string(root.join("Cargo.toml")).expect("read workspace Cargo.toml"),
    )
    .expect("parse workspace Cargo.toml");

    let members = ws["workspace"]["members"]
        .as_array()
        .expect("workspace.members");

    let mut out = BTreeMap::new();
    for m in members {
        let dir = root.join(m.as_str().expect("member path"));
        let manifest: toml::Value = toml::from_str(
            &std::fs::read_to_string(dir.join("Cargo.toml")).expect("read manifest"),
        )
        .expect("parse manifest");

        let name = manifest["package"]["name"]
            .as_str()
            .expect("package name")
            .to_string();

        let mut deps: Vec<String> = manifest
            .get("dependencies")
            .and_then(|d| d.as_table())
            .map(|t| {
                t.keys()
                    .filter(|k| k.starts_with("brolly-"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        deps.sort();
        out.insert(name, deps);
    }
    out
}

/// Every `.rs` file under any crate's `src/`.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.components().any(|c| c.as_os_str() == "src")
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&workspace_root(), &mut out);
    out
}

/// Every `.rs` file in the workspace, wherever it sits: `src/`, `tests/`,
/// `benches/`, `examples/`. `target/` is build output and the spike is
/// throwaway.
fn rust_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|n| n == "target" || n == "spikes" || n == ".git")
                {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&workspace_root(), &mut out);
    out
}

#[test]
fn domain_has_no_internal_dependencies() {
    let deps = internal_deps();
    assert_eq!(
        deps["brolly-domain"],
        Vec::<String>::new(),
        "brolly-domain must stay dependency-free — it is the vocabulary layer"
    );
}

#[test]
fn adapters_do_not_depend_on_each_other() {
    let deps = internal_deps();
    for adapter in ADAPTERS {
        for other in ADAPTERS {
            if adapter == other {
                continue;
            }
            assert!(
                !deps[adapter].contains(&other.to_string()),
                "{adapter} depends on {other}. Adapters must not depend on each other — \
                 put the contract in brolly-domain::ports and let brolly-server inject it."
            );
        }
    }
}

#[test]
fn only_server_depends_on_more_than_one_adapter() {
    for (crate_name, deps) in internal_deps() {
        if crate_name == "brolly-server" {
            continue;
        }
        let count = deps
            .iter()
            .filter(|d| ADAPTERS.contains(&d.as_str()))
            .count();
        assert!(
            count <= 1,
            "{crate_name} depends on {count} adapters. Only brolly-server may compose adapters."
        );
    }
}

/// Crates that mean I/O. `brolly-domain` must not reach any of them: the whole
/// two-layer translation model is pure functions, which is what makes the
/// round-trip property test in `domain/tests/roundtrip.rs` possible.
///
/// This deliberately checks `domain` only. Adapters legitimately need the
/// network — Phase 7 speaks XRPC and PLC over HTTP — so *their* purity is a
/// property of the `Adapter` impl, not of the crate, and review enforces it.
#[test]
fn domain_has_no_io_dependencies() {
    let root = workspace_root();
    let manifest: toml::Value = toml::from_str(
        &std::fs::read_to_string(root.join("domain/Cargo.toml")).expect("read domain manifest"),
    )
    .expect("parse domain manifest");

    const IO: [&str; 6] = ["sqlx", "reqwest", "tokio", "oxigraph", "axum", "hyper"];

    let deps: Vec<String> = manifest
        .get("dependencies")
        .and_then(|d| d.as_table())
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();

    let offenders: Vec<_> = deps.iter().filter(|d| IO.contains(&d.as_str())).collect();
    assert!(
        offenders.is_empty(),
        "brolly-domain depends on {offenders:?}. It must stay pure — use oxrdf \
         for the term model, not oxigraph, and let the store crate own I/O."
    );
}

/// Credential parsing lives in `brolly-identity` and nowhere else.
///
/// The predecessor had four independent `Authorization`-header paths — one each
/// for Solid-OIDC, ATProtocol, Mastodon, and sessions — backed by four token
/// tables. Every handler that wanted to know who was calling reimplemented the
/// question, and the answers differed. One dispatcher produces one `Subject`;
/// this keeps it that way.
#[test]
fn only_identity_parses_credentials() {
    const CREDENTIAL_PATTERNS: [&str; 4] = [
        "strip_prefix(\"Bearer ",
        "strip_prefix(\"DPoP ",
        "TypedHeader<Authorization",
        "headers.get(\"authorization",
    ];

    let offenders: Vec<_> = source_files()
        .into_iter()
        .filter(|p| {
            // brolly-identity owns this, and the spike is throwaway.
            let s = p.to_string_lossy();
            !s.contains("/identity/") && !s.contains("/spikes/")
        })
        .filter(|p| {
            let Ok(text) = std::fs::read_to_string(p) else {
                return false;
            };
            CREDENTIAL_PATTERNS.iter().any(|pat| text.contains(pat))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "credential parsing outside brolly-identity in {offenders:?}. \
         Take a Subject instead — see identity::subject."
    );
}

#[test]
fn app_is_defined_only_in_the_server_crate() {
    let offenders: Vec<_> = source_files()
        .into_iter()
        .filter(|p| {
            let Ok(text) = std::fs::read_to_string(p) else {
                return false;
            };
            text.contains("pub fn app(")
        })
        .filter(|p| !p.components().any(|c| c.as_os_str() == "server"))
        .collect();

    assert!(
        offenders.is_empty(),
        "app() must exist only in brolly-server; found in {offenders:?}. \
         This is the rule that keeps the dependency graph acyclic."
    );
}

/// Mastodon is a **projection**. It reads from stores and writes to none.
///
/// Phase 6's exit criterion states it outright: "`mastodon/` has no write path
/// to a store." The rule matters because the Mastodon API is the surface most
/// under pressure to denormalize — the predecessor's admin list could not open
/// 500 Oxigraph stores to render a table, so display names went back into
/// Postgres with a backfill job. When a projection is allowed to write, the
/// thing it writes becomes a second source of truth that nothing can retire.
///
/// A lint as well as the type system. Pod writes need a `PodWrite`, reached
/// only through `Pod::write`, so the lint looks for those names alongside the
/// store's own write functions and the raw oxigraph calls.
#[test]
fn the_mastodon_crate_never_writes_to_a_store() {
    /// Every mutation entry point in `brolly-store`, plus the raw oxigraph
    /// calls that would bypass it. Kept in sync by hand — but a *new* store
    /// mutator that this list misses is a `brolly-store` review question, and
    /// `store::write`'s own docs say there is exactly one insert.
    const MUTATORS: [&str; 14] = [
        // brolly-store's write path.
        "insert_quads",
        "insert_record",
        "replace_graph",
        "record_note",
        "forget_note",
        "index::clear",
        // A pod write (stage 5a), and the raw escape hatch.
        "PodWrite",
        ".write(|",
        "raw_store",
        // Raw oxigraph, which would sidestep canonicalization entirely.
        ".insert(",
        ".remove(",
        "clear_graph",
        ".transaction(",
        "bulk_loader",
    ];

    let mastodon_sources: Vec<_> = source_files()
        .into_iter()
        .filter(|p| p.to_string_lossy().contains("/mastodon/"))
        .collect();

    assert!(
        !mastodon_sources.is_empty(),
        "no mastodon sources found — this lint would pass vacuously"
    );

    let mut offenders = Vec::new();
    for path in mastodon_sources {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            // `.insert(` is also how a HashMap is filled, which a translation
            // layer does constantly. Only flag it when the receiver is a store.
            let store_shaped = !line.contains(".insert(")
                || line.contains("store.insert(")
                || line.contains("Store.insert(");
            if !store_shaped {
                continue;
            }
            if let Some(found) = MUTATORS.iter().find(|m| line.contains(**m)) {
                offenders.push(format!("{}: {}", path.display(), found));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "brolly-mastodon writes to a store in {offenders:#?}. \
         It is a projection: read from pods and the index, return JSON, own \
         nothing. If a Mastodon read needs data that does not exist yet, the \
         write belongs in the adapter that owns it — see plan §3 Phase 6."
    );
}

/// The metadata graph has one owner: `store/src/resources.rs`.
///
/// Stage 5a keeps existence, containment, versions and blob pointers in
/// `urn:brolly:resources`, where no client write can reach them. Code that
/// named the graph could read or write it around `PodWrite`, and the metadata
/// would stop being true. Everything else asks `resources`.
#[test]
fn only_resources_names_the_metadata_graph() {
    const GRAPH: &str = "urn:brolly:resources";
    let owner = workspace_root().join("store/src/resources.rs");
    assert!(
        std::fs::read_to_string(&owner).is_ok_and(|text| text.contains(GRAPH)),
        "{} no longer names {GRAPH}; this rule would pass vacuously",
        owner.display()
    );

    let offenders: Vec<_> = source_files()
        .into_iter()
        .filter(|p| *p != owner && !p.to_string_lossy().contains("/spikes/"))
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|text| text.contains(GRAPH)))
        .collect();

    assert!(
        offenders.is_empty(),
        "{GRAPH} is named outside store/src/resources.rs in {offenders:?}. \
         Read and write resource metadata through Pod, PodWrite and \
         ResourceRead instead."
    );
}

/// `Pod::raw_store` hands out the bare `Store`: no lock, no metadata. It exists
/// so tests can build old-layout pods. Anywhere else it's the bypass stage 5a
/// closed, so it may appear only in test and bench code, and in `store`'s own
/// source where it's defined.
#[test]
fn raw_store_is_reached_only_from_tests() {
    let store_src = workspace_root().join("store/src");
    let offenders: Vec<_> = rust_files()
        .into_iter()
        .filter(|p| !p.starts_with(&store_src))
        .filter(|p| {
            !p.components()
                .any(|c| c.as_os_str() == "tests" || c.as_os_str() == "benches")
        })
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|text| text.contains("raw_store")))
        .collect();

    assert!(
        offenders.is_empty(),
        "raw_store is used outside test code in {offenders:?}. Write through \
         Pod::write, which keeps the metadata true."
    );
}
