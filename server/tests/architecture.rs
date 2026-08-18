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
