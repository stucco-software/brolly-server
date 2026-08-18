//! Mechanical enforcement of the UI invariants.
//!
//! The previous codebase shipped a polished admin console while login and
//! registration stayed inline `format!` strings. These tests make that
//! regression a build failure rather than a style opinion.
//!
//! See `docs/greenfield-implementation-plan.md` §4.5.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn rust_sources() -> Vec<PathBuf> {
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
fn html_is_never_built_with_format() {
    let needle = concat!("format!(\"", "<");
    let offenders: Vec<_> = rust_sources()
        .into_iter()
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|t| t.contains(needle))
                .unwrap_or(false)
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "HTML built with format! in {offenders:?}. Use a template and the render() helper."
    );
}

#[test]
fn there_is_exactly_one_stylesheet() {
    let static_dir = workspace_root().join("server/static");
    let sheets: Vec<_> = std::fs::read_dir(&static_dir)
        .expect("server/static exists")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "css"))
        .collect();

    assert_eq!(
        sheets.len(),
        1,
        "expected exactly one CSS entrypoint, found {sheets:?}. \
         A new feature extends the tokens or components; it does not add a stylesheet."
    );
}

#[test]
fn components_use_tokens_not_literal_colors() {
    let css = std::fs::read_to_string(workspace_root().join("server/static/brolly.css"))
        .expect("read stylesheet");

    // Everything before the first component rule is the token layer, where
    // literal colors are the point. After it, colors must come from var().
    let marker = "/* --- reset ---";
    let (tokens, components) = css
        .split_once(marker)
        .expect("stylesheet has a reset marker");
    assert!(tokens.contains("--color-bg"), "token layer present");

    let literals: Vec<_> = components
        .lines()
        .filter(|l| {
            let l = l.trim();
            !l.starts_with("/*") && !l.starts_with('*') && l.contains('#') && l.contains(':')
        })
        .collect();

    assert!(
        literals.is_empty(),
        "literal colors outside the token layer: {literals:?}"
    );
}

#[test]
fn every_template_has_one_h1_and_a_main_landmark() {
    let templates = workspace_root().join("server/templates");
    let base = std::fs::read_to_string(templates.join("base.html")).expect("read base.html");

    assert!(
        base.contains("<main"),
        "base.html must provide the <main> landmark"
    );
    assert!(
        base.contains("skip-link"),
        "base.html must provide a skip link"
    );

    for entry in std::fs::read_dir(&templates)
        .expect("read templates")
        .flatten()
    {
        let path = entry.path();
        if path.file_name().is_some_and(|n| n == "base.html") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read template");
        assert_eq!(
            text.matches("<h1").count(),
            1,
            "{path:?} must contain exactly one <h1>"
        );
    }
}
