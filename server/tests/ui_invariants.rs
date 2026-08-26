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

/// HTML tags this looks for. A bare `format!("<` is not enough of a signal:
/// SPARQL wraps IRIs in angle brackets, so `format!("<{iri}>")` in the authz
/// and index queries tripped the naive version of this check. Matching real tag
/// names keeps the invariant meaningful without punishing query builders.
const HTML_TAGS: [&str; 14] = [
    "<!DOCTYPE",
    "<html",
    "<head",
    "<body",
    "<div",
    "<span",
    "<p>",
    "<p ",
    "<a ",
    "<form",
    "<input",
    "<table",
    "<ul",
    "<li",
];

#[test]
fn html_is_never_built_with_format() {
    let needle = concat!("format!(\"", "<");

    let offenders: Vec<_> = rust_sources()
        .into_iter()
        .filter(|p| {
            let Ok(text) = std::fs::read_to_string(p) else {
                return false;
            };
            text.lines()
                .any(|line| line.contains(needle) && HTML_TAGS.iter().any(|tag| line.contains(tag)))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "HTML built with format! in {offenders:?}. Use a template and the render() helper."
    );
}

#[test]
fn the_html_detector_actually_detects() {
    // Guard the guard. A checker this specific can rot into a no-op, so assert
    // it still fires on the thing it exists to catch — and does not fire on the
    // SPARQL pattern that produced a false positive.
    let html = r#"let s = format!("<div class=\"{}\">", x);"#;
    let sparql = r#"let s = format!("<{iri}>");"#;
    let needle = concat!("format!(\"", "<");

    assert!(
        html.contains(needle) && HTML_TAGS.iter().any(|t| html.contains(t)),
        "detector must flag HTML built with format!"
    );
    assert!(
        !HTML_TAGS.iter().any(|t| sparql.contains(t)),
        "detector must not flag SPARQL IRI interpolation"
    );
}

#[test]
fn there_is_exactly_one_hand_authored_stylesheet() {
    let static_dir = workspace_root().join("server/static");
    let sheets: Vec<_> = std::fs::read_dir(&static_dir)
        .expect("server/static exists")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "css"))
        .collect();

    let generated: Vec<_> = sheets
        .iter()
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|t| t.starts_with("/* GENERATED FILE"))
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        generated.len(),
        1,
        "expected exactly one generated token file, found {generated:?}"
    );
    assert_eq!(
        sheets.len() - generated.len(),
        1,
        "expected exactly one hand-authored stylesheet alongside the generated \
         tokens, found {sheets:?}. A new feature extends the tokens or the \
         components; it does not add a stylesheet."
    );
}

#[test]
fn the_token_file_is_never_hand_edited() {
    let tokens = std::fs::read_to_string(workspace_root().join("server/static/tokens.css"))
        .expect("read tokens.css");
    assert!(
        tokens.contains("DO NOT EDIT") && tokens.contains("tools/gen-tokens.sh"),
        "tokens.css must carry its generated-file header"
    );
    assert!(
        tokens.contains("prefers-color-scheme"),
        "the OS colour-scheme bridge must survive regeneration — batklubb emits \
         [data-theme] blocks only, so tools/gen-tokens.sh appends it"
    );
}

#[test]
fn components_use_tokens_not_literal_colors() {
    // Literal colours belong in batklubb.config.js, which generates tokens.css.
    // The hand-authored stylesheet must reference tokens only.
    let css = std::fs::read_to_string(workspace_root().join("server/static/brolly.css"))
        .expect("read brolly.css");

    let literals: Vec<_> = css
        .lines()
        .filter(|l| {
            let l = l.trim();
            !l.starts_with("/*") && !l.starts_with('*') && l.contains('#') && l.contains(':')
        })
        .collect();

    assert!(
        literals.is_empty(),
        "literal colours in the hand-authored stylesheet: {literals:?}. \
         Add them to batklubb.config.js and regenerate."
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

    // Recursive: templates live in subdirectories once a surface has more than
    // one page, and a check that only reads the top level silently stops
    // covering everything added after that.
    let mut pages = Vec::new();
    collect_templates(&templates, &mut pages);
    assert!(
        pages.len() > 3,
        "expected to find the page templates, found {pages:?}"
    );

    for path in pages {
        let text = std::fs::read_to_string(&path).expect("read template");
        assert_eq!(
            text.matches("<h1").count(),
            1,
            "{path:?} must contain exactly one <h1>"
        );
    }
}

/// Every template that renders a whole page.
///
/// `base.html` provides the shell and has no heading of its own, and a leading
/// underscore marks a partial that is included into a page rather than being
/// one — neither should be held to the one-`<h1>` rule, which is about pages.
fn collect_templates(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_templates(&path, out);
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "base.html" || name.starts_with('_') || !name.ends_with(".html") {
            continue;
        }
        out.push(path);
    }
}
