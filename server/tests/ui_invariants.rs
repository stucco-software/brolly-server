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
    // Nothing sets data-theme server-side, so without the unattributed default
    // every semantic var is unset and the whole design silently degrades to
    // the browser's own styles. It renders — it just isn't Brolly.
    assert!(
        tokens.contains(":root:not([data-theme]) {"),
        "the default (day) theme must survive regeneration — batklubb emits \
         [data-theme] blocks only, so tools/gen-tokens.sh appends it"
    );
}

/**
 * Every form the templates post is on the same-origin list.
 *
 * `same_origin` refuses a cross-origin post to the paths in
 * `SAME_ORIGIN_FORMS`, and nothing else. A form whose action is not on the
 * list is a form the check silently does not cover — which is the failure
 * mode of every allow-list. Literal actions are read off the templates;
 * the dynamic ones (`{{ action }}`: the login form's `next`-carrying action,
 * and the consent screen's per-protocol decision endpoint) are pinned by
 * name, so a renamed route fails here rather than in production.
 */
#[test]
fn every_form_post_is_same_origin_checked() {
    let list = brolly_server::SAME_ORIGIN_FORMS;
    // Every template, partials included: the nav partials carry the logout
    // form, and `collect_templates` skips them for the page-level checks.
    fn every_html(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("templates dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                every_html(&path, out);
            } else if path.extension().is_some_and(|e| e == "html") {
                out.push(path);
            }
        }
    }
    let mut templates = Vec::new();
    every_html(&workspace_root().join("server/templates"), &mut templates);

    let mut seen = 0;
    for path in &templates {
        let text = std::fs::read_to_string(path).expect("read template");
        for line in text
            .lines()
            .filter(|l| l.contains("<form") && l.contains(r#"method="post""#))
        {
            seen += 1;
            let action = line
                .split(r#"action=""#)
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_else(|| {
                    panic!("{}: a post form without an action: {line}", path.display())
                });
            if action.starts_with("{{") {
                continue;
            }
            assert!(
                list.contains(&action),
                "{}: form action {action} is not in SAME_ORIGIN_FORMS",
                path.display()
            );
        }
    }
    assert!(
        seen >= 8,
        "expected the door, consent, dashboard and both nav forms, found {seen}"
    );

    for dynamic in [
        "/login",
        "/register",
        "/oauth/solid/authorize",
        "/oauth/authorize",
        "/oauth/atproto/authorize",
    ] {
        assert!(
            list.contains(&dynamic),
            "{dynamic} is rendered as a form action and must be listed"
        );
    }
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

/// Every page template must put its content inside the page container.
///
/// `base.html` hands `<main>` to the page full-bleed, so a band of colour can
/// reach the viewport edge the way brolly.id's sections do. The cost of that
/// freedom is that a page can forget the container entirely and render its
/// prose edge-to-edge, which looks like a bug because it is one. `.wrap` is the
/// measure; every page carries it.
#[test]
fn every_page_template_uses_the_page_container() {
    let mut pages = Vec::new();
    collect_templates(&workspace_root().join("server/templates"), &mut pages);

    for path in pages {
        let text = std::fs::read_to_string(&path).expect("read template");
        assert!(
            text.contains("class=\"wrap") || text.contains(" wrap\""),
            "{path:?} renders outside the page container. Wrap its content in \
             <div class=\"wrap\">, or put a .wrap inside each full-bleed .band."
        );
    }
}

/// Every asset the stylesheet asks for is actually shipped.
///
/// The fonts and the umbrella are referenced by path from a stylesheet no
/// compiler reads, so a rename or a missed `cp` degrades silently to a
/// fallback typeface and a broken image — exactly the kind of regression the
/// rest of this file exists to make loud.
#[test]
fn every_stylesheet_url_resolves_to_a_shipped_file() {
    let root = workspace_root();
    let css = std::fs::read_to_string(root.join("server/static/brolly.css")).expect("read css");

    const OPEN: &str = "url(\"";
    let mut missing = Vec::new();
    for (at, _) in css.match_indices(OPEN) {
        let Some(url) = css[at + OPEN.len()..].split('"').next() else {
            continue;
        };
        let relative = url
            .strip_prefix("/static/")
            .unwrap_or_else(|| panic!("stylesheet URL {url:?} must be absolute under /static/"));
        if !root.join("server/static").join(relative).exists() {
            missing.push(url.to_owned());
        }
    }

    assert!(
        missing.is_empty(),
        "brolly.css references files that are not in server/static: {missing:?}"
    );
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

/// The unauthenticated surface names no product and no protocol.
///
/// A guard rather than a test of behaviour. The protocol cards this replaced
/// were a plausible, well-meant addition — "a member might want to know whether
/// their Mastodon client works here" — and they are how the front page becomes
/// a pitch again a year from now.
///
/// Scoped to the three templates every visitor sees. The authenticated surface
/// keeps saying "point a Solid app here", which is instruction and belongs.
///
/// Case-sensitive on purpose: `base.html` links `/static/brolly.css` and
/// `/static/favicon/…`, and those filenames must keep their names.
///
/// Known gap: the door's heading, intro and alt-link text are Rust string
/// literals in `login_page` and `register_page`, and a scan of `templates/`
/// never sees them. Whoever adds "we speak Solid" to an `intro` and watches
/// this pass should know it was a hole, not a permission.
#[test]
fn the_unauthenticated_surface_sells_nothing() {
    const BANNED: [&str; 4] = ["Brolly", "Solid", "ATProto", "ActivityPub"];
    let templates = workspace_root().join("server/templates");

    for name in ["auth.html", "base.html", "_fine_print.html"] {
        let text = std::fs::read_to_string(templates.join(name)).expect("read template");
        for word in BANNED {
            assert!(
                !text.contains(word),
                "{name} contains {word:?}. The door says only what an operator \
                 configured; see docs/specs/2026-09-10-the-door.md."
            );
        }
    }
}

/// The card replaced the panel, everywhere.
///
/// A page half-converted looks like a page with a rendering bug, and the old
/// class going unused is the only signal that the job finished.
#[test]
fn the_dashboard_panel_is_retired() {
    let mut pages = Vec::new();
    collect_templates(&workspace_root().join("server/templates"), &mut pages);

    for path in pages {
        let text = std::fs::read_to_string(&path).expect("read template");
        assert!(
            !text.contains("dashboard-panel"),
            "{path:?} still uses .dashboard-panel; .dashboard-card replaced it"
        );
    }
}
