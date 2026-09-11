# Member Dashboard Presentation Implementation Plan

<!-- doc-paths: skip -->
<!-- A plan cites the files it is about to create, so the paths it names
     are not expected to resolve until it has been executed. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the member dashboard say what it did, show one object per concern, and name the next step — taking solidid's card-and-`<dl>` idiom without changing what the dashboard can do.

**Architecture:** One behaviour change (`revoke_app` gains the `?saved=true` parameter the other two mutating actions already use) and four presentation changes: `.dashboard-card` replaces `.dashboard-panel`, `<mark>` chips mark only exceptional values, copy names the next step, and copy-to-clipboard arrives as the product's first JavaScript island.

**Tech Stack:** Rust, axum 0.8.9, Askama 0.14, sqlx/Postgres, vanilla JS (one file, no build step).

**Spec:** [`docs/specs/2026-09-10-member-dashboard.md`](../specs/2026-09-10-member-dashboard.md)

---

## Depends on the door plan

[`2026-09-10-the-door.md`](2026-09-10-the-door.md) **Task 2** replaces every
page struct's `instance_name` field with `chrome: Chrome<'a>` and rewrites every
`{{ instance_name }}` to `{{ chrome.instance_name }}`. This plan assumes that
has landed.

It also assumes the door's **Task 3**, which puts `{% block header %}` /
`{% block footer %}` into `base.html` — Task 6 below adds a `<script>` tag to
`<head>`, which sits outside both blocks, so the two edits do not collide.

If the door has not landed, every template snippet below that says
`{{ chrome.instance_name }}` should say `{{ instance_name }}`, and nothing else
changes.

## Ordering

All five tasks are independently deployable. Task 2 (cards) before Task 3
(chips) only because the chips land inside a card that Task 2 builds.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `server/src/account.rs` | `apps` handler gains `Query<Saved>`; `Apps` gains `saved` | Modify |
| `server/templates/account/*.html` | 5 pages convert to cards | Modify |
| `server/templates/admin/*.html` | 2 pages convert to cards; chips in the member list | Modify |
| `server/src/admin.rs` | `MemberView` exposes what the chip needs | Modify |
| `server/static/brolly.css` | `.dashboard-card`, `.chip`; `.dashboard-panel` deleted | Modify |
| `server/static/brolly.js` | the copy-to-clipboard island — the only JS | Create |
| `server/templates/base.html` | `<script defer>` in `<head>` | Modify |
| `server/tests/dashboard.rs` | the revoke notice, the empty state | Modify |
| `server/tests/admin.rs` | the chip assertions | Modify |
| `server/tests/ui_invariants.rs` | §4.5's unwritten form invariant | Modify |

---

## Chunk 1: The one behaviour change

### Task 1: `revoke_app` says what it did

Two of three mutating actions already POST-redirect-GET with `?saved=true`:
`profile_submit` (`account.rs:195`, redirect at `:227`) and `change_password`
(`:293`, redirect at `:333`). `revoke_app` (`:393`, redirect at `:408`)
redirects with no parameter, so you withdraw an application's access to your pod
— a security action — and the page returns looking almost the same.

**Files:**
- Modify: `server/src/account.rs:363-370` (the `apps` handler), the `Apps` struct, `:408`
- Modify: `server/templates/account/apps.html`
- Test: `server/tests/dashboard.rs`

- [ ] **Step 1: Write the failing test**

In `server/tests/dashboard.rs`:

```rust
/// Revoking is a security action, and the only feedback today is that a row
/// vanishes. Same parameter and same extractor as profile and security; only
/// the sentence differs.
#[tokio::test]
async fn revoking_an_app_says_so() {
    let h = harness().await;
    let cookie = h.login().await;
    let client_id = an_authorised_app(&h, &cookie, "Notes App").await;

    let reply = h
        .post(
            "/account/apps",
            &format!(
                "client_id={}",
                form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>()
            ),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location.as_deref(), Some("/account/apps?saved=true"));

    let reply = h.get("/account/apps?saved=true", Some(&cookie)).await;
    assert!(reply.body.contains("Access withdrawn."));
    assert!(reply.body.contains("role=\"status\""));
}

/// ...and the notice is not permanent furniture.
#[tokio::test]
async fn the_apps_page_is_quiet_without_the_parameter() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h.get("/account/apps", Some(&cookie)).await;
    assert!(!reply.body.contains("Access withdrawn."));
}
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo test -p brolly-server --test dashboard revoking_an_app_says_so`
Expected: FAIL — `Location` is `/account/apps`, without the parameter.

- [ ] **Step 3: Implement**

`Saved` already exists at `account.rs:157` and is used by `profile_form` — reuse
it rather than inventing a second query type.

```rust
/// `GET /account/apps`
pub async fn apps(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<Saved>,
) -> Response {
```

Add `saved: bool` to the `Apps` struct and pass `saved: query.saved` where it is
constructed. Change `:408` to `Redirect::to("/account/apps?saved=true")`.

`Saved`'s field is private to the module, so if the compiler objects, mirror
exactly what `profile_form` (`:163`) already does with it.

- [ ] **Step 4: Render the notice**

In `server/templates/account/apps.html`, immediately inside the panel, matching
`profile.html:13`:

```html
{% if saved %}<p class="notice" role="status">Access withdrawn.</p>{% endif %}
```

`role="status"` is a polite live region, so a screen reader announces it without
interrupting. Errors keep `role="alert"`, which is assertive — see
`delete.html:14`.

- [ ] **Step 5: Verify and commit**

Run: `cargo test --workspace`

```bash
git add server/src/account.rs server/templates/account/apps.html server/tests/dashboard.rs
git commit -m "fix(account): revoking an app says so

Two of three mutating actions already redirect with ?saved=true. This
was the one that didn't, and it is the one where silence matters most."
```

---

## Chunk 2: Presentation

### Task 2: Cards replace panels

`.dashboard-panel` is one object per page. That is right for profile, which is
one form, and wrong for security, which is a password form *and* a session count
with no seam between them.

The card **replaces** the panel rather than nesting inside it — a panel inside a
card is a wrapper that exists only because neither was retired. `.dashboard-card`
takes over the measure cap (`max-width: var(--measure)`, `brolly.css:428`) and
`.dashboard-card-wide` replaces `.dashboard-panel-wide` (`:433`), which exists
solely to defeat that cap for the admin member table.

**Files:**
- Modify: `server/static/brolly.css:428-433`
- Modify: all 5 `server/templates/account/*.html` pages and both `admin/` pages

- [ ] **Step 1: Write the failing test**

In `server/tests/ui_invariants.rs` — the conversion is only finished when the
old class is gone anywhere:

```rust
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
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo test -p brolly-server --test ui_invariants the_dashboard_panel_is_retired`
Expected: FAIL — seven templates still use it.

- [ ] **Step 3: Add the card CSS**

In `server/static/brolly.css`, replacing `.dashboard-panel` (`:428`) and
`.dashboard-panel-wide` (`:433`):

```css
/* A card is one concern: a header naming it, a body, and the controls that act
   on it. A page renders as many as it has concerns, which is how the security
   page stops being a password form and a session count in one undivided box. */
.dashboard-card {
  margin-block-start: var(--sp-1);
  max-width: var(--measure);
  border: var(--border-width) solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
}
.dashboard-card > header {
  padding: var(--sp--1) var(--sp-0);
  border-block-end: var(--border-width) solid var(--border);
}
.dashboard-card > header h2 { font-size: var(--txt-0); margin: 0; }
.dashboard-card > section { padding: var(--sp-0); }
.dashboard-card > footer {
  padding: var(--sp-0);
  border-block-start: var(--hairline) solid var(--border-subtle);
}
/* A table is not prose and does not want the reading measure. */
.dashboard-card-wide { max-width: none; }

/* solidid rules each row rather than spacing them; it is what makes a long
   fact list scannable, and it is one property. */
.facts dd { border-block-end: var(--hairline) solid var(--border-subtle); padding-block-end: var(--sp--2); }
.facts dd:last-child { border-block-end: 0; }
```

- [ ] **Step 4: Convert the seven pages**

Card headings are `<h2>`. solidid's card `<header>` holds an `<h1>`, which is
fine in a Svelte component and wrong here — the page's own `<h1>` already exists
and `every_template_has_one_h1_and_a_main_landmark` counts textually.

| Page | Cards |
|---|---|
| `account/overview.html` | one — the facts |
| `account/profile.html` | one — the form |
| `account/security.html` | **two** — Password, Sessions |
| `account/apps.html` | one, holding the list |
| `account/delete.html` | one |
| `admin/overview.html` | one |
| `admin/users.html` | one `.dashboard-card-wide`, holding the table |

The shape, using `account/apps.html` as the worked example:

```html
<section class="dashboard-card">
  <header><h2>Authorised applications</h2></header>
  <section>
    {% if saved %}<p class="notice" role="status">Access withdrawn.</p>{% endif %}
    ...existing body...
  </section>
</section>
```

- [ ] **Step 5: Split the security page**

`account/security.html` becomes two cards. The **Password** card holds the form.
The **Sessions** card holds the count and the sentence that currently sits inside
the form as a `.hint` at `security.html:31`:

> Changing your password signs out every other session.

That sentence **moves, it does not duplicate** — it belongs with the session
count rather than with the field that happens to trigger it, and leaving both
puts the same sentence on one page twice. Delete it from the form.

- [ ] **Step 6: Verify and commit**

Run: `cargo test --workspace`
Expected: PASS, including `the_dashboard_panel_is_retired`.

```bash
git add server/static/brolly.css server/templates server/tests/ui_invariants.rs
git commit -m "feat(ui): cards replace the dashboard panel

One object per concern, so the security page stops being a password form
and a session count in one undivided box."
```

### Task 3: Chips mark the exceptional value

`admin/users.html` renders `role` and `status` as bare table text — the strings
`member` and `active`, straight from Postgres.

**Only the exceptional value is marked.** `member` and `active` are the default
state of almost every row, and marking them makes everything marked, which is
the condition `<mark>` exists to distinguish itself from.

**Files:**
- Modify: `server/static/brolly.css`
- Modify: `server/templates/admin/users.html`
- Test: `server/tests/admin.rs`

- [ ] **Step 1: Write the failing test**

In `server/tests/admin.rs`, following that file's existing harness:

```rust
/// Disabled is the state that must never read as ordinary: an operator
/// scanning for the account they just disabled should find it without reading.
/// Marking `active` too would make everything marked, which is the condition
/// <mark> exists to distinguish itself from.
#[tokio::test]
async fn the_member_list_marks_only_the_exceptional() {
    // Sign in as an admin and add a disabled member — follow the harness at
    // server/tests/admin.rs:16 and the `register` helper at :72.
    let (_, body) = get_as(&router, "/admin/users", Some(&admin_cookie)).await;

    assert!(body.contains("chip-disabled"), "a disabled account is marked");
    assert!(!body.contains("chip-active"), "an active one is not");
    assert!(body.contains("chip-admin"), "an admin is marked");
    assert!(!body.contains("chip-member"), "an ordinary member is not");
}
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo test -p brolly-server --test admin the_member_list_marks`
Expected: FAIL — no `chip-` class in the output.

- [ ] **Step 3: Add the CSS**

```css
/* <mark> rather than a span: it is the element for "this run of text is
   relevant", so the distinction survives with CSS off — the same argument as
   <strong> over a bold class. */
.chip {
  display: inline-block;
  padding: var(--badge-padding-block) var(--badge-padding-inline);
  border-radius: var(--radius-sm);
  font-size: var(--txt--1);
  font-weight: var(--weight-semibold);
}
/* --accent, not --wash-feature: .notice already owns that yellow, and a
   success notice beside a role chip in the same colour would read as related. */
.chip-admin { background: var(--accent); color: var(--accent-fg); }
.chip-disabled { background: var(--destructive); color: var(--destructive-fg); }
```

- [ ] **Step 4: Render them**

In `server/templates/admin/users.html`, replacing the bare `{{ member.role }}`
and `{{ member.status }}` cells:

```html
<td>
  {% if member.role == "admin" %}
  <mark class="chip chip-admin">admin</mark>
  {% else %}member{% endif %}
</td>
<td>
  {% if member.status == "disabled" %}
  <mark class="chip chip-disabled">disabled</mark>
  {% else %}active{% endif %}
</td>
```

`MemberView` (`server/src/admin.rs:172`) already carries `role` and `status` as
`String`, so no Rust change is needed here.

- [ ] **Step 5: Verify and commit**

Run: `cargo test --workspace`

```bash
git add server/static/brolly.css server/templates/admin/users.html server/tests/admin.rs
git commit -m "feat(admin): mark the exceptional value, not every value"
```

### Task 4: Copy that names the next step

**Files:**
- Modify: `server/templates/account/apps.html`

- [ ] **Step 1: Write the failing test**

```rust
/// One is a fact about the database; the other is addressed to a person.
/// Without a test this reverts to a one-liner.
#[tokio::test]
async fn the_empty_apps_state_names_the_next_step() {
    let h = harness().await;
    let cookie = h.login().await;

    let reply = h.get("/account/apps", Some(&cookie)).await;
    assert!(
        reply.body.contains("Solid"),
        "it should say what an authorised application is and where grants come from"
    );
    assert!(!reply.body.contains("You have not authorised any applications yet."));
}
```

Note this deliberately asserts the word "Solid" appears — the door's guard
(`the_unauthenticated_surface_sells_nothing`) is scoped to `auth.html`,
`base.html` and `_fine_print.html`, and the authenticated surface keeps saying
"point a Solid app here" because that is instruction, not advertisement.

- [ ] **Step 2: Rewrite the empty state**

Replacing `apps.html`'s current `<p class="hint">`:

```html
<p class="hint">
  Nothing has asked for access yet. When you sign in to a Solid, Mastodon or
  ATProto application using this account, it appears here — and you can withdraw
  its access from this page at any time.
</p>
```

- [ ] **Step 3: Verify and commit**

Run: `cargo test -p brolly-server --test dashboard the_empty_apps_state`

```bash
git add server/templates/account/apps.html server/tests/dashboard.rs
git commit -m "feat(account): the empty apps state names the next step"
```

---

## Chunk 3: The first JavaScript, and the invariant it forces

### Task 5: Copy to clipboard

Overview shows a WebID and a storage root, and both exist to be pasted into
another application. §4.2 permits this exactly: "Server-rendered Askama,
progressive enhancement. Every form works with JavaScript disabled. Interactive
bits are islands, not an app shell."

**Files:**
- Create: `server/static/brolly.js`
- Modify: `server/templates/base.html` (`<head>`)
- Modify: `server/templates/account/overview.html`

- [ ] **Step 1: Write the island**

`server/static/brolly.js`. The button is created **by** the script, so a member
without JavaScript is never offered a control that does nothing.

```js
// The only JavaScript in the product. An island, per plan §4.2: with script
// off, the value stays a selectable span and nothing is missing but a
// convenience — which is why the button is created here rather than rendered
// dead in the HTML.
document.querySelectorAll("[data-copy]").forEach((el) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "button button-compact";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(el.dataset.copy);
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = "Copy"), 2000);
    } catch {
      // Clipboard access can be refused outright. Say so rather than
      // pretending it worked.
      button.textContent = "Press ⌘C";
    }
  });
  el.insertAdjacentElement("afterend", button);
});
```

**Note:** this uses `.button-compact`, which the door plan's Task 9 deletes as
dead CSS. Either land this first, or re-add the rule here. Check
`brolly.css:277` before assuming it exists.

- [ ] **Step 2: Load it**

In `base.html`'s `<head>`, after the stylesheets. `<head>` is outside the
`{% block header %}` the door introduces, so this loads on the door too — where
it finds no `[data-copy]` and does nothing. One small deferred file is a better
trade than a second base template.

```html
  <script defer src="/static/brolly.js"></script>
```

**Known gap:** `every_stylesheet_url_resolves_to_a_shipped_file`
(`ui_invariants.rs:249`) scans `url("` in CSS only, so a mistyped `src` here
degrades silently — the same gap the door spec recorded for `<img src>`. See the
spec's open question; one check covering CSS `url()`, `<img src>` and
`<script src>` is worth doing deliberately, not as a side effect of this task.

- [ ] **Step 3: Mark the copy targets**

In `account/overview.html`, on the WebID and storage-root values:

```html
<dd><span class="mono" data-copy="{{ webid }}">{{ webid }}</span></dd>
```

- [ ] **Step 4: Verify**

Run: `cargo test --workspace`
Expected: PASS. `there_is_exactly_one_hand_authored_stylesheet` filters on
`extension == "css"` (`ui_invariants.rs:111`), so a `.js` file in `static/`
cannot affect it — no assertion needed, and the spec dropped the row that
claimed otherwise.

- [ ] **Step 5: Commit**

```bash
git add server/static/brolly.js server/templates/base.html server/templates/account/overview.html
git commit -m "feat(account): copy the WebID and storage root

The product's first JavaScript, and an island: with script off the value
stays selectable and only the convenience is missing."
```

### Task 6: §4.5's unwritten form invariant

§4.5 lists "*Every form works without JavaScript* — a test asserting each
`<form>` has a non-JS action + method." **That test does not exist.**
`ui_invariants.rs` implements the `format!` gate, the single stylesheet, the
generated-token file, the colour-literal check, the h1/main lint, the page
container and the stylesheet URLs — and not this one.

It has been free to hold by luck while there was no JavaScript at all. Task 5
introduces some.

**Files:**
- Modify: `server/tests/ui_invariants.rs`

- [ ] **Step 1: Write it**

It needs **its own walker, not `collect_templates`** — that helper skips
`_`-prefixed partials (`ui_invariants.rs:288`), and `account/_nav.html:3` and
`admin/_nav.html:3` both hold `<form method="post" action="/logout">`, which are
exactly the kind of form the invariant exists for.

```rust
/// Every form posts somewhere without JavaScript (§4.5).
///
/// Free to hold by luck while the product shipped no JavaScript at all. It
/// ships some now, so this stops being luck.
///
/// Its own walker rather than `collect_templates`, which skips `_`-prefixed
/// partials — and both `_nav.html` files carry the logout form.
#[test]
fn every_form_works_without_javascript() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read templates").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "html") {
                out.push(path);
            }
        }
    }

    let mut templates = Vec::new();
    walk(&workspace_root().join("server/templates"), &mut templates);
    assert!(templates.len() > 8, "expected the templates, found {templates:?}");

    let mut checked = 0;
    for path in templates {
        let text = std::fs::read_to_string(&path).expect("read template");
        for (i, _) in text.match_indices("<form") {
            let tag = &text[i..text[i..].find('>').map_or(text.len(), |e| i + e + 1)];
            assert!(
                tag.contains("method="),
                "{path:?} has a <form> with no method: {tag}"
            );
            assert!(
                tag.contains("action=") && !tag.contains("action=\"\""),
                "{path:?} has a <form> with no action: {tag}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the walker found no forms, which cannot be right");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p brolly-server --test ui_invariants every_form_works_without_javascript`
Expected: PASS. Every form in the tree already complies; this stops that being
an accident.

**Known limit, recorded rather than papered over:** `auth.html:15` and
`consent.html:31` use `action="{{ action }}"`, so the check can only assert the
attribute is textually non-empty. It cannot see whether `AuthPage.action`ever
resolves to an empty string at runtime.

- [ ] **Step 3: Commit**

```bash
git add server/tests/ui_invariants.rs
git commit -m "test: every form works without JavaScript

Listed in plan section 4.5 and never implemented. It held by luck while
the product shipped no JavaScript; it ships some now."
```

---

## Done when

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
./tools/check-doc-paths.sh
```

All five pass; `/account/apps` says "Access withdrawn." after a revoke; and
`grep -r "dashboard-panel" server/` returns nothing.
