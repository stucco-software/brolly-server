# A Pod Serves Documents — Implementation Plan

<!-- doc-paths: skip -->
<!-- The plan names tests and functions it creates, so not every path it
     cites resolves until it's implemented. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pod stores and serves the document types a web site is made of — HTML, CSS, JS, SVG, fonts, JSON, XML feeds — with the two openings that would make that unsafe closed first.

**Architecture:** Three deployable commits, in the order ADR 0018 requires. (1) The session cookie becomes `__Host-brolly_session`, which a subdomain cannot set and which leaves every pre-`0a465e0` cookie inert; its removal carries the prefix's attributes. (2) A pod refuses to serve a service worker, and `security_headers` answers `frame-ancestors 'self'` on member hosts and `'none'` on the apex. (3) A second allow-list, `ALLOWED_DOCUMENT_TYPES`, joins the media list at the one choke point (`ldp::prepare`); the Mastodon upload checks media-only before it; the tests that pinned the refusal invert.

**Tech Stack:** Rust, axum 0.8, `cookie` 0.18 (via axum-extra `CookieJar`), askama, sqlx. Tests need Docker (testcontainers Postgres).

**Decision record:** `docs/architecture/adr/0018-a-pod-serves-documents.md` — read it first; the seven controls and the three acceptances are the *why* of every task below.

**House rules that bite here:**
- Library crates deny `unwrap`/`expect`/`panic`/`println!`; integration test files carry `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` already; a library crate's in-file `mod tests` is covered by its `lib.rs` `cfg_attr` — add no second attribute.
- No HTML via `format!`; tokens only in `brolly.css`; `server/tests/ui_invariants.rs` enforces the mechanical ones.
- Pre-commit (lefthook) runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `./tools/check-doc-paths.sh`. Run them yourself, gated on exit status: `cargo test … > /tmp/x.log 2>&1 && …`, never a `grep`/`head` at the end of a pipe.
- Trunk-based: commit straight to `main`, one commit per chunk, every commit green. No git remote; do not push.
- **The working tree may hold the operator's uncommitted theme work** (`theme_css` in `server/src/lib.rs`, `server/src/main.rs`, two templates, and every test's `AppState` literal). Never `git add -A`/`.`, stash, reset or checkout a file. A theme hunk must never ride into a commit: `theme_css` is not a field of `AppState` at `HEAD`, so such a commit does not build alone. For a file that carries one, stage it through this filter, which drops every hunk mentioning `theme_css` plus `lib.rs`'s "five"→"six" doc hunk (which does not contain the string). Create it once:

  ```bash
cat > /tmp/dropthemehunks.awk <<'AWK'
function flush() { if (h != "" && h !~ /theme_css|rather than six/) printf "%s", h; h = "" }
/^diff --git/ { flush(); inh = 0 }
/^@@ / { flush(); inh = 1 }
{ if (inh) h = h $0 "\n"; else print }
END { flush() }
AWK
  ```

  (The block is flush left on purpose: the `AWK` terminator must be at column 0.)

  Then for each such file: `git diff -- <file> | awk -f /tmp/dropthemehunks.awk > /tmp/stage.patch && git apply --cached --check /tmp/stage.patch && git apply --cached /tmp/stage.patch`. **Chain every staging command and `test "$(git diff --cached | grep -c theme_css)" = 0` to the `git commit` with `&&`, in every chunk** — a check on its own line does not stop the commit on the next one. Task 2.3 shows the shape. If the chain fails the index may be partly staged: inspect it before retrying. The filter removes theme hunks only, so read `git diff --cached --stat` before committing too. The filter works hunk by hunk, so if one of your edits lands in the same hunk as a theme line, it will be dropped with it: confirm with `git diff --cached --stat` that your edit is staged. After committing, `git show HEAD | grep -c theme_css` must print 0 and `git diff | grep -c theme_css` must equal what it was before you started (record it first). Check `git status --short` before starting: the only modified files may be the theme set above. If anything else is modified (a paused task leaves `server/src/admin.rs`, `identity/src/db.rs` and others mid-edit), another task is mid-flight — stop and report; do not build on it.
- Commit messages: conventional prefix, a body that says why, and the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (the implementer's own model).

---

## Chunk 1: The cookie is `__Host-brolly_session`

Control 6 of ADR 0018. One constant, defined once; a removal that the browser will honour; every test literal through the constant; three doc comments and a spec line.

### Task 1.1: The name, defined once, and the hardened builder

**Files:**
- Modify: `identity/src/extract.rs:15` (the constant) and its three test literals at lines ~85, ~97, ~115
- Modify: `server/src/auth.rs:32` (the constant becomes a re-export), `server/src/auth.rs:710-717` (`session_cookie` becomes `pub(crate)`), the unit test `the_session_cookie_is_hardened`

- [ ] **Step 1: Write the failing unit test**

In `server/src/auth.rs`, replace `the_session_cookie_is_hardened` in `mod tests`:

```rust
    #[test]
    fn the_session_cookie_is_hardened() {
        let cookie = session_cookie("token".into());
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        // ADR 0018, control 6: the `__Host-` prefix is enforced by the
        // browser — Secure, Path=/, no Domain — and a subdomain cannot set
        // one for the apex or for any other host. Cookie tossing from a
        // member page ends here.
        assert!(
            cookie.name().starts_with("__Host-"),
            "got {}",
            cookie.name()
        );
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.domain(), None);
        // One name, defined once: the server's constant is identity's.
        assert_eq!(SESSION_COOKIE, brolly_identity::extract::SESSION_COOKIE);
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p brolly-server --lib -- auth::tests::the_session_cookie_is_hardened > /tmp/t.log 2>&1; grep -E "panicked|got " /tmp/t.log`
Expected: FAIL — `got brolly_session` (the `starts_with("__Host-")` assertion).

- [ ] **Step 3: Implement**

In `identity/src/extract.rs`, replace the constant:

```rust
/// Session cookie name. Shared so the server does not restate it.
///
/// `__Host-` (ADR 0018, control 6): the browser enforces that such a cookie
/// is `Secure`, has `Path=/` and no `Domain`, and refuses to let a
/// subdomain set one for the apex or for any other host. Without the prefix,
/// a page on `alice.<apex>` — same-site with the apex — could toss a
/// `Domain=<apex>` cookie of this name onto a visitor and hand them the
/// attacker's session. The rename also leaves every cookie minted under the
/// old name, including any minted on a member host before `0a465e0`, inert:
/// nothing reads `brolly_session` any more.
pub const SESSION_COOKIE: &str = "__Host-brolly_session";
```

and in its tests, replace the three `brolly_session=xyz` literals with `__Host-brolly_session=xyz` (lines ~85, ~97, ~115 — `grep -n brolly_session identity/src/extract.rs | grep -v __Host-` must then print only the doc comment's "nothing reads `brolly_session` any more" line).

In `server/src/auth.rs`, replace the constant and make the builder crate-visible:

```rust
/// Name of the session cookie — identity's constant, so the two readers
/// (`CookieJar` here, `extract::credential` on the pod) can never disagree
/// on the name. See `brolly_identity::extract::SESSION_COOKIE` for why it is
/// `__Host-`-prefixed.
pub const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;
```

```rust
/// The session cookie, with everything the `__Host-` prefix requires and
/// everything a session cookie should have. Also the shape of its removal:
/// a `__Host-` cookie can only be cleared by a `Set-Cookie` that carries the
/// prefix's attributes, so `logout` and `delete_account` build their removal
/// from this (`CookieJar::remove` keeps the attributes of the cookie it is
/// given and sets only the empty value, `Max-Age=0` and `Expires`).
pub(crate) fn session_cookie(token: String) -> Cookie<'static> {
```

(the body is unchanged.)

- [ ] **Step 4: Run the unit tests**

Run: `cargo test -p brolly-server --lib -- auth::tests > /tmp/t.log 2>&1 && cargo test -p brolly-identity --lib -- extract >> /tmp/t.log 2>&1 && echo PASS || { grep -E "FAILED|panicked|error" /tmp/t.log; false; }`
Expected: `PASS`.

### Task 1.2: Logout and account deletion clear a `__Host-` cookie

**Files:**
- Modify: `server/src/auth.rs:689` (`logout`), `server/src/account.rs:634` (`delete_account`)
- Test: `server/tests/auth_flow.rs`, `server/tests/dashboard.rs`

- [ ] **Step 1: Write the failing tests**

In `server/tests/auth_flow.rs`, after `logout_is_not_reachable_by_get` (grep for it):

```rust
/// A `__Host-` cookie can only be cleared by a `Set-Cookie` that carries the
/// prefix's attributes (ADR 0018, control 6). `CookieJar::remove` on a bare
/// name would emit a removal without `Secure` or `Path`, which the browser
/// drops — the session would be revoked server-side and the cookie would
/// stay in the browser, inert but present. The removal has to be built from
/// the same cookie the login set.
#[tokio::test]
async fn logout_clears_a_host_prefixed_cookie_the_browser_will_honour() {
    let (db, _dir, router) = harness().await;
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let (_, _, cookies, _) = post(
        &router,
        "/login",
        "username=alice&password=correct-horse-battery",
    )
    .await;
    let session = cookies
        .iter()
        .find(|c| c.starts_with("__Host-brolly_session="))
        .expect("a __Host- session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let removal = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("__Host-brolly_session="))
        .expect("a removal Set-Cookie")
        .to_string();
    assert!(removal.starts_with("__Host-brolly_session=;"), "{removal}");
    assert!(removal.contains("Max-Age=0"), "{removal}");
    assert!(removal.contains("Secure"), "{removal}");
    assert!(removal.contains("Path=/"), "{removal}");
    assert!(!removal.contains("Domain="), "{removal}");
}

/// The old name authenticates nothing: a cookie minted on a member host
/// before `0a465e0`, or one tossed by a member page, is inert (ADR 0018).
#[tokio::test]
async fn the_old_cookie_name_is_not_a_session() {
    let (db, _dir, router) = harness().await;
    let user = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let token = db::create_session(&db.pool, user.id, time::Duration::hours(1), None)
        .await
        .unwrap();

    let (status, _, location) =
        get_on_host(&router, "/account", "brolly.test").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "no cookie: to login");
    assert!(location.unwrap().starts_with("/login"));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account")
                .header(header::HOST, "brolly.test")
                .header(header::COOKIE, format!("brolly_session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a valid token under the old name is not a session"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account")
                .header(header::HOST, "brolly.test")
                .header(header::COOKIE, format!("__Host-brolly_session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "the same token under the new name is");
}
```

(`get_on_host` exists in `auth_flow.rs`; check its signature with `grep -n "async fn get_on_host" -A6` and adapt the destructuring if it differs.)

In `server/tests/dashboard.rs`, after `deleting_an_account_removes_the_user_and_the_pod`:

```rust
/// Deletion clears the cookie the way logout does (ADR 0018, control 6).
#[tokio::test]
async fn deleting_an_account_clears_a_host_prefixed_cookie() {
    let h = harness().await;
    let cookie = h.login().await;
    let reply = h
        .post("/account/delete", "confirm=alice", Some(&cookie))
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let removal = reply
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("__Host-brolly_session="))
        .expect("a removal Set-Cookie")
        .to_string();
    assert!(removal.contains("Max-Age=0"), "{removal}");
    assert!(removal.contains("Secure"), "{removal}");
    assert!(removal.contains("Path=/"), "{removal}");
}
```

(`Reply.headers` exists — added for the rate-limit tests.)

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --no-fail-fast -p brolly-server --test auth_flow --test dashboard -- host_prefixed old_cookie_name > /tmp/t.log 2>&1; grep -E "^test |panicked" /tmp/t.log`
Expected (Task 1.1 is done, so the cookie is already `__Host-`-named): `logout_clears…` and `deleting…` FAIL at the `Secure` assertion — the bare-name removal is `__Host-brolly_session=; Max-Age=0; Expires=…` with no `Secure` and no `Path`. `the_old_cookie_name_is_not_a_session` PASSES: it pins Task 1.1, and stays here so the rename cannot be undone without a test saying so.

- [ ] **Step 3: Implement**

In `server/src/auth.rs`, `logout`: replace `let jar = jar.remove(Cookie::from(SESSION_COOKIE));` with

```rust
    // Built from the cookie login set, not from the bare name: a `__Host-`
    // removal must carry `Secure` and `Path=/` or the browser drops it.
    let jar = jar.remove(session_cookie(String::new()));
```

In `server/src/account.rs`, `delete_account`: replace `(jar.remove(Cookie::from(SESSION_COOKIE)), Redirect::to("/")).into_response()` with

```rust
    (
        jar.remove(crate::auth::session_cookie(String::new())),
        Redirect::to("/"),
    )
        .into_response()
```

`account.rs` keeps `use crate::auth::SESSION_COOKIE;` (`require_session` reads it); only its `Cookie` import becomes unused — drop that one.

- [ ] **Step 4: Run the tests**

Run: `cargo test --no-fail-fast -p brolly-server --test auth_flow --test dashboard > /tmp/c1.log 2>&1; grep -E "^test .*FAILED|test result" /tmp/c1.log`
Expected: the three new tests pass. Several *existing* tests fail until Task 1.3 moves their literals — that is the next task; the failures must all be ones that log in by a hardcoded `brolly_session=` (a 303 where 200 was expected, or "a session cookie" not found). Anything else is a real break: stop.

### Task 1.3: Every test literal goes through the constant

**Files:**
- Modify: `server/tests/pod_http.rs` (7 literals), `server/tests/auth_flow.rs` (7), `server/tests/xrpc.rs` (3), `server/tests/admin.rs` (2), `server/tests/mastodon_profile_flags.rs` (2), `server/tests/mastodon_compose.rs` (1), `identity/src/extract.rs` (one new unit test)

- [ ] **Step 1: Replace**

In each of the six files, add near the other `const`s (or after the `use` block):

```rust
/// The session cookie's name, from the one place that defines it.
const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;
```

then replace every occurrence of the literal `brolly_session=` with `{SESSION_COOKIE}=` inside `format!` strings, and `"brolly_session="` prefixes in `starts_with`/`strip_prefix` with `&format!("{SESSION_COOKIE}=")`. Concretely, `format!("brolly_session={}", self.session)` → `format!("{SESSION_COOKIE}={}", self.session)`; `c.starts_with("brolly_session=")` → `c.starts_with(&format!("{SESSION_COOKIE}="))`. **Do not use a blind find-and-replace.** The tests written in Tasks 1.1–1.2 keep their literals on purpose: `__Host-brolly_session` pins the new name (the substring inside it is not a target), and `the_old_cookie_name_is_not_a_session`'s bare `brolly_session={token}` is the old name it exists to refuse.

Four literals do not fit those two shapes and are the ones a red/green check cannot catch — an unread cookie looks exactly like an invalid one, so a test that passes a bad cookie to `get_as` keeps passing whether or not the name is right:
- `server/tests/xrpc.rs` ~line 3134: `c.starts_with("brolly_session")` (no `=`) → `c.starts_with(SESSION_COOKIE)`.
- `server/tests/auth_flow.rs` ~lines 993 and 1041, and `server/tests/admin.rs` ~line 216: `Some("brolly_session=…")` passed to `get_as` → `Some(&format!("{SESSION_COOKIE}=…"))` with the same value.

Also add one unit test to `identity/src/extract.rs`'s `mod tests`, because the pod and the outbox read the cookie through `credential`, not `CookieJar`, and the ADR says the old name authenticates nothing on every reader:

```rust
    #[test]
    fn the_old_cookie_name_is_not_a_credential() {
        // ADR 0018: nothing reads `brolly_session` any more — a cookie minted
        // on a member host before `0a465e0`, or tossed by a member page, is
        // inert on the pod and the outbox as much as on the apex.
        assert!(credential(None, Some("brolly_session=xyz")).is_none());
        assert!(credential(None, Some("__Host-brolly_session=xyz")).is_some());
    }
```

Run `cargo test -p brolly-identity --lib -- extract > /tmp/t.log 2>&1 && echo PASS || { grep panicked /tmp/t.log; false; }` → `PASS` (it passes on first run: the rename in 1.1 is what it pins).

Then the check: `grep -rn "brolly_session" server/tests identity/src server/src | grep -v "__Host-brolly_session\|SESSION_COOKIE"` must print exactly these and nothing else: `extract.rs`'s doc line and the two lines of the new `the_old_cookie_name_is_not_a_credential` test (comment and assert); the `format!("brolly_session={token}")` in `the_old_cookie_name_is_not_a_session`; the `Refused` doc in `pod.rs`; and the test doc at `pod_http.rs` ~2425. The last two are Task 1.4's. Anything else is a literal you missed.

- [ ] **Step 2: Run the server suites**

Run: `cargo test --no-fail-fast -p brolly-server > /tmp/c1.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/c1.log; false; }`
Expected: `PASS`. A failure that reads as "anonymous where a member was expected" is a literal you missed.

### Task 1.4: Doc comments, and commit

**Files:**
- Modify: `server/src/pod.rs:261-267` (the `Refused` doc), `server/src/auth.rs:593-594` (the `create_account` doc), `server/tests/pod_http.rs` ~line 2425 (a test's doc comment), `docs/specs/2026-09-23-solid-http-surface.md:210-211`

- [ ] **Step 1: Rewrite the three comments and the spec line**

`pod.rs`, the `Refused` doc: replace "A `brolly_session` cookie is `SameSite=Lax` (`server/tests/auth_flow.rs:249`)" with "A `__Host-brolly_session` cookie is `SameSite=Lax` (`auth::tests::the_session_cookie_is_hardened`)" — the old citation points into unrelated code; nothing else in that paragraph changes.

`auth.rs`, the `create_account` doc: the sentence spans two comment lines — match on the text, not a line. Replace "A session here would be a cookie a cross-origin script cannot use (`SameSite=Lax`) and a bearer a signup surface has no reason to hold" with "A session here would be a `__Host-` cookie a cross-origin script cannot use or set (`SameSite=Lax`; ADR 0018) and a bearer a signup surface has no reason to hold".

`server/tests/pod_http.rs` ~line 2425: in the doc comment that reads "H2 applies only to the `Authorization` header. `brolly_session` is `SameSite=Lax`…", replace `brolly_session` with `__Host-brolly_session`.

The spec-4 mention at `docs/specs/2026-09-23-solid-http-surface.md:210` is prose about the old name; Chunk 3's Task 3.5 adds the ADR note to spec 4's media-uploads H2 row and leaves this one — add a parenthetical "(now `__Host-brolly_session`, ADR 0018)" there in this task, and repoint the same passage's stale `server/tests/auth_flow.rs:249` citation (line ~211) to `auth::tests::the_session_cookie_is_hardened`.

- [ ] **Step 2: Gates**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1 && ./tools/check-doc-paths.sh && echo PASS || { grep -E "^(warning|error)" -A4 /tmp/clippy.log; false; }`
Expected: `doc paths ok` then `PASS`.

- [ ] **Step 3: The whole workspace**

Run: `cargo test --workspace > /tmp/all.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/all.log; false; }`
Expected: `PASS`. Budget 15 minutes. (The `blobs.rs` quota test has flaked once under full load before; if it is the only failure, rerun it alone three times and proceed if green.)

- [ ] **Step 4: Commit**

Record `git diff | grep -c theme_css` first. Stage theme-free (see the preamble) any of these files that carry a theme hunk — `server/src/lib.rs` is not in this commit; the six test files and `server/src/auth.rs`/`account.rs` may or may not be; check each with `git diff -- <file> | grep -c theme_css`.

```bash
git add identity/src/extract.rs server/src/auth.rs server/src/account.rs server/src/pod.rs docs/specs/2026-09-23-solid-http-surface.md
# plus the six test files, theme-free where needed
git commit -F - <<'EOF'
fix(auth): the session cookie is __Host-brolly_session (documents 1)

A member's subdomain is same-site with the apex, so a page on it could
set a Domain=<apex> cookie named brolly_session and hand a logged-out
visitor the attacker's session — login CSRF, whose next consent
authorises the attacker's account. Nothing a member could host today
runs script; ADR 0018 is about to let it, and this closes the opening
first. The __Host- prefix is enforced by the browser: Secure, Path=/,
no Domain, and a subdomain cannot set one for any host but its own,
where it can carry only a token it already holds.

The rename also retires, at a stroke, every cookie minted under the old
name — including any minted on a member host before 0a465e0, which the
pod and the outbox would still have honoured. Nothing reads
brolly_session any more. Members log in again once.

A __Host- cookie can only be cleared by a Set-Cookie that carries the
prefix's attributes, and CookieJar::remove on a bare name emits
neither; logout and account deletion build the removal from the cookie
login set, and tests read the removal header back. The name is defined
once, in identity, and every test literal goes through it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

Then: `git show HEAD | grep -c theme_css` → 0; `git diff | grep -c theme_css` → unchanged.

---

## Chunk 2: No service workers; framing per host

Controls 7 and 5 of ADR 0018, and the "Framing, per host" section.

### Task 2.1: A pod never serves a service worker

**Files:**
- Modify: `server/src/pod.rs` — `get` (grep `pub async fn get(`)
- Test: `server/tests/pod_http.rs`

- [ ] **Step 1: Write the failing test**

In `server/tests/pod_http.rs`, after `every_response_refuses_framing_and_limits_the_referrer`:

```rust
/// A pod never serves a service worker (ADR 0018, control 7). The browser
/// fetches a worker's script with `Service-Worker: script`; refusing that one
/// fetch blocks registration, and nothing a worker could `importScripts`
/// afterwards matters because there is no afterwards. The scope a worker
/// could claim is its script's directory — the server never sends
/// `Service-Worker-Allowed` — but within it, a worker intercepts every
/// visitor's requests, persistently, which is what a grant on a subtree must
/// not buy.
#[tokio::test]
async fn a_pod_refuses_to_serve_a_service_worker() {
    let h = harness().await;
    let (status, _, _) = h
        .send("PUT", "/~/sw.txt", Some(("text/plain", "self.addEventListener")), true)
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // As the browser fetches it for registration: refused, whoever asks —
    // the owner, and an anonymous caller who would otherwise get the 401.
    // The check runs before the pod or the caller is resolved.
    let sw = [("service-worker", "script")];
    for (status, body, _) in [
        h.send_if("GET", "/~/sw.txt", None, &sw).await,
        run(
            h.router.clone(),
            conditional_request("GET", "/~/sw.txt", None, None, &sw),
        )
        .await,
    ] {
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("service worker"), "{body}");
    }
    // As anything else: served.
    let (status, _, _) = h.send("GET", "/~/sw.txt", None, true).await;
    assert_eq!(status, StatusCode::OK);
}
```

(`send_if` sends as the owner with extra headers; `conditional_request(method, path, body, session, extra)` with `session: None` builds the same request anonymously, and the free function `run(router, request)` sends it — both already in the file, near lines 213 and 239.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p brolly-server --test pod_http -- a_pod_refuses_to_serve_a_service_worker 2>&1 | grep -E "^test|left|right"`
Expected: FAIL — `left: 200, right: 403`.

- [ ] **Step 3: Implement**

In `server/src/pod.rs`, `get`, immediately after `let path = format!("/~/{path}");` and before `resolve`:

```rust
    // ADR 0018, control 7: a pod never serves a service worker. The browser
    // sends this header on the one fetch that registers one; refused by
    // shape, before the pod is resolved or the caller is looked at, because
    // the answer does not depend on either — and a 403 here is not an
    // existence oracle, since it is the same for every path.
    if headers.contains_key("service-worker") {
        return (
            StatusCode::FORBIDDEN,
            "a pod does not serve service workers",
        )
            .into_response();
    }
```

- [ ] **Step 4: Run it**

Run: `cargo test -p brolly-server --test pod_http -- a_pod_refuses_to_serve_a_service_worker > /tmp/t.log 2>&1 && echo PASS || { grep -E "panicked|left|right" /tmp/t.log; false; }`
Expected: `PASS`.

### Task 2.2: `frame-ancestors 'self'` on member hosts, `'none'` on the apex

**Files:**
- Modify: `server/src/lib.rs` — `security_headers` (~lines 340-390) and its layer line (~805)
- Test: `server/tests/pod_http.rs` (`every_response_refuses_framing_and_limits_the_referrer` is rewritten); `auth_flow` and `solid_oidc_flow` are run, not edited

- [ ] **Step 1: Rewrite the failing test**

In `server/tests/pod_http.rs`, replace `every_response_refuses_framing_and_limits_the_referrer` with:

```rust
/// Framing is decided per host (ADR 0018). A member host answers
/// `frame-ancestors 'self'`: SolidOS served from the pod frames the pod's own
/// documents for previews, and nothing a pod page could be dressed up as
/// carries authority anyway. The apex answers `'none'` — the consent screen
/// is there, and `SameSite=Lax` is no defence against a same-site member
/// page framing it; this header is (control 5). `X-Frame-Options` agrees with
/// the CSP on both. The referrer policy is the same everywhere.
#[tokio::test]
async fn framing_is_self_on_a_member_host_and_none_on_the_apex() {
    let h = harness().await;
    h.send("PUT", "/~/paper.pdf", Some(("application/pdf", PDF)), true)
        .await;

    for (path, expected) in [
        ("/~/paper.pdf", StatusCode::OK),
        ("/profile", StatusCode::OK),
        ("/~/nothing-here", StatusCode::NOT_FOUND),
    ] {
        let (status, _, headers) = h.send("GET", path, None, true).await;
        assert_eq!(status, expected, "{path}");
        assert_eq!(
            headers.get("content-security-policy").map(|v| v.to_str().unwrap()),
            Some("frame-ancestors 'self'"),
            "{path}: a member host"
        );
        assert_eq!(
            headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
            Some("SAMEORIGIN"),
            "{path}"
        );
        assert_eq!(
            headers.get("referrer-policy").map(|v| v.to_str().unwrap()),
            Some("strict-origin-when-cross-origin"),
            "{path}"
        );
    }

    // The apex: the same request shape, the instance's host.
    for path in ["/health", "/login"] {
        let response = h
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::HOST, "brolly.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let headers = response.headers();
        assert_eq!(
            headers.get("content-security-policy").map(|v| v.to_str().unwrap()),
            Some("frame-ancestors 'none'"),
            "{path}: the apex"
        );
        assert_eq!(
            headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
            Some("DENY"),
            "{path}"
        );
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p brolly-server --test pod_http -- framing_is_self 2>&1 | grep -E "^test|left|right"`
Expected: FAIL — `left: Some("frame-ancestors 'none'")` on `/~/paper.pdf`.

- [ ] **Step 3: Implement**

In `server/src/lib.rs`, replace `security_headers` and its doc comment's framing paragraph and closing paragraph:

```rust
/// `X-Content-Type-Options: nosniff` on every response (spec 4, H4).
///
/// A browser that follows the header will not second-guess a response's
/// `Content-Type`, so a binary served with the type the server recorded — the
/// allow-list's decision, not the uploader's — is the type it is rendered as.
/// The header is harmless where it is redundant and load-bearing where a type
/// could be second-guessed, and one layer at composition is how it stays on
/// every response: per-route application is how it ends up missing on the one
/// route that matters.
///
/// Two more ride the same layer, for the same reason:
///
/// * `Content-Security-Policy: frame-ancestors …`, and `X-Frame-Options` to
///   match for the browsers that predate CSP 2 — **decided per host** (ADR
///   0018). On the apex, `'none'`/`DENY`: the consent screen is there,
///   rendered inside somebody else's OAuth flow, and `SameSite=Lax` is not
///   its defence — `alice.<apex>` is same-site with the apex, so a document
///   on a member host could frame it with the member's own session and dress
///   the Authorise button as something else. This header is what keeps the
///   frame out, and ADR 0018 lists it among the controls a pod serving
///   documents rests on. On a member host, `'self'`/`SAMEORIGIN`: a pod page
///   carries no authority a foreign frame could abuse, SolidOS served from
///   the pod frames the pod's own documents for previews, and `'self'` is
///   what protects a pod-hosted *app* — which does hold the member's tokens
///   in that origin — from being framed by anyone else. The host test is
///   `subdomain_user`'s, so every subdomain-shaped host gets `'self'`,
///   `www` and unregistered names included; nothing is served there, so
///   nothing is lost.
/// * `Referrer-Policy: strict-origin-when-cross-origin`. A pod URL, an OAuth
///   `state`, a consent request token in a query — none of it belongs in
///   another site's access log.
///
/// No further CSP directives: a member's origin holds no credential the
/// instance issues to a browser, and a pod-hosted app's own tokens would not
/// be protected by a policy permissive enough to run the app (ADR 0018,
/// "What stays as it was").
async fn security_headers(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let member_host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|host| extract::subdomain_user(host, &state.base_domain).is_some());
    let mut response = next.run(request).await;
    // Inserted, not appended: nothing else writes these headers, so there is
    // no value to preserve, and a duplicate would be a spec violation either
    // way.
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    let (frame_ancestors, frame_options) = if member_host {
        ("frame-ancestors 'self'", "SAMEORIGIN")
    } else {
        ("frame-ancestors 'none'", "DENY")
    };
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(frame_ancestors),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static(frame_options),
    );
    headers.insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response
}
```

and the layer line becomes:

```rust
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
```

(`extract` is already imported in `lib.rs` as `brolly_identity::extract` — check with `grep -n "^use brolly_identity" server/src/lib.rs`; `State` is imported.) Keep the comment above the layer line and change "`frame-ancestors 'none'`" in it to "`frame-ancestors`, per host".

- [ ] **Step 4: Run the tests**

Run: `cargo test --no-fail-fast -p brolly-server --test pod_http --test auth_flow --test solid_oidc_flow > /tmp/c2.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/c2.log; false; }`
Expected: `PASS`. (No other test in the workspace asserts `frame-ancestors` or `X-Frame-Options`; the one the plan rewrote was the only one.)

### Task 2.3: Commit

- [ ] **Step 1: Gates, and the whole workspace**

Run: `cargo test --workspace > /tmp/all.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/all.log; false; }`
Expected: `PASS` (same flake note as Task 1.4).

Then the lint gates:

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1 && ./tools/check-doc-paths.sh && echo PASS || { grep -E "^(warning|error)" -A4 /tmp/clippy.log; false; }`
Expected: `doc paths ok` then `PASS`.

- [ ] **Step 2: Commit**

`server/src/lib.rs` and `server/tests/pod_http.rs` carry the operator's theme hunks; `server/src/pod.rs` does not. Stage the two theme-free:

```bash
git add server/src/pod.rs \
  && git diff -- server/src/lib.rs | awk -f /tmp/dropthemehunks.awk > /tmp/stage.patch \
  && git apply --cached --check /tmp/stage.patch && git apply --cached /tmp/stage.patch \
  && git diff -- server/tests/pod_http.rs | awk -f /tmp/dropthemehunks.awk > /tmp/stage.patch \
  && git apply --cached --check /tmp/stage.patch && git apply --cached /tmp/stage.patch \
  && test "$(git diff --cached | grep -c theme_css)" = 0 \
  && git commit -F - <<'EOF'
feat(server): a pod serves no worker, and framing is decided per host (documents 2)

Two of ADR 0018's controls, landing before the document types they
guard. A request carrying Service-Worker: script to a pod path is
refused by shape: the browser sends it on the one fetch that registers
a worker, and a worker — scoped to its script's directory, since the
server never sends Service-Worker-Allowed — would intercept every
visitor's requests under that subtree, persistently; a grant on a
folder must not buy that.

frame-ancestors was 'none' everywhere. On a member host it is 'self'
now, and X-Frame-Options SAMEORIGIN with it: SolidOS served from the
pod frames the pod's own documents for previews, and a pod page
carries no authority a foreign frame could abuse, while 'self' still
protects a pod-hosted app — which does hold the member's tokens — from
every other origin. The apex keeps 'none': the consent screen is there,
and this header, not SameSite=Lax, is what keeps a same-site member
page from framing it. security_headers takes the state to know the
base domain.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

Then the two theme checks.

---

## Chunk 3: The document types

The decision itself: two lists, one gate; the Mastodon upload checks media-only; the tests that pinned the refusal invert; the comments that argued for it are rewritten.

Precondition: the Chunk 1 follow-up that reads the session cookie literally (`extract::session_token`) must be on `main` before this chunk lands.

### Task 3.1: `ALLOWED_DOCUMENT_TYPES` and `is_storable_type`

**Files:**
- Modify: `domain/src/media.rs` — the list's doc comment (lines ~20-24), a new constant after `ALLOWED_MEDIA_TYPES`, `is_allowed_media_type` (~214), a new `is_storable_type`, the test `svg_is_absent_and_stays_absent` (~252)

- [ ] **Step 1: Write the failing tests**

In `domain/src/media.rs` `mod tests`, replace `svg_is_absent_and_stays_absent` with:

```rust
    #[test]
    fn the_document_list_is_what_the_adr_names() {
        // ADR 0018's block, in its order.
        assert_eq!(
            ALLOWED_DOCUMENT_TYPES,
            &[
                "text/html",
                "text/css",
                "text/javascript",
                "application/javascript",
                "application/json",
                "image/svg+xml",
                "image/x-icon",
                "font/woff2",
                "font/woff",
                "font/ttf",
                "application/xml",
                "text/xml",
                "application/rss+xml",
                "application/atom+xml",
            ]
        );
    }

    #[test]
    fn a_document_is_storable_but_is_not_media() {
        // Two lists, one gate (ADR 0018): the pod stores both; a Mastodon
        // attachment is media only. SVG and HTML are the two the old list
        // kept out by decision, and the decision is reversed here, on the
        // record.
        for document in ["text/html", "image/svg+xml", "text/css", "application/rss+xml"] {
            assert!(is_storable_type(document), "{document}");
            assert!(!is_allowed_media_type(document), "{document}");
        }
        for medium in ["image/png", "application/pdf", "text/plain"] {
            assert!(is_storable_type(medium), "{medium}");
            assert!(is_allowed_media_type(medium), "{medium}");
        }
        for neither in ["application/x-sh", "application/rdf+xml", "text/turtle"] {
            assert!(!is_storable_type(neither), "{neither}");
        }
        // The two lists do not overlap: a type is one thing or the other.
        for document in ALLOWED_DOCUMENT_TYPES {
            assert!(!ALLOWED_MEDIA_TYPES.contains(document), "{document} is on both");
        }
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-domain --lib -- media::tests 2>&1 | tail -6`
Expected: compile error — `ALLOWED_DOCUMENT_TYPES`, `is_storable_type` not found.

- [ ] **Step 3: Implement**

In `domain/src/media.rs`, replace the paragraph of the list's doc comment that begins "**`image/svg+xml` is deliberately absent.**" (through "…not a default to slip in.") with:

```rust
/// **`text/html` and `image/svg+xml` are not here — they are on
/// [`ALLOWED_DOCUMENT_TYPES`].** This list is what a Mastodon *attachment*
/// may be; the pod stores both lists (ADR 0018). Spec 4 kept the two off
/// every list while a member's origin held the member's session; it holds
/// none now, and the decision is reversed on the record.
```

After `ALLOWED_MEDIA_TYPES`, add:

```rust
/// The document types a web site is made of (ADR 0018): what a pod stores
/// and serves as typed, beyond media. Kept apart from
/// [`ALLOWED_MEDIA_TYPES`] so that a Mastodon upload — which checks the
/// media list before the pod's gate — cannot become an HTML upload. No
/// `application/wasm`: it needs script to run and nobody has asked.
pub const ALLOWED_DOCUMENT_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "image/svg+xml",
    "image/x-icon",
    "font/woff2",
    "font/woff",
    "font/ttf",
    "application/xml",
    "text/xml",
    "application/rss+xml",
    "application/atom+xml",
];
```

Replace `is_allowed_media_type`'s doc and add `is_storable_type`:

```rust
/// True when `media_type` — a bare, parameter-stripped type — is one a
/// Mastodon attachment may be. The stripping is the caller's
/// ([`crate::syntax::media_type_of`]): `image/png; charset=utf-8` is
/// `image/png`.
pub fn is_allowed_media_type(media_type: &str) -> bool {
    ALLOWED_MEDIA_TYPES.contains(&media_type)
}

/// True when the pod stores `media_type` as a binary: media or a document
/// (ADR 0018). The one question `ldp::prepare` asks.
pub fn is_storable_type(media_type: &str) -> bool {
    is_allowed_media_type(media_type) || ALLOWED_DOCUMENT_TYPES.contains(&media_type)
}
```

- [ ] **Step 4: Run them**

Run: `cargo test -p brolly-domain --lib -- media::tests > /tmp/t.log 2>&1 && echo PASS || { grep -E "panicked|error" /tmp/t.log; false; }`
Expected: `PASS`.

### Task 3.2: The gate, the 415 body, and the adapter test

**Files:**
- Modify: `adapters/solid/src/ldp.rs:178-182` (the 415 body), `:678-685` (the gate and its comment)
- Test: `adapters/solid/tests/ldp_nonrdf.rs` (`an_svg_is_refused_like_any_other_off_list_type` ~line 418, and `an_off_list_binary_is_refused_with_the_list_and_leaves_no_bytes_behind` ~line 383, which PUTs `text/html` and would start passing the gate), `server/tests/pod_http.rs` (Task 3.4's two tests — written *here*, before the gate changes, so they are red at the HTTP level too)

- [ ] **Step 1: Rewrite the failing tests**

In `adapters/solid/tests/ldp_nonrdf.rs`, replace `an_svg_is_refused_like_any_other_off_list_type` and its doc comment with:

```rust
/// ADR 0018 reversed spec 4's one deliberate absence: a pod stores the
/// document types a web site is made of. An SVG and an HTML page land as
/// binaries with their own types — the type the reader will be served, and
/// `nosniff` keeps the browser from second-guessing it.
#[test]
fn a_document_is_stored_with_its_type() {
    let pod = pod();
    for (path, body, media_type) in [
        ("/~/icon.svg", &b"<svg xmlns='http://www.w3.org/2000/svg'/>"[..], "image/svg+xml"),
        ("/~/index.html", &b"<!doctype html><title>alice</title>"[..], "text/html"),
        ("/~/site.css", &b"body{margin:0}"[..], "text/css"),
    ] {
        ldp::put(
            &pod.store,
            Some(&pod.blobs),
            BASE,
            path,
            &alice(),
            body,
            media_type,
            ROOT,
        )
        .unwrap_or_else(|e| panic!("{path}: {e:?}"));
        let recorded = meta(&pod.store, &format!("{ROOT}{}", &path[3..])).expect("recorded");
        assert_eq!(
            recorded.blob.as_ref().map(|b| b.media_type.as_str()),
            Some(media_type),
            "{path}"
        );
    }
}

```

(`meta` returns `Option<ResourceMeta>`; `ResourceMeta.blob` is `Option<BlobMeta>` with `media_type: String` — verified.)

Then change the *existing* `an_off_list_binary_is_refused_with_the_list_and_leaves_no_bytes_behind` (~line 383), which PUTs `text/html` — a type the gate is about to admit — so it keeps testing what it is for: the refusal names the type, nothing is recorded, no orphan blob is left. Change its path to `/~/run.sh`, its body to `b"#!/bin/sh"` and its type to `"application/x-sh"`; `assert_eq!(media_type, "text/html")` to `assert_eq!(media_type, "application/x-sh")`; `said.contains("text/html")` to `said.contains("application/x-sh")`; add `"text/html"` to the `for allowed in […]` array, so the message must name both lists; and point the `meta(…page.html)` check at `run.sh`.

Rewrite its doc comment: it currently says `text/html` is "the type this exists for"; now: "A type on neither list (ADR 0018) is refused before its bytes reach the disk, naming both lists; nothing is recorded and no orphan is left for the sweep."

And in `server/tests/pod_http.rs`, make Task 3.4's two rewrites now (its Step 1 text), so that the HTTP-level tests are red before the gate changes.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-solid --test ldp_nonrdf -- a_document_is_stored an_off_list_binary > /tmp/t.log 2>&1; grep -E "^test |panicked|got" /tmp/t.log` and `cargo test -p brolly-server --test pod_http -- an_svg_and_an_html an_off_list_content_type > /tmp/t2.log 2>&1; grep -E "^test |panicked|left|right" /tmp/t2.log`
Expected: `a_document_is_stored_with_its_type` FAILS with `ContentTypeNotAllowed("image/svg+xml")`; `an_off_list_binary…` fails on the `text/html` assertion (the message lists only media); `an_svg_and_an_html_page_are_served_as_typed` FAILS with 415; `an_off_list_content_type…` fails on the `text/html` list assertion.

- [ ] **Step 3: Implement**

In `adapters/solid/src/ldp.rs`, the 415 body:

```rust
            LdpError::ContentTypeNotAllowed(media_type) => write!(
                f,
                "this server stores media and documents by allow-list, and {media_type} is \
                 not on either; the media it stores are: {}; the documents: {}",
                media::ALLOWED_MEDIA_TYPES.join(", "),
                media::ALLOWED_DOCUMENT_TYPES.join(", ")
            ),
```

and the gate:

```rust
    // The one choke point every protocol's binary passes through (spec 4,
    // H2): Solid PUT/POST and Mastodon's `upload_media` all land here, so the
    // lists are enforced once for all of them. Both lists (ADR 0018): media,
    // and the documents a web site is made of. The Mastodon upload checks
    // the media list on its own before it gets here, so an attachment stays
    // an attachment.
    let media_type = syntax::media_type_of(content_type);
    if !media::is_storable_type(media_type) {
        return Err(LdpError::ContentTypeNotAllowed(media_type.to_string()));
    }
```

- [ ] **Step 4: Run the adapter suite**

Run: `cargo test -p brolly-solid > /tmp/c3.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/c3.log; false; }`
Expected: `PASS`.

### Task 3.3: The Mastodon upload stays an attachment

**Files:**
- Modify: `server/src/mastodon_api.rs` — `upload_media`, after the `bytes.filter(|b| !b.is_empty())` block and before the quota check (~line 566); the comment at ~591-593; the `ContentTypeNotAllowed` → 415 branch at ~628-631
- Test: `server/tests/mastodon_compose.rs` — the *existing* `an_off_list_upload_is_a_415_whose_body_lists_the_allowed_ones` (~line 571) is the test: it uploads `text/html` through `upload_typed` and asserts a 415 whose body names `text/html` and `image/png`. No new test.

- [ ] **Step 1: Watch the existing test fail**

Run: `cargo test -p brolly-server --test mastodon_compose -- an_off_list_upload_is_a_415 > /tmp/t.log 2>&1; grep -E "^test |left|right" /tmp/t.log`
Expected: FAIL — `left: 200, right: 415`. Task 3.2's gate now stores HTML, and this route has no check of its own.

- [ ] **Step 2: Implement**

In `server/src/mastodon_api.rs`, `upload_media`, after the `let Some(bytes) = …` block:

```rust
    // An attachment is media (ADR 0018, "Two lists, one gate"): the pod's
    // gate stores documents too, so this is the one path that checks the
    // media list on its own, before it. The same 415 the gate used to give,
    // naming what was sent and what an attachment may be.
    let bare_type = brolly_domain::syntax::media_type_of(&media_type);
    if !brolly_domain::media::is_allowed_media_type(bare_type) {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &format!(
                "{bare_type} is not a media type this server stores; the types it stores are: {}",
                brolly_domain::media::ALLOWED_MEDIA_TYPES.join(", ")
            ),
        );
    }
```

(`media_type_of` is `brolly_domain::syntax::media_type_of` — `domain/src/syntax.rs:137` — the same function `ldp::prepare` strips parameters with; `brolly-domain` is already a dependency of `brolly-server`. `error(status, &str)` takes a `&str`.)

In `server/tests/mastodon_compose.rs`, rewrite the kept test's comment (~lines 573-576), which says the route shares one list with a Solid PUT and is now false: "ADR 0018: the pod stores `text/html`, an attachment may not be it. `upload_media` checks the media list before the pod's gate, and the 415 is this API's own error shape, with the list in it."

Then the two comments in `upload_media`: at ~591-593, "the allow-list… is enforced for this route by the one check, not a second one here" is now false — rewrite to "`prepare` is the same choke point Solid PUTs pass through; the media-only check above is this route's own, because the gate stores documents too (ADR 0018)". At ~628-631, the `ContentTypeNotAllowed` → 415 branch is unreachable once the pre-check exists: keep it, with a one-line comment "a backstop; the media check above answers first".

- [ ] **Step 3: Run the suite**

Run: `cargo test -p brolly-server --test mastodon_compose > /tmp/c3.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/c3.log; false; }`
Expected: `PASS`, the existing test included.

### Task 3.4: The pod tests invert

**Files:**
- Test: `server/tests/pod_http.rs` — `an_off_list_content_type_is_a_415_whose_body_lists_the_allowed_ones` (~line 695), `an_svg_is_refused_like_any_other_off_list_type` (~719)

These two rewrites are made in Task 3.2 Step 1, before the gate changes, so they are red at the HTTP level and go green with it. This task is their text and their green run.

- [ ] **Step 1: The two tests (written in 3.2)**

Replace `an_off_list_content_type_is_a_415_whose_body_lists_the_allowed_ones` with:

```rust
#[tokio::test]
async fn an_off_list_content_type_is_a_415_whose_body_lists_the_allowed_ones() {
    // H2 (spec 4): a type on neither list is refused, and the 415's body
    // carries both lists, because a client that gets a bare 415 has nothing
    // to act on.
    let h = harness().await;
    let (status, body, _) = h
        .send("PUT", "/~/run.sh", Some(("application/x-sh", "#!/bin/sh")), true)
        .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");
    assert!(body.contains("application/x-sh"), "must name what was sent: {body}");
    for allowed in ["image/png", "application/pdf", "text/html", "image/svg+xml"] {
        assert!(body.contains(allowed), "must list {allowed}: {body}");
    }

    // Nothing was recorded, and nothing is servable.
    let (status, _, _) = h.send("GET", "/~/run.sh", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
```

Replace `an_svg_is_refused_like_any_other_off_list_type` with:

```rust
/// ADR 0018 reversed spec 4's one deliberate absence — this is the test the
/// spec said reopening the question would mean deleting, inverted. A pod
/// stores the document types a web site is made of and serves them as typed,
/// with `nosniff`, from the member's origin. What made that safe is the
/// seven controls the ADR names, each with a test of its own; this one pins
/// only that the documents are served.
#[tokio::test]
async fn an_svg_and_an_html_page_are_served_as_typed() {
    let h = harness().await;
    for (path, body, media_type) in [
        ("/~/icon.svg", "<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml"),
        ("/~/index.html", "<!doctype html><title>alice</title>", "text/html"),
        ("/~/site.css", "body{margin:0}", "text/css"),
        ("/~/app.js", "console.log(1)", "text/javascript"),
    ] {
        let (status, reply, _) = h.send("PUT", path, Some((media_type, body)), true).await;
        assert_eq!(status, StatusCode::CREATED, "{path}: {reply}");

        let (status, served, headers) = h.send("GET", path, None, true).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(served, body, "{path}: the bytes as sent");
        assert_eq!(
            headers.get("content-type").map(|v| v.to_str().unwrap()),
            Some(media_type),
            "{path}: served as typed"
        );
        assert_eq!(
            headers.get("x-content-type-options").map(|v| v.to_str().unwrap()),
            Some("nosniff"),
            "{path}"
        );
    }
}
```

(A served binary's `content-type` is bare — `pod_http.rs` already asserts `"image/png"` exactly — so exact equality holds.)

- [ ] **Step 2: Run them**

Run: `cargo test --no-fail-fast -p brolly-server --test pod_http > /tmp/c3.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/c3.log; false; }`
Expected: `PASS`.

### Task 3.5: Comments, docs, commit

**Files:**
- Modify: `domain/src/media.rs` (the module doc, lines 1-8, and the list's doc, 10-18), `adapters/solid/src/ldp.rs` (the `ContentTypeNotAllowed` variant doc ~120-126; the `prepare` doc ~661-663), `server/src/pod.rs` (~745-748), `docs/specs/2026-09-29-solid-media-uploads.md:352` (the H2 row), `docs/deploying.md`

- [ ] **Step 0: The comments that argued for the old list**

Each of these still describes one list and the XSS it closed; each gets one honest sentence, not a rewrite:
- `domain/src/media.rs:1-8`, the module doc: "One allow-list and one size limit" → "Two allow-lists — media, and the documents a web site is made of (ADR 0018) — and one size limit"; and fix the "both enforced… both advertised" that follows: all are enforced at `ldp::prepare`, only the media list is advertised, and the media list has a second check at the Mastodon upload.
- `domain/src/media.rs:10-18`, the list's doc: "The content types this server stores as media" stays; replace "A binary is stored only if its content type … is on this list. Anything else is a 415 with this list in the body" with "A binary is stored only if its content type … is on this list or on `ALLOWED_DOCUMENT_TYPES` (ADR 0018). Anything else is a 415 with both lists in the body"; keep the "Before the list, a member-typed `text/html`…" sentence but prefix it with "Before any list," and append " — which held while the member's origin carried the member's session, and no longer does (ADR 0018)."
- `adapters/solid/src/ldp.rs` ~120-126, the variant doc: "not on the server's media allow-list… doesn't store it as media" → "on neither of the server's allow-lists (media, documents — ADR 0018)".
- `adapters/solid/src/ldp.rs` ~661-663, the `prepare` doc: "on the media allow-list" → "on one of the two allow-lists (ADR 0018)".
- `server/src/pod.rs` ~745-748: "doesn't store it as media" → "stores neither as media nor as a document".
- `grep -rn "svg" adapters/solid/src/ldp.rs domain/src/media.rs` must then hit only ADR-0018-aware text.

- [ ] **Step 1: The spec's H2 row**

Append to the H2 row's third cell: ` **Superseded on the types by ADR 0018 (2026-10-30): the pod stores and serves HTML, SVG and the rest of the web set; the media list is unchanged and is what a Mastodon attachment may be.**`

- [ ] **Step 2: The deploy doc**

In `docs/deploying.md`, under "Before pointing a live domain at it", add a bullet:

```
- **A pod serves documents** (ADR 0018). A member can host HTML, scripts
  and stylesheets on their own subdomain, and a page there can look like
  anything — the instance's login form included. It cannot *be* the
  instance: a session is only minted on the apex, a form only accepted
  from it. Two things follow for an operator. The session cookie is
  `__Host-brolly_session`, so every member is logged out once at this
  upgrade. And a grant on any folder of a pod is script on that pod's
  whole origin: a member who lets someone else write anywhere in their pod
  has let them read whatever a pod-hosted app keeps in the browser for
  that origin.
```

- [ ] **Step 3: Gates**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1 && ./tools/check-doc-paths.sh && echo PASS || { grep -E "^(warning|error)" -A4 /tmp/clippy.log; false; }`
Expected: `doc paths ok` then `PASS`.

- [ ] **Step 4: The whole workspace**

Run: `cargo test --workspace > /tmp/all.log 2>&1 && echo PASS || { grep -E "^test .*FAILED|panicked" /tmp/all.log; false; }`
Expected: `PASS`. Budget 15 minutes.

- [ ] **Step 5: Commit**

Check `server/tests/pod_http.rs` and `server/tests/mastodon_compose.rs` for theme hunks and stage theme-free if needed.

```bash
git add domain/src/media.rs adapters/solid/src/ldp.rs adapters/solid/tests/ldp_nonrdf.rs server/src/mastodon_api.rs server/src/pod.rs docs/specs/2026-09-29-solid-media-uploads.md docs/deploying.md
# server/tests/pod_http.rs, server/tests/mastodon_compose.rs: theme-free staging
git commit -F - <<'EOF'
feat(solid): a pod serves documents (documents 3, ADR 0018)

PUT index.html answered 415. Spec 4 kept text/html and image/svg+xml
off the allow-list because a member-typed document served from the
member's origin was stored XSS with the pod's cookies in scope. That
was true when written and is not now: the cookie is host-only on the
apex and __Host- prefixed, the door is apex-only, a form post from
another origin is refused, the CORS layer never allows credentials,
the apex cannot be framed, and a pod serves no service worker — the
seven controls ADR 0018 names, the last two landed in the two commits
before this one. A pod that cannot hold an HTML page is not a pod in
the sense Solid means.

Two lists, one gate. ALLOWED_DOCUMENT_TYPES is the web set — HTML,
CSS, JS, JSON, SVG, icons, fonts, XML and feeds — and ldp::prepare
stores the union of it and the media list. The media list is what a
Mastodon attachment may be, and the upload now checks it on its own
before the pod's gate, so an attachment stays an attachment — which
also means an RDF type posted there, once stored as RDF, is now a 415.
The pod's 415 names both lists; the upload's names the media list. The
two tests spec 4 said reopening this would
mean deleting are replaced by their inverse, in both crates.

Members are logged out once at this deploy (documents 1), and
deploying.md names what a member accepts by letting anyone else write
in their pod.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
```

Then the two theme checks, and report: three SHAs, the workspace count, anything skipped.
