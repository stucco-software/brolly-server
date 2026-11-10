# StuccoID Front End Implementation Plan

<!-- doc-paths: skip -->
<!-- The plan names the files, migration and functions it creates, so not
     every path it cites resolves until it's implemented. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let another app front a brolly instance: the apex homepage, `/register` and the account profile/delete pages hand off to it, and it creates, checks, finds, password-checks and deletes accounts over a token-protected JSON API.

**Architecture:** One new `AppState` field, `front_end: FrontEnd`, holds everything a fronting app configures (three URLs and the service token's hash). It derives `Default`, so every test literal gains one line and later fields cost nothing. The service API is a new `server/src/internal_api.rs` under `/internal/v1/`, apex-only, mounted only when `BROLLY_SERVICE_TOKEN` is set. It reuses `auth::create_member` (with a new `Admission::Service` that needs no invite) and a deletion core pulled out of `account::delete_account` into `provision::delete_account`. Emails become case-insensitive by storing them lowercased. Four chunks, each a deployable commit on `main`.

**Tech Stack:** Rust, axum 0.8, askama, sqlx 0.8 (Postgres), serde_json. Tests: `cargo test`, which provisions Postgres via testcontainers (Docker must be running).

**Spec:** `solidid/docs/superpowers/specs/2026-10-09-brolly-migration-design.md` (in the StuccoID repo), pieces 1–3. Read D1, D7 and pieces 1–3 first.

**Deliberately not in this plan** (the spec lists them; each is its own plan or dropped):
- `BROLLY_PROTOCOLS` (Solid-only switch). It reverses ADR 0016 and is independent of the front end. The live instance has no `BROLLY_PLC_SUBMIT`, so no `did:plc` is being published meanwhile. Own plan, own ADR amendment.
- `BROLLY_RESERVED_LABELS`. It existed for the `auth.` host, which the revised spec dropped. StuccoID enforces its stricter list itself, and once `BROLLY_SIGNUP_URL` is set the service API is the only way in. Dropped.
- `POST /internal/v1/password-resets`. Piece 4 (password reset) adds it together with the reset page.
- `Via::Service` in `brolly-identity`. Not needed: `extract::credential` already parses `Bearer` inside `brolly-identity`, which is what `server/tests/architecture.rs` requires. The service check compares hashes and produces no `Subject`.
- Re-pointing the dashboard's Profile and Delete tabs. They keep linking to `/account/profile` and `/account/delete`, which redirect to `BROLLY_ACCOUNT_HOME`: one extra hop, no template change.

**Deviations from the spec, on purpose:**
- `verify-password`'s limit counts every attempt, not only failures: ten per username per fifteen minutes. It's stricter, and it reuses the token-bucket limiter as it is.
- `POST /internal/v1/accounts` answers `{username, email, webId, storage}`, the same shape as the lookup. That's a superset of the spec's `{username, webId, storage}`.

**House rules that bite here:**
- Library crates deny `unwrap`/`expect`/`panic`/`println!`. Integration test files open with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`; new test files in this plan must too. A library crate's in-file `mod tests` is covered by the crate-level `#![cfg_attr(test, allow(…))]`; do not add a second attribute.
- No HTML via `format!`. This plan adds no templates.
- Trunk-based: commit straight to `main`, one commit per chunk, every commit green, **push after every commit**. **Pushing deploys to production:** Railway project `stucco-id` builds `stucco-software/brolly-server` and serves `id.stucco.software`. Every commit must be safe to run live with the production env (which sets none of the new variables).
- Pre-commit (lefthook) runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `./tools/check-doc-paths.sh`. Run them yourself before `git commit`. The code in this plan is not rustfmt-formatted (`rustfmt.toml` sets `max_width = 100`), so every check chain starts with `cargo fmt --all`.
- Stage only the files each task names. Never `git add -A` or `git add .`.
- Gate shell chains on cargo's exit status: `cargo test … > /tmp/x.log 2>&1 && …`, never `cargo test … | grep … && …`.
- Commit messages: conventional prefix, a body that says why, and the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

---

## Chunk 1: The front end's three URLs

When `BROLLY_HOME_URL`, `BROLLY_SIGNUP_URL` or `BROLLY_ACCOUNT_HOME` is set, the matching brolly pages redirect to the fronting app. Unset, nothing changes.

### Task 1.1: `FrontEnd` and `parse_front_end_url`

**Files:**
- Modify: `server/src/lib.rs` (new struct and fn after `parse_www_redirect`; new field on `AppState` after `www_redirect`; unit tests in a new `#[cfg(test)] mod front_end_tests` at the bottom)
- Modify: `server/src/main.rs` (build the field; one helper fn at the bottom)
- Modify: every `AppState { … }` literal in `server/tests/*.rs` (16 literals in 15 files)

- [ ] **Step 1: Write the failing unit tests**

Append to the bottom of `server/src/lib.rs`:

```rust
#[cfg(test)]
mod front_end_tests {
    use super::*;

    #[test]
    fn a_front_end_url_is_an_absolute_http_url() {
        assert_eq!(
            parse_front_end_url("https://stuccoid.stucco.software/account/create"),
            Ok("https://stuccoid.stucco.software/account/create".to_string())
        );
        assert_eq!(
            parse_front_end_url("http://localhost:5173/"),
            Ok("http://localhost:5173/".to_string())
        );
        // A bare origin gains the slash every browser would send anyway.
        assert_eq!(
            parse_front_end_url("https://stuccoid.stucco.software"),
            Ok("https://stuccoid.stucco.software/".to_string())
        );
    }

    #[test]
    fn what_is_not_a_front_end_url_is_refused() {
        assert!(parse_front_end_url("").is_err());
        assert!(parse_front_end_url("/account/create").is_err());
        assert!(parse_front_end_url("ftp://example.org/").is_err());
        assert!(parse_front_end_url("mailto:someone@example.org").is_err());
    }

    #[test]
    fn the_default_front_end_is_brolly_itself() {
        let front_end = FrontEnd::default();
        assert!(front_end.home.is_none());
        assert!(front_end.signup.is_none());
        assert!(front_end.account_home.is_none());
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-server --lib front_end_tests > /tmp/t.log 2>&1; tail -20 /tmp/t.log`
Expected: compile error, `cannot find function parse_front_end_url` / `cannot find type FrontEnd`.

- [ ] **Step 3: Add the struct, the parser and the field**

In `server/src/lib.rs`, directly after `parse_www_redirect`:

```rust
/// Another app in front of this instance: StuccoID in front of
/// `id.stucco.software`, a marketing site in front of a pod provider.
///
/// Each URL hands one of brolly's own pages to that app. Unset, brolly serves
/// the page itself, so a deployment with no front end is unchanged. Read once
/// in `main` and validated there, like `BROLLY_WWW_REDIRECT`: a typo is a
/// startup failure with the value in the log.
#[derive(Clone, Debug, Default)]
pub struct FrontEnd {
    /// `BROLLY_HOME_URL`: where the apex `/` sends a visitor instead of
    /// rendering the login form. `/login` still renders, because every OAuth
    /// flow sends people there.
    pub home: Option<String>,
    /// `BROLLY_SIGNUP_URL`: where `/register` sends a visitor. Set, accounts
    /// are created by the front end alone: the public `POST /api/accounts` is
    /// not mounted, whatever `BROLLY_PUBLIC_REGISTRATION` says.
    pub signup: Option<String>,
    /// `BROLLY_ACCOUNT_HOME`: where `/account/profile` and `/account/delete`
    /// send a member. The front end owns the profile and the account's end.
    pub account_home: Option<String>,
}

/// Validate a front-end URL: absolute, `http` or `https`, with a host.
/// Returned as the URL parser normalizes it.
///
/// Unlike [`parse_www_redirect`] nothing is appended to it, so a query is
/// allowed and kept.
pub fn parse_front_end_url(value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|e| format!("not a URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme must be http or https, not {}",
            url.scheme()
        ));
    }
    if url.host_str().is_none() {
        return Err("no host".into());
    }
    Ok(url.to_string())
}
```

In `AppState`, directly after the `www_redirect` field:

```rust
    /// The app in front of this instance, if there is one. See [`FrontEnd`].
    pub front_end: FrontEnd,
```

- [ ] **Step 4: Build the field in `main.rs`**

In `server/src/main.rs`, in the `AppState { … }` literal directly after the `www_redirect: …,` field:

```rust
        // The app in front of this instance, if any. Each URL validated here,
        // so a typo stops the start with the value in the log.
        front_end: brolly_server::FrontEnd {
            home: front_end_url("BROLLY_HOME_URL")?,
            signup: front_end_url("BROLLY_SIGNUP_URL")?,
            account_home: front_end_url("BROLLY_ACCOUNT_HOME")?,
        },
```

At the bottom of `server/src/main.rs`:

```rust
/// One of the front end's URLs: unset or empty is `None`; set and unusable
/// stops the start.
fn front_end_url(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Ok(value) = std::env::var(name) else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    match brolly_server::parse_front_end_url(value.trim()) {
        Ok(url) => Ok(Some(url)),
        Err(reason) => {
            tracing::error!(variable = name, value = %value, reason = %reason, "not a usable front-end URL");
            Err(reason.into())
        }
    }
}
```

- [ ] **Step 5: Add the field to every test literal**

Every test builds `AppState` literally, and each literal has exactly one `public_registration` field line: `public_registration: false,`, or the shorthand `public_registration,` in `auth_flow.rs`. (`auth_flow.rs` also has two `public_registration: bool,` *parameters*; those must not change.) Insert the new field after each field line, same indentation:

```bash
perl -pi -e 's/^(\s*)(public_registration(?:: false)?,)$/$1$2\n$1front_end: brolly_server::FrontEnd::default(),/' server/tests/*.rs
grep -c "front_end: brolly_server::FrontEnd::default()" server/tests/*.rs | grep -v ':0'
grep -n -A1 "public_registration: bool," server/tests/auth_flow.rs
```

Expected: the second command lists 15 files, `solid_oidc_flow.rs` with `2` and the rest with `1` (16 literals). The third shows each `public_registration: bool,` followed by its own next line, not by `front_end`.

- [ ] **Step 6: Run the unit tests and the whole suite**

Run: `cargo test -p brolly-server --lib front_end_tests > /tmp/t.log 2>&1 && tail -5 /tmp/t.log`
Expected: 3 passed.

Run: `cargo test --workspace > /tmp/all.log 2>&1 && echo GREEN`
Expected: `GREEN`. If it isn't printed, `grep -E "^test .*FAILED|panicked" /tmp/all.log` names the failure.

### Task 1.2: The homepage and the register page hand off

**Files:**
- Create: `server/tests/front_end.rs`
- Modify: `server/src/auth.rs` (new `home` handler; early returns in `register_form` and `register_submit`)
- Modify: `server/src/lib.rs` (`/` routes to `auth::home`; the `accounts` router is empty when signup is delegated)

- [ ] **Step 1: Write the failing tests**

Create `server/tests/front_end.rs`:

```rust
//! An app in front of the instance (`FrontEnd`): the pages it takes over
//! redirect to it, and with nothing configured every page is brolly's own.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, FrontEnd, app};
use http_body_util::BodyExt;
use tower::ServiceExt;

const SESSION_COOKIE: &str = brolly_identity::extract::SESSION_COOKIE;
const HOME: &str = "https://stuccoid.example.org/";
const SIGNUP: &str = "https://stuccoid.example.org/account/create";
const ACCOUNT_HOME: &str = "https://stuccoid.example.org/profile";

fn fronted() -> FrontEnd {
    FrontEnd {
        home: Some(HOME.into()),
        signup: Some(SIGNUP.into()),
        account_home: Some(ACCOUNT_HOME.into()),
    }
}

async fn harness(
    public_registration: bool,
    front_end: FrontEnd,
) -> (brolly_test_support::TestDb, tempfile::TempDir, axum::Router) {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().expect("tempdir");
    let state = AppState {
        pool: db.pool.clone(),
        base_domain: "brolly.test".into(),
        instance_name: "brolly.test".to_string(),
        instance_description: "A private community server.".to_string(),
        source_url: brolly_server::SOURCE_URL_DEFAULT.to_string(),
        terms_url: None,
        privacy_url: None,
        theme_css: false,
        public_registration,
        front_end,
        limiter: std::sync::Arc::new(brolly_server::ratelimit::Limiter::new()),
        www_redirect: None,
        max_upload_bytes: brolly_domain::media::MAX_UPLOAD_BYTES,
        pod_quota_bytes: brolly_domain::media::DEFAULT_POD_QUOTA_BYTES,
        stores: std::sync::Arc::new(
            brolly_store::StoreManager::open(dir.path(), 4, 60).expect("stores"),
        ),
        provider_key: std::sync::Arc::new(
            brolly_solid::oidc::store::load_or_create_key(&db.pool)
                .await
                .expect("provider key"),
        ),
        instance_actor: std::sync::Arc::new(
            brolly_identity::instance::load_or_create(&db.pool, brolly_activitypub::keys::generate)
                .await
                .expect("instance actor"),
        ),
        commits: tokio::sync::broadcast::channel(64).0,
        plc_client: None,
        clients: std::sync::Arc::new(brolly_server::client_metadata::StaticClients::default()),
        solid_clients: std::sync::Arc::new(
            brolly_server::client_metadata::StaticClientDocuments::default(),
        ),
        issuer_discovery: std::sync::Arc::new(
            brolly_server::client_metadata::StaticDocuments::default(),
        ),
        issuer_jwks: std::sync::Arc::new(brolly_server::client_metadata::StaticDocuments::default()),
        webid_documents: std::sync::Arc::new(
            brolly_server::client_metadata::StaticDocuments::default(),
        ),
    };
    let router = app(state, "server/static");
    (db, dir, router)
}

/// Status, `Location`, body.
async fn send(router: &axum::Router, request: Request<Body>) -> (StatusCode, Option<String>, String) {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .to_string();
    (status, location, body)
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().uri(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::empty()).unwrap()
}

fn post_form(path: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

fn post_json(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A member with a live session, made directly: these tests are about where
/// the pages send people, not about the door.
async fn signed_in(db: &brolly_test_support::TestDb, username: &str) -> String {
    let user = db::create_user(
        &db.pool,
        username,
        Some(&format!("{username}@example.org")),
        "correct-horse-battery",
        "member",
    )
    .await
    .unwrap();
    let token = db::create_session(&db.pool, user.id, time::Duration::days(1), None)
        .await
        .unwrap();
    format!("{SESSION_COOKIE}={token}")
}

#[tokio::test]
async fn with_no_front_end_every_page_is_brollys_own() {
    let (_db, _dir, router) = harness(true, FrontEnd::default()).await;

    let (status, _, body) = send(&router, get("/", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("name=\"password\""), "the login form: {body}");

    let (status, _, _) = send(&router, get("/register", None)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = send(
        &router,
        post_json("/api/accounts", r#"{"username":"alice","password":"correct-horse-battery"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "got: {body}");
}

#[tokio::test]
async fn the_homepage_hands_off_and_login_stays() {
    let (_db, _dir, router) = harness(false, fronted()).await;

    let (status, location, _) = send(&router, get("/", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some(HOME));

    // Every OAuth flow sends an anonymous visitor to /login; it must render.
    let (status, _, body) = send(&router, get("/login", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("name=\"password\""), "got: {body}");
}

#[tokio::test]
async fn the_register_page_hands_off_and_creates_nobody() {
    let (db, _dir, router) = harness(true, fronted()).await;

    let (status, location, _) = send(&router, get("/register", None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some(SIGNUP));

    let (status, location, _) = send(
        &router,
        post_form("/register", "username=alice&email=&password=correct-horse-battery", None),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some(SIGNUP));
    assert!(
        db::find_by_username(&db.pool, "alice").await.unwrap().is_none(),
        "a delegated door creates nobody"
    );
}

/// Delegated signup closes the public API even on a public instance: the
/// front end is the only way in, so its records see every account.
#[tokio::test]
async fn delegated_signup_closes_the_public_api() {
    let (db, _dir, router) = harness(true, fronted()).await;

    let (status, _, body) = send(
        &router,
        post_json("/api/accounts", r#"{"username":"alice","password":"correct-horse-battery"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "got: {body}");
    assert!(db::find_by_username(&db.pool, "alice").await.unwrap().is_none());
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-server --test front_end > /tmp/t.log 2>&1; grep -E "^test |test result" /tmp/t.log`
Expected: `with_no_front_end_every_page_is_brollys_own` passes; the other three fail (200 instead of 303; 201 instead of 404).

If `time` is not resolvable from the test crate, check `server/Cargo.toml`: it is a normal dependency of `brolly-server` (auth.rs uses `time::Duration`), and integration tests can use the package's normal dependencies.

- [ ] **Step 3: The `home` handler**

In `server/src/auth.rs`, directly after `login_form`:

```rust
/// `GET /` on the apex.
///
/// With a front end (`BROLLY_HOME_URL`) the homepage is the front end's, so a
/// visitor — and anyone logging out, or finishing an account deletion, both of
/// which land here — is sent there. Without one, `/` is the login form.
pub async fn home(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Query<Next>,
) -> Response {
    if let Some(home) = state.front_end.home.as_deref() {
        return Redirect::to(home).into_response();
    }
    login_form(State(state), headers, query).await
}
```

- [ ] **Step 4: The register page hands off**

In `register_form`, as the first statement:

```rust
    if let Some(signup) = state.front_end.signup.as_deref() {
        return Redirect::to(signup).into_response();
    }
```

In `register_submit`, as the first statement (before the rate-limit gate, so a delegated door spends nothing):

```rust
    // A delegated door creates nobody here; the post goes where the form is.
    if let Some(signup) = state.front_end.signup.as_deref() {
        return Redirect::to(signup).into_response();
    }
```

- [ ] **Step 5: Route `/` to `home`; unmount the public API when delegated**

In `server/src/lib.rs` `app()`, replace the `accounts` router with:

```rust
    // Account creation as an API, for a signup surface on another origin. The
    // same `apex_only` guard for the same reason as the OAuth surface: a
    // member's subdomain is their pod, and an instance-level endpoint does not
    // answer there (ADR 0009). Not mounted at all when a front end owns
    // signup (`BROLLY_SIGNUP_URL`): it creates accounts through the service
    // API, and a second public door would create accounts it never sees.
    let accounts = if state.front_end.signup.is_some() {
        Router::new()
    } else {
        Router::new()
            .route("/api/accounts", post(auth::create_account))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                solid_oidc::apex_only,
            ))
    };
```

And in the `/` route, replace `get(auth::login_form)` with `get(auth::home)`. Update the comment above it: "`/` and `/login` are one template on two routes" becomes "`/` is the login form, or the front end's homepage when there is one (`auth::home`); `/login` is always the form."

- [ ] **Step 6: Run the tests**

Run: `cargo test -p brolly-server --test front_end > /tmp/t.log 2>&1; grep -E "^test |test result" /tmp/t.log`
Expected: 4 passed. With `/api/accounts` unmounted, the Mastodon catch-all `/api/{*rest}` (`mastodon_api::unmatched`) answers the POST with its JSON 404, which is what the test asserts.

### Task 1.3: The profile and delete pages hand off

**Files:**
- Modify: `server/src/account.rs` (`profile_form`, `profile_submit`, `delete_form`, `delete_account`)
- Modify: `server/tests/front_end.rs`

- [ ] **Step 1: Write the failing tests**

Append to `server/tests/front_end.rs`:

```rust
#[tokio::test]
async fn the_profile_and_delete_pages_hand_off() {
    let (db, _dir, router) = harness(false, fronted()).await;
    let cookie = signed_in(&db, "alice").await;

    for request in [
        get("/account/profile", Some(&cookie)),
        post_form("/account/profile", "display_name=Alice&bio=", Some(&cookie)),
        get("/account/delete", Some(&cookie)),
        post_form("/account/delete", "confirm=alice", Some(&cookie)),
    ] {
        let path = request.uri().to_string();
        let (status, location, _) = send(&router, request).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(location.as_deref(), Some(ACCOUNT_HOME), "{path}");
    }

    assert!(
        db::find_by_username(&db.pool, "alice").await.unwrap().is_some(),
        "the handed-off delete deleted nothing"
    );

    // The rest of the dashboard is still brolly's.
    let (status, _, _) = send(&router, get("/account/security", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn without_an_account_home_the_profile_page_is_brollys() {
    let (db, _dir, router) = harness(false, FrontEnd::default()).await;
    let cookie = signed_in(&db, "alice").await;

    let (status, _, _) = send(&router, get("/account/profile", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
}
```

The POST bodies match the handlers' forms (`ProfileForm { display_name, bio }`, `DeleteForm { confirm }`). The hand-off runs inside the handler, after the `Form` extractor, so a body the extractor rejects would answer 422 before the redirect.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-server --test front_end the_profile > /tmp/t.log 2>&1; grep -E "^test |test result" /tmp/t.log`
Expected: FAIL, 200 instead of 303 on `/account/profile`.

- [ ] **Step 3: Add the hand-off**

In `server/src/account.rs`, add one helper above the profile section:

```rust
/// The front end's account page, when it owns the profile and the account's
/// end (`BROLLY_ACCOUNT_HOME`). Checked before the session: the front end
/// has its own login, and a member sent there signed out is still where they
/// should be.
fn handed_off(state: &AppState) -> Option<Response> {
    state
        .front_end
        .account_home
        .as_deref()
        .map(|home| Redirect::to(home).into_response())
}
```

Then make this the first statement of `profile_form`, `profile_submit`, `delete_form` and `delete_account`:

```rust
    if let Some(response) = handed_off(&state) {
        return response;
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p brolly-server --test front_end > /tmp/t.log 2>&1; grep -E "^test |test result" /tmp/t.log`
Expected: 6 passed.

### Task 1.4: Document, verify, commit

**Files:**
- Modify: `docs/deploying.md` (three rows in the env table after `BROLLY_WWW_REDIRECT`; one section after `### BROLLY_WWW_REDIRECT`)

- [ ] **Step 1: Document the variables**

Env table rows:

```markdown
| `BROLLY_HOME_URL` | no | — | An app in front of the instance: the apex `/` redirects there instead of showing the login form. `/login` still renders. |
| `BROLLY_SIGNUP_URL` | no | — | `/register` redirects there, and the public `POST /api/accounts` is not mounted, whatever `BROLLY_PUBLIC_REGISTRATION` says. Accounts come from the service API. |
| `BROLLY_ACCOUNT_HOME` | no | — | `/account/profile` and `/account/delete` redirect there. |
```

Section:

```markdown
### An app in front: `BROLLY_HOME_URL`, `BROLLY_SIGNUP_URL`, `BROLLY_ACCOUNT_HOME`

For a deployment whose public face is another app — StuccoID in front of
`id.stucco.software`. Each variable hands one of brolly's pages to that app;
unset, brolly serves the page itself. brolly keeps login, consent, security,
connected apps and export. Each value must be an absolute `http(s)` URL, or
the server refuses to start.

Set `BROLLY_SIGNUP_URL` only once the front end can create accounts through
the service API (`BROLLY_SERVICE_TOKEN`), or nobody can sign up. On a new
instance, register the first admin with the bootstrap invite *before*
setting it: once it is set, `/register` redirects and the public
`POST /api/accounts` is gone, so the invite has nowhere to be redeemed.
```

- [ ] **Step 2: Run every check the hook runs, then the suite**

```bash
cargo fmt --all && \
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1 && \
./tools/check-doc-paths.sh && \
cargo test --workspace > /tmp/all.log 2>&1 && echo ALL-GREEN
```

Expected: `ALL-GREEN`. On failure read `/tmp/clippy.log` or `/tmp/all.log`.

- [ ] **Step 3: Commit and push**

```bash
git add server/src/lib.rs server/src/main.rs server/src/auth.rs server/src/account.rs \
        server/tests/*.rs docs/deploying.md docs/plans/2026-11-10-stuccoid-front-end.md
git status --short   # should print nothing: this plan rides in with chunk 1
git commit -m "feat(server): an app in front of the instance takes the homepage, signup and account pages

BROLLY_HOME_URL, BROLLY_SIGNUP_URL and BROLLY_ACCOUNT_HOME hand the apex
homepage, /register, and the profile and delete pages to another app, so
StuccoID can be the face of id.stucco.software while brolly keeps login,
consent and the pods. Delegated signup also unmounts the public
POST /api/accounts: a second public door would create accounts the front
end never sees. Unset, every page is brolly's own.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main
```

Production sets none of the three variables, so this deploy changes nothing live.

---

## Chunk 2: One email, any case

`Alice@Example.org` and `alice@example.org` are one address. Password reset (piece 4) finds members by email, and StuccoID signs people up by email, so the store must agree.

Approach: store emails lowercased (by Postgres's `lower()`, on write and on lookup, so Rust and SQL never disagree about Unicode), and add a `CHECK` that every stored email is lowercase. The existing `users_email_key` unique constraint then is case-insensitive, and `create_user`'s constraint-name mapping keeps working unchanged.

### Task 2.1: Pre-flight on production

- [ ] **Step 1: Check production for emails that differ only by case**

The migration's `UPDATE` fails on `users_email_key` if two rows collide once lowercased, and a failed migration stops the server from starting. Ask the user to run this against the `stucco-id` Postgres (Railway → Postgres → Query), or run it yourself if you have the connection string:

```sql
SELECT lower(email), count(*) FROM users
 WHERE email IS NOT NULL GROUP BY lower(email) HAVING count(*) > 1;
```

Expected: no rows. If there are rows, stop and ask the user which account keeps the address before going further.

### Task 2.2: Migration and queries

**Files:**
- Create: `migrations/20261110000001_identity_lowercase_email.sql`
- Modify: `identity/src/db.rs` (`create_user`, `find_by_email`)
- Test: `identity/tests/persistence.rs`

- [ ] **Step 1: Write the failing tests**

Append to `identity/tests/persistence.rs`:

```rust
/// One address in any case: stored lowercased, found in any case, and a
/// second account cannot take it by changing the case.
#[tokio::test]
async fn an_email_is_one_address_in_any_case() {
    let (_db, pool) = fresh().await;
    let alice = db::create_user(&pool, "alice", Some("Alice@Example.ORG"), "correct-horse-battery", "member")
        .await
        .unwrap();
    assert_eq!(alice.email.as_deref(), Some("alice@example.org"));

    let found = db::find_by_email(&pool, "ALICE@example.org")
        .await
        .unwrap()
        .expect("found in another case");
    assert_eq!(found.id, alice.id);

    let second = db::create_user(&pool, "bob", Some("alice@EXAMPLE.org"), "correct-horse-battery", "member").await;
    assert!(matches!(second, Err(DbError::EmailTaken)), "got {second:?}");
}

/// The database holds the rule, not just the Rust that writes today.
#[tokio::test]
async fn the_database_refuses_a_mixed_case_email() {
    let (_db, pool) = fresh().await;
    let refused = sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role)
         VALUES (gen_random_uuid(), 'carol', 'Carol@example.org', 'x', 'member')",
    )
    .execute(&pool)
    .await;
    assert!(refused.is_err(), "a mixed-case email was stored");
}
```

If `gen_random_uuid()` is unavailable on the test Postgres (it is built in from Postgres 13), bind a `uuid::Uuid::new_v4()` instead.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-identity --test persistence email > /tmp/t.log 2>&1; grep -E "^test |test result" /tmp/t.log`
Expected: both FAIL (the email comes back as typed; the mixed-case insert succeeds).

- [ ] **Step 3: Write the migration**

Create `migrations/20261110000001_identity_lowercase_email.sql`:

```sql
-- One address in any case. Emails are stored lowercased, by Postgres's own
-- lower() on every write and lookup, so the existing users_email_key is
-- case-insensitive in effect. The CHECK holds the rule in the database, not
-- only in the code that writes today. Existing rows are lowercased first; a
-- pair that collides once lowercased fails here, loudly, rather than
-- silently keeping two accounts for one address.
UPDATE users SET email = lower(email)
 WHERE email IS NOT NULL AND email <> lower(email);

ALTER TABLE users
    ADD CONSTRAINT users_email_lowercase CHECK (email = lower(email));
```

- [ ] **Step 4: Lowercase on write and on lookup**

In `identity/src/db.rs` `create_user`, change the `VALUES` line to:

```rust
         VALUES ($1, $2, lower($3), $4, $5)
```

In `find_by_email`, change the query to:

```rust
    let sql = format!(
        "SELECT {} FROM users WHERE email = lower($1)",
        user_columns("")
    );
```

and add to its doc comment: "Any case: emails are stored lowercased (migration `identity_lowercase_email`)."

- [ ] **Step 5: Make sure the migration is embedded**

`sqlx::migrate!()` embeds the directory at compile time; `identity/build.rs` exists to re-run it when the directory changes. Run: `cargo test -p brolly-identity --test persistence migrations_apply_cleanly > /tmp/t.log 2>&1; grep "test result" /tmp/t.log`
Expected: 1 passed. If it fails with `VersionMissing`, `touch identity/src/db.rs` and rerun.

- [ ] **Step 6: Run the tests, then everything**

Run: `cargo test -p brolly-identity --test persistence > /tmp/t.log 2>&1; grep "test result" /tmp/t.log`
Expected: all pass.

```bash
cargo fmt --all && \
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1 && \
./tools/check-doc-paths.sh && \
cargo test --workspace > /tmp/all.log 2>&1 && echo ALL-GREEN
```

Expected: `ALL-GREEN`. A test elsewhere that registers `Alice@…` and asserts the stored case would fail here. Fix the test's expectation (the address is now lowercase); do not weaken the migration.

- [ ] **Step 7: Commit and push**

```bash
git add migrations/20261110000001_identity_lowercase_email.sql identity/src/db.rs identity/tests/persistence.rs
git commit -m "feat(identity): an email is one address in any case

Stored lowercased, by Postgres's lower() on write and lookup, with a CHECK
holding the rule. users_email_key is then case-insensitive in effect, so
Alice@Example.org cannot open a second account beside alice@example.org,
and password reset (which finds members by email) finds them whatever
they type. The legacy createSession lookup by email (xrpc) becomes
case-insensitive with it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main
```

After the deploy finishes, check the service logs on Railway for a clean start (the migration ran) and that `https://id.stucco.software/health` answers `{"status":"ok"}`.

---

## Chunk 3: The cores the service API reuses (no behaviour change)

Three refactors, so chunk 4 adds endpoints without copying logic: who may create an account without an invite, which usernames are reserved, and what deleting an account does.

### Task 3.1: `Admission` — how a member came in

Only the `Door` variant lands in this chunk. `Service` arrives in Task 4.3 together with the code that constructs it; added here, rustc's "variant never constructed" warning would fail clippy's `-D warnings` and this commit would not be green.

**Files:**
- Modify: `server/src/auth.rs` (`create_member` and its two callers)

- [ ] **Step 1: Add the type**

Above `create_member`:

```rust
/// How a would-be member came in, which decides whether an invite is needed.
pub(crate) enum Admission<'a> {
    /// The `/register` form or the public `POST /api/accounts`: the
    /// deployment's invite policy applies (`BROLLY_PUBLIC_REGISTRATION`).
    Door { invite: Option<&'a str> },
}
```

- [ ] **Step 2: Thread it through `create_member`**

Change the signature's last parameter from `invite: Option<&str>` to `admission: Admission<'_>`, and make `create_member` `pub(crate)`. Directly above the existing `let role = match (state.public_registration, invite) { … };` block, add:

```rust
    let Admission::Door { invite } = admission;
```

Leave the `let role = …` block itself unchanged. Task 4.3 replaces both lines.

- [ ] **Step 3: Update both callers**

In `register_submit`: `create_member(&state, &form.username, email, &form.password, Admission::Door { invite })`.
In `create_account`: `create_member(&state, &request.username, email, &request.password, Admission::Door { invite })`.

- [ ] **Step 4: Build and run the door's tests**

Run: `cargo test -p brolly-server --test auth_flow > /tmp/t.log 2>&1; grep "test result" /tmp/t.log`
Expected: all pass (no behaviour change).

### Task 3.2: The reserved list is a module constant

**Files:**
- Modify: `server/src/auth.rs` (`validate_username`)

- [ ] **Step 1: Move the list**

Move the `const RESERVED: &[&str] = &[ … ];` out of `validate_username` to module level, renamed `RESERVED_USERNAMES`, keeping its comment. Add:

```rust
/// Whether `username` is one nobody may take. The username check in the
/// service API answers `reserved` rather than `invalid` for these.
pub(crate) fn is_reserved_username(username: &str) -> bool {
    RESERVED_USERNAMES.contains(&username)
}
```

In `validate_username`, replace `if RESERVED.contains(&username)` with `if is_reserved_username(username)`, and make `validate_username` `pub(crate)`.

- [ ] **Step 2: Build**

Run: `cargo build -p brolly-server > /tmp/b.log 2>&1 && echo OK`
Expected: `OK`.

### Task 3.3: `provision::delete_account`

**Files:**
- Modify: `server/src/provision.rs` (new fn at the bottom)
- Modify: `server/src/account.rs` (`delete_account` handler calls it)

- [ ] **Step 1: Move the core**

Append to `server/src/provision.rs`:

```rust
/// Deleting a member failed. What failed is already in the log.
#[derive(Debug)]
pub struct DeletionFailed;

/// Delete a member and everything their account is: the pod, the user row
/// (sessions and tokens cascade with it) and, for a member with a DID, the
/// `#account` event that tells the network.
///
/// The pod goes first. If the user row went first and the `rm -rf` then
/// failed, the bytes would be left with nothing pointing at them and no
/// account able to ask for them again.
///
/// Shared by the dashboard's delete page and the service API's
/// `DELETE /internal/v1/accounts/{username}`.
pub async fn delete_account(
    pool: &PgPool,
    stores: &brolly_store::StoreManager,
    commits: &tokio::sync::broadcast::Sender<brolly_atproto::firehose::Event>,
    user: &db::User,
) -> Result<(), DeletionFailed> {
    if let Err(e) = stores.delete_pod(user.id) {
        tracing::error!(error = %e, user = %user.id, "deleting the pod failed");
        return Err(DeletionFailed);
    }

    // The user row and the `#account` event land in one transaction (1, E):
    // an event for a deletion that did not happen makes a relay drop a live
    // repo, and a deletion without its event leaves the network serving a
    // deleted one. The pod is already gone either way — `rm -rf` is not
    // transactional — so the transaction covers what can be covered.
    //
    // Only a member with a DID announces: an account that never finished
    // provisioning has no identity the network ever learned, and an event a
    // consumer cannot resolve is noise.
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "the deletion could not begin");
            return Err(DeletionFailed);
        }
    };
    if let Err(e) = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(error = %e, user = %user.id, "deleting the user failed");
        return Err(DeletionFailed);
    }
    let account_event = match user.did_plc.as_deref() {
        Some(did) => {
            match brolly_atproto::firehose::record_account(&mut tx, did, false, Some("deleted"))
                .await
            {
                Ok(event) => Some(event),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        user = %user.id,
                        "recording the deletion's firehose event failed"
                    );
                    return Err(DeletionFailed);
                }
            }
        }
        None => None,
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, user = %user.id, "the deletion could not commit");
        return Err(DeletionFailed);
    }
    if let Some(event) = account_event {
        // The fast path (1, G): the transactional notify that rode the deletion
        // above is what the shared listener turns into a rebroadcast, so this
        // send is latency, not correctness. `send` fails only when nobody is
        // listening, which is normal.
        let _ = commits.send(brolly_atproto::firehose::Event::Account(event));
    }
    tracing::info!(user = %user.id, "account deleted");
    Ok(())
}
```

This is `account::delete_account`'s body from `state.stores.delete_pod` to the `tracing::info!` line, re-pointed at the parameters. Before deleting the original, diff the two by eye against `server/src/account.rs` in case it changed after this plan was written. The handler's doc comment paragraph "The pod goes first. …" now lives on this function; delete it from the handler.

- [ ] **Step 2: Call it from the handler**

In `server/src/account.rs` `delete_account`, replace the moved block with:

```rust
    if crate::provision::delete_account(&state.pool, &state.stores, &state.commits, &session.user)
        .await
        .is_err()
    {
        return server_error();
    }
```

leaving the handler's final cookie-clearing redirect in place. Remove imports `account.rs` no longer uses (clippy will name them).

- [ ] **Step 3: Run the suite and commit**

```bash
cargo fmt --all && \
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1 && \
./tools/check-doc-paths.sh && \
cargo test --workspace > /tmp/all.log 2>&1 && echo ALL-GREEN
```

Expected: `ALL-GREEN`. The dashboard's delete tests (`server/tests/dashboard.rs`) are what prove the move kept behaviour.

```bash
git add server/src/auth.rs server/src/provision.rs server/src/account.rs
git commit -m "refactor(server): admission, the reserved list and deletion as shared cores

The service API (next) creates members without an invite, answers whether
a username is reserved, and deletes accounts. Each of those lived inside
an HTML handler; they are now Admission, is_reserved_username and
provision::delete_account, so the API reuses them rather than copying.
No behaviour change.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main
```

---

## Chunk 4: The service API

`/internal/v1/`, apex-only, mounted only when `BROLLY_SERVICE_TOKEN` is set, every call carrying `Authorization: Bearer <token>`.

| Method | Path | Body | Success | Errors |
|---|---|---|---|---|
| `POST` | `/accounts` | `{username, email, password}` | `201 {username, email, webId, storage}` | `409 {error: "username_taken" \| "email_taken"}`, `422 {error: "validation", field, reason}` |
| `GET` | `/usernames/{username}` | — | `200 {available: true}` or `{available: false, reason: "reserved" \| "invalid" \| "taken"}` | — |
| `GET` | `/accounts?webId=` | — | `200 {username, email, webId, storage}` | `404` |
| `POST` | `/accounts/{username}/verify-password` | `{password}` | `204` | `401`; `429` past 10 attempts per username per 15 min |
| `DELETE` | `/accounts/{username}` | — | `204` | `404` |

A body that is not readable JSON with the expected fields answers `422 {error: "validation", field: "body", reason}`. Every endpoint answers `401 {error: "unauthorized"}` without the right token, and `404` on a member's subdomain or when no token is configured. The service is not held by the `Signup` gate: every StuccoID signup comes from the same few Vercel addresses, and StuccoID rate-limits its own forms.

### Task 4.1: The token

**Files:**
- Modify: `server/src/lib.rs` (`FrontEnd` gains `service_token_hash`)
- Modify: `server/src/main.rs`

- [ ] **Step 1: Add the field**

In `FrontEnd`:

```rust
    /// `BROLLY_SERVICE_TOKEN`, hashed (`db::hash_secret`): the front end's
    /// credential for the service API. Unset, the API is not mounted.
    pub service_token_hash: Option<String>,
```

Add `assert!(front_end.service_token_hash.is_none());` to `the_default_front_end_is_brolly_itself`, and `..FrontEnd::default()` to `fronted()` in `server/tests/front_end.rs`.

- [ ] **Step 2: Read it in `main.rs`**

In the `front_end: brolly_server::FrontEnd { … }` literal add:

```rust
            service_token_hash: service_token_hash()?,
```

At the bottom of `main.rs`:

```rust
/// `BROLLY_SERVICE_TOKEN`, hashed for comparison. A short token stops the
/// start: it guards account creation and deletion, so it must not be
/// guessable. `openssl rand -hex 32` makes a good one.
fn service_token_hash() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Ok(token) = std::env::var("BROLLY_SERVICE_TOKEN") else {
        return Ok(None);
    };
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if token.len() < 32 {
        tracing::error!("BROLLY_SERVICE_TOKEN is shorter than 32 characters");
        return Err("BROLLY_SERVICE_TOKEN is shorter than 32 characters".into());
    }
    Ok(Some(brolly_identity::db::hash_secret(token)))
}
```

- [ ] **Step 3: Build**

Run: `cargo build --workspace --all-targets > /tmp/b.log 2>&1 && echo OK`
Expected: `OK`.

### Task 4.2: Tests for the whole API

**Files:**
- Create: `server/tests/internal_api.rs`

- [ ] **Step 1: Write the failing tests**

Create `server/tests/internal_api.rs`, opening with:

```rust
//! The service API (`/internal/v1/`): what an app in front of the instance
//! runs the account lifecycle through.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brolly_identity::db;
use brolly_server::{AppState, FrontEnd, app};
use http_body_util::BodyExt;
use tower::ServiceExt;
```

Then copy `harness` and `send` from `server/tests/front_end.rs`, changing `harness`'s signature to take only the token:

```rust
async fn harness(
    token: Option<&str>,
) -> (brolly_test_support::TestDb, tempfile::TempDir, axum::Router) {
```

and, in its `AppState` literal, these two fields in place of `public_registration,` and `front_end,`:

```rust
        // Invite-only on purpose: the service must not need an open door.
        public_registration: false,
        front_end: FrontEnd {
            service_token_hash: token.map(db::hash_secret),
            ..FrontEnd::default()
        },
```

Then:

```rust
const TOKEN: &str = "0123456789abcdef0123456789abcdef-service";

fn call(method: &str, path: &str, body: Option<&str>) -> Request<Body> {
    call_as(method, path, body, Some(TOKEN), None, None)
}

fn call_as(
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
    host: Option<&str>,
    forwarded_for: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(host) = host {
        request = request.header(header::HOST, host);
    }
    if let Some(ip) = forwarded_for {
        request = request.header("x-forwarded-for", ip);
    }
    match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    }
}

fn alice() -> &'static str {
    r#"{"username":"alice","email":"alice@example.org","password":"correct-horse-battery"}"#
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

#[tokio::test]
async fn without_a_token_configured_the_api_does_not_exist() {
    let (_db, _dir, router) = harness(None).await;
    let (status, _, _) = send(&router, call("POST", "/internal/v1/accounts", Some(alice()))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_missing_or_wrong_token_is_refused() {
    let (db, _dir, router) = harness(Some(TOKEN)).await;
    for token in [None, Some("not-the-token"), Some("")] {
        let (status, _, body) = send(
            &router,
            call_as("POST", "/internal/v1/accounts", Some(alice()), token, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
        assert_eq!(json(&body)["error"], "unauthorized");
    }
    assert!(db::find_by_username(&db.pool, "alice").await.unwrap().is_none());
}

#[tokio::test]
async fn a_members_subdomain_has_no_service_api() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    let (status, _, _) = send(
        &router,
        call_as("GET", "/internal/v1/usernames/bob", None, Some(TOKEN), Some("alice.brolly.test"), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_service_creates_a_member_on_an_invite_only_instance() {
    let (db, _dir, router) = harness(Some(TOKEN)).await;

    let (status, _, body) = send(&router, call("POST", "/internal/v1/accounts", Some(alice()))).await;
    assert_eq!(status, StatusCode::CREATED, "got: {body}");
    let body = json(&body);
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.org");
    assert_eq!(body["webId"], "https://alice.brolly.test/profile#me");
    assert_eq!(body["storage"], "https://alice.brolly.test/~/");

    let alice = db::find_by_username(&db.pool, "alice").await.unwrap().expect("created");
    assert_eq!(alice.role, "member");
    // The whole member: the login works.
    db::authenticate(&db.pool, "alice", "correct-horse-battery").await.unwrap();
}

#[tokio::test]
async fn creation_names_what_is_wrong() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    let (status, _, _) = send(&router, call("POST", "/internal/v1/accounts", Some(alice()))).await;
    assert_eq!(status, StatusCode::CREATED);

    for (request, status, expected) in [
        (
            r#"{"username":"alice","email":"other@example.org","password":"correct-horse-battery"}"#,
            StatusCode::CONFLICT,
            serde_json::json!({"error": "username_taken"}),
        ),
        (
            r#"{"username":"alice2","email":"ALICE@example.org","password":"correct-horse-battery"}"#,
            StatusCode::CONFLICT,
            serde_json::json!({"error": "email_taken"}),
        ),
    ] {
        let (got, _, body) = send(&router, call("POST", "/internal/v1/accounts", Some(request))).await;
        assert_eq!(got, status, "{request}");
        assert_eq!(json(&body), expected, "{request}");
    }

    for (request, field) in [
        (r#"{"username":"bob","email":"bob@example.org","password":"short"}"#, "password"),
        (r#"{"username":"-bob","email":"bob@example.org","password":"correct-horse-battery"}"#, "username"),
        (r#"{"username":"admin","email":"bob@example.org","password":"correct-horse-battery"}"#, "username"),
        (r#"{"username":"bob","email":"  ","password":"correct-horse-battery"}"#, "email"),
        (r#"{"username":"bob"}"#, "body"),
    ] {
        let (got, _, body) = send(&router, call("POST", "/internal/v1/accounts", Some(request))).await;
        assert_eq!(got, StatusCode::UNPROCESSABLE_ENTITY, "{request}");
        let body = json(&body);
        assert_eq!(body["error"], "validation", "{request}");
        assert_eq!(body["field"], field, "{request}");
        assert!(body["reason"].as_str().is_some_and(|r| !r.is_empty()), "{request}");
    }
}

/// Every StuccoID signup comes from the same few addresses. The door's
/// per-address gate (5 per 10 minutes) would stop the sixth person.
#[tokio::test]
async fn the_service_is_not_held_by_the_signup_gate() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    for i in 0..8 {
        let request = format!(
            r#"{{"username":"member{i}","email":"member{i}@example.org","password":"correct-horse-battery"}}"#
        );
        let (status, _, body) = send(
            &router,
            call_as("POST", "/internal/v1/accounts", Some(&request), Some(TOKEN), None, Some("203.0.113.7")),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "signup {i}: {body}");
    }
}

#[tokio::test]
async fn usernames_are_available_taken_reserved_or_invalid() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    send(&router, call("POST", "/internal/v1/accounts", Some(alice()))).await;

    for (username, expected) in [
        ("bob", serde_json::json!({"available": true})),
        ("alice", serde_json::json!({"available": false, "reason": "taken"})),
        ("admin", serde_json::json!({"available": false, "reason": "reserved"})),
        ("-bob", serde_json::json!({"available": false, "reason": "invalid"})),
        ("Bob", serde_json::json!({"available": false, "reason": "invalid"})),
    ] {
        let (status, _, body) =
            send(&router, call("GET", &format!("/internal/v1/usernames/{username}"), None)).await;
        assert_eq!(status, StatusCode::OK, "{username}");
        assert_eq!(json(&body), expected, "{username}");
    }
}

#[tokio::test]
async fn an_account_is_found_by_its_webid_and_nothing_else() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    send(&router, call("POST", "/internal/v1/accounts", Some(alice()))).await;

    let (status, _, body) = send(
        &router,
        call("GET", "/internal/v1/accounts?webId=https%3A%2F%2Falice.brolly.test%2Fprofile%23me", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    let body = json(&body);
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.org");

    for web_id in [
        "https%3A%2F%2Fbob.brolly.test%2Fprofile%23me",       // nobody
        "https%3A%2F%2Falice.elsewhere.test%2Fprofile%23me", // another instance
        "https%3A%2F%2Falice.brolly.test%2Fprofile%2Fcard%23me", // not a brolly WebID
        "https%3A%2F%2Fevil.alice.brolly.test%2Fprofile%23me",   // nested subdomain
    ] {
        let (status, _, _) =
            send(&router, call("GET", &format!("/internal/v1/accounts?webId={web_id}"), None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{web_id}");
    }
}

#[tokio::test]
async fn a_password_is_checked_and_guessing_is_limited() {
    let (_db, _dir, router) = harness(Some(TOKEN)).await;
    send(&router, call("POST", "/internal/v1/accounts", Some(alice()))).await;
    let check = |password: &str| {
        call(
            "POST",
            "/internal/v1/accounts/alice/verify-password",
            Some(&format!(r#"{{"password":"{password}"}}"#)),
        )
    };

    let (status, _, _) = send(&router, check("correct-horse-battery")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(&router, check("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Unknown members answer like wrong passwords.
    let (status, _, _) = send(
        &router,
        call("POST", "/internal/v1/accounts/nobody/verify-password", Some(r#"{"password":"x"}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Ten attempts per username per fifteen minutes; two are spent above.
    for _ in 0..8 {
        send(&router, check("wrong")).await;
    }
    let (status, _, _) = send(&router, check("correct-horse-battery")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_deleted_account_is_gone() {
    let (db, _dir, router) = harness(Some(TOKEN)).await;
    send(&router, call("POST", "/internal/v1/accounts", Some(alice()))).await;

    let (status, _, _) = send(&router, call("DELETE", "/internal/v1/accounts/alice", None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(db::find_by_username(&db.pool, "alice").await.unwrap().is_none());

    let (status, _, _) = send(&router, call("DELETE", "/internal/v1/accounts/alice", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The name is free again.
    let (_, _, body) = send(&router, call("GET", "/internal/v1/usernames/alice", None)).await;
    assert_eq!(json(&body), serde_json::json!({"available": true}));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p brolly-server --test internal_api > /tmp/t.log 2>&1; grep -E "^test |test result" /tmp/t.log`
Expected: `without_a_token_configured_the_api_does_not_exist` and `a_members_subdomain_has_no_service_api` pass (nothing is mounted yet); the rest FAIL with 404.

### Task 4.3: `internal_api.rs`

**Files:**
- Create: `server/src/internal_api.rs`
- Modify: `server/src/lib.rs` (`pub mod internal_api;`, mount it)
- Modify: `server/src/ratelimit.rs` (`Gate::ServicePassword`)
- Modify: `server/src/auth.rs` (`Admission::Service`)

- [ ] **Step 0: `Admission::Service`**

In `server/src/auth.rs`, add the second variant to `Admission`:

```rust
    /// The front end, through the service API. It holds the service token,
    /// which is a stronger credential than any invite, and it runs its own
    /// door; every member it creates is a plain member.
    Service,
```

Then replace the two lines Task 3.1 left, `let Admission::Door { invite } = admission;` and the `let role = match (state.public_registration, invite) { … };` block below it, with:

```rust
    let role = match admission {
        Admission::Service => crate::admin::MEMBER.to_string(),
        Admission::Door { invite } => match (state.public_registration, invite) {
            // Private and no invite: the door does not open.
            (false, None) => return Err(RegistrationError::InviteInvalid),
            // A presented invite is redeemed under either policy.
            (_, Some(code)) => match db::redeem_invite(&state.pool, code).await {
                Ok(granted) => granted.unwrap_or_else(|| crate::admin::MEMBER.to_string()),
                Err(_) => return Err(RegistrationError::InviteInvalid),
            },
            // Public and no invite: a plain member.
            (true, None) => crate::admin::MEMBER.to_string(),
        },
    };
```

Add one line to `create_member`'s doc comment: "The service API admits without an invite (`Admission::Service`)." The variant is constructed by `internal_api::create_account` below, so it compiles warning-free once Step 2 is in.

- [ ] **Step 1: The rate-limit gate**

In `server/src/ratelimit.rs` add to `Gate`:

```rust
    /// `POST /internal/v1/accounts/{username}/verify-password`, keyed by
    /// username: ten attempts per fifteen minutes, so the front end's delete
    /// page cannot be used to guess a member's password.
    ServicePassword,
```

with `Gate::ServicePassword => 10` in `burst` and `Gate::ServicePassword => Duration::from_secs(90)` in `refill_every` (one token every 90 s refills ten in fifteen minutes).

- [ ] **Step 2: Write the module**

Create `server/src/internal_api.rs`:

```rust
//! The service API: what an app in front of the instance (`FrontEnd`) needs
//! to run the account lifecycle — create, check a username, find by WebID,
//! check a password, delete.
//!
//! Under `/internal/v1/`, not `/api/`, which the Mastodon catch-all owns.
//! Apex-only (ADR 0009), and mounted only when `BROLLY_SERVICE_TOKEN` is set.
//! Every call carries `Authorization: Bearer <token>`. The header is parsed by
//! `extract::credential` in `brolly-identity`, the one place that parses
//! credentials (`tests/architecture.rs`); here the token is only hashed and
//! compared. No `Subject` is made: the caller is the front end, not a member.

use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use brolly_identity::db::{self, DbError, User};
use brolly_identity::subject::Credential;
use brolly_identity::{extract, routing, webid};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::auth::{Admission, RegistrationError, create_member, is_reserved_username, validate_username};
use crate::ratelimit::{Gate, too_many};

/// The routes, guarded. Mounted by `app()` only when a token is configured.
pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/internal/v1/accounts", post(create_account).get(find_account))
        .route("/internal/v1/accounts/{username}", delete(delete_account))
        .route(
            "/internal/v1/accounts/{username}/verify-password",
            post(verify_password),
        )
        .route("/internal/v1/usernames/{username}", get(username_availability))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_service,
        ))
        // Outermost, so a member's subdomain answers 404 before the token is
        // looked at: the API does not exist there.
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::solid_oidc::apex_only,
        ))
}

/// The front end's token, or 401.
async fn require_service(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    // Comparing hashes, not tokens: the stored value is the hash, and a
    // timing difference in comparing two SHA-256 digests says nothing useful
    // about the token.
    let presented = match extract::credential(authorization, None) {
        Some(Credential::Bearer(token)) => Some(db::hash_secret(&token)),
        _ => None,
    };
    match (presented, state.front_end.service_token_hash.as_deref()) {
        (Some(presented), Some(expected)) if presented == expected => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response(),
    }
}

/// What the front end learns about an account.
fn account(user: &User, base_domain: &str) -> serde_json::Value {
    json!({
        "username": user.username,
        "email": user.email,
        "webId": webid::webid(&user.username, base_domain),
        "storage": routing::storage_root(&user.username, base_domain),
    })
}

fn validation(field: &str, reason: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "error": "validation", "field": field, "reason": reason })),
    )
        .into_response()
}

/// A body axum could not read (not JSON, wrong content type, a field
/// missing) answers in the API's own shape, not axum's plain text, so the
/// front end can always parse the error.
fn unreadable(rejection: JsonRejection) -> Response {
    validation("body", &rejection.body_text())
}

fn conflict(error: &str) -> Response {
    (StatusCode::CONFLICT, Json(json!({ "error": error }))).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "server_error" })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct NewAccount {
    username: String,
    email: String,
    password: String,
}

/// `POST /internal/v1/accounts`
///
/// No invite (`Admission::Service`) and no `Signup` gate: the front end holds
/// the token, runs its own door, and sends every signup from the same few
/// addresses.
async fn create_account(
    State(state): State<AppState>,
    body: Result<Json<NewAccount>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return unreadable(rejection),
    };
    let email = body.email.trim();
    if email.is_empty() {
        return validation("email", "An email is required.");
    }
    match create_member(
        &state,
        &body.username,
        Some(email),
        &body.password,
        Admission::Service,
    )
    .await
    {
        Ok(user) => (StatusCode::CREATED, Json(account(&user, &state.base_domain))).into_response(),
        Err(RegistrationError::Username(reason)) => validation("username", &reason),
        Err(RegistrationError::PasswordShort) => {
            validation("password", "Use at least 12 characters.")
        }
        Err(RegistrationError::UsernameTaken) => conflict("username_taken"),
        Err(RegistrationError::EmailTaken) => conflict("email_taken"),
        // `Admission::Service` never asks for an invite, so this is a bug.
        Err(RegistrationError::InviteInvalid) | Err(RegistrationError::ServerError) => {
            server_error()
        }
    }
}

/// `GET /internal/v1/usernames/{username}`
async fn username_availability(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Response {
    let body = if validate_username(&username).is_err() {
        let reason = if is_reserved_username(&username) {
            "reserved"
        } else {
            "invalid"
        };
        json!({ "available": false, "reason": reason })
    } else {
        match db::find_by_username(&state.pool, &username).await {
            Ok(Some(_)) => json!({ "available": false, "reason": "taken" }),
            Ok(None) => json!({ "available": true }),
            Err(e) => {
                tracing::error!(error = %e, "username lookup failed");
                return server_error();
            }
        }
    };
    Json(body).into_response()
}

#[derive(Deserialize)]
pub struct ByWebId {
    #[serde(rename = "webId")]
    web_id: String,
}

/// The username a WebID of this instance names, or `None` for anything that
/// is not exactly `webid::webid(username, base)`.
fn username_for_webid(web_id: &str, base_domain: &str) -> Option<String> {
    let url = url::Url::parse(web_id).ok()?;
    let username = extract::subdomain_user(url.host_str()?, base_domain)?;
    (webid::webid(&username, base_domain) == web_id).then_some(username)
}

/// `GET /internal/v1/accounts?webId=`
async fn find_account(State(state): State<AppState>, Query(query): Query<ByWebId>) -> Response {
    let Some(username) = username_for_webid(&query.web_id, &state.base_domain) else {
        return not_found();
    };
    match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) => Json(account(&user, &state.base_domain)).into_response(),
        Ok(None) => not_found(),
        Err(e) => {
            tracing::error!(error = %e, "account lookup failed");
            server_error()
        }
    }
}

#[derive(Deserialize)]
pub struct PasswordCheck {
    password: String,
}

/// `POST /internal/v1/accounts/{username}/verify-password`
///
/// The front end's delete page asks for the password; this is that check.
/// Unknown members and wrong passwords answer alike (`db::authenticate`).
async fn verify_password(
    State(state): State<AppState>,
    Path(username): Path<String>,
    body: Result<Json<PasswordCheck>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return unreadable(rejection),
    };
    if let Err(wait) = state
        .limiter
        .check(Gate::ServicePassword, &format!("user:{}", username.to_lowercase()))
    {
        return too_many(wait);
    }
    match db::authenticate(&state.pool, &username, &body.password).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(DbError::BadCredentials) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "bad_credentials" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "password check failed");
            server_error()
        }
    }
}

/// `DELETE /internal/v1/accounts/{username}`
async fn delete_account(State(state): State<AppState>, Path(username): Path<String>) -> Response {
    let user = match db::find_by_username(&state.pool, &username).await {
        Ok(Some(user)) => user,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "account lookup failed before deletion");
            return server_error();
        }
    };
    match crate::provision::delete_account(&state.pool, &state.stores, &state.commits, &user).await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => server_error(),
    }
}
```

`RegistrationError` is already `pub(crate)`, and Tasks 3.1–3.2 made `create_member`, `validate_username` and `is_reserved_username` `pub(crate)`. `brolly_identity::subject::Credential` is public.

- [ ] **Step 3: Mount it**

In `server/src/lib.rs`: add `pub mod internal_api;` to the module list, and in `app()` after the `accounts` router:

```rust
    // The service API, for the app in front of the instance (`FrontEnd`).
    // Not mounted without a token: an unconfigured instance has no such API.
    let internal = if state.front_end.service_token_hash.is_some() {
        internal_api::routes(state.clone())
    } else {
        Router::new()
    };
```

and `.merge(internal)` directly after `.merge(accounts)`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p brolly-server --test internal_api > /tmp/t.log 2>&1; grep -E "^test |test result" /tmp/t.log`
Expected: 10 passed.

If `the_service_is_not_held_by_the_signup_gate` fails with 429, a gate is being spent on this path. `create_member` spends none; check that `auth::create_account`'s `Gate::Signup` check was not copied in.

### Task 4.4: Document, verify, commit

**Files:**
- Modify: `docs/deploying.md`

- [ ] **Step 1: Document**

Env table row:

```markdown
| `BROLLY_SERVICE_TOKEN` | no | — | Mounts the service API under `/internal/v1/` for an app in front of the instance. At least 32 characters (`openssl rand -hex 32`); shorter stops the start. |
```

Append to the front-end section from Task 1.4 a table of the five endpoints (copy the table at the top of this chunk), the `Authorization: Bearer` header, and one `curl`:

```
curl -H "Authorization: Bearer $BROLLY_SERVICE_TOKEN" \
  https://your-domain/internal/v1/usernames/alice
```

In the "Rate limits, and whose address they key on" table, add this row after the `POST /account/security` row:

```markdown
| `POST /internal/v1/accounts/{username}/verify-password` | the username | 10, then 90 s |
```

and one sentence under the table: "The service API's account creation is not gated: its caller holds the service token and sends every signup from the same few addresses."

- [ ] **Step 2: Every check, then commit and push**

```bash
cargo fmt --all && \
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1 && \
./tools/check-doc-paths.sh && \
cargo test --workspace > /tmp/all.log 2>&1 && echo ALL-GREEN
```

Expected: `ALL-GREEN`.

```bash
git add server/src/internal_api.rs server/src/lib.rs server/src/main.rs server/src/ratelimit.rs \
        server/src/auth.rs server/tests/internal_api.rs server/tests/front_end.rs docs/deploying.md
git commit -m "feat(server): the service API an app in front of the instance runs accounts through

Create (no invite, no per-address gate), check a username, find by WebID,
check a password (ten tries per username per fifteen minutes), delete.
Under /internal/v1/, apex-only, mounted only when BROLLY_SERVICE_TOKEN is
set, and every call carries that token. This is what lets StuccoID own
signup and the account's end while brolly keeps login and the pods.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main
```

Production has no `BROLLY_SERVICE_TOKEN` yet, so the API is not mounted live. Setting it, and later the three front-end URLs, is spec piece 6.

---

## After this plan

- Piece 4 (password reset: `POST /internal/v1/password-resets` and the reset page) gets its own plan; it adds one route to `internal_api::routes`.
- Piece 5 (StuccoID's `$lib/brolly.js`) can start against a local brolly with `BROLLY_SERVICE_TOKEN` set once chunk 4 is on `main`.
- Update the spec's piece 1 to drop `BROLLY_RESERVED_LABELS` and move `BROLLY_PROTOCOLS` to its own plan, as decided at the top of this one.
