# Admin Console Actions Implementation Plan

<!-- doc-paths: skip -->
<!-- A plan cites the files it is about to create, so the paths it names
     are not expected to resolve until it has been executed. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the admin console the verbs it has none of — disable, enable, promote, demote, end sessions, delete, and invite management — and close the two disclosure holes that would otherwise make the Disable button a lie.

**Architecture:** Five new `identity/src/db.rs` functions, one generic `ConfirmPage` page template behind every high-consequence action, a member detail page, and an invites list. Before any of it, two `is_active` filters that make disabling mean what the console will claim it means.

**Tech Stack:** Rust, axum 0.8.9 (brace route params — `:id` panics), Askama 0.14, sqlx/Postgres, testcontainers.

**Spec:** [`docs/specs/2026-09-10-admin-actions.md`](../specs/2026-09-10-admin-actions.md)

---

## Depends on the other two plans

- **The door plan, Task 2** replaces `instance_name` with `chrome: Chrome<'a>`
  on `OverviewPage` and `UsersPage` (`server/src/admin.rs`). Every new page
  struct below carries `chrome: Chrome<'a>` on that assumption.
- **The dashboard plan, Tasks 2–3** define `.dashboard-card` and `.chip` /
  `.chip-admin` / `.chip-disabled`. The detail page uses both. If that has not
  landed, the detail page renders bare strings for a while, which is survivable.

## Ordering

**Chunk 1 ships first and alone.** It is a disclosure fix, it is independent of
every UI change below, and the console must not offer Disable while it is
outstanding.

Within the rest, the only hard constraint is that Task 3 (db layer) precedes
everything that calls it, and Task 5 (`ConfirmPage`) precedes every confirmed
action.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `server/src/xrpc.rs` | `resolve_repo` gates on `is_active` | Modify |
| `server/src/mastodon_api.rs` | `local_author`, `fetch_note` gate on `is_active` | Modify |
| `identity/src/db.rs` | 5 new functions; one misplaced doc comment | Modify |
| `server/src/admin.rs` | detail page, actions, invites — grows substantially | Modify |
| `server/templates/admin/confirm.html` | the one confirmation page | Create |
| `server/templates/admin/user_detail.html` | one account | Create |
| `server/templates/admin/invites.html` | list + mint | Create |
| `server/tests/admin.rs` | the guards and the actions | Modify |
| `server/tests/xrpc.rs`, `mastodon_compose.rs` | the two holes | Modify |
| `server/tests/admin_cli.rs` | new: spawns the binary | Create |

**On `server/src/admin.rs` growing:** it is 217 lines today and this roughly
triples it. If it passes ~600 lines, split it the way mycomyco does —
`admin/mod.rs` (router, guard, tabs), `admin/users.rs`, `admin/invites.rs` —
rather than letting one file hold the guard, six actions and two lists.

**Every new template must carry `class="wrap"`.**
`every_page_template_uses_the_page_container` (`server/tests/ui_invariants.rs:224`)
asserts it on every non-`_`-prefixed template, so `confirm.html`,
`user_detail.html` and `invites.html` each fail `cargo test --workspace` without
it. They must also have exactly one `<h1>` (`:183`). Both are easy to forget on
a new file and neither failure is obvious from the page itself.

---

## Chunk 1: Make disabling mean what it says

### Task 1: ATProto stops serving disabled members

`resolve_repo` (`server/src/xrpc.rs:128`) has four branches — `did:plc`,
`did:web`, handle, bare username — and filters `is_active` on **none** of them.
Its result flows unchecked into three public, unauthenticated endpoints
(`xrpc.rs:743-745`): `getRecord` (`:258`), `describeRepo` (`:309`) and
`sync.getRepo` (`:348`), the last of which returns the entire repository as a
CAR.

**Files:**
- Modify: `server/src/xrpc.rs:128-166`
- Test: `server/tests/xrpc.rs`

- [ ] **Step 1: Write the failing test**

Nothing in `server/tests/xrpc.rs` currently sets `status = 'disabled'`, so this
is new ground in that file.

This file's helper is `get(h: &Harness, uri) -> Reply` (`xrpc.rs:109`) — there
is no bare `router` or `db` binding, and the pool is `h.db.pool`.

```rust
/// Disabling an account must stop it serving, on every protocol.
///
/// Before this, an admin could disable a member for moderation reasons, watch
/// their pod 404 and their actor stop resolving, and anyone on the internet
/// could still download their whole repository as a CAR.
#[tokio::test]
async fn a_disabled_member_serves_no_repo() {
    let h = harness().await;
    // ...create alice and provision her repo, following this file's existing
    // setup for a repo-reading test.

    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&h.db.pool)
        .await
        .unwrap();

    // All three, because resolve_repo feeds all three — testing two would
    // leave the fix looking complete while one endpoint still served.
    for uri in [
        "/xrpc/com.atproto.repo.getRecord?repo=alice.brolly.test\
         &collection=app.bsky.feed.post&rkey=self",
        "/xrpc/com.atproto.repo.describeRepo?repo=alice.brolly.test",
        "/xrpc/com.atproto.sync.getRepo?did=alice.brolly.test",
    ] {
        let reply = get(&h, uri).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{uri} still served a disabled member"
        );
    }
}
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo test -p brolly-server --test xrpc a_disabled_member_serves_no_repo`
Expected: FAIL — 200, with the repo.

- [ ] **Step 3: Filter inside the function**

The filter goes **inside `resolve_repo`**, on the value it returns, not at the
call sites. There are **five** callers, not the three above: `:412`
(`create_record`) and `:523` (`delete_record`) use it for the "you may only
write to your own repository" check. Filtering inside covers all five.

The effect on the two write paths is benign: `caller` (`:79`) already filters
`is_active`, so a legitimate self-write still resolves, and a disabled target
still produces the same 403 by a shorter route.

Each of the four branches already yields `Option<User>`; add
`.filter(User::is_active)` to each, matching the idiom at `pod.rs:183` and
`auth.rs:410`. For the `did:plc` branch, which uses a `match`:

```rust
        return match row {
            Some((id,)) => db::find_by_id(&state.pool, id)
                .await
                .ok()
                .flatten()
                .filter(User::is_active),
            None => None,
        };
```

- [ ] **Step 4: Verify no regression on the write paths**

```rust
/// The filter touches create_record and delete_record too. This is the
/// regression it could cause.
#[tokio::test]
async fn an_active_member_can_still_write_to_their_own_repo() {
    // Follow the existing create_record test in this file; assert it still
    // succeeds for an active member.
}
```

Run: `cargo test -p brolly-server --test xrpc`
Expected: PASS, all of it.

- [ ] **Step 5: Commit**

```bash
git add server/src/xrpc.rs server/tests/xrpc.rs
git commit -m "fix(atproto): a disabled member serves no repo

resolve_repo filtered is_active on none of its four branches, so
getRecord, describeRepo and sync.getRepo kept serving a disabled
member's data to anonymous callers — getRepo hands out the entire
repository as a CAR."
```

### Task 2: The public Mastodon timeline stops showing disabled members

`public_timeline` (`server/src/mastodon_api.rs:327`) is unauthenticated — it
checks `wrong_host` and nothing else — and resolves note authors through
`local_author` (`:117`) and `fetch_note` (`:373`), both bare
`db::find_by_username` calls with no status filter.

**Files:**
- Modify: `server/src/mastodon_api.rs:117`, `:373`
- Test: `server/tests/mastodon_compose.rs` — **not** `mastodon_api.rs`

- [ ] **Step 1: Write the failing test, in the right file**

The test needs a member who has actually posted, and `server/tests/mastodon_api.rs`
cannot do that: its `request()` helper (`:78`) only sends empty bodies, and its
one public-timeline test (`:392`) just asserts an empty array.

The machinery lives in `server/tests/mastodon_compose.rs` — `post_form` (`:89`),
`a_member` (`:105`), and `a_public_post_reaches_the_server_index` (`:383`),
which is almost exactly this test's setup. Put it there.

```rust
/// The same class of hole as resolve_repo, on a different code path, so it
/// needs its own assertion rather than being assumed from the ATProto fix.
#[tokio::test]
async fn a_disabled_member_is_off_the_public_timeline() {
    // Follow `a_public_post_reaches_the_server_index` (:383) to get a member
    // with a public note, and confirm it appears on the timeline first —
    // otherwise this passes for the wrong reason.

    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
        .execute(&h.db.pool)
        .await
        .unwrap();

    let reply = get(&h, "/api/v1/timelines/public", None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        !reply.body.contains("alice"),
        "a disabled member's notes are still on the public timeline"
    );
}
```

Asserting the note is present *before* disabling is not ceremony: without it,
an empty timeline for any reason makes this pass.

- [ ] **Step 2: Run and watch fail**

Run: `cargo test -p brolly-server --test mastodon_api a_disabled_member_is_off`
Expected: FAIL — alice is still there.

- [ ] **Step 3: Filter both lookups**

At `:117` and `:373`, both currently
`db::find_by_username(&state.pool, &username).await.ok()??`:

```rust
    let user = db::find_by_username(&state.pool, &username)
        .await
        .ok()
        .flatten()
        .filter(User::is_active)?;
```

`public_note_iris` is a store-index query with no notion of account status, so
the filter must sit here, in the layer that resolves each note's owner.

- [ ] **Step 4: Verify and commit**

Run: `cargo test --workspace`

```bash
git add server/src/mastodon_api.rs server/tests/mastodon_api.rs
git commit -m "fix(mastodon): a disabled member is off the public timeline

public_timeline is unauthenticated and resolved note authors through two
bare find_by_username calls."
```

**Not closed, deliberately:** `subscribe_repos` (`xrpc.rs:660`) backfills the
commit log with no user lookup at all, on an argument borrowed from ADR 0016.
That ADR scopes a global `FEDERATION_ENABLED` constant to ActivityPub delivery
and has nothing to say about one member, so closing it is a new decision rather
than a bug fix. Task 6's confirmation copy names the gap.

---

## Chunk 2: The database layer and the detail page

### Task 3: Five new `db` functions

**Files:**
- Modify: `identity/src/db.rs`
- Modify: `server/src/admin.rs:24-26` (two new constants)

- [ ] **Step 1: Write the failing tests**

In `identity/tests/persistence.rs`, following that file's existing shape:

```rust
#[tokio::test]
async fn status_round_trips() {
    // create a user, set_status(.., "disabled"), assert !is_active, set back.
    //
    // The literal, not `admin::DISABLED`: those constants live in
    // `server/src/admin.rs`, and `brolly-identity` cannot depend on
    // `brolly-server` — the dependency runs the other way.
}

#[tokio::test]
async fn revoking_all_sessions_leaves_none() {
    // create two sessions, revoke_all_sessions, assert count_sessions == 0
}

#[tokio::test]
async fn invites_list_with_a_null_inviter() {
    // create_invite(pool, None, …) — which is what bootstrap and the CLI both
    // do — then assert list_invites returns a row whose inviter is None.
}

#[tokio::test]
async fn revoking_by_hash_stops_redemption() {
    // create_invite, hash it, revoke_invite_by_hash, assert redeem_invite fails
}
```

- [ ] **Step 2: Add the constants**

In `server/src/admin.rs`, beside `ADMIN` and `MEMBER` (`:24-26`):

```rust
/// The two values `users.status` permits.
///
/// A `CHECK` constraint is what actually enforces them, so a typo reaching the
/// database is a 500 rather than a compile error. These constants do not
/// prevent that — they only mean call sites share one spelling. A newtype would
/// enforce it, and is not worth it for two values behind one setter.
pub const ACTIVE: &str = "active";
pub const DISABLED: &str = "disabled";
```

- [ ] **Step 3: Write the functions**

```rust
/// Set a member's status.
///
/// Sibling of `set_role`, and deliberately not "disable"/"enable" for the same
/// reason: the caller decides, and the guard against stranding an instance with
/// no admin lives with the caller that can explain it to a human.
pub async fn set_status(pool: &PgPool, user_id: Uuid, status: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE users SET status = $2 WHERE id = $1")
        .bind(user_id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

/// End every session a member has.
///
/// `revoke_other_sessions` cannot serve this: it takes a `keep_token` to
/// preserve the caller's own session, and an admin acting on somebody else has
/// no token to keep and wants none kept.
pub async fn revoke_all_sessions(pool: &PgPool, user_id: Uuid) -> Result<u64, DbError> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// One outstanding invite, as the console lists it.
///
/// No `code`: `invites.code_hash` is the primary key and the plaintext is never
/// stored, for the same reason session tokens are not. A minted code is visible
/// exactly once, in the response to the POST that minted it.
///
/// `inviter` is the *username*, resolved by a LEFT JOIN rather than a lookup
/// per row — the same N+1 the actor index exists to prevent, at a smaller
/// scale. It is `Option` from two directions: the column is `ON DELETE SET
/// NULL`, and both existing minters (`bootstrap` and `brolly-admin invite`)
/// pass `None`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteRow {
    pub code_hash: String,
    pub inviter: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub expires_at: Option<time::OffsetDateTime>,
    pub max_uses: i32,
    pub uses: i32,
    pub revoked_at: Option<time::OffsetDateTime>,
    pub grants_role: Option<String>,
}

pub async fn list_invites(pool: &PgPool) -> Result<Vec<InviteRow>, DbError> {
    Ok(sqlx::query_as::<_, InviteRow>(
        "SELECT i.code_hash, u.username AS inviter, i.created_at, i.expires_at,
                i.max_uses, i.uses, i.revoked_at, i.grants_role
         FROM invites i
         LEFT JOIN users u ON u.id = i.created_by
         ORDER BY i.created_at DESC",
    )
    .fetch_all(pool)
    .await?)
}

/// Revoke an invite the console can see but cannot read.
///
/// `revoke_invite` takes plaintext and hashes it. The console only ever has the
/// hash, which is safe to put in a form action: `hash_secret` is hex SHA-256 of
/// a high-entropy random value, so it is URL-safe and reverses to nothing.
/// One account, by id, with the columns the console's list already renders.
///
/// `find_by_id` returns `User`, which has no `created_at` — and widening `User`
/// would touch four explicit-column queries to serve one page. `UserRow` is
/// already the right shape; this is `list_users` with a `WHERE`.
pub async fn find_row_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRow>, DbError> {
    Ok(sqlx::query_as::<_, UserRow>(
        "SELECT id, username, role, status, did_plc, created_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn revoke_invite_by_hash(pool: &PgPool, code_hash: &str) -> Result<u64, DbError> {
    let result =
        sqlx::query("UPDATE invites SET revoked_at = now() WHERE code_hash = $1 AND revoked_at IS NULL")
            .bind(code_hash)
            .execute(pool)
            .await?;
    // Returns the row count, as `revoke_all_sessions` does: without it the
    // console cannot tell a bogus hash from a successful revoke, and would
    // report "revoked" either way.
    Ok(result.rows_affected())
}
```

`redeem_invite` (`:282`) already checks `revoked_at IS NULL`, so this genuinely
stops redemption rather than only hiding a row.

- [ ] **Step 4: Move the orphaned doc comment**

`identity/src/db.rs:407-411` holds a block reading "Delete a user outright. /
Sessions, invites, keys and OAuth grants cascade. The pod is a separate `rm -rf`
the caller performs…" — it runs straight into `count_users`' own doc at `:412`
and therefore **documents `count_users` (`:417`)**. `delete_user` (`:480`) has
no doc comment at all.

Move it to `delete_user`, and correct it on the way: invites are
`ON DELETE SET NULL`, not cascade.

That file is visibly mid-edit — there are further duplicated doc blocks around
`:243` and `:271-281` — so re-check every line number here against the file
before editing rather than trusting this plan's copy.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p brolly-identity`

```bash
git add identity/src/db.rs identity/tests/persistence.rs server/src/admin.rs
git commit -m "feat(identity): status, session and invite functions for the console

Plus: the 'delete a user outright' doc comment was attached to
count_users, and claimed invites cascade when they SET NULL."
```

### Task 4: The member detail page

**Files:**
- Modify: `server/src/admin.rs` (`MemberView` gains `id`; new `detail` handler)
- Create: `server/templates/admin/user_detail.html`
- Modify: `server/templates/admin/users.html` (link each row)
- Modify: `server/src/lib.rs` (route)

- [ ] **Step 1: Write the failing test**

```rust
/// The guard is the whole feature, and it applies to every new route.
#[tokio::test]
async fn a_member_cannot_see_a_detail_page() {
    // harness, register alice as member, register bob as admin
    let (status, _) = get_as(&router, &format!("/admin/users/{alice_id}"), Some(&alice)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "404, not 403 — see require_admin");
}

#[tokio::test]
async fn an_admin_sees_one_account() {
    let (status, body) = get_as(&router, &format!("/admin/users/{alice_id}"), Some(&admin)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("alice"));
    assert!(body.contains("Disable"));
}
```

- [ ] **Step 2: Add `id` to `MemberView`**

`MemberView` (`server/src/admin.rs:172`) drops `id` when it maps `UserRow`, so
the list cannot link anywhere. Add `id: uuid::Uuid` and carry `row.id` through.

- [ ] **Step 3: Write the handler**

```rust
#[derive(Template)]
#[template(path = "admin/user_detail.html")]
struct DetailPage<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    member: MemberView,
    sessions: i64,
    /// Whether the acting admin is looking at themselves. Actions the guards
    /// forbid are not rendered — but the handlers re-check regardless. Hiding a
    /// button is a courtesy; the guard is the control.
    is_self: bool,
    /// Whether demoting or disabling this member would strand the instance.
    is_last_admin: bool,
}

/// `GET /admin/users/{id}`
pub async fn detail(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let admin = match require_admin(&state, &jar, &format!("/admin/users/{id}")).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Some(member)) = db::find_by_id(&state.pool, id).await else {
        return not_found();
    };
    let sessions = db::count_sessions(&state.pool, id).await.unwrap_or(0);
    let admins = db::count_admins(&state.pool).await.unwrap_or(0);

    render(&DetailPage {
        chrome: state.chrome(),
        tabs: tabs("/admin/users"),
        is_self: member.id == admin.id,
        is_last_admin: member.role == ADMIN && member.status == ACTIVE && admins <= 1,
        member: /* map from `member` as `users()` maps UserRow */,
        sessions,
    })
}
```

**`find_by_id` cannot feed this page, and the fix is a fifth db function.**
`find_by_id` returns `User` (`identity/src/db.rs:48-56`), which has no
`created_at`; `MemberView` needs `created: String` (`admin.rs:177`). Three ways
out, and the third is the one to take:

- *Add `created_at` to `User`* — it is a `sqlx::FromRow` struct built by four
  explicit-column queries (`db.rs:113`, `:132`, `:148`, `:223`), so this is a
  four-site change to serve one page. No.
- *Drop "created" from the detail page* — silently loses a field the spec's
  Facts list names. No.
- **Add `find_row_by_id(pool, id) -> Option<UserRow>`**, mirroring `list_users`
  (`db.rs:471`) with a `WHERE id = $1`. `UserRow` already carries exactly the
  five columns this page renders, and `MemberView` is already built from one.
  One function, no ripple.

Also note `server/src/admin.rs` imports only `axum::extract::State` (`:14`):
`Path` and, for the POST handlers in Tasks 5–8, `Form` both need adding.

- [ ] **Step 4: Write the template**

`server/templates/admin/user_detail.html`, one `<h1>`, using `.dashboard-card`
and `.facts` from the dashboard plan, and `.chip` for role and status.

Actions render as links to confirmations, or direct POSTs for enable and
end-sessions. Suppress any action `is_self` or `is_last_admin` forbids.

- [ ] **Step 5: Route it**

In `server/src/lib.rs`, beside `:141-142`. **Braces, not colons** —
`server/Cargo.toml:34` pins `axum = "0.8.9"`, which panics at startup on `:id`.
Every existing parameterised route uses braces (`lib.rs:179`,
`mastodon_api.rs:1017`, `xrpc.rs:759`).

```rust
        .route("/admin/users/{id}", get(admin::detail))
```

These need no host guard, for two reasons the comment at `lib.rs:138-140`
already gives: the session cookie sets no `Domain` (`auth.rs:413-419`), and
`/admin/*` is a reserved path on member subdomains under ADR 0009 —
`identity/src/routing.rs:101` names `/admin/users`.

- [ ] **Step 6: Link the list**

In `admin/users.html`, wrap each row's username:
`<a href="/admin/users/{{ member.id }}">@{{ member.username }}</a>`

- [ ] **Step 7: Verify and commit**

Run: `cargo test --workspace`

```bash
git add server/src/admin.rs server/templates/admin server/src/lib.rs server/tests/admin.rs
git commit -m "feat(admin): one account, in detail"
```

---

## Chunk 3: The actions

### Task 5: `ConfirmPage`, and disable/enable

`delete_account` (`server/src/account.rs:511`) already makes a member type their
own username to delete their pod. mycomyco generalises exactly that. Adopted as
**one full page template**, not a `_`-prefixed partial: Askama's `{% include %}`
type-checks against the including struct, so a partial would mean four page
templates each carrying the same seven fields, plus the partial — five files
where one will do.

**Files:**
- Create: `server/templates/admin/confirm.html`
- Modify: `server/src/admin.rs`, `server/src/lib.rs`
- Test: `server/tests/admin.rs`

- [ ] **Step 1: Give the test harness a `post_as`**

**Every POST test below depends on this and it does not exist.**
`server/tests/admin.rs` has `get_as(router, path, Option<&str>)` (`:90`) but
`post(router, path, body)` (`:45`) takes **no cookie**. An anonymous POST to an
admin route gets `require_admin`'s 303 to `/login`, not the 400 or 404 these
tests assert — so without this step every one of them fails for the wrong
reason.

Add a cookie parameter to `post`, mirroring `get_as`:

```rust
async fn post_as(
    router: &axum::Router,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, String, Vec<String>) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    // ...body and response handling identical to `post` at :45.
}
```

Keep `post` as a thin wrapper passing `None`, so the existing callers at `:73`
and elsewhere do not move.

Run: `cargo test -p brolly-server --test admin`
Expected: PASS, unchanged — this step adds capability and changes no behaviour.

- [ ] **Step 2: Write the failing tests**

```rust
/// Disabling is not "cannot log in" on this server. It is "every URL under
/// alice.example.org returns 404, on every protocol, immediately."
#[tokio::test]
async fn disabling_a_member_takes_their_pod_offline() {
    // confirm the pod serves, disable via post_as with the typed confirmation,
    // then assert BOTH:
    //   - the pod 404s (pod.rs:52)
    //   - the actor stops resolving (activitypub.rs:58 gates member_actor and
    //     webfinger) — the spec asks for both, and an admin will check both
    //     by hand.
}

/// Otherwise disable is a one-way door dressed as a toggle. The spec calls
/// this out by name and it is the easiest assertion to skip.
#[tokio::test]
async fn enabling_restores_everything_disabling_took() {
    // disable, confirm the pod 404s and the actor is gone, then POST enable
    // and confirm both come back and alice can log in again.
}

/// Disable needs no revocation step: auth.rs:410 filters session_user on
/// is_active, so cookies stop resolving on the next request. This exists so
/// that fact cannot rot silently into dead revocation code.
#[tokio::test]
async fn a_disabled_members_session_stops_resolving_with_no_revocation() {
    // alice signs in, gets /account 200; disable her; same cookie now redirects
}

/// The "changes nothing" half is the one worth asserting.
#[tokio::test]
async fn a_mistyped_confirmation_changes_nothing() {
    let (status, body, _) = post(&router, &format!("/admin/users/{id}/disable"),
                                 "confirm=nope").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("did not match"));
    // and alice is still active
}
```

**400, not 422.** The house pattern is `account.rs:513`; mycomyco's 422 is not
adopted. There is no `render_with_status` helper in this workspace — use the
tuple form as `account.rs:512` does.

- [ ] **Step 3: Write the confirmation page**

```rust
#[derive(Template)]
#[template(path = "admin/confirm.html")]
struct ConfirmPage<'a> {
    chrome: Chrome<'a>,
    tabs: Vec<Tab>,
    /// "Disable this account", "Delete this account".
    action_label: &'a str,
    target_username: &'a str,
    target_id: uuid::Uuid,
    form_action: String,
    /// Plain text, never HTML — this is the only place the console explains an
    /// irreversible act, so it is the field most likely to attract markup.
    warning_text: String,
    danger: bool,
    error: Option<&'a str>,
}
```

`admin/confirm.html` has one `<h1>` (the action label) and a form posting to
`form_action` with a `confirm` field, mirroring `account/delete.html`.

- [ ] **Step 4: Write the disable confirmation copy**

This is the spec's main obligation. It must say what disabling does, and it must
name the gap Chunk 1 did not close:

> Disabling **@alice** takes their pod offline: every URL under
> `alice.brolly.test` will return 404, their profile will stop resolving on the
> fediverse, and their open sessions will stop working on the next page they
> load. They will not be able to log in.
>
> One exception: notes they have already published stay in the ATProto firehose
> backfill, which is not filtered by account status. Anyone already consuming
> that stream keeps what they have.
>
> This is reversible — you can enable the account again from the same page.

- [ ] **Step 5: Implement the handlers**

`GET /admin/users/{id}/disable` renders `ConfirmPage`. `POST` checks, in this
order: `require_admin`, member exists, **not self**, **not the last active
admin**, typed confirmation matches. Then `db::set_status(pool, id, DISABLED)`
and redirect to the detail page.

`POST /admin/users/{id}/enable` is a direct POST with no confirmation — it
restores a previous state and is undone by the button next to it.

- [ ] **Step 6: Route them**

```rust
        .route("/admin/users/{id}/disable", get(admin::disable_form).post(admin::disable))
        .route("/admin/users/{id}/enable", post(admin::enable))
```

- [ ] **Step 7: Verify and commit**

Run: `cargo test --workspace`

```bash
git add -A
git commit -m "feat(admin): disable and enable an account

Disable is confirmed rather than a toggle: on this server it is not
'cannot log in', it is 'every URL under their subdomain returns 404'."
```

### Task 6: Promote, demote, and the two guards

**Files:**
- Modify: `server/src/admin.rs`, `server/src/lib.rs`
- Test: `server/tests/admin.rs`

- [ ] **Step 1: Write the failing tests**

```rust
/// Three separate cases, because a guard that covers two of three is worse
/// than none — it teaches the operator to trust it.
#[tokio::test]
async fn an_admin_cannot_act_on_themselves() {
    for verb in ["disable", "demote", "delete"] {
        let (status, _, _) = post(&router, &format!("/admin/users/{own_id}/{verb}"),
                                  &format!("confirm={own_username}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{verb} on self");
    }
}

/// The unrecoverable state: an instance with no admin cannot be recovered from
/// the web at all.
#[tokio::test]
async fn the_last_active_admin_cannot_be_demoted_or_disabled() {
    // Two admins; demote one via a second admin's session so the self-guard
    // does not fire first; then assert the last one cannot be demoted.
}

/// Already true via count_admins' SQL. Pinned because it is load-bearing and
/// invisible: a disabled admin cannot log in to undo anything, so counting them
/// would let an instance strand itself.
#[tokio::test]
async fn a_disabled_admin_does_not_count_toward_the_total() {
    // `counting_admins_ignores_disabled_ones` (server/tests/admin.rs:278)
    // already asserts the db-level fact. This asserts the guard reads it.
}
```

- [ ] **Step 2: Implement both, with both guards**

`db::count_admins` (`identity/src/db.rs:429`) already counts
`role = 'admin' AND status = 'active'`, which is exactly the right population.

Write the last-admin guard even though the self-guard makes it unreachable in
the console. mycomyco's implementation carries a comment (`users.rs:545`)
conceding exactly that — and **the reasoning does not transfer**, because
`brolly-admin demote` has no acting admin and nothing constrains its target. The
guard is live on the CLI and defence in depth here. Put that in a comment so the
next reader does not delete the "unreachable" one.

**Delete needs no last-admin guard**, and that is a conclusion rather than an
omission: the self-guard forbids deleting yourself, so the acting admin survives
every deletion and `count_admins` cannot reach zero. Unlike demote, there is no
second entry point — `brolly-admin` has no delete verb.

- [ ] **Step 3: Route them, in this task**

A task that ends red is not a task. Task 6's tests exercise `demote`, so its
routes belong here rather than in Task 7 — otherwise they hit the router's own
404 and the asserted 400 never happens.

```rust
        .route("/admin/users/{id}/promote", get(admin::promote_form).post(admin::promote))
        .route("/admin/users/{id}/demote", get(admin::demote_form).post(admin::demote))
```

The `delete` arm of `an_admin_cannot_act_on_themselves` moves to Task 7 for the
same reason — that route does not exist yet either. Iterate
`["disable", "demote"]` here and add `delete` there.

- [ ] **Step 4: Verify and commit**

Run: `cargo test --workspace`

```bash
git add -A
git commit -m "feat(admin): promote and demote, behind both guards"
```

### Task 7: End sessions, and delete

**Files:**
- Modify: `server/src/admin.rs`, `server/src/lib.rs`
- Test: `server/tests/admin.rs`

- [ ] **Step 1: Write the failing tests**

```rust
/// Not the same as disable: a member whose laptop was stolen needs their
/// sessions ended without their account being disabled.
#[tokio::test]
async fn ending_sessions_leaves_the_account_active() {
    // alice signs in twice; admin POSTs end-sessions; both cookies stop
    // resolving, but alice can still log in again.
}

/// Either alone is a leak.
#[tokio::test]
async fn deleting_a_member_removes_the_pod_and_the_row() {
    // assert the pod directory is gone AND find_by_id returns None
}
```

- [ ] **Step 2: Implement**

`end-sessions` is a direct POST — non-destructive, and the member simply logs
back in. It calls `db::revoke_all_sessions`.

`delete` is confirmed, and reuses `delete_account`'s order **exactly**
(`account.rs:524` then `:528`): `state.stores.delete_pod(id)` first, then
`db::delete_user`. Reversing it orphans a pod directory whose owner no longer
exists, and nothing would ever collect it.

- [ ] **Step 3: Route them**

```rust
        .route("/admin/users/{id}/end-sessions", post(admin::end_sessions))
        .route("/admin/users/{id}/delete", get(admin::delete_form).post(admin::delete))
```

The promote and demote routes are **not** here — they land in Task 6, with the
handlers they serve.

- [ ] **Step 4: Assert the guard covers the POSTs too**

```rust
/// A POST-only hole is invisible in a browser, which is exactly why it would
/// survive review.
#[tokio::test]
async fn a_member_gets_404_on_every_admin_post() {
    for verb in ["disable", "enable", "promote", "demote", "end-sessions", "delete"] {
        let (status, _, _) = post(&router, &format!("/admin/users/{id}/{verb}"),
                                  "confirm=whatever").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{verb}");
    }
}
```

- [ ] **Step 5: Verify and commit**

Run: `cargo test --workspace`

```bash
git add -A
git commit -m "feat(admin): end a member's sessions, and delete an account"
```

---

## Chunk 4: Invites, and the CLI

### Task 8: The invites page

**Files:**
- Create: `server/templates/admin/invites.html`
- Modify: `server/src/admin.rs` (`tabs()` gains an entry), `server/src/lib.rs`
- Test: `server/tests/admin.rs`

- [ ] **Step 1: Write the failing tests**

```rust
/// The awkward property, pinned so a later refactor cannot quietly store the
/// plaintext to make the UI nicer.
#[tokio::test]
async fn a_minted_code_is_shown_once_and_never_again() {
    let (_, body, _) = post(&router, "/admin/invites", "uses=1").await;
    let code = /* extract from body */;

    let (_, list) = get_as(&router, "/admin/invites", Some(&admin)).await;
    assert!(!list.contains(&code), "the list cannot show a code it never stored");
}

/// The console refuses, matching the shipped CLI (bin/admin.rs:123-126).
/// Silently coercing to 1 would make the two entry points disagree about the
/// same rule, which is worse than either behaviour alone.
#[tokio::test]
async fn an_admin_invite_with_several_uses_is_refused() {
    let (status, body, _) = post(&router, "/admin/invites", "uses=5&admin=on").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("single-use"));
}

/// The bootstrap invite is row one on every new instance, and it has no
/// inviter — both existing minters pass None.
#[tokio::test]
async fn an_invite_with_no_inviter_renders() {
    // bootstrap() has already run in the harness; just GET the page
}

/// "Who did I invite and when" is a question operators ask, and a list that
/// silently drops rows cannot answer it.
#[tokio::test]
async fn spent_and_revoked_invites_stay_listed() { /* … */ }

#[tokio::test]
async fn revoking_by_hash_stops_the_code_working() { /* … */ }
```

- [ ] **Step 2: Implement**

The mint response is the only sight of the code, so it says so in as many words
— an admin who navigates away has lost it and must mint another.

Each row shows inviter (or "the instance" when `None`), created, expires, uses
of max-uses, whether it grants admin, and whether it is revoked. The revoke
button posts to `/admin/invites/{code_hash}/revoke`.

- [ ] **Step 3: Route**

```rust
        .route("/admin/invites", get(admin::invites).post(admin::mint_invite))
        .route("/admin/invites/{code_hash}/revoke", post(admin::revoke_invite))
```

Add an Invites entry to `tabs()` (`server/src/admin.rs:110`). It maps an array
of `(&'static str, &'static str)` tuples and stays that shape.

- [ ] **Step 4: Verify and commit**

Run: `cargo test --workspace`

```bash
git add -A
git commit -m "feat(admin): see and revoke invites

The list cannot show a code — code_hash is the primary key and the
plaintext is never stored. The mint response says so."
```

### Task 9: A test harness for `brolly-admin`

**Nothing in the workspace tests the binary.** `set_role` (`bin/admin.rs:157`)
is private to a binary crate and cannot be called from an integration test, so
the CLI's last-admin guard — which is the entry point where that guard is
actually *live* — is untested.

**Files:**
- Modify: `test-support/src/lib.rs:24-27`, `:44-50`
- Create: `server/tests/admin_cli.rs`

- [ ] **Step 1: Expose the connection URL**

`TestDb` (`test-support/src/lib.rs:24`) has only `_container` and `pub pool` —
there is no way to get a `DATABASE_URL` out of it, and the CLI authenticates on
exactly that. The URL is already built at `:44` and then dropped, so this is two
lines:

```rust
pub struct TestDb {
    _container: ContainerAsync<Postgres>,
    pub pool: PgPool,
    /// The connection string, for tests that spawn a subprocess rather than
    /// using the pool — `brolly-admin` authenticates on `DATABASE_URL`.
    pub url: String,
}
```

and `url,` added to the `TestDb { … }` constructor at `:49`.

- [ ] **Step 2: Write it**

```rust
//! The CLI, spawned as a real binary.
//!
//! `brolly-admin`'s last-admin guard is the one that matters: unlike the
//! console, it has no acting admin, so nothing constrains its target. The
//! console's copy of the guard is defence in depth; this one is load-bearing.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[tokio::test]
async fn demote_refuses_the_last_active_admin() {
    let db = brolly_test_support::postgres().await;
    brolly_identity::db::MIGRATOR.run(&db.pool).await.unwrap();
    // create exactly one admin

    let output = Command::new(env!("CARGO_BIN_EXE_brolly-admin"))
        .args(["demote", "alice"])
        .env("DATABASE_URL", &db.url)
        .output()
        .expect("spawn brolly-admin");

    assert!(!output.status.success(), "demoting the last admin must fail");
    // The exact wording, from bin/admin.rs:186 — there is no "last" in it.
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("only active admin"),
        "and say why"
    );
}
```

- [ ] **Step 3: Verify and commit**

Run: `cargo test -p brolly-server --test admin_cli`
Expected: PASS. `CARGO_BIN_EXE_brolly-admin` is set by Cargo for integration
tests in the same package that declares the binary, which `server` does.

```bash
git add test-support/src/lib.rs server/tests/admin_cli.rs
git commit -m "test: brolly-admin refuses to demote the last admin

First test in the workspace that exercises the CLI at all, which is why
TestDb had no connection string to hand a subprocess."
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

All five pass, and an operator with no shell can disable, enable, promote,
demote, delete and invite entirely from `/admin`.
