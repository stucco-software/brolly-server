# Admin console — account actions and invites

**Status:** Draft (2026-09-10)
**Plan:** §4.1 audience table ("low traffic, high consequence"), §4.4 phase 5–7
UI deliverable, §4.5 UI invariants.
**Extends:** [`2026-09-09-admin-console.md`](2026-09-09-admin-console.md) —
**slice 2** of its table ("disable / re-enable an account, revoke sessions,
invite management"), **plus promote/demote and delete**, which that table does
not list anywhere. They are here because promote and demote already exist on the
CLI and the console is where they belong, and because delete is the verb an
operator most often needs and has no home at all today. Slice 1 shipped; slice 3
is the actor index and slice 4 is moderation, both deferred. See Non-goals.
**Depends on:** ADR 0005 (R5), ADR 0016 (what the federation switch governs),
and [`2026-09-10-member-dashboard.md`](2026-09-10-member-dashboard.md) for
`.chip` and `.dashboard-card`.

## Problem

Slice 1 shipped and it is read-only. `require_admin`, `bootstrap`, `/admin` and
`/admin/users` all work (`server/src/admin.rs`), and an admin can look at a
table of accounts and change nothing.

`brolly-admin` does not close the gap, and it is worth being exact about how far
it falls short. Its verbs are `invite`, `promote`, `demote`, `plc-retry` and
`whoami` (`server/src/bin/admin.rs:16–38`). So:

- **Promote and demote** exist on the CLI and need shell access.
- **Disable, enable, delete an account, and revoke an invite** exist *nowhere*.
  Today they are hand-written SQL against production.

An instance can now be handed over without a database credential and then cannot
be moderated without one. That is the gap.

### What disabling actually does — and the hole underneath it

The 2026-09-09 spec left an open question: *"Does disabling an account stop its
pod from serving?"* The answer is mostly yes, and the exception is serious
enough that this spec has to fix it before it can put a Disable button on a page.

`User::is_active` is checked here:

| Site | Effect when `status = 'disabled'` |
|---|---|
| `server/src/pod.rs:52` | the whole pod 404s — "no such pod", before any WAC evaluation |
| `server/src/pod.rs:154`, `:183` | a disabled member cannot be resolved as an authenticated subject |
| `server/src/auth.rs:410` | `session_user` filters on it, so **live sessions stop resolving on their next request** |
| `server/src/activitypub.rs:58` (`active_member`) | gates `member_actor` (`:80`) and `webfinger` (`:168`) — this is the direct answer to the earlier spec's "their actor document still resolves" |
| `server/src/mastodon_api.rs:198`, `:398` | those two Mastodon surfaces reject |
| `server/src/mastodon_api.rs:123` (`counts`) | instance metadata counts only active accounts |
| `server/src/outbox.rs:274` | `deliver_locally` declines when the *recipient* is inactive |
| `server/src/mastodon_api.rs:80`, `server/src/xrpc.rs:79` (`caller`), `:120` (`token_caller`) | the authenticated **caller** is filtered |

That last row is the trap, and it applies to Mastodon exactly as it does to
ATProto. Those functions filter who is *asking*. Nothing filters whose data is
being *read*.

There are **two** such holes, one per protocol.

**ATProto.** `resolve_repo` (`server/src/xrpc.rs:128`) has four branches —
`did:plc`, `did:web`, handle, bare username — and filters `is_active` on none of
them. Its result flows unchecked into three public, unauthenticated endpoints:

| Endpoint | Handler | What a disabled member still serves |
|---|---|---|
| `com.atproto.repo.getRecord` | `:258` | any record |
| `com.atproto.repo.describeRepo` | `:309` | DID, handle, collections |
| `com.atproto.sync.getRepo` | `:348` | **the entire repo as a CAR** |

**Mastodon.** `public_timeline` (`server/src/mastodon_api.rs:327`) is
unauthenticated — it checks `wrong_host` and nothing else — and renders through
`local_author` (`:117`) and `fetch_note` (`:373`), both of which are bare
`db::find_by_username` calls with no status filter. A disabled member's public
notes keep appearing on `GET /api/v1/timelines/public`, bylined, to anonymous
callers.

So an admin disables a member for moderation reasons, watches their pod go to
404 and their actor stop resolving, and anyone on the internet can still
download their whole repository and read their posts on the public timeline. A
console that offers Disable without closing this is worse than one that offers
nothing, because it makes a promise the server does not keep.

**This spec closes both.** `.filter(User::is_active)` is the same idiom
`pod.rs:183` and `auth.rs:410` already use:

- **`resolve_repo`** takes the filter **inside the function**, on the value it
  returns, rather than at its call sites. It has **five** callers, not the three
  above: `:412` (`create_record`) and `:523` (`delete_record`) also use it for
  the "you may only write to your own repository" check. Filtering inside covers
  all five, and the effect on the two write paths is benign — `caller` already
  filters `is_active`, so a legitimate self-write still resolves, and a disabled
  target still produces the same 403 by a shorter route. Nothing in
  `server/tests/xrpc.rs` sets `status = 'disabled'`, so no existing test moves.
- **`local_author` and `fetch_note`** take the filter on their own
  `find_by_username` calls. `public_note_iris` is a store-index query with no
  notion of account status, so the filter has to sit in the Mastodon layer that
  resolves each note's owner.

This is scope the spec did not go looking for and cannot honestly decline: Goal
2 is not met by the ATProto fix alone.

**The firehose is a separate question and is not closed here.**
`subscribe_repos` (`xrpc.rs:660`) backfills commits with no user lookup at all,
deliberately — its doc comment borrows ADR 0016's reasoning: *"Ungated (ADR
0016): consumers connect to us, so there is nothing outbound to suppress."*

Whether a disabled member's commits should keep backfilling is a question about
per-account moderation, and ADR 0016 does not answer it — that ADR scopes the
global `FEDERATION_ENABLED` constant to ActivityPub delivery, and a global
switch has nothing to say about one member. So closing this is most likely a new
decision rather than a bug fix, and making it inside a UI spec would be setting
federation policy by side effect. It is recorded in Open questions, and — this is
the part that matters — **the confirmation copy says so**, rather than claiming a
completeness the server does not have.

## Goals

1. Disable, enable, promote, demote, delete and revoke-invite are all reachable
   from the console; four of them exist nowhere else.
2. Disabling means what the console says it means.
3. Irreversible and high-consequence actions are typed-confirm, not one click.
4. An instance cannot be left with no admin, from either entry point.
5. Invites can be seen and revoked, not only minted blind.

## Non-goals

Inherited wholesale from the 2026-09-09 spec — no federated moderation, no
analytics, no impersonation, no admin read access to pod contents, no email, no
bulk actions — plus:

- **Slice 3 is not here.** The actor index, display names in the list and
  account search are R3/R5 work. This spec's member list stays Postgres-only,
  for the reason ADR 0005 exists.
- **Slice 4 is not here.** Reports, rules and moderation actions are R6 state in
  the server-agent store as RDF. That is store-modelling work, it is Phase 8's
  blocker, and it gets its own spec. Mixing it in is how the admin surface
  becomes the only polished thing in the product — the failure mode the earlier
  spec named.
- **No forced password reset.** mycomyco has one; it mints a token and renders
  the raw value on screen for the admin to relay out of band. With no mail path
  there is no better option, and "no better option" is not "good": it puts a live
  credential in a page, a log and a scrollback. Deferred with the mail path.
- **No account creation from the console.** An admin mints an invite. That is
  the same action with the member's consent attached, and it already exists.

## Design

### The confirmation is the house pattern already

`delete_account` (`server/src/account.rs:511`) already makes a member type their
own username to delete their pod, with the comment "this is the one irreversible
action in the product, and it is reached from a nav tab." mycomyco generalises
exactly that into one `confirm_action.html` parameterised by label, target, form
action, warning text and button class.

Adopted as **one full page template, `confirm.html`, rendered by a single
`ConfirmPage` struct** — not as a `_`-prefixed partial. Askama's `{% include %}`
inherits the *including* struct's fields, so a partial would mean four page
templates (disable, promote, demote, delete) each carrying the same seven
fields, plus the partial itself: five files where one will do. A page template
has its own `<h1>` and satisfies
`every_template_has_one_h1_and_a_main_landmark` without needing the `_` escape
hatch at all. The 2026-09-09 spec's non-goals exist because the predecessor grew
thirteen admin templates; this is the cheapest place to not start.

The parameters carry **text, never HTML**. mycomyco's spec is explicit ("the
template receives `warning_text`, a plain string, not `warning_html`"), and it
matters more here: the warning is the only place the console explains an
irreversible act, so it is the field most likely to attract markup.

Every confirmed action is `GET` for the form and `POST` for the act. No
JavaScript, per §4.5, and a mistyped `POST` URL is a 405 rather than an action.

A mistyped confirmation answers **400**, matching `account.rs:513`, not
mycomyco's 422. The house pattern wins; the difference is noted so it does not
look like an oversight. There is no `render_with_status` helper — the tuple form
`(StatusCode::BAD_REQUEST, render(&page))` is what `account.rs:512` uses.

### Which actions are confirmed, and which are one click

| Action | Confirmed? | Why |
|---|---|---|
| Disable | **yes** | it 404s the member's pod and stops their actor resolving, immediately |
| Enable | no | it restores a previous state and is undone by the button next to it |
| Promote | **yes** | it hands over the console, and the recipient can then demote you |
| Demote | **yes** | it takes the console away, and rule 4 can make that unrecoverable |
| Delete | **yes** | irreversible, and it deletes a pod |
| End sessions | no | non-destructive; the member logs back in |
| Revoke invite | no | a spent credential; re-minting costs one click |

Disable being confirmed rather than a toggle departs from mycomyco, where
`disable_post` is a direct POST (`users.rs:731`). It is warranted by the table
above: on this server disable is not "cannot log in", it is "every URL under
`alice.example.org` returns 404 and your actor stops resolving." The
confirmation says that in those words — **and names the firehose exception**,
because an admin who wanted to stop someone being readable and was not told
about the backfill has been failed by the UI, not by their own carelessness.

### End sessions, which is not the same as disable

Slice 2 lists "revoke sessions" as a distinct action, and it is: a member whose
laptop was stolen needs their sessions ended without their account being
disabled.

`db::revoke_other_sessions` (`identity/src/db.rs:393`) cannot serve it — it
takes a `keep_token` to preserve the caller's own session, and an admin acting
on someone else has no token to keep and wants none kept. A new
`revoke_all_sessions(pool, user_id)` is the same query without the `<>` clause.

This is separate from disable, which needs no revocation at all: `auth.rs:410`
filters `session_user` on `is_active`, so a disabled member's cookies stop
resolving on their next request. Adding a revocation step to disable would be
dead code that looks load-bearing. That mechanism is also what makes promotion
take effect on open sessions, which
`promotion_reaches_a_session_that_is_already_open` (`server/tests/admin.rs:242`)
already pins.

### The two guards

**Self-action.** An admin cannot disable, demote or delete themselves.
mycomyco's `promote_post` and `demote_post` both open with
`if target.id == admin.user_id()`. Same rule here.

**Last admin.** `demote` and `disable` both refuse when the target is the last
active admin. `db::count_admins` (`identity/src/db.rs:429`) already counts
`role = 'admin' AND status = 'active'`, which is the right population — a
disabled admin cannot log in to undo anything.

mycomyco's implementation carries a long comment (`users.rs:545`) conceding this
branch is **unreachable**: the acting admin is necessarily an active admin, so
if the target is someone else the count is at least one, and if the target is
themselves the self-guard already returned. That reasoning is correct there and
worth not inheriting silently, because **it does not hold across brolly's two
entry points.**

`brolly-admin demote` has no acting admin. It authenticates on `DATABASE_URL`
and takes a username, so nothing constrains the target — the guard is live, and
`server/src/bin/admin.rs:152–156` already documents it as such. In the console
the same guard is defence in depth against a future entry point that weakens the
self-guard. Both are kept; the difference is written down so the next reader
does not delete the "unreachable" one.

**Delete needs no last-admin guard, and that is a conclusion rather than an
omission.** The self-guard already forbids deleting yourself, so the acting
admin survives every deletion and `count_admins` cannot reach zero. Unlike
demote, there is no second entry point to worry about: `brolly-admin` has no
delete verb. Stated because its absence, sitting beside two paragraphs of
careful reasoning about the other two verbs, otherwise reads as something that
was forgotten.

### The member detail page

`/admin/users/{id}`, keyed on the id `UserRow` already carries. Note that
`MemberView` (`server/src/admin.rs:172`) drops `id` when it maps the row, so the
list cannot link anywhere until that field is added — a one-line change in a
struct that exists.

Three regions, following mycomyco's shape minus what brolly cannot answer:

- **Facts.** Username, WebID, role and status as `.chip`s, created, `did:plc` if
  provisioned, and open session count via `db::count_sessions`
  (`identity/src/db.rs:380`).
- **Actions.** Disable/enable, promote/demote, end sessions, delete — each a
  link to its confirmation, or a direct POST where the table above says so.
  Actions the guards forbid are not rendered, and the handler re-checks anyway.
  Hiding a button is a courtesy; the guard is the control.
- **No activity timeline.** mycomyco merges `created_at`, `email_verified_at`,
  `last_login_at` and consent rows. A `last_login_at` column does exist
  (`migrations/20260820000000_identity_users.sql:25`) but **nothing writes it**,
  and neither `User` nor `UserRow` selects it. There is no email verification
  either. The merge would be one row, so it is omitted rather than stubbed.

**No display name**, for the reason ADR 0005 exists: it lives in the member's
pod, and opening a store to render it is the documented mistake. It arrives with
slice 3.

### Invites, and the fact that codes are hashed

`/admin/invites` lists what the `invites` table holds, with a mint form and a
revoke button per row.

The list cannot show the code. `invites.code_hash` is the primary key and the
plaintext is never stored, deliberately, for the same reason session tokens are
not. A minted code is visible exactly once, in the response to the POST that
minted it, and an admin who navigates away has lost it and must mint another.
That is the correct security posture and a genuinely awkward UI, so the mint
response says so in as many words.

Revocation cannot use `db::revoke_invite` (`identity/src/db.rs:301`), which
takes plaintext and hashes it. Rows are identified by `code_hash` — safe in a
form action because `hash_secret` is hex SHA-256 of a high-entropy random value,
so it is both URL-safe and irreversible. `redeem_invite` already checks
`revoked_at IS NULL`, so revoking by hash genuinely stops redemption rather than
only hiding a row.

`created_by` is `Option`, from two directions: the column is
`ON DELETE SET NULL` (`migrations/20260820000002_identity_invites.sql:8`), and
**both existing minters pass `None`** — `bootstrap` (`server/src/admin.rs:53`)
and `brolly-admin invite` (`bin/admin.rs:129`). So `InviteRow` carries
`Option<String>` from a LEFT JOIN, and the list renders "the instance" or
similar for an unattributed row. This is not an edge case: the bootstrap invite
is the first row on every new instance.

Each row shows created-by, created, expires, uses of max-uses, whether it grants
admin, and whether it is revoked. Spent and revoked invites stay listed rather
than disappearing: "who did I invite and when" is a question operators ask, and a
list that silently drops rows cannot answer it.

The mint form offers uses, expiry and an admin checkbox. The earlier spec's open
question — *should `--admin` invites be single-use by construction?* — **is
already answered in the shipped CLI**, which refuses rather than coerces:

```rust
if admin && uses != 1 {
    eprintln!("--admin invites are single-use; drop --uses");
    return ExitCode::FAILURE;
}
```
(`server/src/bin/admin.rs:123–126`)

The console refuses too, re-rendering the form with an error. Silently coercing
to 1 would make the two entry points disagree about the same rule, which is
worse than either behaviour alone.

### New database functions

| Function | Why it is new |
|---|---|
| `set_status(pool, user_id, status)` | sibling of `set_role` (`:442`), same reasoning about guards living with the caller |
| `revoke_all_sessions(pool, user_id)` | `revoke_other_sessions` (`:394`) requires a `keep_token` an admin does not have |
| `list_invites(pool) -> Vec<InviteRow>` | nothing lists invites today |
| `revoke_invite_by_hash(pool, code_hash)` | `revoke_invite` (`:301`) takes plaintext the console does not have |
| `find_row_by_id(pool, id) -> Option<UserRow>` | `find_by_id` (`:147`) returns `User`, which carries no `created_at`, and the detail page shows one |

`find_by_id` (`:147`), `count_sessions` (`:380`), `count_admins` (`:429`),
`set_role` (`:442`) and `delete_user` (`:480`) all already exist — listed to
record that they were checked rather than assumed.

`users.status` is `CHECK (status IN ('active','disabled'))`, and that constraint
is the only thing enforcing it — a typo reaches the database and returns a 500.
Constants do not fix that; they only make call sites share one spelling, which
is worth having and worth not overselling. `ACTIVE` and `DISABLED` join `ADMIN` and
`MEMBER` at `server/src/admin.rs:24–26`. A typo should not be a 500.

Admin deletion reuses `delete_account`'s order exactly (`account.rs:524` then
`:528`): `stores.delete_pod` first, then `db::delete_user`. Reversing it orphans
a pod directory whose owner no longer exists, and nothing would ever collect it.

**Nearby, and worth fixing while in the file:** the doc block reading "Delete a
user outright. / Sessions, invites, keys and OAuth grants cascade. The pod is a
separate `rm -rf` the caller performs…" sits at `identity/src/db.rs:407–411`,
runs straight into `count_users`' own doc at `:412`, and therefore **documents
`count_users` (`:417`)**. `delete_user` (`:480`) has no doc comment at all. So
this is a move, not a rewording — and the claim itself needs correcting on the
way past, because invites are `ON DELETE SET NULL`, not cascade.

That file is visibly mid-edit — there are further duplicated doc blocks around
`:243` and `:271–281` — so treat every line number cited into `identity/src/db.rs`
as needing a re-check at implementation time rather than trusting this spec's
copy of it.

### Routes

Added to the main router beside `lib.rs:141–142`. Those are two flat `.route()`
calls, **not** an apex-only group: there is no layer to add these to, unlike
`solid_oidc::apex_only` which wraps the OAuth router at `lib.rs:86–105`.

The comment at `lib.rs:138–140` gives two reasons these need no host guard, and
the second is the stronger one: the session cookie sets no `Domain`
(`auth.rs:413–419`), *and* `/admin/*` is already a reserved path on member
subdomains under ADR 0009 — `identity/src/routing.rs` asserts `/admin/users`
never reaches the LDP handler. The new routes inherit both.

Path parameters use **braces**: `server/Cargo.toml:34` pins `axum = "0.8.9"`,
which panics at startup on the `:id` form. Every existing parameterised route in
the workspace already uses braces — `lib.rs:179`, `mastodon_api.rs:1017`,
`xrpc.rs:759`.

```
GET  /admin/users/{id}                   detail
GET  /admin/users/{id}/disable           confirm
POST /admin/users/{id}/disable
POST /admin/users/{id}/enable            no confirmation
GET  /admin/users/{id}/promote           confirm
POST /admin/users/{id}/promote
GET  /admin/users/{id}/demote            confirm
POST /admin/users/{id}/demote
POST /admin/users/{id}/end-sessions      no confirmation
GET  /admin/users/{id}/delete            confirm
POST /admin/users/{id}/delete
GET  /admin/invites                      list + mint form
POST /admin/invites                      mint; the response is the only sight of the code
POST /admin/invites/{code_hash}/revoke
```

`tabs()` (`server/src/admin.rs:110`) gains an Invites entry. It maps an array of
`(&'static str, &'static str)` tuples and stays that shape.

Every handler calls `require_admin` first, as `overview` and `users` do. A
member gets the same 404 on all of them: this spec adds no new authorization
concept, only new things behind the existing one.

## Testing

### Existing tests this spec interacts with

`counting_admins_ignores_disabled_ones` (`server/tests/admin.rs:278`) already
asserts the population `count_admins` uses. It is not new work; the last-admin
guard builds on it.

`promotion_reaches_a_session_that_is_already_open` (`:242`) already pins the
per-request role read. The disable case extends it rather than duplicating it.

### The `brolly-admin` assertion needs test infrastructure that does not exist

Nothing in the workspace tests the binary. `set_role` (`bin/admin.rs:157`) is
private to a binary crate and cannot be called from an integration test, so the
CLI last-admin assertion means spawning
`Command::new(env!("CARGO_BIN_EXE_brolly-admin"))` against the testcontainer's
`DATABASE_URL` and reading the exit code. That is a small, standard harness, but
it is *new* — it should be planned as a task rather than assumed to be one line
in a table, and it is the first thing in the workspace that would exercise the
CLI at all.

### New assertions

| Assertion | Why |
|---|---|
| A disabled member's repo is not served by `getRecord`, `describeRepo` or `getRepo` | the ATProto hole; three endpoints because `resolve_repo` feeds all three |
| A disabled member's notes do not appear on `GET /api/v1/timelines/public` | the Mastodon hole; the same class, and it needs its own assertion because it is a different code path |
| An active member can still write to their own repo after the `resolve_repo` filter lands | the filter touches `create_record` and `delete_record` too; this is the regression it could cause |
| A member gets 404 on every new route, including the POSTs | the guard is the whole feature, and a POST-only hole is invisible in a browser |
| Disabling a member 404s their pod and stops their actor resolving | the two surfaces an admin will check by hand |
| A disabled member's open session stops resolving with no revocation call | it is why disable has no revocation code, and it would rot silently |
| Enabling restores all of it | otherwise disable is a one-way door dressed as a toggle |
| End-sessions ends a member's sessions and leaves their account active | the action that is not disable |
| An admin cannot disable, demote or delete themselves | 400, three separate cases |
| Demoting the last active admin is refused in the console | rule 4 where the self-guard makes it defence in depth |
| Demoting the last active admin is refused by `brolly-admin` | rule 4 where the guard is actually live — and see the harness note below |
| Disabling the last active admin is refused | the same unrecoverable state by a different verb — the case mycomyco does not have |
| A mistyped confirmation answers 400, re-renders with an error, and changes nothing | the "changes nothing" half is the one worth asserting |
| Deleting a member removes the pod directory *and* the row | either alone is a leak |
| A minted invite's plaintext appears in the mint response and never again | pinned so a later refactor cannot quietly store it |
| Revoking by `code_hash` marks the row and the code stops redeeming | the new function's whole job |
| The console **refuses** an admin invite with uses > 1, matching the CLI | the two entry points must agree |
| An invite with `created_by = NULL` renders without panicking | the bootstrap invite is row one on every new instance |
| Spent and revoked invites remain listed | a list that drops rows cannot answer "who did I invite" |

## Open questions

- **Does per-account moderation gate the firehose, and does ADR 0016's
  pull argument survive contact with it?** `subscribe_repos` (`xrpc.rs:660`)
  backfills with no user lookup, and its doc comment borrows ADR 0016's
  reasoning: consumers connect to us, so there is nothing outbound to suppress.
  Note that this is a borrowed *argument*, not a decision ADR 0016 actually
  made — that ADR scopes the global `FEDERATION_ENABLED` constant to ActivityPub
  delivery, and a global switch has nothing to say about one member. So this is
  most likely a **new decision** rather than a revision, and it is the most
  consequential item on this list. Until it is answered the disable confirmation
  copy names the gap rather than claiming a completeness the server lacks.
- **Does deleting a member with a `did:plc` need a tombstone?** Admin deletion
  inherits `delete_account`'s behaviour: the local PLC log rows cascade
  (`migrations/20260826000004_atproto_plc_log.sql:15`) and the DID stays live in
  the directory with nothing marking it dead. Pre-existing, but this spec gives
  it a second entry point.
- **Should the console mint an invite on someone's behalf?** `create_invite`
  takes `created_by: Option<Uuid>` and the console will pass the acting admin —
  the first caller ever to pass `Some`. Whether an operator should be able to
  attribute an invite to another admin is a question about audit, and there is no
  audit log yet to make it matter.
- **Should `delete` offer an export first?** A member deleting their own account
  is pointed at `/account/export`. An admin deleting someone else's cannot
  reasonably hand them the data, and offering it would be an admin reading a
  member's pod — an explicit non-goal. Recorded because the asymmetry looks like
  an oversight and is not.
