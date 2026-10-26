# Member quotas: set by an admin, seen by the member

<!-- doc-paths: skip -->
<!-- The spec names a migration and functions this work creates, so not
     every path it cites resolves until it's implemented. -->

**Status:** Draft, 2026-10-26. Brainstormed with the operator the same day
and revised the same day after one review against the tree, which found the
console list does not go through `User` at all (H4), one `SELECT` the column
list would have missed (H1), and three places the size grammar was looser
than its own examples (H2). Five decisions taken with the operator are
recorded under Decisions.
**Builds on:** `76e508f` (`feat(server): a pod has a quota`), which made the
pod's quota one instance-wide number — `BROLLY_POD_QUOTA_BYTES`, read once in
`main`, enforced by `pod::within_quota` on the three LDP write handlers and the
Mastodon upload.
**Depends on:** `docs/specs/2026-09-09-admin-console.md` (slice 1, shipped:
`require_admin`, `/admin/users`), `docs/specs/2026-09-10-member-dashboard.md`
(the overview and its cards), the same-origin form check (`3a90b5a`) and the
apex-only door group (`0a465e0`).
**Relation to the admin-actions spec:** `docs/specs/2026-09-10-admin-actions.md`
(slice 2) plans the console's account actions — disable, revoke, invites,
promote, demote, delete — and is unbuilt. This spec adds one action of its own
and does not pre-empt that one; it is the console's first write, and it takes
the shape slice 2 will take (a form per row, `require_admin`, a redirect back).

## Problem

`76e508f` gave every pod the same quota. That is the right default — the
quota exists to bound what one grant (a public inbox, a shared container) can
cost the instance, not to meter members — but one number for everyone is wrong
the first time it is wrong: the member who hosts the community's photo archive
needs more than a gibibyte, and the only way to give it to them today is to
raise the ceiling for everybody and redeploy. The reverse is as true: an
instance that wants a tighter default for new members but has one member with
a legitimate larger pod has no way to say so.

Three things follow from a per-member number, and none of them exists:

1. **Nowhere to keep it.** `users` (`migrations/20260820000000_identity_users.sql`)
   has no quota column; `AppState.pod_quota_bytes` is the whole story.
2. **No way to set it.** The console is read-only (`server/src/admin.rs`
   has `overview` and `users` and nothing else); `brolly-admin` has `invite`,
   `promote`, `demote`, `plc-retry`, `blob-sweep`, `whoami`
   (`server/src/bin/admin.rs`).
3. **No way to see it.** The member overview shows `pod_bytes` as a bare
   number of bytes (`server/templates/account/overview.html:35`) with no
   ceiling beside it, so a member's first notice of their quota is a 507.

## Goals

- **One effective quota per member,** decided in one place: the member's
  override if an admin set one, else the instance default.
- **An admin sets it from the console or the CLI,** in human sizes, and can
  clear it back to the default.
- **The member sees usage against it** on their overview, before a 507 does
  the telling.
- **No new query on the write path.** The write handlers already hold the
  member's row; the override rides on it.
- **The console's first write action takes the shape its later ones will:**
  `require_admin`, a form per row, the same-origin and apex-only guards,
  a redirect back to the list.

## Non-goals

- **An instance default editable at runtime.** The default stays
  `BROLLY_POD_QUOTA_BYTES` (Decisions, D1).
- **An "unlimited" value.** An admin who wants no effective cap sets a large
  number (Decisions, D3).
- **Quota history** beyond who last set it and when.
- **Per-container, per-protocol or per-media-type quotas.** One number per
  pod, measured as the pod's directory on disk, as `76e508f` defined it.
- **Telling a member when an admin changes theirs.** There is no mail path,
  and the overview shows the new number on the next load.
- **Advertising the quota to Solid clients** in the storage description.
  There is no standard predicate for it; revisit if one appears.
- **A CLI test harness.** `brolly-admin` has none today; the new verb is thin
  over a tested function and stays that way.
- **Changing what the quota measures or how a 507 reads.** Both are
  `76e508f`'s and unchanged.

## Design

### H1. The number lives on the user row

A migration, `migrations/<timestamp>_identity_user_quotas.sql`, adds to
`users`:

```sql
quota_bytes   BIGINT      NULL,   -- NULL: the instance default applies
quota_set_at  TIMESTAMPTZ NULL,
quota_set_by  UUID        NULL REFERENCES users(id) ON DELETE SET NULL
```

`quota_bytes` is `NULL` or a non-negative count; a `CHECK (quota_bytes IS NULL
OR quota_bytes >= 0)` says so in the schema. `quota_set_by` is the admin who
set it through the console, `NULL` when the CLI did (the CLI is the database,
not a person); `ON DELETE SET NULL` so deleting an admin does not delete the
fact that a quota was set.

`User` (`identity/src/db.rs`) gains `quota_bytes: Option<i64>`. Four
`SELECT`s in `db.rs` list the user columns by hand — `find_by_username`,
`find_by_id` (the Mastodon id resolver, ADR 0015), `find_by_email`, and
`user_for_session` — and a fifth copy is how one gets missed (the first
draft of this spec missed `find_by_id`), so this chunk puts the list in one
`const USER_COLUMNS: &str` and uses it from all four. Nothing constructs
`User` literally (it is `sqlx::FromRow` only), so the new field is a
one-place change.

The console's member list is a different row. `admin::users` calls
`db::list_users` → `Vec<UserRow>`, a lighter struct with its own `SELECT`,
projected into `MemberView` for the template. `UserRow` gains three fields
in that one `SELECT` — `quota_bytes: Option<i64>`, `quota_set_at:
Option<OffsetDateTime>`, `quota_set_by: Option<String>` (the setter's
username, by a self-join on `users`) — so the list page's quota, chip and
provenance are one query for every row, not one per row.

**Effective quota is one function:**

```rust
impl User {
    /// The member's quota: an admin's override if there is one, else the
    /// instance default. The only place the two are combined.
    pub fn quota(&self, instance_default: u64) -> u64
}
```

A negative stored value cannot occur (the `CHECK`), and the conversion from
`i64` saturates at zero rather than failing, so the function is total.

Two store functions:

```rust
/// Set or clear a member's override. `None` clears it; `set_by` is the
/// admin acting through the console, `None` for the CLI.
pub async fn set_quota(pool, user_id: Uuid, quota_bytes: Option<i64>, set_by: Option<Uuid>) -> Result<(), DbError>

/// Who set a member's override and when — the CLI's readback, since `User`
/// carries the number but not the provenance. The console reads the same
/// facts off `UserRow` instead, one query for the whole list.
pub async fn quota_provenance(pool, user_id: Uuid) -> Result<Option<QuotaProvenance>, DbError>
// QuotaProvenance { set_at: OffsetDateTime, set_by: Option<String> /* username */ }
```

`set_quota` takes `i64` because the column is `BIGINT`; `parse_size` (H2)
never yields more than `i64::MAX`, and the two call sites convert with
`i64::try_from(..).unwrap_or(i64::MAX)` — saturating, so total, and in
practice never saturating. `set_quota` writes all three columns in one
statement; clearing sets all three to `NULL`. `quota_provenance` joins
`users` to itself for the setter's username and returns `None` when there is
no override.

### H2. Sizes are parsed and printed in one place

`domain/src/media.rs` gains:

```rust
/// "5G", "512M", "100K", "5GiB", "512 MiB", "1.5G", "1024" — a number with
/// an optional decimal fraction, then a binary unit (K, M, G, T; case-
/// insensitive; an optional "iB" or "B" after it; whitespace tolerated
/// between number and unit), or plain digits for bytes. The result is
/// rounded down to a whole byte. Nothing else parses.
pub fn parse_size(text: &str) -> Result<u64, SizeError>

/// The inverse for display: the largest binary unit not exceeding the
/// value; printed whole when the value is an exact multiple of it, else to
/// one decimal — "5 GiB", "512 MiB", "1.5 GiB", "412.5 MiB", "1023 B",
/// "0 B". Always a string `parse_size` accepts.
pub fn format_size(bytes: u64) -> String
```

`SizeError` names the one thing wrong: empty, not a number, unknown unit, or
too large — the ceiling is `i64::MAX`, because the column is `BIGINT` and no
larger number is a meaningful quota. Negative numbers are "not a number":
the grammar has no sign. A fraction on input is allowed so that every string
`format_size` prints parses back: the console prefills the field with the
formatted override, and an admin who saves a row untouched must not be
refused a value the system itself displayed. Saving a displayed value sets
the displayed value — within half a unit's tenth of what was stored, which
is the precision the display promised. The console field, the CLI argument,
the CLI's readback, the console cell and the member overview all go through
these two, so a number reads the same everywhere it appears. The word
`default` is not a size: the console clears on an empty field and the CLI on
the literal word, and each surface handles that before calling `parse_size`.

### H3. Enforcement reads the row it already has

`pod::within_quota` (`server/src/pod.rs`) changes from
`(state, user: Uuid, incoming)` to `(state, user: &User, incoming)` and
compares against `user.quota(state.pod_quota_bytes)` instead of
`state.pod_quota_bytes`. Its four callers already hold the row: the three
LDP write handlers through `request.user`, the Mastodon upload through
`user`. No query is added to any write.

Everything else about enforcement is `76e508f`'s and unchanged: measured
from the pod's directory, the incoming body counted in full, 507 in each
surface's own error shape, fail-open on a size that cannot be read.

**Lowering below usage.** An admin who sets a member's quota below what the
pod holds refuses that member's next write that would add bytes, until they
are under it. Nothing is deleted and nothing is refused that does not add:
a `DELETE` always runs, and that is how the member gets back under. The
console shows usage beside the field (H4) so the admin sees what they are
setting against.

### H4. The console: a form per row

`/admin/users` (`server/templates/admin/users.html`) gains a **Quota**
column. Each row shows:

- the effective quota, formatted (`format_size`), from `UserRow.quota_bytes`
  or the instance default;
- a chip: `default`; `set by @nikolas, 26 Oct 2026` when the console set it;
  `set 26 Oct 2026` when the CLI did (`quota_set_by` is `NULL`) — all from
  `UserRow`, no query per row;
- current usage, formatted, from `stores.pod_bytes` — so the admin sets a
  number against what the member holds — or the word `unknown` when the
  directory cannot be read (the overview's `unwrap_or(0)` would show a full
  pod as empty; a console that is about to set a limit should not);
- one form: a text input named `quota` prefilled with the override formatted
  (empty when there is none), a Save button, posting to
  `POST /admin/users/{username}/quota`.

The handler, `admin::set_quota`:

1. `require_admin` — a member gets the 404 the console gives members
   everywhere, anonymous is sent to log in and back.
2. Resolve `{username}`; unknown is 404.
3. Empty (after trim) clears the override; otherwise `parse_size`. A
   `SizeError` re-renders the users page as 400 with the message against
   that row and the bad value kept in the field, and sets nothing.
   `MemberView` gains `quota_error: Option<String>` and `quota_entered:
   Option<String>` for that one row; the error path re-runs `list_users`
   and the usage walks, as a page load does — so a bad save walks every
   pod twice, once for the page the admin was on and once for the
   re-render. That is the cost of keeping the error against the row, and
   at D16's scale it is a page load, not a problem.
4. `db::set_quota(user.id, value, Some(admin.id))`.
5. 303 to `/admin/users`.

Routing: the route joins the apex-only `door` group in `lib::app`, beside
`/admin` and `/admin/users`. The same-origin check (`3a90b5a`) keys on
`SAME_ORIGIN_FORMS`, an exact-path list; this action's path carries a
username, so the list gains its first prefix entry — `/admin/users/` — and
`same_origin` matches a prefix entry by `starts_with`. The ui_invariants test
that reads every `<form method="post">` out of the templates learns that an
action containing `{{ … }}` is matched by its literal prefix against a prefix
entry, so a templated action still has to be listed.

**Cost.** `pod_bytes` is a directory walk, one per row. At D16's scale
(thousands of members, not tens of thousands) a console page that walks
every pod is acceptable, and it is the honest number — the one the writes
are held to. `UserRow`'s doc comment calls a per-row store open "the exact
mistake ADR 0005 exists to prevent"; the walk reads the directory, not the
store — no pod is opened, no LRU slot taken — and chunk 3 amends that comment
to draw the line. If the walk ever is too much, the figure the index keeps
(ADR 0005, R5) is the place for a cached one; this spec does not build that.

### H5. The CLI: `brolly-admin quota`

```
brolly-admin quota <username>                 print the effective quota
brolly-admin quota <username> <size>          set an override
brolly-admin quota <username> default         clear it
```

Without a size: prints `@alice: 5 GiB (set 2026-10-26)` or
`@alice: 1 GiB (instance default)`. With one: sets it through
`db::set_quota(user.id, …, None)` and prints the same line for the new
state. `<size>` goes through `parse_size`; a bad one prints `SizeError`'s
message and exits non-zero. Unknown username exits non-zero. `USAGE` in
`server/src/bin/admin.rs` gains the verb and `docs/deploying.md`'s
"Afterwards" list gains a line for it.

### H6. The member overview: usage against quota

`account::overview` (`server/src/account.rs`) already computes `pod_bytes`;
it adds `quota_bytes: session.user.quota(state.pod_quota_bytes)` and the
template's "Data stored" row (`overview.html:34`) becomes:

```html
<dd>
  <meter min="0" max="{{ quota_bytes }}" value="{{ pod_bytes }}"
         high="{{ warn_at }}">{{ used }} of {{ quota }}</meter>
  {{ used }} of {{ quota }}
</dd>
```

`used` and `quota` are `format_size` strings; `warn_at` is 90% of the quota,
so the native rendering turns when a member is close. No `low`: there is no
"too little" storage. `<meter>` is native, needs no script, and is styled
from the token layer only — one rule in `server/static/brolly.css`, no
literal colours (the ui_invariants gate). The text beside the meter carries
the same words, so a screen reader and a text browser read the same thing a
sighted member sees. A member an admin has set below their usage sees the
meter full and the text honest — `1.2 GiB of 1 GiB` — which is the state H3
describes: nothing deleted, adds refused until they are under.

## What this changes in the code

| Where | What |
|---|---|
| `migrations/<ts>_identity_user_quotas.sql` | three columns, one `CHECK` |
| `identity/src/db.rs` | `User.quota_bytes`, `User::quota`, `USER_COLUMNS` (used by `find_by_username`, `find_by_id`, `find_by_email`, `user_for_session`), `UserRow`'s three quota fields and the self-join in `list_users`, `set_quota`, `quota_provenance`, `QuotaProvenance` |
| `domain/src/media.rs` | `parse_size`, `format_size`, `SizeError` |
| `server/src/pod.rs` | `within_quota(state, &User, incoming)` |
| `server/src/mastodon_api.rs` | the upload's call site |
| `server/src/admin.rs` | `set_quota` handler; `MemberView` gains quota, provenance, usage, and the per-row `quota_error`/`quota_entered` for the 400 re-render |
| `server/templates/admin/users.html` | the Quota column and its form |
| `server/src/lib.rs` | the route in the door group; a prefix entry in `SAME_ORIGIN_FORMS`; `same_origin` matches prefixes |
| `server/tests/ui_invariants.rs` | templated form actions matched against prefix entries |
| `server/src/bin/admin.rs` | the `quota` verb, `USAGE` |
| `server/src/account.rs`, `server/templates/account/overview.html`, `server/static/brolly.css` | usage against quota, the meter |
| `docs/deploying.md` | the CLI verb; a sentence under `BROLLY_POD_QUOTA_BYTES` that it is the default an admin can override per member |

## Chunks

Four, one commit each, every one deployable:

1. **The number.** Migration, `User.quota_bytes`, `User::quota`,
   `USER_COLUMNS`, `set_quota`, `quota_provenance`; `parse_size` and
   `format_size`; `within_quota` takes the `User`. Tests: sizes; the store
   round-trip; the pod and Mastodon enforcement honouring an override set
   directly in the database. *First because every surface reads it, and
   because it is the one chunk that touches the write path.*
2. **The CLI.** The `quota` verb. *Second because it gives an operator the
   ability before the console does, and it is thin.*
3. **The console.** `UserRow`'s three quota fields and the self-join in
   `list_users` (their only consumer is here, which keeps chunk 1 to the
   write path); the column, the form, the handler, the route, the prefix
   entry in `SAME_ORIGIN_FORMS`, the invariant's prefix rule. Tests:
   set, clear, bad size, member 404, cross-origin 403, listed-forms
   invariant.
4. **The overview.** The meter. Tests: "of" the effective quota, override
   and default.

## Decisions

Taken with the operator on 2026-10-26.

| # | Decision | Why |
|---|---|---|
| D1 | Per-member override plus the env-var default; the default is not editable at runtime | Covers "this member needs more" without touching the deployment; a runtime default is a second configuration surface nobody asked for |
| D2 | Both the console and the CLI | The console is where an admin already looks at members; the CLI is for the operator without a session |
| D3 | No "unlimited" sentinel | A second meaning for one column; the first bug it causes is `0` meaning "nothing" to the code and "unlimited" to a person. A large number does the job |
| D4 | Members see usage against quota | A member near the limit learns it before a 507 does; the same number the writes enforce |
| D5 | The override lives on `users`, not its own table | Every write already loads the row, so enforcement costs no query; operational state belongs in Postgres (D2/D5 of the plan); last-set provenance is enough history |

## Testing

Every test is written before the code it tests, and watched fail.

- **Sizes** (`domain`): `parse_size` accepts `5G`, `5g`, `5GiB`, `512 MiB`,
  `100K`, `1.5G`, `1024`, `0`; refuses `""`, `-1`, `5X`, `G`, `1.5`
  (a fraction of a byte is nothing), and `99999999999G` (over `i64::MAX`);
  `format_size` prints `5 GiB`, `512 MiB`, `1.5 GiB`, `412.5 MiB`, `1023 B`,
  `0 B`; every string `format_size` prints is accepted by `parse_size`, and
  a whole number of a unit round-trips exactly.
- **The row** (`identity`): `set_quota` then `find_by_username` reads the
  override; clearing reads `None`; `quota_provenance` names the setter and
  `None` for the CLI; deleting the setter keeps the quota and loses the name.
- **Enforcement** (`pod_http`, `mastodon_compose`): default 2 MiB, alice's
  override 4 MiB → a third mebibyte fits; override 1 MiB below usage → the
  next add is 507 and a `DELETE` still runs and makes room; the upload
  honours the override the same way.
- **The console** (`admin`): an admin sets `5G` and the row reads `5 GiB`,
  `set by @…`; a CLI-set override reads `set <date>` with no name; blank
  clears it and the row reads `default`; `5X` is a 400 with the message and
  nothing set; a member's POST is 404; a cross-origin POST is 403; an unknown
  username is 404. That the list is one query however many members is true
  by construction — one `sqlx::query_as` with a self-join — and is checked
  by reading `list_users`, not by a test: there is no SQL-log capture in the
  workspace, and building one for a property a reviewer can see is not
  worth a harness.
- **The invariant** (`ui_invariants`): the quota form's templated action is
  matched by its prefix; removing the prefix entry fails the test.
- **The overview** (`dashboard`): reads `… of 1 GiB` with the default and
  `… of 5 GiB` with an override; the meter's `max` is the effective quota.
