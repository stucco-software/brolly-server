# Admin console

**Status:** Draft (2026-09-09)
**Plan:** §4.1 audience table, §4.4 phase 5–7 UI deliverable, §4.5 UI invariants.
**Depends on:** ADR 0005 (R5, R6), ADR 0011 (scope vocabulary), ADR 0016 (what
the federation switch actually governs).

## Problem

Phases 5–7 are shipped, and the admin console was their UI deliverable. It does
not exist. Nothing is mounted at `/admin`, and the gap is wider than a missing
page:

- **`role` is inert.** The column exists with `CHECK (role IN ('member',
  'admin'))`, but registration hardcodes `"member"` (`server/src/auth.rs`), and
  `User::is_admin()` has exactly one caller in the workspace — a test asserting
  it returns false. Nothing grants the role and nothing reads it.
- **There is no bootstrap.** Registration is invite-only, invites come from
  `brolly-admin`, and `brolly-admin` authenticates on `DATABASE_URL`. The first
  account on a new instance therefore requires shell access to the box. That
  works, but it means an instance cannot be handed to an operator who should not
  have a database credential — which is precisely the "turnkey into a community"
  case (D1).
- **There is no moderation state at all.** No reports, no rules, no domain
  blocks, in any store.

That last point is what makes this urgent rather than cosmetic. Phase 8 —
"Federation on" — lists *allow/block lists* and a *moderation surface* among its
deliverables, before `FEDERATION_ENABLED` flips. There is nowhere to put them.
The admin console is on Phase 8's critical path, not parallel to it.

## Goals

1. `role` means something: a guard that admin surfaces actually consult.
2. A new deployment can mint its first admin without a database credential.
3. The moderation state Phase 8 needs has a home, in the place ADR 0005 already
   assigned it.
4. The console follows the same rules as the member dashboard — server-rendered,
   works without JavaScript, one stylesheet, AA in both themes.

## Non-goals

Stated explicitly, because this surface historically grew until it was the only
polished thing in the product (plan §4, the 13-template predecessor).

- **No federated moderation.** Remote reports, remote suspensions and instance
  defederation are Phase 8's, once there is a remote to moderate.
- **No analytics or dashboards.** Instance counters exist for NodeInfo (R8);
  the console reads them, it does not grow charts.
- **No user impersonation, and no admin read access to pod contents.** An admin
  can disable an account and see what the index already holds about it. Reading
  a member's private graphs is a WAC decision, and the answer is no.
- **No email.** Notification of a moderation action is out of scope until there
  is a mail path at all.
- **No bulk actions.** One user, one decision. Bulk tooling is how a console
  acquires the ability to do irreversible things quickly.

## Design

### Who is an admin

`role` stays a column on `users` rather than becoming a permission table. Two
roles, checked directly. A permission system is the right answer at the point
there is a third role with a partial grant, and it is the wrong answer now —
ADR 0005's R6 puts moderation *state* in the server agent, so the thing a
permission table would guard is a handful of routes, not a matrix.

The guard is a sibling of the one the dashboard already uses. `require_session`
in `server/src/account.rs` redirects an anonymous visitor to the login form;
`require_admin` wraps it and answers **404, not 403**, for a signed-in member
who is not an admin. 403 confirms the surface exists and that the visitor found
a real URL; on an instance where the admin set is one person, that is a
disclosure with no upside. An admin who mistypes a URL gets the same 404 as
anyone else, which is a cost worth paying.

### Bootstrap

Three mechanisms, in order of who they serve:

1. **`brolly-admin promote <username>` / `demote <username>`.** The operator
   with a shell. Demote refuses to remove the last admin, because an instance
   with no admin cannot recover without a database credential — the state this
   whole section exists to avoid.
2. **`brolly-admin invite --admin`.** Mints an invite that grants `admin` on
   redemption. This is what lets an operator hand over an instance: the invite
   is a one-time credential that is useless after redemption, unlike a database
   password. It requires a new nullable `grants_role` column on `invites`.
3. **A logged bootstrap invite.** On every start, an instance with zero users
   mints a single-use admin invite and logs it at `warn`. The operator copies it
   out of the logs and registers. This is the turnkey path, and it is the only
   one that works on a platform deploy where there is no shell.

   The alternative — opening registration while the instance is empty — was
   rejected. It leaves a window in which whoever finds the URL first owns the
   instance, and that window is as long as the operator's attention span. A code
   in the logs closes it: reading it requires access you already need to deploy.

   Minting on *every* start, rather than once, is deliberate. An operator who
   misses the line on first boot can restart to get another; the invites stop
   the moment anybody registers, which is the condition the test pins.

### Where moderation state lives

ADR 0005 already decided this and it is easy to get wrong: **R6 (reports, rules,
actions) is authoritative instance state in the server-agent store**, as RDF —
not a Postgres table. It is explicitly exempt from the `instance-reindex`
rebuild, because it never existed in a pod and cannot be derived from one.

This spec does not relitigate that. It does mean the moderation slice is
store work rather than a migration, and it should be scheduled with that in
mind — it is not the cheap part.

The one thing that *does* want a migration is `invites.grants_role`, above.
`users.role` already exists.

### The admin user list (R5)

R5's index shape is `⟨actor IRI, handle, display name, created, status⟩`. Four
of those five are columns on `users` today. `display_name` is not — it lives in
each member's pod, and it is the exact case ADR 0005 cites as the reason the
index exists at all ("the `profile_display_name` case": the predecessor's admin
list could not open 500 stores to render a table).

`store/src/index.rs` currently records notes only. R3 and R5 both need an actor
index and it does not exist yet. The first slice of the console therefore lists
what Postgres can answer alone — handle, created, status, role — and leaves
display name to the slice that builds the actor index, rather than opening a
store per row to get it. Doing it the other way is the documented mistake.

### Slices

Each is independently deployable, per the trunk-based rule that `main` is always
shippable.

| Slice | Contents | Blocks |
|---|---|---|
| **1 — identity** | `require_admin`, promote/demote, `--admin` invites, first-run bootstrap, `/admin` shell, users list from Postgres | everything below |
| **2 — actions** | disable / re-enable an account, revoke sessions, invite management (list, revoke) | — |
| **3 — actor index** | R3 + R5 index, display names in the list, account search | Mastodon directory |
| **4 — moderation** | R6 in the server agent: reports, rules, actions | Phase 8 |

Slice 4 is the one Phase 8 waits on. Slices 2 and 3 are independently useful and
can be reordered against it.

## Information architecture

`/admin`, tabbed like the dashboard, reusing its `_tabs.html` shape:

```
/admin              overview — counts, instance posture, federation switch state
/admin/users        the member list; one row per account
/admin/users/{id}   one account: identity, status, sessions, actions
/admin/invites      outstanding invites; mint and revoke
/admin/reports      slice 4
/admin/rules        slice 4
```

The overview names the federation switch's current value, because "is this
instance talking to anyone" is the single most consequential fact about a
deployment and it is currently only discoverable by reading
`adapters/activitypub/src/federation.rs`.

Admin lives at the apex only. On a member subdomain `/admin` is pod storage or a
404 by ADR 0010, and the reserved-path test in `identity/src/routing.rs` already
asserts `/admin/users` never reaches the LDP handler.

## Testing

Beyond the §4.5 UI invariants, which `server/tests/ui_invariants.rs` applies to
every template automatically:

| Assertion | Why |
|---|---|
| A member gets 404 on every `/admin` route | the guard is the whole feature |
| An anonymous visitor gets the login redirect, not a 404 | otherwise the login form is unreachable from a bookmarked admin URL |
| The bootstrap invite produces an admin on an empty instance | the turnkey path works at all |
| No bootstrap invite is minted once anybody has registered | otherwise every restart mints a fresh key to the instance |
| `demote` refuses the last active admin | the unrecoverable state |
| A disabled admin does not count toward that total | a disabled admin cannot log in to undo anything |
| An `--admin` invite grants the role exactly once | a redeemed invite is spent |
| Promotion is visible to an already-signed-in session | the role is read per request, not cached in the cookie |

The last one is the sharp edge: sessions resolve to a `User` on every request
(`db::user_for_session`), so a promoted member gains the console without
re-authenticating and a demoted one loses it immediately. That is the behaviour
we want, and it is worth a test that pins it rather than leaving it incidental.

## Notes from implementation

- **`admin` and `root` are reserved usernames.** `validate_username` refuses
  both, along with `api`, `oauth`, `www`, `mail`, `support` and `brolly` —
  usernames become subdomains, so the reservation is a routing concern rather
  than a cosmetic one. The first admin therefore cannot be called `admin`. Worth
  knowing before you stand an instance up and try the obvious name twice.
- **The instance's own identity is configuration now.** `BROLLY_INSTANCE_NAME`
  and `BROLLY_INSTANCE_DESCRIPTION` replaced thirteen hardcoded `"Brolly"`
  literals across the auth, dashboard, consent and Mastodon-metadata surfaces.
  One image serves many deployments; every one of them was previously claiming
  to be the flagship. The name falls back to the base domain, which is never
  wrong.

## Open questions

- **Should `--admin` invites be single-use by construction?** `create_invite`
  takes a `uses` count. An admin invite with `--uses 5` is probably a mistake
  rather than an intent; the CLI could refuse it. Leaning yes.
- **Does disabling an account stop its pod from serving?** `status = 'disabled'`
  currently gates login (`User::is_active`), but a disabled member's pod is
  still readable by anyone the ACLs allow, and their actor document still
  resolves. Slice 2 needs an answer; it is a moderation semantics question, not
  a UI one.
