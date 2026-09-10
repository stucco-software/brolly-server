# The member dashboard — how it talks to people

**Status:** Draft (2026-09-10)
**Plan:** §4.2 (server-rendered Askama, progressive enhancement, islands not an
app shell), §4.5 UI invariants.
**Reference:** solidid's account surface — `src/routes/profile/`.
**Sequenced with:** [`2026-09-10-the-door.md`](2026-09-10-the-door.md) (deletes
`.card`, restructures `base.html`) and
[`2026-09-10-admin-actions.md`](2026-09-10-admin-actions.md) (owns the admin
member detail page). See "Ordering" below.

## Problem

The member dashboard is feature-complete and its feedback is *nearly*
consistent. Overview, profile, security, apps, export and delete all exist and
all work. Two of the three mutating actions already do the right thing:

| Action | Success path | Verdict |
|---|---|---|
| `profile_submit` (`account.rs:195`) | `Redirect::to("/account/profile?saved=true")` (`:227`) | correct |
| `change_password` (`:293`) | `Redirect::to("/account/security?saved=true")` (`:333`) | correct |
| `revoke_app` (`:393`) | `Redirect::to("/account/apps")` (`:408`) | **no parameter, so no feedback** |

So POST-redirect-GET with `?saved=true` is already the house pattern, there is
already a shared `Saved` query type (`:156`), and exactly one action drifts from
it. That one matters because of what it is: you click Revoke on an application
that has access to your pod — a security action — and the page comes back
looking almost the same, with no statement that anything happened. The row is
simply gone.

The rest of the gap is presentation, and it is real but smaller than it looks:

- **Empty states dead-end.** `apps.html` says "You have not authorised any
  applications yet." and stops. solidid, in the same situation, says what to do
  next: "StuccoID has not been used for any applications yet. Browse the App
  Store to get started." One is a fact about the database; the other is
  addressed to a person.
- **There is no vocabulary for state.** `admin/users.html` renders `role` and
  `status` as bare table text — the strings `member` and `active`, straight from
  Postgres. solidid marks status with `<mark>`, which is both a visual chip and
  the correct element for "this is the relevant bit."
- **One page is one panel.** Every dashboard page wraps its content in a single
  `.dashboard-panel`. That is right for profile, which is one form, and wrong
  for security, which is a password form *and* a session count — two unrelated
  concerns with no seam between them. solidid's settings page is three separate
  cards for exactly this reason.

## Goals

1. `revoke_app` says what it did, using the pattern the other two already use.
2. A page with two concerns can show two objects.
3. Empty states name the next step.
4. Status is a chip, not a bare string.

## Non-goals

- **No new dashboard features.** Everything here already exists. This is
  presentation and copy. Two consequences are decided rather than deferred, in
  "What this does not add" below.
- **No new notice vocabulary.** `?saved=true` and the `Saved` extractor stay
  exactly as they are. An earlier draft of this spec proposed a `?ok=<slug>`
  scheme on the premise that the three actions used three patterns; they use
  two, and a slug map would have *introduced* the second name for an event that
  already has one.
- **No nav change.** solidid uses a left `<aside>` rail; the tabs stay.
  solidid's rail is three flat links and reads as a SvelteKit layout convenience
  rather than an IA decision. Note that `account/_tabs.html` and
  `admin/_tabs.html` are two near-identical files, not one shared partial —
  the shape is common, the file is not — so this non-goal is also declining to
  unify them, which is separate work.
- **No SPA, no app shell.** §4.2, and it is not close.
- **No membership or billing.** solidid's settings page leads with a Stripe
  membership card. There is no billing in this product.

## Design

### The one drift

`revoke_app` is changed to redirect to `/account/apps?saved=true`, and
`apps.html` gains the same `.notice` the other two pages already render, with
its own sentence: "Access withdrawn." Same parameter, same extractor, different
sentence — which is already how profile ("Profile saved.") and security
("Password changed. Other sessions have been signed out.") differ from each
other.

The handler needs two small additions it does not have: `apps`
(`account.rs:363`) takes no `Query` extractor, and `Apps` has no `saved` field.
Both are copies of what `profile_form` already does with `Saved`
(`account.rs:157`).

`.notice` with `role="status"` is right and stays: `status` is a polite live
region, so a screen reader announces the confirmation without interrupting.
Errors keep `role="alert"`, which is assertive, as `delete.html:14` already does.

### Cards, from solidid

`.dashboard-panel` gains a sibling: `.dashboard-card` — a bordered box with a
`<header>` holding the heading and a rule under it, a `<section>` holding a
`<dl>`, and an optional `<footer>` holding the actions. That is solidid's
`.card`, under a different name.

**The name is not incidental.** The door spec deletes `.card`, `.card-grid`,
`.card h2`, `.card p` and `.card-feature` (`brolly.css:294–311`) along with
`landing.html`. Introducing solidid's card as `.card` would point that deletion
at a live rule. `.dashboard-card` is unambiguous whichever spec lands first.

Card headings are `<h2>`. solidid's card `<header>` holds an `<h1>`, which is
fine in a Svelte component and wrong here —
`every_template_has_one_h1_and_a_main_landmark` counts `<h1>` textually, and the
page's own `<h1>` already exists. This is the detail most likely to be copied
wrong from the reference.

**The card replaces `.dashboard-panel`; it does not nest inside it.** A panel
inside a card, or a card inside a panel, is a wrapper that exists only because
neither was retired. So `.dashboard-card` takes over the measure cap that
`.dashboard-panel` carries today (`max-width: var(--measure)`, `brolly.css:428`),
and `.dashboard-card-wide` replaces `.dashboard-panel-wide` (`:433`) — which
exists solely to defeat that cap for the admin member table, since a table is
not prose and does not want a reading measure. Once every page is converted,
`.dashboard-panel` and `.dashboard-panel-wide` are dead and are deleted.

Every page converts, so none is left as the odd one out:

| Page | Cards |
|---|---|
| `account/overview.html` | one — the facts |
| `account/profile.html` | one — the form |
| `account/security.html` | **two** — Password, Sessions |
| `account/apps.html` | one, holding the list |
| `account/delete.html` | one |
| `admin/overview.html` | one |
| `admin/users.html` | one `.dashboard-card-wide`, holding the table |

The `<dl>` inside is `.facts`, which already exists (`brolly.css:465`) and is
already how `account/overview.html` renders WebID, storage root and DID. solidid
puts a rule under each `<dd>`; `.facts` uses spacing instead. The rule is
adopted — it is what makes a long fact list scannable, and it is one property.

### Status chips

A `.chip` class, rendered as `<mark>`, for role and status. `<mark>` rather than
`<span class="chip">` because it is the element for "this run of text is
relevant," so the distinction survives with CSS off — the same argument as
`<strong>` over a bold class.

**Only the exceptional value is marked.** `member` and `active` are the default
state of almost every row, and marking them makes everything marked, which is
the condition `<mark>` exists to distinguish itself from. They render as plain
text. Two modifiers, and no chip at all otherwise:

| Value | Rendering | Tokens |
|---|---|---|
| `role = admin` | `<mark class="chip chip-admin">admin</mark>` | `--accent` / `--accent-fg` |
| `status = disabled` | `<mark class="chip chip-disabled">disabled</mark>` | `--destructive` / `--destructive-fg` |
| `role = member`, `status = active` | plain text | — |

`--accent` rather than `--wash-feature` for the admin chip, because `.notice`
already uses `--wash-feature` (`brolly.css:481`) and the two can appear on the
same page — a success notice and a role chip in the same yellow would read as
related. All four tokens are defined in both themes; none is new.

The modifier classes are what makes the disabled case assertable: a test can
look for `chip-disabled` rather than trying to infer a colour. And the claim
that an operator scanning the member list finds the account they just disabled
without reading is literally true, because it is the only marked thing in the
column.

**Scope: the admin surface only, and only `admin/users.html` here.** The admin
member detail page is proposed by the admin-actions spec, which specifies its
own Facts region including role and status — it renders chips because this spec
defines them, and that spec owns the page.

Chips do **not** go on the account overview. A member reading their own
dashboard is by definition active — `require_session` (`account.rs:78`) admits
only `user.is_active()` — so the chip would always read the same, and `Overview`
(`account.rs:119`) carries no `role` or `status` field today. Adding one would
be new data plumbing to display a constant, which fails this spec's own non-goal
twice over.

### Copy that names the next step

Empty states and destructive framings are rewritten in solidid's register. The
rule: say what is true, then say what to do about it.

`apps.html`'s empty state names what an authorised application *is* and where
grants come from, rather than reporting a count of zero. The delete page already
does this well — it points at `/account/export` before the form — and it is the
model for the rest.

Destructive actions keep the framing `delete.html` established: consequence
first, then the escape route, then the control. solidid marks its delete block
with a `.danger-zone` class on the `<dd>` rather than a heading; neither the
class nor a "Danger Zone" heading is adopted, because the consequence sentence
already does that work.

### The first JavaScript: copy to clipboard

Overview shows a WebID and a storage root, and both exist to be pasted into
another application. solidid does this for its two equivalents — WebID and
public profile URL (`src/routes/profile/+page.svelte:92–108`); it has no storage
root. This is the one place the dashboard genuinely wants script.

§4.2 permits it precisely: "Server-rendered Askama, progressive enhancement.
Every form works with JavaScript disabled. Interactive bits are islands, not an
app shell."

**One shipped file, not an inline script:** `server/static/brolly.js`, loaded
from `base.html`'s `<head>` with `<script defer src="/static/brolly.js">`. It
finds `[data-copy]` and attaches a button. With script off, the value stays a
selectable `.mono` span and nothing is missing but a convenience. The button is
created *by* the script rather than rendered dead in the HTML, so a member
without JavaScript is never offered a control that does nothing.

Two consequences, both deliberate:

- **It loads on the door too.** `<head>` is outside the `{% block header %}` the
  door spec suppresses. On a page with no `[data-copy]` the script does nothing,
  and one small deferred file is a better trade than a second base template or a
  conditional block. There is no CSP header set anywhere in `server/src/`, so
  nothing blocks either choice today; the file is chosen on maintainability.
- **A mistyped `src` degrades silently.** `every_stylesheet_url_resolves_to_a_shipped_file`
  (`ui_invariants.rs:249`) scans `url("` in CSS only, so it does not cover
  `<script src>` — the same gap the door spec recorded for `<img src>`. Recorded
  here rather than fixed; one broken-asset check covering CSS `url()`,
  `<img src>` and `<script src>` is worth doing once, deliberately, and not as a
  side effect of this spec.

### What this does not add

Two things the cards make conspicuous, decided here so a planner is not blocked:

- **No "sign out everywhere" button.** `revoke_other_sessions`
  (`identity/src/db.rs:394`) exists and `change_password` already calls it, so
  the control is one handler away — and it is a new action, which this spec's
  non-goals forbid. The Sessions card shows the count and states that changing
  your password ends every other session, which is true, already implemented,
  and gives the card something to say.

  That sentence **moves rather than duplicates**: `security.html:31` already
  renders it as a `.hint` inside the password form. It belongs with the session
  count, not with the field that happens to trigger it, and leaving both would
  put the same sentence on one page twice.
- **No activity or login history.** There is no `last_login_at` column. A card
  with one row in it is worse than no card.

## Ordering

This spec touches `base.html` (the `<script>` tag) and introduces
`.dashboard-card`; the door spec restructures `base.html` (header/footer blocks)
and deletes `.card`. They do not conflict — different lines, different class
names — but if the door lands first, its `base.html` is the one to add the
script tag to. If this lands first, the door's `.card` deletion list is still
accurate because the new class is `.dashboard-card`.

The admin-actions spec depends on this one for `.chip` and `.dashboard-card`.
Landing this first is simpler; landing it second means the detail page renders
bare strings for a while, which is survivable.

## Testing

`server/tests/dashboard.rs`'s `Reply` already carries `location` (`:89`), so no
helper extension is needed. `revoking_an_app_stops_it_refreshing` (`:532`) and
`changing_a_password_ends_every_other_session` (`:347`) assert only `SEE_OTHER`
and never inspect `Location`, so retargeting the revoke redirect touches
neither.

| Assertion | Why |
|---|---|
| Revoking an app redirects to `/account/apps?saved=true` and the page says "Access withdrawn." | the one drift, and the only behaviour change in this spec |
| `/account/apps` without the parameter renders no notice | otherwise the notice is permanent furniture |
| A notice carries `role="status"`; an error carries `role="alert"` | polite versus assertive is the whole reason the elements differ |
| The apps empty state names what to do, not just that the list is empty | goal 3, and it will be reverted to a one-liner without a test |
| A disabled account renders `chip-disabled` in the member list, and an active one renders no chip at all | the one state that must not read as ordinary, and the modifier is what makes it assertable |
| `.dashboard-panel` and `.dashboard-panel-wide` survive nowhere in `server/templates/` | the conversion is only finished when the old class is gone |
| Every `<form>` in every template — **including `_`-prefixed partials** — has a `method` and a non-empty `action` | §4.5's unwritten invariant, written |
| Every page still has one `<h1>` and lives inside `.wrap` | existing invariants, over the new cards |

### The §4.5 invariant that was never written

§4.5 lists "*Every form works without JavaScript* — a test asserting each
`<form>` has a non-JS action + method." **That test does not exist.**
`ui_invariants.rs` implements the `format!` gate, the single stylesheet, the
generated-token file, the colour-literal check, the h1/main lint, the page
container and the stylesheet URLs — and not this one. It has been free to hold
by luck while there was no JavaScript at all, and this spec introduces some, so
it is written now.

It needs **its own walker, not `collect_templates`.** That helper skips
`_`-prefixed partials, and `account/_nav.html:3` and `admin/_nav.html:3` both
contain `<form method="post" action="/logout">` — reusing it would silently skip
the two logout forms, which are exactly the kind of form the invariant exists
for.

Its known limit, recorded rather than papered over: `auth.html:15` and
`consent.html:31` use `action="{{ action }}"`, so the check can only assert the
attribute is textually non-empty. It cannot see whether `AuthPage.action` ever
resolves to an empty string at runtime.

## Open questions

- **Where does `consent.html` fit?** It uses `.auth-card`, not the dashboard
  vocabulary, and §4.5 requires all three OAuth handlers share it. Untouched
  here, but it is the one signed-in page that looks like neither the door nor
  the dashboard — and the door spec has the same question open from the other
  side.
- **Should the broken-asset check be generalised?** CSS `url()` is covered;
  `<img src>` and `<script src>` are not, and this spec adds the first
  `<script src>`. Worth one test covering all three, scheduled on its own.
