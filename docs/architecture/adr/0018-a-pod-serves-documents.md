# 0018 — A pod serves documents

**Status:** Accepted (2026-10-30). Drafted the same day and revised after two
adversarial reviews against the tree. The first found two attacks the draft
had not named (cookie tossing, and sessions minted on member hosts before
`0a465e0`) and one incompatibility with the decision's own motivating client
(SolidOS frames its own pod). The second found that the cookie rename would
silently break logout (a `__Host-` removal needs the prefix's attributes
too), that the apex's framing header belongs among the controls, and an
overstated worker scope. All are folded in.
**Scopes:** spec 4 (Solid media uploads), H2 — supersedes its exclusion of
`text/html` and `image/svg+xml`, and the "own serving rules (`Content-
Disposition`, CSP)" condition it set for reopening.

## Context

Spec 4's H2 put the server's binaries behind an allow-list and kept
`text/html` and `image/svg+xml` off it, for one stated reason: a member-typed
HTML or SVG document, served back as typed from the member's own origin, was
"stored XSS with the pod's cookies in scope" (`domain/src/media.rs`, the list's
doc comment; `docs/specs/2026-09-29-solid-media-uploads.md:161`). That was
true when it was written. The session cookie was minted wherever a member
logged in, the door answered on member subdomains, no form checked `Origin`,
and nothing refused framing.

Most of that is no longer true. The session cookie is host-only on the apex
and never sent to `alice.<apex>` (`auth::session_cookie`: `Secure`,
`HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`); the door, the dashboard
and the console are apex-only (`0a465e0`), so no session is minted on a
member host any more; a form post from any origin but the apex is refused
(`3a90b5a`); nothing served may be framed (`aa8c418`); the CORS layer never
allows credentials, so a same-site response is never readable from another
origin.

Two things remain, and they are what script on a member's origin could still
reach:

- **Cookie tossing.** The apex is not on the Public Suffix List, so
  `alice.<apex>` and the apex are one *site*. A script on a member host can
  write `document.cookie = "brolly_session=<attacker's token>; Domain=<apex>"`,
  and the browser sends that cookie to the apex and to every member host. A
  logged-out visitor then carries the attacker's session: their next consent
  authorises the attacker's account, and their app writes into the attacker's
  pod. Two readers of the cookie disagree on which of two same-named cookies
  wins (`identity/src/extract.rs` takes the first, `CookieJar` the last), and
  logout removes only the host-only one.
- **Sessions minted on member hosts before `0a465e0`.** Sessions live thirty
  days, nothing revoked the ones minted on member hosts, and the sessions
  table does not record the host. The pod (`pod.rs`) and `POST /outbox`
  (`outbox.rs`) accept `brolly_session` as full authority, and neither is in
  `SAME_ORIGIN_FORMS`. Wherever such a cookie survives, a page on any member
  host can publish or write as that member with one same-site request.

Meanwhile a pod that cannot hold an HTML page is not a pod in the sense
Solid means: SolidOS, every pod-hosted app, and a member's own site all put
documents in storage and expect them served as typed. The 415 on
`PUT index.html` is the first thing a member trying to do that sees.

## Decision

**A pod stores and serves the document types a web site is made of**, as
typed, through the one choke point every binary already passes
(`ldp::prepare`) — and the two openings above are closed first, in the same
change, because the decision rests on them being closed.

### The document types

```
text/html, text/css, text/javascript, application/javascript,
application/json, application/manifest+json,
image/svg+xml, image/x-icon, image/vnd.microsoft.icon,
font/woff2, font/woff, font/ttf, font/otf,
application/xml, text/xml, application/rss+xml, application/atom+xml
```

`application/json` is not an RDF syntax here (`syntax.rs`), so it lands as a
document. No `application/wasm`: it needs script to run and nobody has asked.

**Two lists, one gate.** `ALLOWED_MEDIA_TYPES` stays what it is: what a
Mastodon attachment may be. `ALLOWED_DOCUMENT_TYPES` is the set above.
`ldp::prepare` accepts the union (`media::is_storable_type`). The Mastodon
upload (`mastodon_api::upload_media`) — which today calls `prepare` with no
check of its own — refuses anything not on the media list *before* `prepare`,
so an attachment stays an attachment. (The instance advertises a hardcoded
subset of the media list as `supported_mime_types`, with a test that it is a
subset; that is unchanged.) The 415 body names both lists. `Accept-Put` stays
`*/*` and `Accept-Post` stays the RDF syntaxes: neither named the media list
before, and this does not start.

### The controls the decision rests on

Seven. The first five exist; the last two land with this change.

1. The session cookie is host-only on the apex (`auth::session_cookie`).
2. The door, the dashboard and the console are apex-only (`0a465e0`).
3. A form post from any origin but the apex is refused (`3a90b5a`).
4. The CORS layer never allows credentials.
5. The apex answers `frame-ancestors 'none'` (`aa8c418`): member hosts are
   same-site with the apex, so `SameSite=Lax` does nothing against a member
   page framing the consent screen — this header is what does.
6. **The session cookie is `__Host-brolly_session`.** The `__Host-` prefix
   is enforced by the browser: such a cookie must be `Secure`, `Path=/`, and
   carry no `Domain`, and a subdomain cannot set one for the apex or for any
   other host. That closes cookie tossing, on one condition: the server reads
   the name literally. The browser enforces the prefix on the literal name,
   so `__%48ost-brolly_session` is an ordinary cookie a member page can set
   with `Domain=<apex>`, and a percent-decoding parser such as `CookieJar`
   would read it as the session. Nothing may read this cookie through a
   decoding parser: `extract::session_token` is the one reader, and
   `server/tests/architecture.rs` holds the line. The guarantee also depends
   on the browser refusing nameless `__Host-` cookies: one sends
   `=__Host-brolly_session=x` as a bare value, which the server can't tell
   from the real cookie. What has been tested is narrow: Chrome 156, over
   `http://`, setting the cookie with `document.cookie`, refused it — and
   an insecure context may be the whole reason, since a `__Host-` cookie
   needs `Secure` whatever its name, so that run says nothing about the
   nameless-cookie rule itself. **Before deploying, the operator checks it
   over HTTPS**: a page on a real member subdomain sets
   `=__Host-brolly_session=x; Domain=<apex>; Path=/; Secure`, in Chrome,
   Safari and Firefox, and the apex must not receive it. A compliant
   browser can't send the name twice, so `session_token` answers no
   session if it appears more than once, which fails closed. The rename
   also closes the legacy opening at a stroke: the server stops reading
   `brolly_session` at all, so every cookie minted on a member host before
   `0a465e0` — and every tossed one — is inert from the deploy. Members
   log in again once; nothing else changes. The pod and the outbox keep
   reading the (renamed) cookie, for the non-browser clients and tests that
   present it: a browser never sends the apex's `__Host-` cookie to a member
   host, and a member-host script can set a `__Host-` cookie only for its
   own host, carrying only a token it already holds — which authenticates
   the attacker, not the member. (An
   `Authorization` header still wins over the cookie, so a planted cookie
   cannot override a Solid app's DPoP credential. The residual: a planted
   page can set that cookie for its own host, after which every
   header-less request there — a visitor's, or alice's own address-bar
   navigation — runs as the planter; harmless, since the planter already
   holds that token, and named here because it is the cost of letting the
   pod keep reading the cookie.) Two things follow for the code: the name
   is defined in both `auth.rs` and `identity/src/extract.rs`, and one must
   re-export the other; and **a `__Host-` cookie can only be cleared by a
   `Set-Cookie` that carries the prefix's attributes** — `cookie`'s
   `remove` emits neither `Secure` nor `Path`, so the browser would drop the
   removal and logout would silently leave the cookie behind (inert, since
   the session is revoked server-side, but there). `/logout` and
   `/account/delete` emit `auth::session_removal` unconditionally, built from
   `session_cookie` with `Max-Age=0`, since `remove` also emits nothing for a
   cookie the jar didn't parse. A test reads the removal header back.
7. **A pod never serves a service worker.** A request carrying
   `Service-Worker: script` to `/~/{*path}` (`pod::get`; the root is a
   container, served as RDF) is refused (403, "a pod does not serve service
   workers"). A worker's scope is its script's directory — the server never
   sends `Service-Worker-Allowed` — so a grant on `/~/x/` reaches `/~/x/`,
   not the origin. The point is persistence: without this, anyone with
   Write or Append on a subtree could register a worker that intercepts
   every request under it, for every visitor, until unregistered. No
   pod-hosted app this server targets needs one.

### Framing, per host

`frame-ancestors 'none'` stays on the apex (control 5). On a member host
it becomes `frame-ancestors 'self'`, and `X-Frame-Options` goes from `DENY`
to `SAMEORIGIN` with it (modern browsers ignore XFO when `frame-ancestors`
is present; the two must still agree): SolidOS — the decision's motivating
client — renders HTML and PDF previews in iframes of the pod's own
documents, and `'none'` would break it. SolidOS meets this server three
ways, and `'self'` treats them differently, on purpose: *browsing and
editing* is `fetch()` with a DPoP token through the CORS layer — framing
never enters into it, and it works from wherever SolidOS is hosted; *SolidOS
served from the pod* (mashlib under `/~/`, as solidcommunity.net does) is
what this ADR enables, and `'self'` is what lets its previews frame the
pod's own documents; *SolidOS hosted elsewhere* browses and edits as
before, but its HTML and PDF preview iframes are refused. The alternative,
`frame-ancestors *` on member hosts, would restore that third case at the
cost of the second: a pod-hosted app holds the member's tokens in the
browser's storage for that origin, and a foreign site could frame it and
clickjack what it does to the member's own pod. The server cannot tell an
app from a document, so it cannot have both; it protects the app. `'self'`
keeps every other origin out, which is what protects a pod page from being
dressed as something else. `security_headers` branches on the host the way
`apex_only` does — it becomes a `from_fn_with_state` layer to know the base
domain — so every subdomain-shaped host, `www` and unregistered names
included, gets `'self'`; harmless, since nothing is served there.

### What stays as it was, and why

Spec 4 and the `media.rs` doc comment said SVG, when wanted, "wants its own
serving rules (`Content-Disposition`, CSP)", and `security_headers` said a
script policy would be reopened if SVG were admitted. Those conditions were
written when a member's origin held the member's session. It holds no
credential the instance issues to a browser now — no cookie a browser would
send there. What it may hold is a pod-hosted app's own tokens, at the
member's choice (the second acceptance below), and a CSP would not protect
those: a policy permissive enough to run the hosted app runs a page planted
beside it just the same. A `Content-Disposition: attachment` would defeat
the purpose — a page is served to be rendered. The three comments are updated to say so, and the
`ldp::prepare` comment that calls SVG's absence deliberate goes with them.

### What is accepted, by name

- **A member can host, on their own subdomain, a page that looks like
  anything** — the apex's login form included. The page cannot *be* the
  apex: a session is only minted there, a form only accepted from there.
  This is the acceptance every pod host and GitHub Pages makes; the
  reputational cost is the instance's to govern through its members.
- **A grant on one container is script on the whole origin.** A pod-hosted
  app keeps its tokens in the browser's storage for `alice.<apex>`; anyone
  alice grants Write or Append on any folder can plant a page there that
  reads them. Nothing the server provisions grants a third party Write or
  Append — that is the member's choice, and now a choice with this
  consequence. The dashboard's apps page and the consent screen do not
  change; a sentence in `docs/deploying.md` names it.
- **Apex GETs with side effects** — a `prompt=none` authorize with a
  remembered consent, `/account/export` — are reachable from a member page
  with the Lax cookie. They give no more than any cross-site top-level
  navigation gives today, and their responses cannot be read.
- A member page can set enough `Domain=<apex>` cookies that requests are
  refused, or that the session is evicted. Eviction costs a login. Refusal
  locks that browser out of the instance, login included, until the cookies
  expire or are cleared. Neither grants access, provided the browser rejects
  nameless `__Host-` cookies.

## Consequences

- Members are logged out once at the deploy: the cookie's name changes.
- `an_svg_is_refused_like_any_other_off_list_type` — in both
  `server/tests/pod_http.rs` and `adapters/solid/tests/ldp_nonrdf.rs`, the
  test spec 4 said reopening this question would mean deleting — is replaced
  by its inverse: an SVG and an HTML page are stored and served as typed,
  with `nosniff`.
- New tests: a `Service-Worker: script` request to `/~/{*path}` is 403; a
  Mastodon `text/html` upload is refused; a member host answers
  `frame-ancestors 'self'` / `SAMEORIGIN` and the apex `'none'` / `DENY`; a
  `brolly_session` cookie (old name) authenticates nothing; the session
  cookie is set as `__Host-brolly_session` with the attributes the prefix
  requires, and `/logout` and `/account/delete` emit a removal that carries
  them too.
- Spec 4's H2 row carries a note pointing here.
- Reopened if any of the seven controls is loosened: the decision rests on
  all of them.
