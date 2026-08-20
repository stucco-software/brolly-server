# 0011 — One consent vocabulary across three protocols

**Status:** Accepted (2026-08-20)
**Closes:** open decision O8.

## Context

The OAuth consent screen is the highest-stakes surface in the product (§4.1).
It renders *inside someone else's app flow* and it is the moment a person
decides whether to hand an app access to their pod. There are three callers —
Solid-OIDC, ATProtocol, Mastodon — and they spell authority incompatibly:

| Protocol | Example scopes |
|---|---|
| Mastodon | `read`, `read:statuses`, `write:statuses`, `follow`, `admin:write` |
| ATProtocol | `atproto`, `transition:generic`, `transition:chat.bsky` |
| Solid-OIDC | `openid`, `webid`, `offline_access` |

`Subject` keeps scopes **verbatim** per protocol, deliberately: translating
`read:statuses` into `transition:generic` would invent authority nobody granted.
That is right for enforcement and useless for a human being asked to approve it.

Three separate screens would drift, and the drift would be invisible — nobody
compares consent copy across protocols.

## Decision

**One component, one vocabulary, three callers.** A scope is rendered as a
plain-language capability grouped by the resource it touches, with the raw
protocol scope shown beneath it.

- **Group by resource, not by protocol.** "Your posts", "Your pod", "Your
  profile", "Your account". A person reasons about what an app can reach, not
  about which spec named it.
- **Show the raw scope.** Small, under the summary. A developer debugging a
  grant needs the literal string, and hiding it makes the screen unauditable.
- **An unrecognised scope is displayed verbatim and flagged**, never omitted and
  never silently approved. This is the load-bearing rule: a protocol will add
  scopes we have not mapped, and the failure mode must be "the user sees
  something they do not recognise" rather than "the user approves something
  invisible."
- **Admin scopes are marked distinctly.** `admin:write` is not a bigger version
  of `write`; it reaches other people's data.

## Consequences

- **One place to change consent copy**, so wording cannot drift between
  protocols.
- **Unknown scopes degrade toward caution.** A new Mastodon scope shows up
  loudly on the screen the day it appears, rather than being dropped.
- **The mapping table is data, not branches** — adding a protocol's scope is a
  row, and a test asserts every scope in the table has non-empty copy.
- **Enforcement is untouched.** This is presentation only; `Subject` still
  carries scopes verbatim and `brolly-authz` still matches them literally. The
  screen never widens or narrows what is granted.
- **A cost worth naming:** plain-language summaries are an interpretation. If a
  summary is wrong it misleads someone into approving something. That is why the
  raw scope is always shown and why unmapped scopes are never guessed at.
