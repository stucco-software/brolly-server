# 0010 — All user LDP content under `/~/`

**Status:** Accepted (2026-08-19)
**Supersedes:** ADR 0009 (reserved paths on user subdomains).

## Context

ADR 0009 reserved apex protocol prefixes on user subdomains so a user's LDP
catch-all could not shadow `/oauth/token` and friends. It closed the
credential-capture path, but it did so with a **blocklist**, which has two
standing costs:

- **It can drift.** Adding an apex endpoint without adding it to the reserved
  list creates a writable shadow of that endpoint in every user's pod. ADR 0009
  needed a test purely to keep the list synchronized with reality.
- **The dangerous default is still the default.** The LDP catch-all sits at the
  subdomain root and everything not explicitly excluded is user-writable.

The inverse is available: scope user content to a prefix and let everything
outside it be unrouted. Then no list exists to drift, and the catch-all cannot
shadow anything because it is not at the root.

Critically, this needs no client cooperation. Solid storage roots are
**discovered**, not assumed — a client reads `space:storage` from the WebID
profile and writes there. The predecessor already emitted
`space:storage <{origin}/>`; the value simply pointed at the root, which is what
created the collision.

## Decision

**User and app LDP content lives under `https://<user>.<base>/~/`.** Everything
outside it on a user subdomain is either an explicit protocol resource or a
`404`.

```
alice.brolly.id/~/**                 LDP. User- and app-writable. Catch-all lives HERE.
alice.brolly.id/profile              WebID document        — server-managed
alice.brolly.id/actor                AS2 actor             — server-managed
alice.brolly.id/inbox, /outbox       AS2 collections       — server-managed
alice.brolly.id/followers,/following AS2 collections       — server-managed
alice.brolly.id/xrpc/*               ATProtocol repo       — server-managed
alice.brolly.id/anything-else        404. No fallback.
brolly.id/**                         server-wide (ADR 0008)
```

The WebID profile advertises `space:storage <https://alice.brolly.id/~/>` and
that container is typed `pim:Storage` + `ldp:BasicContainer`. A Solid app that
follows the spec finds it without being told.

`~` is in RFC 3986's unreserved set, so it needs no encoding, and "tilde means
home" is legible to anyone reading a URL.

## Why the protocol resources stay at the root

`/profile`, `/actor`, `/inbox` and the rest are **not arbitrary user content** —
they are protocol-defined projections the server generates from the pod's graphs
(the canonical layer, D7/D8). Keeping them at the root preserves
`https://alice.brolly.id/profile#me` as the WebID, which is the subject IRI every
protocol asserts onto (D8) and the one thing least worth making uglier.

So the split is by *ownership*, not by convenience: the server owns the root
namespace, the user owns `/~/`.

## Consequences

- **The credential path is structurally impossible, not merely closed.** There
  is no way to write to `alice.brolly.id/oauth/token` because no LDP handler is
  mounted anywhere near it.
- **The reserved list is deleted**, along with the two tests that existed to
  keep it honest. Adding an apex endpoint is now free.
- **New protocol endpoints can never collide with user data**, in either
  direction — including ones invented by protocols that do not exist yet.
- **Default-deny on subdomains.** An unmatched subdomain path is a `404`, not a
  pod write. The predecessor's benign version of this bug — unmatched `/api/v*`
  falling through to LDP and returning RDF to Mastodon clients — cannot occur.
- **Storage discovery becomes load-bearing**, which it already was by spec. A
  test asserts the profile advertises the same root the router mounts; the
  predecessor never checked that they agreed.
- **One real restriction:** a user cannot own the subdomain root. `GET
  alice.brolly.id/` is a server-rendered profile page, not her LDP root
  container. That is a fair trade for a namespace the server can extend safely
  forever.
- **App-scoped storage becomes possible later** — `/~/app/<client-id>/` — without
  another namespace decision. Not built now, but the room exists.
