# 0008 — OAuth endpoint layout: discovery, not shape-sniffing

**Status:** Accepted (2026-08-19)
**Supersedes the approach in:** predecessor ADR 0002 (OAuth path multiplex).

## Context

Three protocols need an OAuth surface: ATProtocol (PAR + DPoP), Solid-OIDC
(PKCE + DPoP), and Mastodon (PKCE, plain Bearer). The predecessor put ATProtocol
at the bare `/oauth/authorize` and `/oauth/token` first, then discovered that
Mastodon clients — Phanpy, Ivory, Tusky, Mona — **hardcode** those paths and
never look them up. Its visible failure was a Mastodon client receiving
`Failed to deserialize query string: missing field 'request_uri'` from the
ATProtocol handler.

The fix was a dispatcher that inspected request shape: `request_uri` param or
`DPoP` header meant ATProtocol, otherwise Mastodon. Solid-OIDC was parked at
`/oidc/*` to stay out of the fight, and its own ADR noted that a third surface
at `/oauth/*` would require extending the dispatcher.

That dispatcher was solving a self-inflicted problem. Checking what each
protocol actually requires:

| Protocol | Endpoint discovery | Can we choose the path? |
|---|---|---|
| ATProtocol | `/.well-known/oauth-authorization-server` | **Yes** |
| Solid-OIDC | `/.well-known/openid-configuration` | **Yes** |
| Mastodon | none — no discovery document exists | **No** |

Only one of the three cannot be told where to go.

## Decision

**Give the bare paths to Mastodon, because it is the only protocol that cannot
be moved. Give the others their own paths and advertise them in the discovery
documents they already publish.**

```
/oauth/authorize            Mastodon    (hardcoded by clients)
/oauth/token                Mastodon    (hardcoded by clients)
/api/v1/apps                Mastodon    (client registration)

/oauth/atproto/par          ATProtocol  (advertised in oauth-authorization-server)
/oauth/atproto/authorize    ATProtocol
/oauth/atproto/token        ATProtocol

/oauth/solid/authorize      Solid-OIDC  (advertised in openid-configuration)
/oauth/solid/token          Solid-OIDC
/oauth/solid/register       Solid-OIDC  (dynamic client registration)
```

No request-shape inspection is required to route a correctly-configured client.
Adding a fourth protocol adds a path prefix and a discovery entry; it does not
touch a dispatcher that every other protocol depends on.

## Defensive detection, not routing

A misconfigured or naive client may still arrive at a bare path carrying
ATProtocol or Solid-OIDC shape. That must not produce a deserialization error
naming an internal field.

`identity::oauth::detect_misrouted` recognizes the shapes — `request_uri`
present, or a `DPoP` header, or a `client_id` that is a URL — and the handler
answers `400` with the correct endpoint in the body. Detection is for
diagnosing, never for routing: a request that looks like ATProtocol at a
Mastodon path is a client bug, and telling the developer where to go beats
silently making it work at a path the spec never promised.

## Host scope

All of these are **apex-only** — `https://brolly.id/oauth/...`. They are not
served on user subdomains, and because a user subdomain ends in a catch-all LDP
handler, they must be *reserved* there rather than merely unmounted. See
ADR 0009.

## Consequences

- **Mastodon clients work unconfigured**, which was the requirement that forced
  the original multiplex.
- **The dispatcher disappears.** No shared code path where a change for one
  protocol can break another.
- **A fourth protocol is additive.** This is what the predecessor's ADR 0002
  explicitly flagged as the cost of its design.
- **Discovery documents become load-bearing.** If
  `oauth-authorization-server` advertises the wrong path, ATProtocol clients
  break — so a test asserts the advertised paths match the mounted routes.
- **`/oauth/par` moves** to `/oauth/atproto/par`. Nothing hardcodes it; PAR is
  reached through discovery by definition.
