# 0009 — Reserved paths on user subdomains

**Status:** Accepted (2026-08-19)
**Extends:** ADR 0008 (OAuth endpoint layout).

## Context

Two decisions interact badly if left implicit.

Per-user subdomains mean `alice.brolly.id` serves Alice's resources, and Solid
LDP is **generic CRUD** (D9) — Alice may create a resource at any path in her
pod. So the per-user router ends in a catch-all that handles `GET`, `PUT`,
`POST`, `PATCH`, and `DELETE` for arbitrary paths.

Server-wide protocol endpoints live on the apex. ADR 0008 listed OAuth paths
without saying which host serves them, which left the question open: is
`alice.brolly.id/oauth/token` a route?

Under a naive reading it is — not as a protocol endpoint, but as **an LDP
resource Alice controls**. The predecessor's per-user router had exactly this
shape and no reserved-path logic, so the answer there was yes.

That is worse than untidy. A client misconfigured with `alice.brolly.id` as its
instance host would send an authorization code, and possibly a client secret, to
a path inside Alice's pod. Non-RDF request bodies are stored as binary
resources, so the credential would land somewhere Alice can read it. Exploitation
needs a client pointed at the wrong host, which is not the common case — but it
is a credential-exfiltration path that costs nothing to remove and cannot be
removed later without breaking whatever users have stored there by then.

The predecessor also hit the benign version of this: unmatched `/api/v*`
requests fell through to the LDP handler and returned HTML or RDF to Mastodon
clients, which was recorded as a P0 correctness defect.

## Decision

**Host scope is explicit, and protocol path prefixes are reserved on user
subdomains.**

| Path | Apex `brolly.id` | Subdomain `alice.brolly.id` |
|---|---|---|
| `/oauth/*` | all three protocols (ADR 0008) | **reserved** |
| `/.well-known/*` | webfinger, nodeinfo, host-meta, `did.json`, both OAuth/OIDC discovery docs | **reserved** |
| `/api/*` | Mastodon Client API | **reserved** |
| `/admin/*`, `/dashboard/*`, `/login`, `/register` | server UI | **reserved** |
| `/index/*` | server-agent index | **reserved** |
| `/inbox` | AP **shared** inbox | Alice's personal inbox — *both are real* |
| `/profile`, `/actor`, `/outbox`, `/followers`, `/following` | — | Alice's |
| `/xrpc/*` | multiplexed by DID for the relay | Alice's repo |
| anything else | `404` | Alice's LDP resources |

A reserved path on a subdomain returns **`404` with a `Link` header pointing at
the apex equivalent**, and never reaches the LDP handler. It is not a redirect:
following one automatically would let a client believe its misconfiguration
worked, and the client author should see the mistake.

Users cannot create resources under a reserved prefix. That is a real
restriction on "generic CRUD" and it is deliberate — the alternative is a pod
whose contents can shadow a protocol endpoint.

## Consequences

- **`alice.brolly.id/oauth/token` is not a route and not writable.** The
  credential path is closed by construction rather than by client discipline.
- **`/inbox` legitimately exists on both hosts.** The apex one is the AP shared
  inbox; the subdomain one is the user's. Neither is reserved against the other.
- **The reserved list is a choke point** — `identity::routing::reserved_on_subdomain`
  — with a test asserting every apex protocol prefix appears in it. Adding an
  apex endpoint without reserving it fails that test rather than silently
  creating a writable shadow.
- **A restriction we can loosen but not tighten.** Reserving a prefix later,
  after users have stored resources under it, breaks their data. Reserving now
  costs nothing.
- **Mastodon clients pointed at a subdomain fail loudly**, with the apex in a
  `Link` header, instead of receiving RDF.
