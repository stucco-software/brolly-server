# 0012 — The publication surface is the AS2 outbox

**Status:** Accepted (2026-08-24)
**Closes:** open decision O3.

## Context

D9 says Solid LDP is generic CRUD, and that a write becomes a *post* only when
it has the right shape in the right place: "if a Solid app writes data that
looks like a post where the posts go, then it's a post. Otherwise it's just
something else."

O3 asked how a generic Solid app discovers where "where the posts go" is. It
must be readable from the data, not a path the app hardcodes.

The obvious move is to invent a term — `brolly:PublicationSurface` on a typed
container, linked from the profile. That works and is one more vocabulary
nobody else speaks.

## Decision

**Reuse `as:outbox`. Invent nothing.**

The ActivityPub actor document already declares `as:outbox`, the WebID profile
already links to the actor, and ActivityPub's client-to-server protocol already
defines the semantics we want: POST an object there and it is published on the
author's behalf. A generic client discovers it by dereferencing the actor, which
it can already do.

```
alice.brolly.id/profile      →  WebID, links to the actor
alice.brolly.id/actor        →  declares as:outbox
alice.brolly.id/outbox       →  as:OrderedCollection. POST here to publish.
alice.brolly.id/~/**         →  private CRUD. No activity, no repo commit.
```

So the rule is precise:

- **POST an `as:Note` (or other AS2 object) to the outbox** → published:
  delivered over ActivityPub, indexed in the server-agent store, mirrored to the
  ATProtocol repo.
- **Any write under `/~/`** → storage. No side effects, whatever it is shaped
  like and whatever the container is called.

The outbox is a **protocol resource at the subdomain root**, not a container
inside `/~/`, which follows from ADR 0010: it is server-managed rather than
arbitrary user content, and the server maintains its collection semantics.

## Consequences

- **No new vocabulary**, so no adoption problem. An app that speaks ActivityPub
  C2S already knows how to publish here.
- **Publication is impossible by accident.** A user cannot create a container
  inside `/~/` that publishes, because `/~/` has no publication path at all —
  not because we check its type. Naming a container `outbox` inside the pod does
  nothing.
- **The ACL on the outbox is the "may post as me" grant**, which is legible:
  it is one resource with one ACL, rather than a capability implied by a type
  triple somewhere in the pod.
- **The predecessor's removed mirror comes back correctly scoped.** `v0.16/06a`
  removed LDP→ATProto mirroring because most LDP writes are not posts. That was
  right globally; the outbox is the narrow place where it belongs.
- **A cost:** an app that wants to publish must dereference the actor rather
  than writing to a well-known pod path. That is one extra request and the
  reason it works with a generic client.
