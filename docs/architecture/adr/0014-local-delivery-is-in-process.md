# 0014 — Local delivery is in-process, and outbound signing stays dormant

**Status:** Accepted (2026-08-26)
**Qualifies:** D12's "all federation code paths still exercised locally".

## Context

D12 says federation ships off *and* that every federation code path is still
exercised locally, so that Phase 8's flip turns on code already known to work.
The predecessor did this and §0 of the learnings records it as one of the things
that worked.

Adopting `activitypub_federation` (ADR 0003) turns out to conflict with the
second half. `build_tasks` filters recipients before signing:

```rust
inboxes.into_iter().unique().filter(|i| !config.is_local_url(i))
```

Local inboxes are dropped, not signed and not sent. The framework assumes the
application delivers same-instance activities itself, which is how Lemmy uses
it. There is no supported way to make it sign to a local inbox, and the
signature primitives are `pub(crate)` (ADR 0003 §2), so we cannot sign one
ourselves either.

There is a wrinkle that made this look avoidable at first: `is_local_url`
compares the host to `config.domain` exactly, and our members live on
subdomains. `alice.brolly.id` does not equal `brolly.id`, so the framework would
in fact treat every member inbox as remote and sign and send to it — over real
HTTP, to ourselves.

## Options

**A — In-process for local, framework for remote.** What the framework expects.
Fan-out stays N store writes.

**B — HTTP loopback for everything.** Lean on the subdomain mismatch so every
delivery is signed and sent. Literally satisfies D12 and needs no second code
path. Costs one real HTTP round trip per local follower: the learnings budget a
1,000-follower post at 1,000 inbox writes, and this makes it 1,000 loopback
requests, at the scale D16 targets.

**C — In-process, plus tests that sign real requests at the inbox endpoint.**
A, with inbound verification exercised on every CI run.

## Decision

**Option A. Local delivery is in-process. Outbound signing is not exercised
until federation is enabled.**

The delivery path itself *is* exercised on every local post — recipient
resolution, the federation switch, the processors, inbox containment, the index
write. What is not exercised is request signing and inbound signature
verification, because with federation off no request is ever made.

## Consequences

- **Fan-out cost is what the learnings budgeted.** N store writes, not N HTTP
  requests. This is the main reason B was refused.
- **`should_deliver` still runs on every recipient**, local or remote, so the
  switch is real code on the live path rather than a branch nobody takes.
- **Signing and verification are the untested surface at the Phase 8 flip.**
  That is the accepted cost, and it is the thing most likely to be broken when
  federation is first turned on. Phase 8 should treat "sign a request and verify
  one" as its first task, not assume it works.
- **Option C remains available and cheap.** If the Phase 8 risk reads as too
  high later, adding signed-request tests against the inbox endpoint gets most
  of D12's intent back without touching the delivery design. It was not taken
  now only because the inbound endpoint does not exist yet.
- **The subdomain/`config.domain` mismatch is a live trap.** Any future code
  that hands member inboxes to the framework will send them real HTTP requests,
  because the framework does not recognise them as ours. Whoever wires
  `SendActivityTask` in Phase 8 has to filter local recipients out first.
