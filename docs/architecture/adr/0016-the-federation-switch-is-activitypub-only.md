# 0016 — The federation switch governs ActivityPub, not ATProtocol

**Status:** Accepted (2026-08-26)
**Scopes:** decision D12, which reads "federation off by default" without
naming a protocol.

## Context

D12 was written as a single global posture: ship dormant, exercise every
federation code path locally, flip a constant in Phase 8. Phase 5 implemented it
that way — `brolly_activitypub::federation::FEDERATION_ENABLED`, with a tripwire
test that fails if it is flipped early.

Phase 7 then read D12 as covering ATProtocol too, and deferred `did:plc`
submission behind it. That reading is wrong, and it is wrong because the two
protocols do not have the same shape of "federation".

**ActivityPub pushes.** Delivery is an outbound act aimed at a specific remote
inbox. Shipping dormant means not spraying activities at instances that never
asked for them, which is a real safety posture and the thing D12 was protecting.
Suppressing delivery costs the local member nothing: their post still exists,
still reaches local followers, still renders.

**ATProtocol pulls.** A PDS hosts repositories; AppViews and relays fetch from
it. There is no per-recipient delivery to suppress, and no other server is
imposed on. Hosting a repo is not an outbound act — it is the entire
participation model.

The consequences of conflating them are not symmetric either:

- A member on a dormant-ActivityPub instance has a working local account.
- A member with no `did:plc` has **no ATProtocol identity at all**. Not a
  degraded one — none. They cannot use bsky.app, cannot be resolved, cannot be
  followed, and cannot take their identity elsewhere later, because the DID they
  would take is the one that was never created.

That last point is the decisive one. `did:plc` is not a federation feature; it
is identity, and it is the *portable* half of the identity — the DID commits to
the member's keys and belongs to them rather than to us (see ADR 0015's
reasoning about derived identifiers). Withholding it is not a conservative
default, it is a decision to keep members' identities hostage to a switch that
was designed for a different problem.

It also made Phase 7's own exit criterion unreachable: "bsky.app renders a
profile and a post" cannot happen for a member who has no DID.

## Decision

**`FEDERATION_ENABLED` governs ActivityPub delivery and nothing else.
ATProtocol is always on.**

Concretely:

- `did:plc` registration, key rotation, XRPC, OAuth, service auth and the
  firehose are unconditional. They are how a PDS works.
- ActivityPub delivery to remote inboxes stays behind the switch, unchanged,
  with its tripwire intact. Phase 5's behaviour does not move.
- The constant stays where it is, in the ActivityPub adapter, which is now
  where its name is accurate rather than merely where it was convenient.

## Consequences

- **Phase 7's second exit criterion becomes reachable.** It was previously
  blocked by this misreading rather than by anything real.
- **The switch means something narrower and truer.** "Federation" in this
  codebase now names one protocol's outbound delivery, which is what the flag
  has always actually controlled.
- **Phase 8 shrinks slightly.** It is ActivityPub's flip plus the moderation and
  relay surface, not a general unlocking.
- **A relay registration is still an announcement.** Telling a relay we exist is
  the one ATProtocol action that resembles reaching outward. It is in scope and
  ungated, because a PDS no relay knows about is a PDS nobody can read — which
  is the same "no identity at all" failure in a different place.
- **D12 is scoped, not reversed.** Its safety argument still holds everywhere it
  was actually aimed.
