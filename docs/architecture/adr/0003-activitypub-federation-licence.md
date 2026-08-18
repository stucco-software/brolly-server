# 0003 — `activitypub_federation` forces AGPL-3.0 on the whole product

**Status:** Proposed — needs a product decision (2026-08-18)
**Blocks:** open decision O1, ActivityPub half. Blocks Phase 5.

## Context

The plan assumed we would adopt `activitypub_federation` for inbox, delivery,
retries, and HTTP signatures, the way Lemmy does — the old research recorded it
as "AP1 ✅ PASS, Lemmy proves Mastodon-compat empirically" and flagged only a
version concern about axum.

Spiking it surfaced two facts that survey missed entirely.

### 1. It is AGPL-3.0, and so is its whole signature stack

```
activitypub_federation            0.7.0-beta.11   AGPL-3.0
http-signature-normalization      0.7.1           AGPL-3.0
http-signature-normalization-reqwest 0.14.1       AGPL-3.0
activitystreams-kinds             0.3.0           GPL-3.0
```

Linking these makes the combined work AGPL-3.0. The workspace currently declares
`Apache-2.0 OR MIT`. AGPL's network clause means anyone running a *modified*
brolly-server must offer source to its users over the network — which lands
directly on the "turnkey it into a community" use case, where operators are
exactly the people likely to modify it.

### 2. You cannot take just the signatures

`sign_request`, `verify_signature`, and `verify_body_hash` are all `pub(crate)`
(`src/http_signatures.rs:81,122,264`). There is no supported way to use the
cavage implementation without adopting the framework's traits, config, and
delivery queue wholesale. It is a framework, not a library of parts.

### 3. Secondary: version and advisory posture

- `0.7.0` has **never shipped stable.** `0.7.0-beta.11` is still the newest
  release and has not moved since the predecessor's research cited it roughly
  three months ago. Stable `0.6.5` pins **axum 0.7**, which double-pins axum
  against our 0.8 — confirmed in the spike, and beta.11 does unify on 0.8.9.
- It pulls `rsa 0.9.10`, carrying **RUSTSEC-2023-0071** (Marvin timing
  sidechannel, no fixed release available). Note the predecessor used `rsa`
  directly for the same purpose, so this is not a regression — but adopting the
  framework means inheriting it rather than choosing it.

## Options

**A — Adopt it and relicense to AGPL-3.0.** Cheapest path to conformant
federation. Puts us in the same licence family as Mastodon, Lemmy, and Pixelfed,
which is defensible and arguably native to the fediverse. Costs: permissive
relicensing is off the table afterwards, and we inherit a stalled beta plus the
`rsa` advisory.

**B — Hand-roll ActivityPub, keep Apache-2.0/MIT.** What the predecessor did:
~450 lines of cavage HTTP signatures plus delivery and inbox queues we already
understand. Keeps licensing free and the dependency surface small. Costs the
conformance benefit that motivated adoption, and puts security-critical
signature code back in our hands.

**C — Adopt for the parts that are not AGPL.** Not available. The signature
primitives are `pub(crate)`; there is nothing to take piecemeal.

## Recommendation

**B for Phase 5, with the licence question decided separately and deliberately.**

The rationale is that the licence decision should be driven by what we want the
product to be, not by a transitive dependency of one adapter. If AGPL is right
for brolly, choose it on its merits and then option A becomes free. If it is
not, option A was never actually available and discovering that in Phase 5
would be expensive.

Hand-rolling cavage is a known quantity here — the predecessor's implementation
interoperated with the whole fediverse, and its module boundary was clean. This
is the one place where "we already did it once and it worked" is real evidence.

## Consequences of deferring

Phase 5 cannot start until this is decided. Phases 0–4 and 7 are unaffected:
ADR 0002's ATProtocol stack is MIT throughout.
