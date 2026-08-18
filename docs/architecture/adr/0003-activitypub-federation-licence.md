# 0003 — `activitypub_federation` forces AGPL-3.0 on the whole product

**Status:** Accepted (2026-08-18)
**Closes:** open decision O1, ActivityPub half. Unblocks Phase 5.

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

## Decision

**Option A. Adopt `activitypub_federation`, and licence brolly-server
`AGPL-3.0-or-later`.**

The licence is not a cost we are absorbing to get a dependency — it is the
intended posture. brolly is meant as a public good, and the network clause is
the point: an operator who modifies it owes their users the source. That places
us in the same licence family as Mastodon, Lemmy, and Pixelfed, which is native
to the fediverse rather than a concession to it.

Because the licence question is settled on its own merits, the framework's AGPL
status stops being a blocker and the `pub(crate)` signature primitives stop
mattering — we are adopting the whole framework deliberately.

### Accepted alongside it

- **`rsa 0.9.10` / RUSTSEC-2023-0071.** No fixed release exists and none is
  expected; upstream's only remediation is "do not use this crate." Recorded as
  an explicit, justified `ignore` in `deny.toml` with a review trigger, rather
  than by loosening the advisory gate. Our RSA private-key use is outbound
  signature generation, not a decryption oracle, and the exposure is identical
  to the predecessor's and to the rest of the Rust fediverse.
- **A stalled pre-release.** We pin `0.7.0-beta.11` because it is the only
  version that unifies on axum 0.8; `0.7.0` has never shipped and beta.11 has
  not moved in roughly three months. Treat a version bump as a change requiring
  the spike to be re-run, and watch for the crate going unmaintained.

## Consequences

- **The whole workspace is AGPL-3.0-or-later.** `LICENSE` carries the full text;
  the workspace manifest declares it; every crate inherits it. Permissive
  relicensing is off the table from here, which is the intended outcome.
- **Phase 5 is unblocked** and gets the framework's inbox, delivery, retry, and
  cavage signature handling instead of ~450 hand-rolled lines.
- **`cargo deny` now allows AGPL-3.0 and GPL-3.0** because they are compatible
  with our own licence, not because the gate was weakened.
- **ADR 0002's ATProtocol stack is unaffected** — `atrium-*` is MIT, which is
  compatible with an AGPL combined work.

## Superseded reasoning

An earlier draft of this ADR recommended option B (hand-roll ActivityPub, keep
Apache-2.0/MIT) on the grounds that the licence should be chosen deliberately
rather than inherited from a transitive dependency. That reasoning was right and
the deliberate choice was made — it simply came out the other way. Recorded here
so the argument is not re-run.

## Consequences of deferring
