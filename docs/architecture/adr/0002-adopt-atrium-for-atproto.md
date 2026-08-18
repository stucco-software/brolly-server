# 0002 — Adopt `atrium-*` for ATProtocol primitives

**Status:** Accepted (2026-08-18)
**Closes:** open decision O1, ATProtocol half.

## Context

The predecessor hand-rolled the ATProtocol primitives: MST (553 lines), repo and
CAR (615), service-auth JWT, key handling. Its adopt-upstream effort ran at month
three and largely failed — the `rsky-*` ecosystem was unusable (half unpublished,
the rest pinned to a yanked `core2` via `cid 0.10.1`), and of eleven proposed
`atrium-*` swaps **four were no-ops** because the verdict table had been built
from file line counts rather than from reading the modules. One swap shipped.

The plan (§6, O1) therefore requires a spike rather than a survey: write one
throwaway end-to-end path first.

## Decision

Adopt `atrium-*` from the first commit of Phase 7. Do not hand-roll MST, CAR,
commit signing, or `did:key` handling.

Resolved versions, all MIT-licensed:

| Crate | Version |
|---|---|
| `atrium-api` | 0.25.8 |
| `atrium-common` | 0.1.4 |
| `atrium-crypto` | 0.1.3 |
| `atrium-identity` | 0.1.9 |
| `atrium-repo` | 0.1.8 |
| `atrium-xrpc` | 0.12.4 |

## Evidence

`spikes/upstream/src/bin/atproto.rs` — 9 probes, all passing:

```
PASS  BYO key: export/import round-trip   32 bytes
PASS  did:key derivation                  did:key:zQ3shiMMpJY64QsQ…
PASS  commit bytes exposed for signing    119 bytes to sign
PASS  genesis commit finalized            root bafyreiaual5grxkiynxc5…
PASS  signature verifies via atrium       verify_signature(did:key, bytes, sig)
PASS  tampered payload is rejected        flipped one byte
PASS  record written, CID returned        bafyreig3tnjgd5dkqfgmh7rf…
PASS  second commit signed + finalized    new root bafyreifvtst5vyggj6i4…
PASS  record reads back through our blockstore
```

Two properties matter more than the pass count:

- **Storage is genuinely pluggable.** `AsyncBlockStoreRead` and
  `AsyncBlockStoreWrite` are a two-method contract; the probe implements them
  over a `HashMap` we own and drives the whole repo through it. Our per-user
  store slots in behind the same trait. This is the constraint the old research
  marked PASS on inspection and then had to rewrite the sub-plan for — it holds
  when actually exercised.
- **Keys stay ours.** `RepoBuilder::bytes()` hands out the commit payload and
  `finalize(sig)` takes back a signature. atrium never sees a private key, so
  key storage, rotation, and PLC remain entirely under our control.

## Consequences

- Phase 7 drops the largest block of hand-rolled protocol code in the
  predecessor. No MST, no CAR writer, no commit-signing crypto of our own.
- The blockstore trait is the seam between atrium and our storage. Keep it thin;
  it is the only coupling.
- `atrium-repo` is 0.1.x and will churn. Pin exact versions and treat a bump as
  a change requiring the spike to be re-run.
- MIT throughout, so no licensing constraint on the ATProtocol side (contrast
  ADR 0003).
