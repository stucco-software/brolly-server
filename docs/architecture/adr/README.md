# Architecture Decision Records

One decision per file. ADRs append; they don't get rewritten. If a decision is
reversed, mark its status `Superseded by NNNN` and write a new ADR explaining
the reversal.

The locked decisions D1–D16 live in
[`../../greenfield-implementation-plan.md`](../../greenfield-implementation-plan.md) §1.
Reversing one of those requires an ADR here that supersedes that row.

## Format (Michael Nygard)

```markdown
# NNNN — Short title

**Status:** Accepted (YYYY-MM-DD)

## Context
What was happening, what alternatives existed.

## Decision
The choice we made, in active voice.

## Consequences
What follows. Both intended outcomes and accepted tradeoffs.
```

Keep them to a screen or two.

## Index

| # | Title | Status |
|---|-------|--------|
| [0001](0001-locked-decisions-live-in-the-plan.md) | Locked decisions live in the plan, not in ADRs | Accepted |
| [0002](0002-adopt-atrium-for-atproto.md) | Adopt `atrium-*` for ATProtocol primitives | Accepted |
| [0003](0003-activitypub-federation-licence.md) | Adopt `activitypub_federation`; brolly is AGPL-3.0-or-later | Accepted |
| [0004](0004-design-tokens-from-batklubb.md) | Design tokens from båtklubb; components hand-authored | Accepted |
| [0005](0005-instance-wide-read-inventory.md) | The instance-wide read inventory | Accepted |
| [0006](0006-store-budget.md) | Store budget: what a pod actually costs | Accepted |
| [0007](0007-refuse-rdf-xml-on-input.md) | Refuse RDF/XML on input | Accepted |
| [0008](0008-oauth-endpoint-layout.md) | OAuth endpoint layout: discovery, not shape-sniffing | Accepted |
| [0009](0009-reserved-paths-on-user-subdomains.md) | Reserved paths on user subdomains | Superseded by 0010 |
| [0010](0010-user-storage-root.md) | All user LDP content under `/~/` | Accepted |
| [0011](0011-consent-scope-vocabulary.md) | One consent vocabulary across three protocols | Accepted |

## When to write one

Whenever a decision constrains future code organization or routing, picks one
approach where several are defensible, or documents a tradeoff that would
surprise a maintainer in six months. If you can't state the Context in 4–6
lines, it isn't ADR-worthy yet.
