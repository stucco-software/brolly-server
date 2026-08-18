# 0001 — Locked decisions live in the plan, not in ADRs

**Status:** Accepted (2026-08-18)

## Context

The predecessor project accumulated ~200 plan documents and 11 ADRs. The ADRs
aged well; the plans did not. Several plans were marked `status: done` for work
that had not shipped — structured logging was marked done twice while the
codebase carried 238 `eprintln!` calls and zero `tracing::` calls.

This project starts with sixteen decisions already made, derived from that
retrospective. They need a single home that is obviously authoritative, and
they need to be hard to reverse by accident.

## Decision

The locked decisions live in `docs/greenfield-implementation-plan.md` §1 as
D1–D16. They are not restated as individual ADRs.

Reversing one requires a new ADR in this directory that names the decision it
supersedes and explains why. Ordinary plan documents may not contradict §1.

New decisions made during implementation — ones not covered by D1–D16 — get
ordinary ADRs here.

## Consequences

- **One authoritative list.** A contributor reads §1 and knows the ground rules
  without reconstructing them from sixteen files.
- **Reversal is deliberate.** Changing course means writing an ADR, not editing
  a table.
- **ADRs stay for genuinely new decisions**, which keeps this directory small
  and readable.
- **Phase completion is defined by exit criteria, not by a status field.** A
  phase is done when its exit command passes in CI. `status: done` in a document
  proves nothing — that lesson is why this ADR exists.
