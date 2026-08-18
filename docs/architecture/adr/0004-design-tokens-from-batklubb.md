# 0004 — Design tokens from båtklubb; components hand-authored

**Status:** Accepted (2026-08-18)
**Closes:** open decision O6, and O7 (dark mode) with it.

## Context

Phase 0 shipped a hand-rolled stylesheet: 8 colour tokens, a hand-written space
and type scale, dark mode via `prefers-color-scheme`. It worked, and it was a
placeholder — the predecessor's equivalent was 78 lines with 8 tokens and no
dark mode at all, which is what a "design system" degrades into when nothing
generates it.

båtklubb is the author's existing Svelte 5 component library. It is not on npm;
components are copy/paste, and tokens are generated from a local config. The
open question was whether to take tokens, tokens *and* components, or neither.

## Decision

**Take the tokens. Do not take the components.**

- `batklubb.config.js` at the repo root is the token source of truth.
- `tools/gen-tokens.sh` regenerates `server/static/tokens.css` and fails if any
  colour pair misses WCAG AA.
- `server/static/brolly.css` is the only hand-authored stylesheet and references
  tokens exclusively. Enforced by `server/tests/ui_invariants.rs`.

**Components are out** because they are Svelte 5 + Bits UI and assume a
SvelteKit shape. Adopting them means a JavaScript toolchain and client-side
islands in a product whose selling point is one Docker image (D1), against a
server-rendered, progressive-enhancement UI that is already decided.

**Node is an authoring dependency only.** The generated CSS is committed, so
building and running the server needs Rust and nothing else. D1 holds.

## Why the tokens are worth taking

båtklubb's model is two-layer — raw palette ramps, then semantic roles
(`background`, `foreground`, `surface`, `primary`, `muted-fg`, `border`,
`border-subtle`, `ring`, `destructive`, …) — plus a Utopia fluid type and space
scale, typography roles, scale aliases, and motion tokens. That is a real design
system where the Phase 0 stylesheet was a colour list.

The decisive evidence arrived on first run. Generating brolly's tokens
immediately failed the contrast gate:

```
✗ FAIL  UI: border visibility (background / border) — 1.3:1 (need 3:1)   [dag]
✗ FAIL  UI: border visibility (background / border) — 1.5:1 (need 3:1)   [natt]
```

The hand-rolled stylesheet had exactly this defect in both themes and no way to
notice it. The fix — a mid-grey `--ink-mid` for informational borders, keeping
the lighter shade as `border-subtle` for decorative dividers — is the
distinction båtklubb's role vocabulary already encodes and the hand-rolled one
did not. Both themes now pass at 4:1 and 4.4:1, and every pair passes AA.

Getting an accessibility gate (plan §4.3) for free, from the token generator,
is worth more than the tokens themselves.

## Known integration gap: the colour-scheme bridge

båtklubb emits themes as `[data-theme="dag"]` / `[data-theme="natt"]` only. We
are server-rendered with no JavaScript, so an anonymous visitor — the front door,
audience one in the plan's §4.1 — never has that attribute set and would always
get the day theme.

`tools/gen-tokens.sh` therefore appends a bridge that re-emits the night theme
under `@media (prefers-color-scheme: dark)`, scoped `:root:not([data-theme="dag"])`
so an explicit choice always wins. A test asserts the bridge survives
regeneration, because it is the kind of thing a future `batklubb tokens` run
would silently drop.

This also settles **O7**: dark mode is in, at the token layer, from Phase 0.

## Consequences

- **Two stylesheets, one hand-authored.** The invariant changes from "exactly
  one CSS file" to "exactly one generated token file plus exactly one
  hand-authored stylesheet", with a test for each.
- **Literal colours are a build failure** in `brolly.css`. They belong in
  `batklubb.config.js`.
- **Contrast is gated at authoring time**, not review time.
- **båtklubb is a soft dependency.** `BATKLUBB_HOME` overrides its location, and
  a contributor without it can still build, run, and test everything — they just
  cannot regenerate tokens.
- **If båtklubb ever ships server-friendly components**, revisit. Nothing here
  forecloses it; only the component half was declined.
