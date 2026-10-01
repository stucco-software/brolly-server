# Greenfield Implementation Plan

**Date:** 2026-08-18
**Language:** Rust (decided)
**Companion:** [`greenfield-learnings.md`](greenfield-learnings.md) — the evidence
behind every decision locked below. This document does not re-argue them.

---

## 1. Decisions locked

Do not relitigate these in plan docs or PRs. Reversing one requires an ADR that
supersedes this section.

| # | Decision | Consequence |
|---|---|---|
| D1 | **Rust**, single binary, single Docker image, turnkey | No sidecars, no per-user process provisioning |
| D2 | **Per-user embedded Oxigraph stores**, one directory each | Physical isolation, `rm -rf` delete, per-user quota by `du` |
| D3 | **SPARQL-first** — joins/traversals/aggregations are queries | Engine quality is a hard requirement; this is why D1 |
| D4 | **Server-agent store** — the instance is an agent with WebID, DID, keypair, store | Owns the cross-user query surface and all instance state |
| D5 | **Index holds pointers + filter keys only**, never content | Dangling refs are the correct steady state |
| D6 | **Push, not pull** — your inbox *is* your home timeline | Reads answer from the viewer's own store by default |
| D7 | **Two-layer vocabulary** — faithful always, canonical where things are the same thing | Export is complete; harmonization is opt-in per entity |
| D8 | **Harmonize on the subject IRI**, not via `owl:sameAs` | All writers assert onto `…/profile#me`; nothing to join |
| D9 | **Solid LDP is generic CRUD.** Publication = shape + location | A typed publication container, not a sync flag |
| D10 | **No automatic cross-protocol collapse.** Bridging is an explicit per-write user decision | Display across surfaces is fine; delivery is opt-in |
| D11 | **`did:plc` in every wire format** from the first commit; `did:web` for routing only | No AT-URI migration later |
| D12 | **Federation off by default**; all federation code paths still exercised locally. **Scoped to ActivityPub by ADR 0016** — ATProtocol is always on, because a PDS hosts rather than pushes and a member without a `did:plc` has no identity at all | Ship dormant, flip in a one-line commit |
| D13 | **Drop `com.mycorriza.rdf.resource`** | Nothing publishes arbitrary Solid RDF outward |
| D14 | **Adopt `atrium-*` from commit one** | No hand-rolled MST, CAR, or service-auth JWT |
| D15 | **Trunk-based**, every commit deployable | Risky work ships behind a module constant |
| D16 | Scale target: **thousands of users, under ten thousand** | Sizes the index, the LRU, and the box |

---

## 2. Architecture

### 2.1 Crate graph

Acyclic, enforced by a CI test. `app()` lives in `server/` and **nowhere else** —
this single rule is what keeps the graph acyclic and is the one that decayed last
time.

```
domain/       canonical vocabulary, quad model, projections, IRI canonicalization.
              Zero protocol deps. Zero I/O.
store/        StoreManager (per-user), server-agent store, query helpers.
authz/        WAC as SPARQL, evaluated on every read. Depends on domain + store.
identity/     users, WebID, did:web + did:plc, keys, sessions, Subject.
adapters/
  solid/      LDP-RS/-NR/-BC, N3 Patch, SPARQL Update PATCH, Solid-OIDC provider
  atproto/    XRPC, MST/repo/CAR (atrium), PLC, OAuth, firehose
  activitypub/ AS2 delivery, inbox, HTTP signatures (cavage-09)
  mastodon/   client API — projection only, no storage of its own
server/       composes adapters, owns app(), spawns workers. The ONLY crate
              depending on more than one adapter.
```

### 2.2 Storage topology

| Store | Contains | Query scope |
|---|---|---|
| **Per-user pod** (`/data/users/<uuid>/rdf`) | all authoritative content, every protocol | cross-*protocol* joins within one user |
| **Server-agent store** (`/data/instance/rdf`) | pointers + filter keys for all users, moderation, instance metadata | cross-*user* queries |
| **Postgres** | operational only: users, sessions, tokens, keys, queues, blob metadata | no user content, ever |
| **Blobs** (`/data/users/<uuid>/blobs`) | media bytes, content-addressed | — |

Every query resolves to exactly one of the first two. Nothing federates across
stores.

### 2.3 Read rule

> **If a query can be answered from the viewer's own store, it must be.**
> Routing it through the server index instead is how you get a mirror you can't
> retire.

---

## 3. Phases

Each phase states falsifiable exit criteria. A phase is not done because the
plan file says `status: done` — it is done when its exit command passes in CI.

### Phase 0 — Foundations (week 1)

Everything here is load-bearing precisely because it never gets retrofitted.

- Workspace with the §2.1 crate graph; a test asserting the dependency graph and
  that `app()` exists only in `server/`.
- `#![deny(clippy::print_stderr, clippy::print_stdout)]` in every library crate.
  `tracing` with structured fields from the first log line.
- `unwrap_used`, `expect_used`, `panic`, `todo` = **deny** in library crates
  (warn was not enough last time).
- **testcontainers-rs** so `cargo test` provisions its own Postgres. No
  `#[ignore]` for DB tests — if it only runs on request, it stops passing.
- rustfmt, clippy, cargo-deny, lefthook, CI on every push.
- ADR directory; CI check that every filesystem path cited in `docs/` resolves.
- **Library survey ADR** (see §6) — resolved before Phase 1 ends, not month three.

**Exit:** CI green on an empty workspace; `cargo test` passes with no env setup
on a clean clone; a deliberate `println!` in a library crate fails the build.

### Phase 1 — Vocabulary and adapter contract (no HTTP)

The bet starts here. If this is wrong, everything downstream is this codebase
again.

- `domain/vocab` — canonical terms: AS2 + FOAF/vCard, plus our own namespace for
  the handful of things neither covers.
- `domain/canon` — IRI canonicalization table (AS2 `http://` vs `https://`,
  `w3id.org/security` v1/v2, `joinmastodon.org/ns#`) applied at one choke point.
- **Two-layer emission** (D7): every adapter emits *faithful* quads always, and
  *canonical* quads for the entities in the mapping table.
- NSID→namespace function for atproto lexicons, so `app.bsky.feed.post#text` and
  `site.standard.doc#text` never collide.
- Adapter trait: `wire → quads` and `quads → wire`, **pure** — no store, DB, or
  network in the function body.
- The canonical mapping table starts with **profile only**. A second entity
  earns its way in later.

**Exit:** proptest round-trip (`wire → quads → wire`) green for AS2 and for two
unrelated atproto lexicons; a test asserting no quad in a fixture store uses a
non-canonical namespace; adapters compile with zero I/O deps.

### Phase 2 — Store, authz, server agent

- `StoreManager`: per-user directory, moka LRU. **Benchmark one store's open cost
  and steady-state memory, multiply by the LRU ceiling, size the box.** The old
  500/1h defaults were never validated.
- Server-agent store; instance WebID, DID, keypair.
- **Canonicalization enforced on the single write path** (Phase 1's table), with
  a test that non-canonical input is normalized on the way in.
- **WAC as SPARQL**, evaluated in the store layer on every read, for every
  protocol. `acl:agentGroup` → `vcard:hasMember` is a property path; effective-ACL
  discovery is a query, not a container walk with string manipulation.
- **The instance-wide read inventory** (§5) becomes the index schema. Write it
  down before writing the index.
- `instance-reindex` command that rebuilds the index from pods in one pass.

**Exit:** one authorization conformance matrix, run identically through a stub of
each of the four surfaces; `instance-reindex` on a seeded instance produces an
index isomorphic to the incrementally-built one.

### Phase 3 — Identity and auth dispatch

- users, WebID, keys, sessions.
- `did:web` for routing; **`did:plc` in every wire format from the first commit**
  (D11). No "we'll migrate the AT-URIs later."
- **One auth dispatcher** returning a normalized `Subject { kind, user_id, did,
  webid, scope, via }`. Every handler takes a `Subject`.
- **OAuth path multiplex designed up front**, with a written precedence table
  covering atproto (PAR / `request_uri`, DPoP), Mastodon (PKCE, Bearer), and
  Solid-OIDC. Do not discover this when a client fails to log in.

**Exit:** a test per branch of the precedence table; every handler signature takes
`Subject` and none parses an `Authorization` header itself.

### Phase 4 — Solid

The least opinionated surface, and the one that exercises store, authz, and
vocabulary hardest. Ship it before anything federates.

- LDP-RS, LDP-NR (binary), LDP-BC; content negotiation.
- N3 Patch and `application/sparql-update` PATCH — both through the same solver
  this time, not one delegating to the engine and one hand-rolled.
- Solid-OIDC provider (issuer) and verifier.
- **Reject `application/rdf+xml` on every write path** with 415, per ADR 0007 —
  two live DoS advisories in `quick-xml` are reachable from federation input
  otherwise, and the dependency cannot be removed.
- **User storage mounted at `/~/`** (ADR 0010), typed `pim:Storage` +
  `ldp:BasicContainer`, with `space:storage` in the WebID profile advertising the
  same root the router mounts. Everything outside `/~/` on a subdomain is an
  explicit protocol resource or a 404 — no fallback.
- **The typed publication container** (D9): a container whose type marks it a
  publication surface. A write of `rdf:type as:Note` *there* is a post; anywhere
  else is private CRUD. ACL defaults must state that Append on it means "may post
  as me."

**Exit:** LDP + WAC conformance suite green; a write to a non-publication
container provably emits no activity and no repo commit.

### Phase 5 — ActivityPub

Thin, because AS2 is the canonical vocabulary.

- Actor docs, WebFinger, NodeInfo, shared inbox — now backed by a real instance
  actor (D4).
- Delivery + inbox queues; HTTP Signatures cavage-09.
- **Inbox arrival writes containment plus a sort key** — the missing piece that
  forced outbox-walking last time.
- **The server agent is a delivery recipient**, and its processor writes the
  pointer row. The index is populated by push, never by crawling.
- `federation_enabled = false` (D12).

**Exit:** local follow → post → like → delete flows green end to end; the public
index is populated entirely through the delivery path with no crawler.

### Phase 6 — Mastodon

Projection only. A dependency lint forbids this crate from writing to any store.

- Home timeline = **query the viewer's own inbox graphs**. Not outbox-walking,
  which also silently drops every remote followee.
- Public/local timeline = query the server index.
- Status composition with media, CW, language, visibility — the things silently
  dropped last time.
- Status IDs: either encode the owning user, or a pure `id → user_id` routing
  table. Decide in §6.

**Exit:** Phanpy works end to end against a private instance; every defect in the
old `2026-06-11-mastodon-p0-correctness-design.md` list has a regression test;
`mastodon/` has no write path to a store.

### Phase 7 — ATProto

Last, because it is the hardest map onto AS2 and the most ecosystem-dependent.

- `atrium-*` for crypto, MST, repo, CAR, identity (D14). No hand-rolled MST.
- PLC client, key rotation, XRPC, service auth, OAuth (PAR + DPoP), firehose.
- Faithful layer via NSID-derived namespaces — **any** lexicon ingests without a
  mapping; mapped ones additionally assert canonical triples.
- No `com.mycorriza.rdf.resource` (D13).

**Exit:** CAR export validates against an independent IPLD implementation;
bsky.app renders a profile and a post; an unmapped third-party lexicon
round-trips and appears in export.

### Phase 8 — Federation on

- Relay registration, remote-actor cache, allow/block lists, moderation surface.
- Flip `federation_enabled` in a one-line commit.

**Exit:** a post reaches a real Mastodon instance and a real AppView; inbound from
both verifies.

---

## 4. Web surface — UI/UX

The current codebase inverts the priority: the **admin console** (13 Askama
templates, shared `base.html`, a token-based stylesheet) is the polished surface
that almost nobody sees, while **login and registration** — the front door of a
product you "turnkey into a community" — are still inline `format!("<…")` strings
in `auth_routes.rs`. Fix that ordering greenfield.

### 4.1 The four audiences

| Audience | Surface | Stakes |
|---|---|---|
| **Anonymous visitor** | landing, login, register, invite redemption, password reset | First contact. Determines whether anyone joins at all. |
| **Member** | `/dashboard` — overview, profile, apps, security, export, delete | Daily surface. Must make pod ownership legible. |
| **Admin** | `/admin` — users, invites, reports, rules, apps | Low traffic, high consequence. |
| **Protocol clients** | **OAuth authorize / consent screens** | See below — the highest-stakes screen in the product. |

The fourth is the one that gets missed. **The consent screen is UI that renders
inside someone else's app flow**, and it is the moment a user decides whether to
hand an app access to their pod. There are three of them — Solid-OIDC, ATProto
OAuth, Mastodon OAuth — and they must be one component with one scope-rendering
vocabulary, not three screens that drifted. A user granting `write` to a Solid app
and `write:statuses` to a Mastodon client should see the same shape of question.

**Not in scope:** a hosted Mastodon web client. Unauthenticated visitors hit the
login wall; members use Phanpy or any stock client.

### 4.2 Decisions to lock (see §6, O6–O8)

The default recommendation, consistent with D1 (single binary, single image,
turnkey):

- **Server-rendered Askama, progressive enhancement.** Every form works with
  JavaScript disabled. Interactive bits are islands, not an app shell.
- **No SPA.** A client-side app needs a token flow, fights the per-user subdomain
  model, and puts a build toolchain in the critical path of a product whose
  selling point is one Docker image.
- **Tokens are the design system contract.** Today's stylesheet is 78 lines with
  8 tokens and no dark mode. Start from a real token set — color (light *and*
  dark), space, type scale, radius, shadow — and let components consume only
  tokens. Retrofitting dark mode after components exist is expensive; deciding it
  at the token layer is nearly free.
- **One stylesheet, one token source.** A new feature extends tokens or
  components. It does not add a stylesheet.

Open: whether the tokens (and optionally components) come from the existing
**båtklubb** Svelte 5 library. Taking *tokens* from it is compatible with
server-rendering and probably a straight win. Taking *components* implies a build
step and JS islands — viable (Svelte compiles to static assets built inside the
image), but it needs to be a decision, not a drift. See O6.

### 4.3 Working process for the implementing agent

Follow this order. Skipping to markup is how you get 78 lines of CSS called a
design system.

1. **Read the audience table and the IA before writing markup.** Name which
   audience and which page a change serves, in the commit message.
2. **Tokens → components → pages.** Never the reverse. A page that needs a
   one-off style means a missing token or component; add it there.
3. **Write a spec doc before implementing a surface**, in
   `docs/specs/<date>-<surface>.md`, following the existing house format:
   Problem / Goals / Non-goals / Design / IA / Testing. The
   `2026-06-09-member-dashboard-redesign-design.md` spec is a good model — it
   states non-goals explicitly, which is what kept it shippable.
4. **Verify visually, not just by compiling.** Run the app, load the page, take a
   screenshot, check it at 375px and 1280px, and check both color schemes. A
   template that compiles is not a page that works.
5. **Accessibility is a gate, not a polish pass.** Every form control has a label,
   every page has one `h1` and a landmark structure, focus is visible, contrast
   meets WCAG AA against both themes, and the whole flow is keyboard-operable.
   Check this before review, not after.
6. **Figma is available** via MCP if a design exists or needs producing — but
   design-in-Figma is optional. Tokens and components in code are the source of
   truth; Figma is a communication tool, not the contract.

### 4.4 Where UI lands in the phases

UI is not a phase; it threads through. Minimum viable surface per phase:

| Phase | UI deliverable |
|---|---|
| 0 | Token set (light + dark), base layout shell, one page rendered end to end as the reference |
| 3 | **Auth surfaces**: login, register, invite redemption, password reset, email verification. The front door ships with identity, not after it. |
| 3 | **The unified consent screen** — one component, three protocol callers |
| 4 | Member dashboard: overview, profile, security, apps, export, delete |
| 5–7 | Admin console: users, invites, reports, rules, apps — grows as moderation surfaces do |

### 4.5 UI invariants

Enforced the same way as §5 — mechanically where possible.

| Invariant | Enforcement |
|---|---|
| No HTML built with `format!` in Rust | grep gate in CI: `format!("<` in `src/` fails the build |
| One stylesheet, one token source | CI check: exactly one CSS entrypoint in `static/` |
| No hardcoded colors in components | CI grep for hex literals outside the token block |
| Every form works without JavaScript | a test asserting each `<form>` has a non-JS action + method |
| Every page has one `h1` and a `<main>` | template lint over `templates/` |
| Consent screens share one component | the three OAuth handlers render the same template |

## 5. Cross-cutting invariants

These are the things that decayed last time. Each is enforced mechanically, not
by intention.

| Invariant | Enforcement |
|---|---|
| `app()` only in `server/` | dependency-graph test |
| No `print!`/`eprintln!` in libraries | `deny(clippy::print_stderr, print_stdout)` |
| Errors on delivery / federation / storage are never discarded | clippy `let_underscore_must_use` + review |
| Every write canonicalizes IRIs | test asserting no non-canonical namespace in a store |
| Authz evaluates on every read path | conformance matrix run through all four surfaces |
| Answer from the viewer's own store when possible | review rule; index additions need a stated reason |
| Index holds pointers + filter keys only | schema test: no content predicates in the index graph |
| `brolly-domain` is pure | `server/tests/architecture.rs` — no sqlx/reqwest/tokio/oxigraph/axum/hyper. Adapter *impls* are pure too, but the crates legitimately need the network (XRPC, PLC), so that half is a review rule, not a test. |
| Docs cite paths that exist | CI path-resolution check |
| Migrations prefixed by owning crate | naming test in CI |

---

## 6. Open decisions — close these before the phase that needs them

| # | Decision | Needed by | Notes |
|---|---|---|---|
| ~~O1~~ | **CLOSED — ADR 0002, 0003.** Library survey ADR — `atrium-*` versions, `activitypub_federation` 0.7.x pin, cargo-deny clearance | end of Phase 0 | **Spike it, don't survey it.** The last attempt built its verdict table from line counts and four of eleven swaps turned out to be no-ops. Write one throwaway end-to-end path first: sign a commit, write a record, verify an inbound signature. |
| ~~O2~~ | **CLOSED — ADR 0005.** Instance-wide read inventory — the complete list of queries no single pod can answer | Phase 2 | Public/local timeline, search, admin lists, ID routing, moderation. Short and knowable now; discovering it one denormalization at a time produced four create-then-drop migration pairs. |
| ~~O3~~ | **CLOSED — ADR 0012, reuse `as:outbox`.** Publication container vocabulary term — how a Solid app discovers a container is a publication surface | Phase 4 | Must be readable by a generic client, not a hardcoded path. |
| ~~O4~~ | **CLOSED — ADR 0015.** Mastodon status ID scheme | Phase 6 | Fixed-width, lexically sortable, self-describing. The constraint is sortability, not numerics: Pleroma and GoToSocial both ship non-numeric IDs and both preserved lexical sort. Resolution stays O(1) with no index, so ADR 0005's R2 needs none. |
| ~~O5~~ | **CLOSED — ADR 0006.** Store benchmark numbers | Phase 2 | LRU miss 8.1 ms vs hit 541 ns; 435 KB floor per empty pod. Resident memory still unmeasured. |
| ~~O6~~ | **CLOSED — ADR 0004.** Design system source — tokens from båtklubb, tokens *and* components, or hand-rolled | Phase 0 | Tokens-only is compatible with server-rendering. Components imply a build step and JS islands — viable, but decide it rather than drift into it. |
| ~~O7~~ | **CLOSED — ADR 0004, yes.** Dark mode | Phase 0 | Nearly free at the token layer, expensive after components exist. Defaulting to "yes" costs almost nothing. |
| ~~O8~~ | **CLOSED — ADR 0011.** Scope vocabulary for the consent screen — how Solid, ATProto, and Mastodon scopes render as one comprehensible question | Phase 3 | The highest-stakes screen in the product; three protocols must not each invent their own wording. |
| O9 | **Independent Solid conformance verification in CI** — running the Solid Conformance Test Harness (or any external conformance runner) as a CI gate against a containerized instance | Stage 5d / roadmap finish-line item 5 (deferred 2026-10-01) | **Open.** The 5d spike (findings and citations: `docs/specs/2026-09-29-solid-auxiliary-resources.md`, H7) established the standing fact: no headless client can complete brolly's OIDC flow today — consent is human by design, refresh tokens are key-bound, there is no credentials grant. That is the security posture working as intended, and it is why an external harness has no way in; each of the spike's findings is a deliberate, advertised brolly design, and accommodating the harness would mean weakening that surface for tooling convenience. Re-entry, any one of which reopens it: the CTH grows ES256 DPoP and consent-screen handling (its own code carries the ES256 TODO); a credible runner not shaped around Inrupt's stack appears; stage 6 (Solid identity: Client ID Documents, `prompt=none`, `docs/specs/2026-09-29-solid-identity.md`) deliberately decides a machine-client auth path — that is where one would live. Filing the ES256/consent case upstream is an operator follow-up, not agent work. |

---

## 7. Explicitly not building

Recorded so they don't get rediscovered as scope.

- **A cross-protocol bridge that collapses types automatically** (D10). Different
  data types stay different unless a user makes an explicit per-write decision.
  Display across surfaces is fine; *delivery* across surfaces is opt-in.
- **Horizontal scale-out.** Single host, single image (D1, D16).
- **A Postgres mirror of user content.** Operational state only.
- **RFC 9421 HTTP signatures.** Cavage-09 only until fediverse adoption moves.
- **Custom lexicons for publishing Solid RDF outward** (D13).
- **Reverse migrations.** Forward-only, per sqlx convention.
- **A hosted Mastodon web client.** Members use Phanpy or any stock client; our
  web surface is auth, dashboard, admin, and consent (§4).
- **A single-page app.** Server-rendered with progressive enhancement (§4.2).

---

## 8. Sequencing rationale

Phases 1–3 are the whole bet. They are vocabulary, storage semantics, and
identity — the three things every adapter is a thin function over. If they are
right, Phases 4–7 are adapters. If they are wrong, no amount of adapter quality
recovers it, and the failure mode is exactly the one documented in the companion:
four protocols, four private representations, and a `rawJson` escape hatch
admitting the triples were never canonical.

Resist building protocols in parallel. Solid first, alone, proves the foundation
under real load before a second adapter can paper over a crack in it.
