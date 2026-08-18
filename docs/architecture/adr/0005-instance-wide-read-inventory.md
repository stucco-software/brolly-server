# 0005 — The instance-wide read inventory

**Status:** Accepted (2026-08-18)
**Closes:** open decision O2. Required by Phase 2.

## Context

Per-user stores make cross-user queries impossible in the engine — embedded
Oxigraph has no federated query, so a question spanning two users must be
answered by application code. Decision D6 says most reads never need that: push
delivery puts activities in the recipient's own store, so a home timeline is a
single-store read.

But some reads genuinely cannot be localised, and the predecessor discovered
them **one denormalization at a time**. That produced four create-then-drop
migration pairs inside a single week (`ap_status_index`, `ap_follows`,
`ap_status_reactions`, `mastodon_notifications`), and then — seven weeks after
adopting pod-canonical storage on principle — a `profile_display_name` column
added back to Postgres with a backfill job, because the admin list could not
open 500 stores to render a table.

The failure was not choosing wrong. It was discovering the list late, repeatedly,
under pressure, in whatever storage happened to be at hand.

## Decision

The list is enumerated here, up front. Every entry lives in the server-agent
store (D4) as pointers and filter keys, never content (D5). Anything not on this
list must be answered from the viewer's own store; adding an entry requires
amending this ADR with a stated reason.

| # | Read | Why no single pod can answer it | Index shape |
|---|---|---|---|
| R1 | **Public / local timeline** | no user recipient — nobody delivered it to anyone | `⟨note IRI, author, published, audience, inReplyTo⟩` |
| R2 | **Status lookup by opaque ID** | a Mastodon status ID does not name its owner | `⟨status ID → note IRI⟩`; see note below |
| R3 | **Account search / directory** | matches across all local users | `⟨actor IRI, handle, display name, discoverable⟩` |
| R4 | **Hashtag / full-text search** | spans every author | `⟨note IRI, tag⟩`, `⟨note IRI, author, published⟩` |
| R5 | **Admin user list** | one table across all users — the `profile_display_name` case | `⟨actor IRI, handle, display name, created, status⟩` |
| R6 | **Moderation queue** — reports, rules, actions | instance state, owned by nobody | server-agent graphs, authoritative not derived |
| R7 | **Remote actor / federation cache** | shared across all users who interact with a remote actor | `⟨actor IRI, inbox, public key, fetched-at⟩`, authoritative |
| R8 | **Instance metadata** — NodeInfo, `/api/v2/instance` counts | aggregate over all users | counters, derived |
| R9 | **WebFinger / handle → actor resolution** | lookup before any user context exists | `⟨handle → actor IRI⟩` |
| R10 | **Relay / firehose cursor** — `subscribeRepos` backfill | sequence across all repos | authoritative |

**R2 may not need an index at all.** A resource IRI already names its owner
(`https://alice.base/notes/01H…`), so lookup by IRI is O(1) with no index.
Only Mastodon's opaque IDs lose the author. Prefer minting Mastodon-facing IDs
that encode the owning user; fall back to a pure `id → user_id` routing table
(an address, not a copy) only if that proves impractical. Decide in Phase 6.

**R6, R7 and R10 are authoritative, not derived.** They are instance state that
never existed in a pod, so they are not rebuildable from pods and are exempt
from the reconciliation pass below. Everything else (R1, R3, R4, R5, R8, and R2
if it becomes an index) is derived and must be rebuildable.

## Rebuild

`instance-reindex` rebuilds every derived entry from pods in one pass, and is a
Phase 2 deliverable rather than a later addition. Its existence is what keeps
the index honest: an index that cannot be rebuilt has quietly become a source of
truth.

Populate by push, not by crawling (see the plan §4.2 constraint 2) — the server
agent is a delivery recipient like any other, and its processor writes the
pointer row. `instance-reindex` is the repair path, not the normal path.

## Consequences

- **Phase 2 has a concrete schema to build**, not a placeholder.
- **The list is short and closed.** Ten entries, three of them authoritative
  state that was never a pod concern. That is the whole cross-user surface.
- **Additions are visible.** Amending this ADR is the cost of a new
  denormalization, which is exactly the friction that was missing before.
- **Dangling pointers are expected** (D5). A deleted note leaves a row that
  sweeps lazily on dereference; account deletion stays `rm -rf` on one store.
