# 0015 — Mastodon status IDs: what an opaque ID has to carry

**Status:** Proposed (2026-08-26)
**Opens:** open decision O4. Must be Accepted before Phase 6 mints its first ID.

## Context

Every other identifier in brolly names its owner. A note lives at
`https://alice.brolly.id/~/notes/01H…`, so resolving one is O(1) with no index
and no routing — the host *is* the answer. ADR 0005 leans on this: R2 "may not
need an index at all".

Mastodon's API breaks that. `GET /api/v1/statuses/:id` takes an opaque
identifier that carries no author, and clients hold those IDs for a long time —
in caches, in `max_id` pagination cursors, in local databases. Whatever we mint
is public, permanent, and effectively un-migratable: reissuing IDs invalidates
every client's stored state.

So this has to be right before the first ID is minted, not after. The plan
records a preference — "prefer minting Mastodon-facing IDs that encode the
owning user; fall back to a pure routing table only if that proves impractical"
— and this ADR exists to test that preference rather than inherit it.

The constraint that makes it interesting is **pagination**. Mastodon's docs say
an ID is an opaque string, but `max_id`/`since_id`/`min_id` are ranges, and the
question is whether ordering has to live *in* the ID or can live in the server
that interprets it.

## Options

### A — Owner-encoding snowflake

64 bits, so it still parses as an `i64`: milliseconds, a compact owner number,
a sequence. Lookup stays O(1) with no index, exactly like an IRI.

The bit budget is tight at D16's scale. Roughly 41 bits of millisecond
timestamp (~69 years), 14 bits of owner (16,384 members — "thousands, under ten
thousand" leaves little headroom), 9 bits of sequence (512 statuses per
millisecond instance-wide). Workable, but every field is sized against a
guess, and the timestamp field is the one that ages.

It also needs something we do not have: a **compact integer per member**. Users
are UUIDs, so this means a new serial column, and that column becomes
load-bearing forever — it is baked into every ID ever issued.

### B — Routing table

Mint a ULID (or snowflake) and keep `⟨status ID → note IRI⟩` in the server
index. ADR 0005 already sanctions this as "an address, not a copy", and lists
R2 among the derived entries that `instance-reindex` must rebuild.

No bit budget, no collision risk, no new column, and the ID scheme can change
later because the table absorbs it.

The cost is a row per status **including private ones** — R1 only indexes
public posts, so this is strictly more index than the instance carries today,
and it grows without bound rather than with the public timeline.

### C — Encode the IRI itself

The ID *is* the note IRI, base64url-encoded. Self-describing, so lookup is O(1)
with no index, no new column and no bit budget. Nothing to migrate because
nothing is allocated.

The ID is then neither numeric nor chronologically sortable. GoToSocial ships
ULIDs and Pleroma ships FlakeIDs against the same clients, so non-numeric is
demonstrably fine — but both are still *sortable*, and this is not.

## The question this ADR exists to settle

**Does any Mastodon client we care about sort status IDs locally, rather than
passing them back as opaque cursors?**

If ordering is purely server-side — the client sends `max_id`, we decode it,
resolve the note, and page by its stored timestamp — then C is strictly better
than both A and B: same O(1) lookup as A, none of A's bit budget or new column,
none of B's unbounded index.

If any target client sorts IDs itself, C is unshippable and the choice is
between A's permanent bit budget and B's permanent index row.

This is empirical and cheap to answer. Phase 6's exit criterion is already
"Phanpy works end to end against a private instance", so the check is: mint
non-sortable IDs behind a module constant, point Phanpy, Ivory and Tusky at it,
and watch whether timelines assemble in the right order.

## Recommendation

**Try C, with B as the fallback**, and treat A as a last resort.

C is the only option that adds no permanent structure — no column, no index, no
bit budget — and it is the one most consistent with how every other identifier
in the system already works: the identifier names its owner, so nothing has to
be looked up. If the client check fails, B is boring, reversible and already
sanctioned by ADR 0005.

A is last because it is the only option whose mistakes are permanent. A field
sized wrong in 2026 is a field that is still wrong when the instance has more
members than the owner field can name, and by then every issued ID depends on
it.

## Consequences if accepted as recommended

- **Phase 6 gains a verification step before it mints anything**: point real
  clients at non-sortable IDs and confirm ordering survives.
- **`instance-reindex` stays unchanged** unless the fallback is taken. If B is
  taken, R2 becomes a derived entry it must rebuild, and ADR 0005's rebuild
  section already covers that.
- **The status ID becomes a decode, not a lookup**, so the Mastodon crate needs
  no store access to resolve one — which is what Phase 6's "projection only, a
  dependency lint forbids writing to any store" requires anyway.
- **If the check fails, nothing is lost.** No IDs have been issued, so falling
  back to B costs a table and no migration.
