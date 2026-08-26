# 0015 — Mastodon status IDs must be sortable, not numeric

**Status:** Accepted (2026-08-26)
**Closes:** open decision O4.

## Context

Every other identifier in brolly names its owner. A note lives at
`https://alice.brolly.id/~/notes/01H…`, so resolving one is O(1) with no index
and no routing — the host *is* the answer. ADR 0005 leans on this: R2 "may not
need an index at all".

Mastodon's API breaks that. `GET /api/v1/statuses/:id` takes an opaque
identifier carrying no author, and clients hold those IDs for a long time — in
caches, in `max_id` pagination cursors, in local databases. Whatever we mint is
public, permanent and effectively un-migratable, so it has to be right before
the first ID exists.

An earlier draft of this ADR framed the open question as *"do clients sort
status IDs locally, or pass them back as opaque cursors?"* — on the theory that
if ordering were purely server-side we could encode the note IRI directly and
need no index at all.

**That question was wrong, and researching it produced a better answer.**

## What the ecosystem actually requires

Mastodon's guidelines say "always treat IDs as opaque strings" and "clients
generally do not need to sort IDs; the server is responsible for sorting". If
that were the whole story, a non-sortable ID would be fine.

But the same page then publishes a client-side sorting recipe:

> Sort by length. Newer statuses will have longer IDs. Sort lexically. Newer
> statuses will have at least one digit that is higher when compared
> positionally.

A recipe that exists because clients do sort. And every implementation that
departed from Mastodon's numeric IDs kept that recipe working:

| Implementation | ID format | Numeric? | Lexically sortable? |
|---|---|---|---|
| Mastodon | 64-bit snowflake | yes | yes |
| Pleroma / Akkoma | 128-bit FlakeID | **no** | **yes** — docs call it out explicitly |
| GoToSocial | ULID | **no** | **yes** |

Pleroma's documentation states its IDs are twice Mastodon's width and then
notes "just like Mastodon's ids, they are lexically sortable strings". That is
a property they went out of their way to preserve. GoToSocial ships ULIDs and
its FAQ reports no ID-format compatibility problems, naming Tusky, Pinafore and
Feditext as well-supported.

Upstream issue [mastodon#25244] proposes relaxing the "string representations of
numbers" wording precisely because ULIDs work — and its argument is that the
documented sort "works for any ASCII strings with characters 0-9 and a-z/A-Z".
The proposal rests on sortability, not on numerics.

So:

- **Non-numeric is proven safe.** Three independent implementations ship it.
- **Non-sortable has never been attempted by anyone**, and its failure mode is
  the bad one: the documented client recipe would happily mis-sort a base64
  blob and produce a silently scrambled timeline rather than an error.

## Decision

**Mint fixed-width, lexically sortable, self-describing status IDs.**

A timestamp prefix followed by enough encoded identity to reconstruct the note
IRI, in an alphabet that sorts correctly (Crockford base32: `0-9A-Z`, no
ambiguous characters). Concretely: the note's own local identifier becomes a
ULID, and the status ID is that ULID followed by the owning user's UUID in
base32.

This keeps what made the discarded option attractive — resolving a status ID is
a decode plus a primary-key lookup on `users`, with **no new index and no new
column** — while satisfying the constraint the ecosystem actually has.

**Fixed width is load-bearing, not tidiness.** The documented recipe sorts by
*length first*. Variable-length IDs — which is what encoding a 2-to-32-character
username directly would produce — would make a member with a longer name sort
as permanently newer. Every field is padded to constant width so that clause
degenerates to a plain lexical sort, which the ULID prefix then dominates.

## Consequences

- **R2 stays un-indexed.** ADR 0005 guessed it "may not need an index at all";
  it does not. `instance-reindex` gains nothing to rebuild.
- **The Mastodon crate needs no store access to resolve an ID**, which is what
  Phase 6's "projection only, a dependency lint forbids writing to any store"
  wants anyway.
- **IDs are long** — roughly 52 characters against Mastodon's ~18. They are
  opaque strings, GoToSocial's 26-character ULIDs already establish that
  non-numeric lengths are tolerated, and no part of the API constrains length.
  This is the accepted cost.
- **The plan's stated preference is overturned.** It preferred an
  owner-encoding 64-bit snowflake. At D16's scale that budget is tight —
  ~14 bits of owner is 16,384 members against a target of "under ten thousand"
  — it needs a compact per-member integer we do not have, and a field sized
  wrong now is still wrong when the instance outgrows it, with every issued ID
  depending on it. Sortable-and-self-describing gets the same O(1) resolution
  with no fixed budget to get wrong.
- **What was verified and what was not.** The ID formats, the sorting recipe and
  the upstream proposal are documented and quoted above. Individual client
  source was *not* inspected — the conclusion does not rest on knowing which
  clients sort, only on the fact that the documented contract permits sorting
  and every shipped implementation honours it.

[mastodon#25244]: https://github.com/mastodon/mastodon/issues/25244
