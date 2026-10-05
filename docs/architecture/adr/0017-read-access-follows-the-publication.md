# 0017 — Read access follows the publication

**Status:** Accepted (2026-10-05)
**Scopes:** spec 4 (Solid media uploads), H5.

## Context

A post is published by one transaction: `outbox::deliver`'s single
`Pod::write` stores the note, the activity, and the outbox entry. Media were
outside that story twice over. An uploaded medium was minted into the
composer's ground (`/~/media/{ulid}`) with no ACL of its own, so it sat under
the root's `acl:default` — owner-only — no matter how public the post that
carried it: a public post with unreadable media, and a followers-only post
whose media only the author could open. And deleting a post left its media
behind, because the Mastodon delete surface did not exist at all — so a
public post's media quietly outlived it, permanently public, permanently
orphaned.

Access that lags the publication by a transaction is a privacy bug. It is
also the wrong shape: the audience is *known* at the moment of composition —
it is the note's own `to`/`cc` — and every moment after that is a guess.

## Decision

**The composer writes the audience's grants in the same transaction that
stores the publication, and the media go when the post goes.**

- **Audience → WAC grants, by the note's addressing** (spec 4, H5's table):

  | Audience | Grant on note, activity, and each medium |
  |---|---|
  | `public` | `acl:agentClass foaf:Agent`, Read |
  | `unlisted` | `acl:agentClass foaf:Agent`, Read |
  | `private` | one `acl:agent` Read grant per **local** follower's WebID, snapshotted at compose time |
  | `direct` | one `acl:agent` Read grant per recipient's WebID, local or remote |

  Unlisted shares the public row because unlisted is a discoverability
  question, not an access one — timelines decide what to list, and Mastodon
  serves unlisted statuses anonymously, so we do too.

- **Every composer-written ACL carries the author's own grant** — Read,
  Write, and Control, the same shape the root ACL provisions. It must,
  because the closest ACL governs to the exclusion of every ancestor's: an
  audience-only ACL would leave the author — not being among their own
  followers — holding *nothing* on their own followers-only note, with no
  Control to fix it with. This is the hole the stage-6 review caught for the
  public type index; this ADR catches it before the composer shipped it.

- **The snapshot is the model.** New followers do not gain read on old
  followers-only posts — Mastodon's own behaviour for delivered content, and
  simple to reason about. A dynamic followers-group grant (`acl:agentGroup` +
  a `vcard:Group` the server keeps fresh) is a recorded follow-up design, not
  smuggled in here.

- **No `acl:default`**: attachments are *beside* their note, not inside it,
  and default-inheritance is for subtrees, not siblings.

- **A medium's ACL is an ordinary `.acl` beside it**, writable by the member
  under stage 0's Control rule, so the composer's grant is a default, not a
  leash.

- **Only the composer's media follow the post.** The boundary is the minting
  ground: `{base}/~/media/{minted id}` is what `upload_media` mints, and a
  binary the member PUT themselves — even one PUT under `/~/media/` with an
  unminted name — keeps its own access and survives the post. A medium the
  member *linked* from their own Solid data is likewise not granted and not
  deleted: the server deciding to publish or destroy a member's private
  resource because a note named it is a privacy decision the server must not
  make (H6's avatar reasoning, one surface over).

- **Deleting a status deletes its media**, auxiliaries included (spec 5d,
  H5), in the same write that removes the note. Mastodon semantics, and the
  only thing that keeps public media from outliving their post. A member who
  linked a composer medium from their own Solid data loses that link with
  the post: recorded, and accepted, because the medium was the post's.

- **Direct messages to remote recipients** name the remote WebID exactly as
  addressed, federation off; when ADR 0016's switch flips, the grants are
  already the right shape. Remote *followers* are not granted on private
  posts — an agent that cannot authenticate here cannot present the grant,
  and inventing it now would be granting to nobody.

## Consequences

- **No migration for existing posts, and for a reason better than scope:**
  the compose-time audience snapshot is recorded nowhere, so a migration
  could only grant *today's* followers — a different and leakier policy than
  the snapshot. Existing publications keep today's owner-only media; new
  ones get audience ACLs from the first compose.
- **The Mastodon delete surface ships with this decision** (`DELETE
  /api/v1/statuses/{id}`, driving the outbox's existing `Delete` path). The
  spec's H5 cites the route; a cited route that does not exist is a route to
  build, and the media-deletion half of the decision has no other caller.
- **`POST /outbox` gains the same behaviour for free**, because both
  surfaces end in `outbox::deliver` — one path, or the second one rots.
- **A follower gained later cannot read a followers-only post that predates
  them.** Accepted twice over: it is Mastodon's own behaviour, and the
  alternative is a grant that changes under a post that never changed.
- **The author can always fix access afterwards** — every composer-written
  ACL carries Control for the author, and the `.acl` is an ordinary
  auxiliary beside the resource.
