# 0022 — The pod is the core; protocols are interfaces

**Status:** Accepted (2026-11-26)
**Refines:** D9 (load-bearing now), D10 (an exception for identity).
**Scopes:** stage 4's ATProto half (parts a–e), stage 8 (Spaces), and every
protocol surface after them.

## Context

brolly-server speaks Solid and ATProto (and ActivityPub, dormant). The
ATProto side had grown a second model of the member's data beside the pod.
Records were written into `at://…` named graphs outside `/~/`. Since the
2026-09-22 storage split, a graph outside `/~/` is "protocol state": in the
export, but not an LDP resource, so no Solid app could read a member's posts
and no ACL governed them. The write path ran repo-first: `createRecord`
signed a commit and then copied the record into the pod as a best effort,
logging when the copy failed. No decision chose this. It accumulated, and it
let an interface shape the core. ActivityPub had not drifted: its notes are
ordinary resources under `/~/notes/` (ADR 0012).

The operator's goal (nk, 2026-11-26): "a single unified model of how users
create content and provide identity, which speaks both Solid and ATProto.
The interface should not impact the core, which means writing a Solid
server that can support ATProto interfaces."

## Decision

**The pod is the source of truth.** Everything a member creates or asserts
about themselves is LDP resources under `/~/` (or the WebID profile),
governed by WAC. Every write, from any surface, is a pod write through one
write path.

**Protocol surfaces are adapters over the pod.** XRPC, the Mastodon API and
AS2 read and write through the core, like a Solid client does. They add no
store of their own for member data.

**The ATProto repo is a projection of the pod.** The MST, the signed
commits, the CAR exports and the firehose are the ATProto adapter's signed
view of the pod's collection containers. The adapter keeps that view in step
inside the same pod write, so `swapCommit`, `swapRecord` and rev ordering
still hold. If the two ever disagree, the pod wins and the repo is rebuilt
from it. Concretely:

- `at://{did}/{collection}/{rkey}` is the resource
  `https://{member}.{base}/~/{collection}/{rkey}`. The mapping is the
  identity function.
- `createRecord` is a pod write into `/~/{collection}/`, the same write a
  Solid `POST` makes. Who may write is WAC's answer, whatever the surface.
- A blob a record references is a pod binary (`/~/media/{cid}`). The CID is
  derived from the same SHA-256 the blob store already addresses by
  (ADR 0013).

**Protocol rules plug into protocol-neutral hooks, never the reverse.** The
core offers D9's "publication = shape + location": a container may
constrain what its members must be. ATProto's lexicons are one provider for
that hook. The core never learns what a lexicon, a DID or a commit is.

**Identity is one fact, harmonized everywhere (refines D10).** D10 forbids
automatic cross-protocol collapse of *content*: bridging a post is an
explicit per-write decision, and that stands. A member's name, bio and
avatar are not content. They are who the member is, and they are kept
equal on every surface in both directions. The avatar is an exception that
keeps H6's rule: it flows to a protocol whose avatars are public only when
its target is already publicly readable.

## Consequences

- **The write path inverts.** ATProto writes stop being repo-first. A
  failure to project into the repo fails the pod write too, so the pod and
  the repo never diverge. A projection that can't be built is refused, not
  logged.
- **Existing `at://` graphs move.** A one-time upgrade on pod open turns
  each one into its `/~/{collection}/{rkey}` resource. The repo is
  unchanged, because the same records project to the same MST.
- **Solid apps see and write ATProto data.** A write into a collection
  container must pass the container's constraint (for ATProto, the record's
  lexicon) or it is refused. Granting `acl:Write` on a collection lets the
  grantee publish as the member, because the member granted it. Consent
  and docs say so.
- **Read ACLs cannot unpublish.** ATProto records are public by protocol:
  the signed repo and firehose carry every record. Tightening a record
  resource's ACL governs Solid reads only. That is stated, not hidden.
- **Spaces (stage 8) follows the same rule.** Space records are pod
  resources too, and the space repos are projections.
- **ActivityPub federation, when it is switched on, is an adapter over the
  same pod.** Its notes already live there.
- Postgres stays machinery. Repo heads and indexes may live there because
  they can be rebuilt from the pod. The firehose log may too: it is a
  record of deliveries, not member data.
