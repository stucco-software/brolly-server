# 0013 — Binary resources are content-addressed blobs beside the graph

**Status:** Accepted (2026-08-26)

## Context

Phase 4 requires LDP-NR: a pod holds images and PDFs, not only triples. The
bytes have to live somewhere, and three options were open.

Storing them *in* the graph as base64 literals keeps everything in one place and
makes export trivially complete. It also puts multi-megabyte literals in a
triple store, where every pattern scan steps over them — the predecessor's pods
degraded exactly this way, and the fix there was to stop storing media at all.

Storing them in Postgres contradicts D2 and D5: operational state only, no user
content, ever. It would also mean a pod delete is no longer `rm -rf` on one
directory.

Storing them on disk beside the pod keeps D2's physical isolation and leaves the
graph queryable, at the cost of a second thing to keep consistent with the
triples that describe it.

## Decision

**Bytes go on disk under `users/<uuid>/blobs`, addressed by `sha256(content)`.
The graph holds a digest, a media type and a size; the digest is the join.**

The pod graph moves to `users/<uuid>/rdf` alongside it, which is what plan §2.2
specified all along.

Three predicates in our namespace, because no standard vocabulary names a
content-addressed blob:

```
<resource> a ldp:NonRDFSource, ldp:Resource ;
    brolly:blobDigest "…64 hex…" ;
    brolly:mediaType  "image/png" ;
    brolly:byteSize   "4096"^^xsd:integer .
```

The presence of `brolly:blobDigest` is what makes a resource an LDP-NR. Reads
and deletes branch on the triple, not on the request, so a binary behaves
identically however it is reached.

## Consequences

- **WAC is unchanged.** A binary is a named graph like any other resource, so
  the ACL check that already runs is the one that governs it. There is no second
  authorization path for media — the failure mode where a media route reads off
  disk without consulting the ACL cannot arise, because the bytes are only
  reachable after `read` has authorized.
- **Containment, container listing and delete are unchanged**, for the same
  reason.
- **A re-uploaded unchanged file is free**, and two resources may name one blob.
  Which means delete must check: bytes are released only when no other resource
  still references the digest. Deleting one of two resources sharing content
  must not blank the other.
- **The digest is untrusted input.** It reaches the blob store from a triple,
  and a pod's triples are writable by any app the member has authorised, so it
  is attacker-influenced on its way to becoming a filesystem path. `is_digest`
  validates alphabet and length before the path is built.
- **A digest is not a capability.** It is derived from content, so anyone
  holding the file can compute it. Every lookup is therefore scoped to one pod's
  directory; a digest from Alice's pod resolves to nothing in Bob's.
- **Export stays complete** (D7) for triples, but the N-Quads dump names blobs
  by digest rather than embedding them. A full account export that includes
  media bytes is a separate archive format, and is not built.
- **Orphan bytes are possible** after a crash between the graph write and the
  blob write. They cost disk and nothing else, and a future sweep can find them
  by diffing the blob directory against the digests in the graph.
