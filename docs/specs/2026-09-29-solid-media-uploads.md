# Stage 4 (Solid scope): media uploads

<!-- doc-paths: skip -->
<!-- The spec names files this stage creates, so not every path it cites
     resolves until it's implemented. -->

**Status:** Implemented, 2026-10-06, in four commits: `fd73f5e` (atomic
writes and sweeps), `0d430e3` (the media gate), `353f323` (publication
access and ADR 0017), `8b58883` (the depiction). Drafted 2026-09-29 and
revised after one adversarial review against the Solid Protocol, WAC, LDP,
ADR 0013, RFC 9110, and the code it cites — every claim in the Problem was
checked against the tree. Stage 5a and 5b were each revised through three
passes before approval; this one was implemented after its first, and the
close's re-read of every H against the landed tree was its second.
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 4 —
**re-scoped 2026-09-29 to the Solid half only.** Every upload is one pod
resource over ADR 0013's store; this stage makes uploads safe (atomic,
bounded, typed, un-sniffable) and makes read access follow the publication
a medium belongs to. The ATProto half (`uploadBlob`/`getBlob`/`listBlobs`,
blob CIDs in the firehose) waits for stages 1–3 as the roadmap's dependency
order already says; the Mastodon-half leftovers (JSON `media_ids`, multipart
`update_credentials`) move to the post-stage-3 remainder with it.
**Depends on:** ADR 0013 (content-addressed blobs — this stage implements
two of its deferred promises), stage 5a (blob metadata in the metadata
graph), stage 5b (the response-header surface), stage 5d (`.meta`, where
description triples live by the time this lands), stage 6 (the writable
profile, for `foaf:depiction`).

## Problem

Binaries are stored and served, and — since 5a — every protocol's media
already lands in one blob store. What surrounds the bytes is not safe to
face members or a network:

1. **Blob writes are not atomic.** `BlobStore::put` writes bytes directly
   at the final content-addressed path with `std::fs::write`
   (`store/src/blobs.rs:51-64`), then relies on `path.exists()` to
   short-circuit future writes of the same content (`:56-58`). A crash
   mid-write leaves a **partial file at the digest path forever**: the
   digest is what makes the path, the path now exists, and every future
   upload of that content returns early and serves the truncated bytes.
   ADR 0013 flagged "atomic blob writes" as a stage-4 commitment; it is
   the roadmap's wording, not an aspiration.
2. **Every content type on earth is accepted.** The RDF-or-binary decision
   is `syntax::is_parseable_rdf` and nothing else
   (`domain/src/syntax.rs:148-150`): any string that isn't one of the five
   parseable RDF syntaxes — `rdf+xml`, the sixth, has ADR 0007's refusal of
   its own — is stored as a binary with the client's `Content-Type` verbatim
   (`ldp::prepare`, `adapters/solid/src/ldp.rs:505-522`). `text/html`, `image/svg+xml`,
   `application/x-httpd-php` — all stored, all served back with the
   client-chosen type. A member can store an HTML page on their pod and
   have a browser render it on the member's own origin, cookies and all.
3. **Nothing sets `nosniff`.** A workspace grep for
   `X-Content-Type-Options` returns nothing but this stage's roadmap row.
   With client-chosen types and no `nosniff`, what a browser *does* with
   a pod resource is the client's choice, which is the definition of the
   hole the header exists to close.
4. **There is no upload size limit.** No `DefaultBodyLimit`, no limit
   layer, no size check anywhere in the upload path
   (`server/src/main.rs:119-120` mounts a bare `axum::serve`; the upload
   handlers read whole `Bytes`). Meanwhile the instance advertises
   `image_size_limit: 10 MiB` (`adapters/mastodon/src/instance.rs:59-92`)
   that nothing enforces — an advertised contract the server does not
   keep.
5. **Media is owner-only, always.** The root ACL grants the member alone
   (`server/src/provision.rs:52-64`), so every attachment of every post is
   unreadable to everyone else — the roadmap's exact words: "Everything
   under `/~/` is owner-only, so post attachments are unreadable to anyone
   else." A public post's image 401s for the public the post was published
   to. Timelines work only because the Mastodon surface reads pods
   internally, bypassing WAC (`server/src/mastodon_api.rs:341-351`) —
   which means the *server* knows the media is public while every
   standards-conformant reader is refused.
6. **There is no avatar mechanism at all.** The vocab constant exists
   (`FOAF_DEPICTION`, `domain/src/vocab.rs:61`) but nothing writes or reads
   it — no handling, just the word — and Mastodon's account JSON carries no
   avatar. With stage 6's writable
   profile a member can *write* a depiction triple; nothing makes the
   target readable or the fact visible to any client.
7. **ADR 0013's orphan sweep was never built.** "A future sweep can find
   [orphaned bytes] by diffing the blob directory against the digests in
   the graph" (`docs/architecture/adr/0013-…md:67-69`) — today only
   explicitly *released* digests are ever swept
   (`store/src/resources.rs:362-378`); a crash between blob write and
   graph commit orphans bytes permanently, and H1's temp files will add a
   second orphan class.

## Goals

- **A blob file at a digest path is always the complete bytes of that
  digest,** whatever crashed when.
- **The server chooses what it stores,** from a list it can defend, and
  tells browsers not to second-guess it.
- **One explicit, configurable size limit** — enforced, and matching what
  the instance advertises.
- **A public post's media is public; a followers-only post's media is
  followers-only; a direct post's media is its recipients.** The same
  transaction that publishes the post publishes the access.
- **An avatar is a depiction:** a pod binary the profile points at, public
  if the member shares it, rendered by every surface that renders the
  member.
- **Orphaned bytes are findable and sweepable**, by the running server for
  temp files and by an operator for the full diff.

## Non-goals

- **The ATProto media half** — `uploadBlob`/`getBlob`/`listBlobs`, blob
  CIDs, firehose blob events. Stages 1–3, per the roadmap's own
  dependency order ("Stage 4 needs stage 1's blob links and stage 3's
  surface").
- **JSON `media_ids` and multipart `update_credentials`** — Mastodon-surface
  work, moved to the post-stage-3 remainder with the ATProto half. The
  *read* side of Mastodon media (alt text, media JSON) is unchanged and
  stays.
- **Image processing.** No thumbnails, no blurhash, no transcoding, no
  dimension checks. Bytes are stored as received; `meta: {}` stays empty
  and honest.
- **Quotas.** `dir_bytes` exists for accounting; enforcing a per-member
  quota is a product decision this stage does not make.
- **Changing the blob model.** Content addressing, dedup, and the
  release-on-commit sweep are ADR 0013's and stay exactly as they are.

## Design

### H1. Atomic blob writes

`BlobStore::put` writes to a temp file in the same fanout directory
(`{dir}/{first2}/{digest}.tmp-{ulid}`), flushes, `fsync`s the file, then
`rename`s onto the final digest path. `rename(2)` on the same filesystem is
atomic; a crash leaves either the old bytes or no file — never a partial at
the digest path, which is the invariant the dedup short-circuit depends on.
A concurrent write of the same content racing the rename is harmless: same
bytes, atomic replace. A crash between temp-write and rename leaves a
`.tmp-*` file, which H7 sweeps.

The `fsync` before the rename plus a `fsync` of the fanout directory after
it is the whole durability story. The file `fsync` alone is not: a rename
is durable only once its directory entry is, and without the directory
`fsync` a power loss after the graph commit can leave the graph naming
bytes no disk ever held. With both, after a successful `PUT` returns, the
bytes are on disk even if the process dies before the graph commit, and
an orphaned-but-complete blob is sweepable (H7) rather than corrupting.

### H2. A content-type allow-list, at the one choke point

`ldp::prepare`'s binary branch — the single point every protocol's binary
already passes through (Solid `PUT`/`POST`, Mastodon `upload_media`) —
accepts a binary only if its content type is on the list:

```
image/jpeg  image/png  image/gif  image/webp  image/avif
audio/mpeg  audio/ogg  audio/wav  audio/flac  audio/webm
video/mp4   video/webm
application/pdf  application/zip
text/plain  text/markdown  text/csv
application/octet-stream
```

- **Refusal is 415 with the list in the body.** The type is syntactically
  fine; this server just doesn't store it as media.
- **`image/svg+xml` is deliberately absent.** SVG is script; a member-hosted
  SVG on the member's origin, rendered by any browser that follows the
  type, is stored XSS with the pod's cookies in scope. When SVG is wanted,
  it wants its own serving rules (`Content-Disposition`, CSP), and that is
  a recorded decision to reopen, not a default to slip in.
- `text/plain` and friends are stored as binaries (they are not RDF
  syntaxes) and served with their type — plain text is not script.
- **Parameters are stripped before matching** (`media_type_of` already
  does this, `domain/src/syntax.rs:125-127`) — `image/png;
  charset=utf-8` is `image/png`.
- The six RDF syntaxes and ADR 0007's `rdf+xml` refusal are upstream of
  this and unchanged. The list lives in one constant with a test asserting
  the Mastodon instance's advertised `supported_mime_types` is a subset
  (today it is: jpeg, png, gif, webp), so the two can never drift apart
  silently.

### H3. One size limit, explicit, enforced, and as advertised

- A `DefaultBodyLimit` of **10 MiB** (matching the advertised
  `image_size_limit`) on the pod routes and the media upload routes, with
  `BROLLY_MAX_UPLOAD_BYTES` overriding it. Exceeding it is axum's 413.
- The instance configuration keeps advertising 10 MiB; the two values come
  from the same place in code, with a test asserting the constant and the
  advertised number are equal. An advertised limit and an enforced limit
  that differ is a bug we currently have and this closes.
- The limit is bytes-on-the-wire; no per-type matrix, no image dimension
  checks (non-goal). One recorded consequence: the media routes read
  multipart (`upload_media`, `server/src/mastodon_api.rs:488-519`), so a
  file at exactly the advertised limit costs its framing too and 413s.
  Accepted — clients pre-validate against the advertised number, and the
  one constant is worth more than a fudge factor.

### H4. `nosniff`, everywhere, one middleware

`X-Content-Type-Options: nosniff` on **every** response, via one layer at
app composition — not just binary reads. The header is harmless where it is
redundant and load-bearing where a type could be second-guessed, and
per-route application is how it ends up missing on the one route that
matters. Binary responses already carry the recorded `BlobMeta` media type
(stage 5a) — with the allow-list and `nosniff`, what a browser does with a
pod binary is the server's decision, made from the server's records.

No CSP header in this stage: the allow-list excludes the scriptable types,
and a CSP layered on client-typed storage is a bandage on a hole H2 already
closed. Reopened if SVG is ever admitted.

### H5. Read access follows the publication — ADR 0017

One ADR ships with this stage: **read access follows the publication**. The
composer (`compose` + `outbox::deliver`), in the *same* `Pod::write` that
writes the note and the activity, writes an ACL for each resource the
publication mints — the note, the activity, and each attachment — mapping
the note's audience to WAC grants. **Every one of those ACLs also carries
the author's own grant** — Read, Write, and Control on the resource, the
same shape the root ACL provisions (`server/src/provision.rs:52-64`) —
and it must, because the closest ACL governs to the exclusion of every
ancestor's (`authz/src/wac.rs:142-154`): an audience-only ACL would leave
the author holding Read alone on their own public notes (as one
`foaf:Agent` among many) and — the author not being among their own
followers — nothing at all on their own followers-only and direct ones,
with no Control to fix it with. This is the hole the stage-6 review caught
for the public type index, caught here before it was built.

| Visibility | Grant on note, activity, and each medium |
|---|---|
| `public` | `acl:agentClass foaf:Agent`, Read |
| `unlisted` | `acl:agentClass foaf:Agent`, Read — discoverability lives in timelines, not in access control; Mastodon serves unlisted statuses anonymously and so do we |
| `private` (followers) | one `acl:agent` Read grant per **local** follower's WebID, snapshotted at compose time |
| `direct` | one `acl:agent` Read grant per recipient's WebID, local or remote |

- **The media is governed by its own ACL, not by magic:** an ordinary
  `.acl` resource beside the medium, writable under stage 0's `Control`
  rule, so the member can tighten or loosen it afterwards like any ACL.
  The composer's grant is a default, not a leash.
- **`acl:default` is not used**: attachments are *beside* their note, not
  inside it, and default-inheritance is for subtrees, not siblings.
- **The snapshot is the model.** New followers do not gain read on old
  followers-only posts — which is Mastodon's own behaviour for delivered
  content and is simple to reason about. A dynamic followers-group grant
  (`acl:agentGroup` + a `vcard:Group` the server keeps fresh) is recorded
  as a follow-up design, not smuggled in here.
- **Deleting a status deletes its media.** The composer minted the media
  resources for the status (`/~/media/{ulid}`, `mastodon_api.rs:441-443`);
  deleting the status (`DELETE /api/v1/statuses/{id}`) removes those
  resources — and, by 5d's H5, their auxiliaries — in the same write.
  Mastodon semantics, and it prevents the quiet residue of orphaned
  public media outliving its post. A member who linked a composer medium
  from their own Solid data loses that link with the post: recorded, and
  accepted, because the medium was never theirs to link — it was the
  post's.
- **Direct messages to remote recipients** name remote WebIDs in the ACL
  today, federation off; when ADR 0016's switch flips, the grants are
  already the right shape. Nothing here is federation-gated.
- **No migration for existing posts, and for a reason better than scope:**
  the compose-time audience snapshot is not recorded anywhere, so a
  migration could only grant *today's* followers — a different and leakier
  policy than the snapshot. Existing publications keep today's
  owner-only media; new ones get audience ACLs from the first compose.

### H6. The avatar is a depiction

- `foaf:depiction` on the WebID profile (writable via stage 6's `PUT`/`PATCH`
  on `/profile`) pointing at any pod binary is the avatar mechanism. The
  profile projection (stage 6) does not derive or filter it; it is member
  data.
- **The Mastodon account JSON and the AS2 actor read it:** `avatar` /
  `avatar_static` (Mastodon) and `icon` (AS2, local rendering only —
  federation is off) resolve the depiction triple from the profile graph
  and emit the target IRI. One place to set your face, every surface
  shows it.
- **Public read on the depiction target is the member's call**, made with
  the standard tool: an `.acl` on the binary (Solid apps' share UIs do
  exactly this). No auto-grant on writing the triple — an upload the
  member keeps private is a valid avatar for a private audience, and the
  server guessing which is a privacy decision it should not make. The
  profile page (HTML) renders the depiction only if the *requesting*
  caller can read the target, which the pod surface already knows how to
  check.

### H7. Sweeps

- **Temp sweep, on `Pod::open`:** delete `.tmp-*` files in the blob
  fanout, and only those older than an hour (mtime). Within one process
  the sweep cannot race an upload — a live handle pins the pod, so an
  in-flight upload is never sweeping under (`store/src/manager.rs:161-166`)
  — but a second process sharing the pod dir could sweep the first's
  in-flight temp, and the bound makes that impossible too: no legitimate
  temp is an hour old. Cheap, safe (no digest path ever matches), closes
  H1's orphan class at startup.
- **The full diff, as an operator command:** `brolly-admin blob-sweep`
  walks the pod's **`blobs/` directory only** against every digest in the
  metadata graph, reports unreferenced bytes, and removes them with
  `--apply`. `blobs/` only because the pod directory holds a second
  content-addressed store — `repo_blocks`, the ATProto repo's CAR blocks
  (`store/src/manager.rs:139-147`) — whose blocks are referenced by repo
  history, not the resource metadata graph: a sweep diffing the whole pod
  directory would delete every repo block. Read-only by default. This is
  ADR 0013's promised sweep, delivered as an admin verb because running it
  automatically on every open walks gigabytes to save kilobytes, and an
  operator can schedule it.

## What this changes in the code

| File | Change |
|---|---|
| `store/src/blobs.rs` | temp-write + fsync + rename (H1); `sweep_temp` (H7) |
| `store/src/resources.rs` | `Pod::open` runs the temp sweep (H7); nothing else — the release/sweep model is unchanged |
| `adapters/solid/src/ldp.rs` | `prepare` enforces the allow-list (H2); new `LdpError::ContentTypeNotAllowed` → 415 |
| `server/src/lib.rs` | `DefaultBodyLimit` on the pod and media routes (H3); `nosniff` layer (H4) |
| `server/src/main.rs` | `BROLLY_MAX_UPLOAD_BYTES` (H3) |
| `domain/src/media.rs` | new: the allow-list constant (H2), with the instance-advertisement subset test |
| `adapters/mastodon/src/instance.rs` | `image_size_limit` from the one constant (H3) |
| `server/src/outbox.rs`, `adapters/mastodon/src/compose.rs` | audience + author ACLs in the compose transaction (H5); status delete removes media (H5) |
| `server/src/mastodon_api.rs` | account JSON/actor `icon` from `foaf:depiction` (H6); `upload_media` unchanged (already through `ldp::prepare`) |
| `server/src/bin/admin.rs` | `blob-sweep` (H7) |
| `docs/architecture/adr/0017-read-access-follows-the-publication.md` | new (H5) |

**Tests whose expectations change:** every binary-PUT test using an
off-list type moves onto the list or asserts the new 415 (the existing
`application/pdf` fixtures stay valid — pdf is on the list); the owner-only
media assertions (`pod_http.rs:631-648`) gain the published-media cases
that now read 200 for the right audiences; the anon-401 binary test keeps
its 401 for *unpublished* media. `mastodon_compose.rs` gains
visibility→grant coverage, including "direct to a remote WebID names it in
the ACL" and the author's Read/Write/Control on every composer-written
ACL.

## Chunks

Four, one commit each:

1. **Atomic writes and sweeps.** Temp+fsync+rename, temp sweep on open,
   `brolly-admin blob-sweep`. *Data-safety first: everything else lands on
   top of a store whose invariant is "the digest path is the truth".*
2. **The gate.** Allow-list, size limit, `nosniff`, the
   advertisement-subset tests. *One commit because the three together are
   "the server decides what it stores" — splitting them leaves a commit
   where the list exists but a 20 MiB text/html still lands.*
3. **Publication access + ADR 0017.** Audience ACLs in the compose
   transaction, media deletion with the status. *The only chunk that
   changes what other people can read; carries the ADR and its own revert
   boundary.*
4. **Depiction.** Profile triple → account JSON / actor icon / profile
   page. *Reads only; the smallest chunk, and it depends on stage 6's
   writable profile, so it lands last.*

## Decisions

| # | Decision | Why |
|---|---|---|
| H1 | Temp file + fsync + rename onto the digest path, and fsync the fanout directory after the rename; races harmless; temp files swept at open | `path.exists()` is the dedup oracle; a partial file at a digest path poisons that content forever — the one corruption this store cannot tolerate. The directory fsync is what makes "the bytes are on disk" true through a power loss, not just a process death |
| H2 | Binary content types allowed by list only (no SVG), 415 with the list, matched after parameter stripping, at `ldp::prepare` for every protocol | One choke point already exists; a member-typed `text/html` on the member origin is stored XSS; SVG's absence is a recorded decision to reopen, not an oversight |
| H3 | One explicit limit (default 10 MiB, `BROLLY_MAX_UPLOAD_BYTES`), enforced by `DefaultBodyLimit`, advertised from the same constant | The server currently advertises a limit it does not enforce; one constant with a test is how that stays true |
| H4 | `nosniff` app-wide, one layer | Per-route application is how the header ends up missing on the one route that matters; the cost of the redundant cases is zero |
| H5 | The composer writes audience + author ACLs for note, activity, and media in the same transaction; snapshot grants; no migration for existing posts; media deleted with the status; ADR 0017 | Access that lags publication by a transaction is a privacy bug; the closest ACL governs to the exclusion of ancestors, so an audience-only ACL locks the author out of their own note; the snapshot is unrecoverable post hoc, which is why there is no migration; the member keeps `Control` over the written ACLs — defaults, not leashes |
| H6 | Avatar = `foaf:depiction` → pod binary; every surface renders it; public read is the member's `.acl` call | One mechanism, no upload path to invent; the server guessing privacy on a member's behalf is the decision it must not make |
| H7 | Temp sweep at open, mtime-bounded; full diff as `brolly-admin blob-sweep` over `blobs/` only, read-only without `--apply` | Closes ADR 0013's open promise; the mtime bound closes the cross-process temp race; `repo_blocks` is history, not resources — the metadata-graph diff must never see it; the full walk is an operator verb because running it on every pod open spends gigabytes to save kilobytes |
