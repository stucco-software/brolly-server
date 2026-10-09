# Interop roadmap: Bluesky, ATProto apps, Solid apps

**Status:** In progress. Stage 0 done 2026-09-18. Solid stages (5–7) next.
**Scope:** Umbrella. It sets the finish line and orders the work. Each stage
gets its own spec and plan.
**Supersedes in priority:** `docs/specs/2026-09-16-mycorhizza-migration.md`,
which is paused until this is done.

## Problem

The plan's protocol phases are marked done, but nobody has checked them against
real clients. Two code surveys on 2026-09-17 found that none of the three
audiences can use brolly-server today:

- **The Bluesky app can't log in.** It uses `com.atproto.server.createSession`,
  which doesn't exist here. Even after a login, every `app.bsky.*` call would
  return 501: nothing forwards them to the AppView, and there's no local
  `getPreferences`.
- **Relays and the AppView can't index a member.**
  - Firehose frames don't follow the lexicon: `rev` is an integer, CIDs are
    strings, `blocks` is empty, and `#commit` is the only event type.
  - `listRepos`, `getLatestCommit` and `/.well-known/atproto-did` are missing.
  - Record keys aren't TIDs.
- **ATProto OAuth clients can't finish logging in.**
  - The protected-resource metadata and DPoP nonces are missing.
  - The XRPC token check compares against a hardcoded `https://{base}/xrpc/`
    and `POST` instead of the real request.
- **The repo loses or refuses writes.** `putRecord` can't update an existing
  record, and two concurrent writes can drop one of them.
- **Media:**
  - There are no blobs, so no images or avatars on Bluesky.
  - Everything under `/~/` is owner-only, so post attachments are unreadable to
    anyone else.
- **Solid apps break on creating things.**
  - Empty containers and documents return 404 after creation.
  - POST ignores `Slug` and can't create containers.
  - The profile can't be written and has no type indexes.
  - `client_id` URLs are rejected, and `prompt=none` isn't supported.
- **Two security holes:**
  - WAC doesn't require `acl:Control` to read or write a `.acl`.
  - ATProto OAuth never fetches client metadata, so `redirect_uri` is
    unchecked: an open redirect that leaks authorization codes.

## Finish line

This is done when every item below passes against a deployed instance on a real
domain. Passing unit tests doesn't count.

1. **Bluesky.** An account on the instance, using bsky.app:
   - logs in
   - sets a display name, bio and avatar
   - posts text and images, replies, likes, reposts and follows

   A separate bsky.social account sees and interacts with those posts, and the
   handle shows as valid.
2. **Relay.** `requestCrawl` to the Bluesky relay, then the account's repo,
   commits and blobs are indexed with no errors. goat or a local indigo relay
   also validates the firehose.
3. **ATProto OAuth app.** A third-party app that uses OAuth with DPoP logs in
   and writes its own lexicon's records (e.g. WhiteWind or Smoke Signal).
4. **Solid apps.** The SolidOS data browser and Penny log in with Solid-OIDC,
   browse the pod, create containers and documents, edit the profile, and share
   a resource with another WebID.
5. **Automated gates in CI:**
   - the atproto-interop-tests vectors (syntax, data model, MST, crypto) as unit
     tests
   - the Solid Conformance Test Harness against a containerized instance, with
     each failing test that's accepted listed in the stage spec that owns it —
     **deferred 2026-10-01, after the 5d spike** (O9,
     `docs/greenfield-implementation-plan.md` §6): no headless client can
     complete brolly's OIDC flow today — consent is human by design, refresh
     tokens are key-bound, there is no credentials grant

## Stages

Each stage leaves `main` deployable. Unfinished behaviour ships dormant, behind
a constant (trunk-based), the way `FEDERATION_ENABLED` does.

| # | Stage | Contents | Why here |
|---|---|---|---|
| 0 | **Security fixes** (done, 2026-09-18) | Activities only touch graphs their actor owns. `.acl` read and write require `acl:Control`. DPoP proofs are single-use. Outbound HTTPS works. ATProto OAuth fetches and validates client metadata, checks `redirect_uri` and scope against it, and applies the loopback rules. See `docs/specs/2026-09-17-security-fixes.md` and `docs/plans/2026-09-17-security-fixes.md`. | Exploitable today on any running instance. Small and self-contained. |
| 1 | **ATProto repo and firehose** (done, 2026-10-09) (`docs/specs/2026-10-06-atproto-repo-firehose.md`) | Signed-commit `rev` as a TID, stored and emitted. Head updates check nothing changed. `putRecord` updates, and `createRecord` refuses an existing record. `swapRecord`/`swapCommit`. `applyWrites`. TID record keys, and validation of NSIDs and record keys. Blob refs as real CID links. `#commit` frames that follow the lexicon: CAR `blocks`, `since`, `prevData`, `time`, CID links. `#identity`, `#account`, `#sync`, `#info`. Cursor rules and closing the backfill race. Events written by any process reach live subscribers (`LISTEN`/`NOTIFY`). | Everything ATProto writes goes through this path. Nothing on the network is correct until it is. |
| 2 | **ATProto auth** | Legacy sessions: `createSession`, `getSession`, `refreshSession`, `deleteSession`, app passwords. OAuth completion: protected-resource metadata, the missing authorization-server fields, DPoP nonces, `htu`/`htm` checked against the actual request, scope checks on XRPC, token lifetimes. `getServiceAuth`. | Without this, nobody can log in from outside the web UI. |
| 3 | **PDS surface** | `atproto-proxy` forwarding with service auth, defaulting to the Bluesky AppView and refusing protected methods. `app.bsky.actor.getPreferences`/`putPreferences`. `identity.resolveHandle`, `/.well-known/atproto-did`, `/.well-known/did.json`. `repo.listRecords` and a real `describeRepo`. `sync.listRepos`, `getRepoStatus`, `getLatestCommit`, `getBlocks`, `getRecord`. `requestCrawl` sent on startup. | The Bluesky app works and relays can crawl. This is finish-line items 1–3, apart from media. |
| 4 | **One media model** (plus an ADR) — **Solid half done, 2026-10-06** (re-scoped 2026-09-29: the Solid half only, `docs/specs/2026-09-29-solid-media-uploads.md`) | Every upload is one pod resource over ADR 0013's store, whatever protocol wrote it. The Solid half: LDP-NR uploads that are atomic, size-limited, on a content-type allow-list, served with `nosniff`; read access that follows the publication (public post, avatar) rather than the owner-only default; `foaf:depiction` as the avatar mechanism; alt text that replaces the previous value (done in 5a, relocated to `.meta` by 5d); ADR 0017. The remainder — ATProto blob CIDs through `uploadBlob`/`getBlob`/`listBlobs`, ActivityPub `icon` on the wire, JSON `media_ids`, multipart `update_credentials` — waits for stages 1–3, per the dependency below. | Finish-line item 1 needs avatars and images. The Solid half no longer blocks on ATProto: the blob store, metadata, `.meta` and the writable profile it builds on all land in stages 5 and 6. |
| 5 | **Solid LDP conformance** (parts a–d done, 2026-10-01; 5d's harness deferred) | Empty resources exist. POST honours `Slug` and `Link rel=type`. Containment triples are protected (409). PATCH creates the resource and takes Append for inserts. ETag and `If-Match`/`If-None-Match`. `Accept-Patch`/`Accept-Put`/`Allow` computed per resource. 401 vs 403 with `WWW-Authenticate`. Storage-root `Link` headers and `solid:storageDescription`. `WAC-Allow` with `public=`. `Link rel=describedby`. Deleting a resource deletes its auxiliary resources. Container listings carry `dcterms:modified`/`stat:size`. CORS echoes the origin and exposes the full header set. Conformance harness in CI — deferred after the 5d spike: no headless client can complete brolly's OIDC flow, by design (O9, `docs/greenfield-implementation-plan.md` §6; findings in `docs/specs/2026-09-29-solid-auxiliary-resources.md` H7). | Solid apps and finish-line item 5. |
| 6 | **Solid identity** (`docs/specs/2026-09-29-solid-identity.md`) | A writable WebID profile, with type indexes and a preferences file provisioned. Client ID Documents. `prompt=none`. Accept DPoP tokens from other Solid-OIDC issuers, so resources can be shared across servers. | Finish-line item 4. |
| 7 | **Notifications** | Solid Notifications Protocol, WebSocketChannel2023, and whether to also support legacy `solid-0.1` `Updates-Via` for SolidOS. | The Solid Protocol requires it (§7.1), and SolidOS uses it for live updates. It comes last because apps still work without it, just without live refresh. |

Stages 0–3 are ordered by what they depend on — except stage 4, whose
remaining half (the ATProto blob surface) needs stage 1's blob links and
stage 3's surface. Stages 5–7 are independent of the ATProto stages.

**Order of work (revised 2026-09-29):** Solid first. After stage 0, the stages
run 5 (c, d), 6, 4 (Solid scope), then 1, 2, 3, then 4's remainder and 7 in
either order. The 2026-09-22 order ran 5, 6, 7, 1, 2, 3, 4; stage 4's
re-scope (Solid half only, above) removes its ATProto dependency, and stage
7 (notifications) is the one Solid item apps tolerate the absence of, so it
yields its slot to media. Stage 4's Solid half landed 2026-10-06; stage 1
landed 2026-10-09 — so stage 4's remainder is unlocked on its blob-link
dependency and waits only on stage 3's surface, per the dependency above.
Stages 2 and 3 are next.

**Stage 5 is four parts,** because the first one had to move state before
anything could report it:

| Part | Spec | State |
|---|---|---|
| a | Server-managed resource metadata: existence, kind, containment, modified time, version, blob pointers, and conditional requests (`docs/specs/2026-09-22-solid-resource-metadata.md`) | Done, 2026-09-23 |
| b | The HTTP surface: 401/403 with `WWW-Authenticate`, per-resource `Allow`/`Accept-*`, `Link` headers and the storage description, `WAC-Allow public=`, `Vary`, CORS, 201 on create, 409 on a non-empty container (`docs/specs/2026-09-23-solid-http-surface.md`) | Done, 2026-09-29 |
| c | Write semantics: `Slug`, creating containers by `POST`, `/foo` vs `/foo/`, PATCH access modes (`docs/specs/2026-09-29-solid-write-semantics.md`) | Done, 2026-09-30 |
| d | Auxiliary resources: `.meta`, `Link rel=describedby`, deleting a resource's auxiliaries with it, and the Solid Conformance Test Harness in CI (`docs/specs/2026-09-29-solid-auxiliary-resources.md`) | H1–H6 done 2026-10-01; the harness deferred after the spike — every finding is a deliberate brolly design, and the re-entry conditions are O9 (`docs/greenfield-implementation-plan.md` §6) |

## Not in scope

- Federating ActivityPub (ADR 0016's switch stays off).
- Account migration endpoints (`importRepo`, the PLC operation signing
  endpoints, `listMissingBlobs`). They belong to the paused migration.
- Access Control Policy. WAC is the Solid Protocol's other allowed choice, and
  we keep it.
- Email flows. There's still no mail path; `getSession` reports
  `emailConfirmed` from what's stored.

## Test infrastructure this needs

- **A deployed test instance with a wildcard domain, for finish-line items 1–4.**
  Bluesky's relay and AppView must be able to reach it, so an OrbStack domain
  isn't enough. Set it up alongside stage 1 so each stage is checked on the real
  network as it lands.
- **A bsky.social test account and a second Solid WebID on another provider.**
