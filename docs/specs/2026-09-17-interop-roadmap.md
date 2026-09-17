# Interop roadmap: Bluesky, ATProto apps, Solid apps

**Status:** Draft (2026-09-17)
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
     each failing test that's accepted listed in the stage spec that owns it

## Stages

Each stage leaves `main` deployable. Unfinished behaviour ships dormant, behind
a constant (trunk-based), the way `FEDERATION_ENABLED` does.

| # | Stage | Contents | Why here |
|---|---|---|---|
| 0 | **Security fixes** | `.acl` read and write require `acl:Control`. ATProto OAuth fetches and validates client metadata, checks `redirect_uri` against it, and applies the loopback rules. The PAR, auth-code and DPoP `jti` replay cache. | Exploitable today on any running instance. Small and self-contained. |
| 1 | **ATProto repo and firehose** | Signed-commit `rev` as a TID, stored and emitted. Head updates check nothing changed. `putRecord` updates, and `createRecord` refuses an existing record. `swapRecord`/`swapCommit`. `applyWrites`. TID record keys, and validation of NSIDs and record keys. Blob refs as real CID links. `#commit` frames that follow the lexicon: CAR `blocks`, `since`, `prevData`, `time`, CID links. `#identity`, `#account`, `#sync`, `#info`. Cursor rules and closing the backfill race. Events written by any process reach live subscribers (`LISTEN`/`NOTIFY`). | Everything ATProto writes goes through this path. Nothing on the network is correct until it is. |
| 2 | **ATProto auth** | Legacy sessions: `createSession`, `getSession`, `refreshSession`, `deleteSession`, app passwords. OAuth completion: protected-resource metadata, the missing authorization-server fields, DPoP nonces, `htu`/`htm` checked against the actual request, scope checks on XRPC, token lifetimes. `getServiceAuth`. | Without this, nobody can log in from outside the web UI. |
| 3 | **PDS surface** | `atproto-proxy` forwarding with service auth, defaulting to the Bluesky AppView and refusing protected methods. `app.bsky.actor.getPreferences`/`putPreferences`. `identity.resolveHandle`, `/.well-known/atproto-did`, `/.well-known/did.json`. `repo.listRecords` and a real `describeRepo`. `sync.listRepos`, `getRepoStatus`, `getLatestCommit`, `getBlocks`, `getRecord`. `requestCrawl` sent on startup. | The Bluesky app works and relays can crawl. This is finish-line items 1–3, apart from media. |
| 4 | **One media model** (plus an ADR) | Every upload is one pod resource over ADR 0013's store, whatever protocol wrote it. Each protocol reads it its own way: Solid `foaf:depiction` and LDP-NR, ActivityPub `icon`/`attachment`, Mastodon `avatar` and attachments, ATProto blob CIDs through `uploadBlob`/`getBlob`/`listBlobs`. Read access follows the publication it belongs to (public post, avatar) rather than the owner-only default. Also: atomic blob writes, content-type allow-list and `nosniff`, alt text that replaces the previous value, JSON `media_ids`, and multipart `update_credentials`. | Finish-line item 1 needs avatars and images. It also has to land before stage 6 settles profile writes. |
| 5 | **Solid LDP conformance** | Empty resources exist. POST honours `Slug` and `Link rel=type`. Containment triples are protected (409). PATCH creates the resource and takes Append for inserts. ETag and `If-Match`/`If-None-Match`. `Accept-Patch`/`Accept-Put`/`Allow` computed per resource. 401 vs 403 with `WWW-Authenticate`. Storage-root `Link` headers and `solid:storageDescription`. `WAC-Allow` with `public=`. `Link rel=describedby`. Deleting a resource deletes its auxiliary resources. Container listings carry `dcterms:modified`/`stat:size`. CORS echoes the origin and exposes the full header set. Conformance harness in CI. | Solid apps and finish-line item 5. |
| 6 | **Solid identity** | A writable WebID profile, with type indexes and a preferences file provisioned. Client ID Documents. `prompt=none`. Accept DPoP tokens from other Solid-OIDC issuers, so resources can be shared across servers. | Finish-line item 4. |
| 7 | **Notifications** | Solid Notifications Protocol, WebSocketChannel2023, and whether to also support legacy `solid-0.1` `Updates-Via` for SolidOS. | The Solid Protocol requires it (§7.1), and SolidOS uses it for live updates. It comes last because apps still work without it, just without live refresh. |

Stages 0–3 are ordered by what they depend on. Stage 4 needs stage 1's blob
links and stage 3's surface. Stages 5–7 are independent of the ATProto stages
and could run in parallel with them.

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
