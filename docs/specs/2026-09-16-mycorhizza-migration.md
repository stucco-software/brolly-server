# Migrating brolly.id off mycorhizza

**Status:** Draft (2026-09-16)
**Scope:** Umbrella spec. It records the decisions and splits the work into four
pieces, each of which gets its own spec and plan.
**Depends on:** ADR 0002 (atrium), ADR 0010 (storage root), ADR 0013 (blobs),
ADR 0015 (status IDs), ADR 0016 (federation switch).

## Problem

brolly.id is live on mycorhizza, the predecessor this repository replaces
(`docs/greenfield-learnings.md`). Deploying brolly-server to brolly.id without
moving mycorhizza's state first would destroy real accounts, and brolly-server
has no way to import them: `brolly-admin` only has `invite`, `promote`,
`demote`, `plc-retry` and `whoami`, and nothing reads a CAR, an N-Quads dump or
an existing key.

### What is live (checked 2026-09-16)

- **Ten members, each with a public `did:plc`:** nikolas, beporter, davidcelis,
  flores, hvarf, lunarobverse, nim, octocal, reid, yves. Three of them have an
  ATProto repo (`com.atproto.sync.listRepos` on brolly.id returns yves, nikolas
  and octocal).
- **Every DID has exactly one PLC operation, and one rotation key.** That key is
  mycorhizza's instance key, stored unencrypted in the `pds_config` table. The
  server that holds it can move every identity, so no member depends on a key
  they hold themselves.
- **PDS endpoints differ between members.** nikolas's DID document points at
  `https://brolly.id`; the other nine point at `https://<username>.brolly.id`.
- **Bluesky is reading these repos.** The AppView, several relays and
  independent crawlers (microcosm lightrail, hubble-sync) call
  `/.well-known/atproto-did`, `describeServer`, `listRepos`, `getRepo`,
  `getLatestCommit`, `getBlocks` and `getBlob` every few minutes.
- **ActivityPub never federated.** mycorhizza rejects every remote HTTP
  signature (`mycorriza-activitypub/src/inbox.rs`), so there are no remote
  followers to keep and none that could notice IRIs changing.
- **It's small.** The Postgres and store volumes are 500 MB each.

## Decisions

| # | Decision | Why |
|---|---|---|
| M1 | **Keep identity, ATProto and posts.** Carry over accounts, password hashes, `did:plc` identities, handles, ATProto repos and their blobs, notes, follows between members, profiles and avatars. **Drop** post media attachments, Solid resources that members stored, sessions, every kind of OAuth grant, Mastodon tokens, invites, blocks, mutes, reports, instance rules, and the old note, media and root-level Solid URLs. | Members keep who they are and what they published. Everything dropped is either re-created by logging in again, not worth carrying on a 10-person beta, or has no audience: nothing federated, so nobody depends on the old URLs. |
| M2 | **Two stages: mycorhizza exports a bundle, brolly-server imports it.** | brolly-server never learns mycorhizza's schema. The bundle can be inspected before anything irreversible happens, and a rehearsal is just an import into an empty instance. Reading mycorhizza's stores directly isn't possible anyway: Oxigraph 0.4.11 and 0.5.9 use incompatible on-disk formats. |
| M3 | **The bundle holds protocol formats, not either server's RDF.** Notes are AS2 JSON, repos are CAR files, and avatars and blobs are bytes plus metadata. | The exporter is the only code that knows mycorhizza, and the importer writes through brolly-server's ordinary write paths: canonicalization, the faithful layer, the public index. Neither server's internal vocabulary appears in the bundle. |
| M4 | **Replace the rotation key, keep the old one as backup.** Each DID gets a PLC update with `rotationKeys: [<new per-user key>, <mycorhizza instance key>]`. After the migration is verified, a second update removes the instance key. | brolly-server's model is one rotation key per user (`server/src/provision.rs`). While the old key stays listed, it can sign a new operation on top of the head at any time, so a lost or wrongly encoded new key can still be recovered from. PLC gives the first key priority, so the old key cannot override anything the new key signs. The backup protects against losing the new key. It doesn't protect against an update that the new key signs and that removes the old key, which is why removing it is a separate, later step. |
| M5 | **Import each member's existing signing key unchanged.** | Existing commits stay valid and record CIDs don't change, so replies and likes from Bluesky users still point at the right posts. The PLC update only changes the rotation keys and the PDS endpoint. |
| M6 | **Announced maintenance window.** Take mycorhizza offline, export a final snapshot, import, switch the domains, submit the PLC updates, request re-crawls. Rehearse first on a copy of production. | With ten members, adding incremental sync or running both servers side by side isn't worth the work. Railway's `*.brolly.id` wildcard can only point at one service anyway. |
| M7 | **The import never signs a PLC operation. `plc-adopt` signs and submits in one step, after the checks.** | The import can be wiped and re-run. A submitted PLC operation cannot be undone. If the importer built signed updates, every rehearsal would leave valid, submittable operations for ten live DIDs in a staging database, and the existing `brolly-admin plc-retry` would submit them: it sends every row with `submitted_at IS NULL` and checks no environment variable. |
| M8 | **Every member's PDS endpoint moves to `https://brolly.id`.** Nine DIDs currently point at `https://<username>.brolly.id`; nikolas's already points at the apex. | brolly-server serves XRPC on the apex and mints genesis operations for it (`server/src/provision.rs`). Relays track PDS hosts by hostname, so one host is simpler for them than ten. Keeping the subdomain endpoints would mean serving XRPC on member subdomains, against ADR 0009. The cost is that relays treat those nine accounts as having moved host, so the runbook handles the identity events and asks members not to post during the switch. |
| M9 | **The rehearsal bundle has no instance rotation key.** | Staging can then never sign for a live DID, whatever runs there. `plc-adopt` refuses without the key, and the rehearsal checks the signing path offline instead (piece 2). |
| M10 | **Avatars use the same media model as every other upload, on every protocol.** There is no special case for avatars in the migration. | A profile picture is an upload that happens to be referenced from a profile. If Solid, ActivityPub, Mastodon and ATProto each stored their own copy, they would drift apart, which is the predecessor's mistake again. The importer writes the avatar once, through the shared path. |
| M11 | **A post exists either as an AS2 note or as an ATProto record, never both.** | Confirmed for mycorhizza's data. The importer handles the two separately, with no de-duplication. |

## The pieces

Ship in order. Each gets its own spec under `docs/specs/` and plan under
`docs/plans/`.

### 1. ATProto parity

brolly-server doesn't yet serve what the network already expects from
brolly.id, and it has two protocol bugs. This piece is needed regardless of the
migration.

- **`/.well-known/atproto-did` on member subdomains.** Without it every
  `@<username>.brolly.id` handle fails verification. This needs an entry in ADR
  0009's reserved-path table.
- **`com.atproto.sync.listRepos`, `getLatestCommit`, `getBlocks`, `getBlob`.**
- **One way to store media, for every protocol (M10).** An avatar, a Mastodon
  or ActivityPub attachment, a Solid binary upload and an ATProto blob are all
  the same kind of thing: bytes in ADR 0013's content-addressed store, described
  by a resource in the pod. Each protocol gets its own view of that resource:
  - Solid: the LDP binary, and `foaf:depiction` on the profile for an avatar
  - ActivityPub: `icon` and `attachment`
  - Mastodon: `avatar` and media attachments (both `null` or missing today,
    `adapters/mastodon/src/translate.rs`)
  - ATProto: the blob CID behind `getBlob` and the profile record's `avatar`

  Setting an avatar through any one protocol shows it in all of them. ADR 0013
  keys by the content's SHA-256, and the repo block store already strips the
  codec from CIDs (`adapters/atproto/src/blocks.rs`), so a raw-codec blob CID
  can find the same bytes. Piece 1's spec designs this and records it in an
  ADR.
- **`rev` must be a TID.** `atproto_repos.rev` is an integer counter, and
  `adapters/atproto/src/firehose.rs` sends it as `rev`. Relays compare revs as
  TIDs and ignore commits that don't advance, so after an import every existing
  repo would appear stuck.
- **Record keys must be TIDs.** New records get ULIDs; the `app.bsky.feed.post`
  lexicon declares `key: tid`.
- **`#identity` and `#account` firehose events.** They tell relays and the
  AppView to re-resolve a DID after its PLC document changes. Check whether they
  exist; add them if not.
- **Firehose events written by any process reach live subscribers.** Today live
  delivery is an in-process broadcast (`server/src/xrpc.rs`), so a row that
  `brolly-admin` writes reaches a relay only after it reconnects. Subscribers
  need to follow the durable log, for example via Postgres `LISTEN`/`NOTIFY`,
  so that `plc-adopt` running as a CLI can emit `#identity`.
- **Firehose `seq` continuity.** Relays hold cursors from mycorhizza's
  `repo_event_seq`. If brolly-server's `atproto_firehose.seq` restarts at 1,
  every relay asks for a future cursor. The import must start the sequence
  above the bundle's highest `seq`.

### 2. Adopting existing identities

These are the building blocks the importer calls. Each one is testable without
a bundle.

- **Create an account from existing values:** UUID, username, email, Argon2 PHC
  hash, role and status. `identity/src/db.rs` already verifies any Argon2 PHC
  string. Only the insert needs a variant that doesn't mint a UUID or hash a
  password.
- **Store imported keys.** `db::store_key` already upserts. The encodings have
  to match what generation writes: `atproto_signing` as a 32-byte secp256k1
  scalar with a `did:key` public key, `activitypub_rsa` as a PKCS#8/SPKI PEM
  pair. Mint a new `atproto_rotation` key per user (M4).
- **Record an adopted `did:plc`.** `db::set_did_plc` exists but nothing calls
  it.
  - Write the fetched PLC audit log into `atproto_plc_operations`, with
    `submitted_at` set from the directory's `createdAt`. These operations are
    already on the directory, so `plc-retry` must never see them as pending.
  - `identity::head` orders by `created_at`, and rows inserted in one
    transaction share `now()`. Head must follow the `prev` chain instead.
- **Hold the backup rotation key as instance state, not as a user's key.**
  `user_keys` allows one row per `(user_id, purpose)`, and the old key belongs
  to no user: it's mycorhizza's instance key and is authoritative for all ten
  DIDs. It goes in its own instance-level row, marked as a backup PLC rotation
  key, and is deleted by `plc-drop-backup`.
- **Gate every PLC submission in the admin binary itself.** `BROLLY_PLC_SUBMIT`
  is read only by the web process today (`server/src/main.rs`). `plc-retry`,
  `plc-adopt` and `plc-drop-backup` all refuse without it.
- **`brolly-admin plc-adopt --endpoint https://brolly.id`**, for each adopted
  DID, one at a time:
  1. Refuse unless `--endpoint` equals `https://<BROLLY_BASE_DOMAIN>`. A staging
     instance can't point a live DID at itself by accident.
  2. Fetch the DID's current log from plc.directory. Refuse unless its head CID,
     rotation keys and signing key match what was imported. That catches
     anything that changed after the export, such as mycorhizza's "fix
     endpoints" admin action.
  3. Build the update:
     - `prev` is that head's CID
     - `rotationKeys` is `[new per-user key, backup key]` (M4)
     - `verificationMethods.atproto` is the unchanged signing key (M5)
     - `alsoKnownAs` is unchanged
     - `services.atproto_pds.endpoint` is the apex (M8)

     Sign it with the backup key, which is authoritative today.
     `plc::rotate_rotation_keys` exists but only tests use it; start from there.
  4. Record it, submit it, and read it back from the directory until it
     appears.
  5. Emit `#identity`, then `#account` (active), on the firehose. This depends
     on piece 1's cross-process delivery.

  With no backup key (M9), it refuses.

  `--offline` exercises everything except submission, for the rehearsal:
  - recompute every audit-log operation's CID and compare it with the
    directory's
  - build the update against the bundled log
  - sign it with a throwaway key, and verify that signature
  - check that the stored per-user rotation key's public half encodes to the
    `did:key` placed first in `rotationKeys`

  **Re-running after a failed submission** reuses the recorded operation if the
  directory's head is still its `prev`. Otherwise it refuses. `plc-retry` would
  also send that row without step 2's checks, which is harmless because the
  directory checks `prev` itself.
- **Nullified entries.** Head follows the `prev` chain and skips audit-log
  entries marked `nullified`.
- **`brolly-admin rotation-keys-export`** writes every per-user
  `atproto_rotation` key, `age`-encrypted to a given recipient, for runbook
  step 10.
- **Where the commands run:** every `brolly-admin` step in the runbook runs
  through `railway ssh` into the brolly-server service, so the command shares
  the service's `DATABASE_URL` and volume. Changing `BROLLY_PLC_SUBMIT`
  redeploys the service, and that's expected.
- **`brolly-admin plc-drop-backup`**, for each DID:
  1. Refuse unless the directory's `rotationKeys[0]` equals the public half of
     the stored per-user `atproto_rotation` key.
  2. Refuse unless `--confirm-offline-backup` is passed (runbook step 10).
  3. Sign an update with `rotationKeys: [per-user key]` using the per-user key,
     submit it, and read it back.

  Once every DID is done, delete the backup key.

### 3. The bundle, the exporter, the importer

**The exporter** is a binary in the mycorhizza repository. It opens the stores
with mycorhizza's own Oxigraph 0.4, reads `repo_blocks` directly, and fetches
each DID's PLC audit log from plc.directory, because mycorhizza never wrote
`plc_operations`.

- **The instance key is `pds_config.rotation_key_private`.** The per-user
  `rotation_keys` table is written but appears in no DID document. Exporting it
  as the rotation key would be a silent, fatal mistake. The exporter checks the
  key it exports against each audit log's `rotationKeys[0]`.
- **The exporter runs as the mycorhizza service's start command.** RocksDB takes
  an exclusive lock, so it can't open the stores beside the running server, and
  a Railway volume is only mounted while the service is deployed. Each export,
  rehearsal included, is a short deploy with the start command swapped to the
  exporter, then a deploy back. The exporter is built on top of the commit
  that's currently deployed (`0929d6d`) and nothing newer, so that deploying
  back never runs new code or migrations against production. That makes a rehearsal export a brief outage;
  announce it. It doesn't touch the wipe path, which lives in the server's
  `main`.
- **It writes to a Railway bucket in the brolly.id project**, encrypted with
  `age` to the operator's public key. `--without-rotation-key` produces the
  rehearsal bundle (M9).

**The bundle** (format version 1; each piece of data is specified in piece 3's
spec):

```
manifest.json            format version, source base domain, created_at,
                         max firehose seq, per-account counts (including repo
                         events), each DID's current head CID, rotation key
                         and signing key, sha256 of every file
instance/rotation-key    the PLC key that is authoritative today    [secret]
accounts/<uuid>/
  account.json           username, email, email_verified, password_hash,
                         role, status, created_at, last_login_at  [secret]
  keys.json              atproto signing scalar, RSA PEM pair      [secret]
  plc-audit.json         PLC log as fetched
  atproto/repo.car       full repo, current head (absent if no repo)
  atproto/blobs/<cid>    blob bytes
  activitypub/objects.jsonl   one AS2 activity per line, with source IRIs
  activitypub/follows.jsonl   follower, followee, state
  profile.json           name, summary, manuallyApprovesFollowers, bot,
                         discoverable
  profile/avatar         bytes, plus media type (absent if none)
```

**Rewriting IRIs follows one rule.** The importer builds a map from every source
IRI listed in the bundle (notes and activities) to the IRI it mints for that
item, then rewrites every IRI found in bundle content through that map.
References to dropped media are left as they are and will 404. It never parses
an IRI to work out its shape, so it needs no knowledge of mycorhizza's URL
layout. Notes keep their ULID (`/outbox/<ULID>` becomes `/~/notes/<ULID>`), so
they stay in order. Actor IRIs are identical on both servers
(`https://<username>.brolly.id/actor`) and need no mapping.

**The exporter leaves out:**
- every Solid resource and post media attachment (M1)
- `urn:atproto:*` graphs, because the CAR is the authoritative copy of ATProto
  records

**`brolly-admin import-bundle <path>`** runs as the brolly-server service's
start command for one deploy, like the exporter, so it has the volume. It reads
the bundle from the bucket, with the `age` identity supplied as a variable that
is removed afterwards.
- **Refuses a non-empty instance** (any `users` row or anything under
  `BROLLY_DATA_DIR/users/`). Postgres and the on-disk pods can't share one
  transaction, so recovering from a failure means wiping and running again, not
  resuming.
- **Verifies before writing anything:** every checksum in the manifest; each
  exported signing key's public half against its audit log; and, when present,
  the backup key against every audit log's `rotationKeys[0]`. `--check` stops
  after verification and prints what it would import.
- **First:** move the firehose sequence past the manifest's max `seq`, before
  anything can write a firehose row.
- **For each account:**
  1. Adopt the identity (piece 2).
  2. Provision the pod with its root ACL.
  3. Write the profile, and the avatar through the shared media path (M10).
  4. Store the CAR's blocks unchanged, set the head to the CAR's commit, and
     ingest its records into the pod through the faithful layer.
  5. Store the ATProto blobs through the same media path, so that a profile
     record's avatar blob and the member's avatar are one resource.
- **Then, across accounts:**
  1. Replay notes and activities through the local delivery path
     (ADR 0014), so that inboxes and the public index fill the way they do in
     normal operation.
  2. Write follows.
  3. Store the backup rotation key, if the bundle has one. No PLC operation is
     built or signed (M7).
- **Repos without a head:** seven of the ten DIDs have no repo. Those accounts
  get a new empty repo from `repo::create`, signed with the imported key.

**The bundle is a secret.** It holds private keys that control ten public
identities, plus password hashes. It's never committed, and it's encrypted with
`age` from the moment it's written. It's deleted once `plc-drop-backup` has
run, and only after the offline backup in runbook step 10 exists.

### 4. Cutover runbook

A runbook, written as docs/migrating-from-mycorhizza.md, first run end to end
against a rehearsal.

0. **Now, before anything else: unset `MYCORRIZA_WIPE_ON_START`** on the
   production mycorhizza service. It names a user, and on every start
   mycorhizza wipes that user's ATProto repo. If the repo has more than 10
   events it exits with code 2 instead, unless `MYCORRIZA_WIPE_REALLY=yes`
   (`mycorriza/src/main.rs`), and `railway.json` restarts on failure up to 10
   times. Every deploy this runbook needs (exports, rollback) would trigger it.
   Unsetting it is itself a redeploy, and the new deployment starts without the
   variable. Record `listRepos` and each repo's event count before and after.
1. **Rehearse.**
   - Export with `--without-rotation-key` (M9); this is a short announced blip.
   - Import into a staging Railway project on a throwaway domain.
   - Run the step 6 checks, plus `plc-adopt --offline` for every DID.
   - Time how long Railway takes to issue certificates when a wildcard custom
     domain moves between services, because that adds to the window.
   - Destroy the staging database, volume and bucket objects.

   Repeat until it runs cleanly.
2. **Announce** the window to the ten members. They'll log in again with the
   same password and re-authorize apps. They shouldn't post anywhere until step
   8 is done, and anything posted after step 5 is lost if you roll back.
3. **Freeze and export.** Deploy mycorhizza with the exporter as its start
   command. It is offline from here. The final bundle includes the rotation key.
4. **Import** into the production brolly-server service: its own volume, a
   fresh Postgres, `BROLLY_BASE_DOMAIN=brolly.id`, `BROLLY_PLC_SUBMIT` unset.
   Afterwards, remove the `age` identity variable and redeploy with the normal
   start command.
5. **Move `brolly.id` and `*.brolly.id`** from the mycorhizza service to
   brolly-server. Wait for the certificates. Until step 7, nine DIDs still name
   `<username>.brolly.id` as their PDS, and brolly-server serves no XRPC there.
   Relay errors against those hosts are expected here, not a failed check.
6. **Check before PLC. This is a hard gate:**
   - every member can log in
   - `listRepos` shows every repo, and each head CID matches the manifest
   - `/.well-known/atproto-did` answers for all ten members
   - notes appear on the public timeline
   - avatars show in a Mastodon client, on the ActivityPub actor and in each
     profile's `getBlob`
7. **Adopt.** Set `BROLLY_PLC_SUBMIT=1`, run
   `brolly-admin plc-adopt --endpoint https://brolly.id`, then send
   `com.atproto.sync.requestCrawl` for `brolly.id` to the Bluesky relay.
8. **Check in bsky.app** that each handle is valid, existing posts render, and a
   new post from one member arrives.
9. **Unset `BROLLY_PLC_SUBMIT`.**
10. **After a quiet week:**
    1. Run `brolly-admin rotation-keys-export` to offline storage that doesn't
       depend on Railway, and confirm it decrypts.
    2. Set `BROLLY_PLC_SUBMIT=1` and run
       `brolly-admin plc-drop-backup --confirm-offline-backup`.
    3. Unset `BROLLY_PLC_SUBMIT`, delete the bundle, and decommission
       mycorhizza and its volumes.

**Rollback:**
- **Relays have already seen brolly-server, in either case.** From step 5 they
  hold firehose cursors above anything mycorhizza has, and they may have seen
  new empty repos. Before mycorhizza starts again, set its `repo_event_seq`
  above brolly-server's highest `atproto_firehose.seq`. After it's back, send
  `requestCrawl` for `brolly.id` and every member subdomain.
- **Before step 7:** do the above, move the domains back, and redeploy
  mycorhizza with its normal start command. No DID has changed. Anything
  members posted to brolly-server in the meantime is lost.
- **After step 7:** while the backup key is still listed, it can sign an update
  on top of the head at any time, with no time limit. That update points each
  DID back at mycorhizza, which is its PDS again. The per-user key could
  override that update within 72 hours, but only if someone uses it, and it sits
  in brolly-server's database. So rollback is dependable until step 10. After
  step 10 there is no going back, which is why step 10 waits a week and needs
  the offline backup.

## Known losses

- Post media attachments, and Solid resources that members stored.
- Old URLs 404: `/outbox/<ULID>`, `/media/<owner>/<id>/<name>`, and Solid
  resources outside `/~/`.
- Mastodon status IDs change (ADR 0015's format carries the owner). Clients
  re-fetch.
- Every session and OAuth grant: Solid, ATProto, Mastodon. Members log in again
  and re-authorize apps.
- Blocks, mutes, reports and instance rules. Record their counts at rehearsal;
  expected to be near zero.

## Open questions

None at umbrella level. Resolved on 2026-09-16: media attachments and Solid
resources are dropped (M1), avatars share one media model (M10), and notes and
ATProto records don't overlap (M11).
