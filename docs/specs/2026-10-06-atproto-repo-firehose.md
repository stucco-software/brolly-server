# Stage 1: ATProto repo and firehose

<!-- doc-paths: skip -->
<!-- The spec names files and a migration this stage creates, so not every
     path it cites resolves until it's implemented. -->

**Status:** Draft (2026-10-06), revised 2026-10-06 after one adversarial
review against the ATProtocol Sync and Repository specifications
(atproto.com, as of this date), the generated lexicon types in
atrium-api 0.25.8, the public API surface of atrium-repo 0.1.8, and the code
it cites. The review corrected the blocks cap (2 MB, not 200 KB), the
`tooBig`/`blobs` fields (deprecated; fixed values, not mechanisms), the
omission of `prevData` (effectively required), the per-op `prev` CID, the
`createRecord` failure mode (refused today, not overwriting), and the
concurrent-write answer (server-side optimistic retry, not a hard error).
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 1. The
foundation for finish-line items 1–3: "an account on the instance, using
bsky.app, logs in, posts…", "the account's repo, commits and blobs are
indexed with no errors", and "a third-party OAuth app writes its own
lexicon's records". Stages 2 (auth) and 3 (PDS surface) build on it, and
stage 4's ATProto half needs its blob links.
**Depends on:** stage 0
(`docs/specs/2026-09-17-security-fixes.md` — the hardened document fetch the
client metadata path already rides), ADR 0002 (atrium for MST, repo, CAR),
ADR 0016 (the federation switch is ActivityPub-only; ATProto is
unconditional).

## Problem

Everything ATProto writes goes through one path — a signed commit on the
repo, a row in the event log, a frame on the firehose — and none of the three
is correct on the wire today. The roadmap's survey
(`docs/specs/2026-09-17-interop-roadmap.md:19-23`) named the findings; here
they are against the current tree:

1. **`rev` is an integer, not a TID.** `atproto_repos.rev` is a `BIGINT`
   (`migrations/20260826000002_atproto_repos.sql:20`), incremented by
   `state::advance` (`adapters/atproto/src/state.rs:49-61`), and the firehose
   row carries the same `BIGINT`
   (`migrations/20260826000005_atproto_firehose.sql:20`). A revision is a
   TID — a 13-character base32 timestamp-sortable identifier — and every
   consumer that orders, compares, or echoes it expects one. A `rev` of
   `"7"` is not a slightly wrong TID; it is a parse failure.
2. **The frame builder serializes JSON, not IPLD.** `firehose::frame`
   (`adapters/atproto/src/firehose.rs:168-192`) builds a `serde_json::Value`
   and hands it to `serde_ipld_dagcbor`. JSON has no CID type, so `commit`
   and each op's `cid` encode as **text strings** where the lexicon demands
   CID links (DAG-CBOR tag 42). The reference stack parses these frames with
   strict CID decoding and cannot read ours as links.
3. **`blocks` is empty, `since` is the wrong field, `time` and `prevData`
   are absent.** The frame emits `"blocks": []` (`firehose.rs:183`) where
   the Sync spec wants a CAR *diff slice* — the commit block, the new MST
   nodes, and the new record values, up to a 2,000,000-byte hard limit. It
   sets `"since": event.prev_cid` (`firehose.rs:176`) — the CID of the
   previous *commit*, where `since` is the *rev* the commit is based on.
   `time` is absent, and so is `prevData` — the previous MST root, which the
   spec calls "effectively required for MST inversion" and no inductive
   consumer can work without.
4. **`putRecord` cannot update.** Both routes are served by the one
   `create_record` handler (`server/src/xrpc.rs:767-768`), which calls
   `repo::put_record` (`adapters/atproto/src/repo.rs:94-118`) →
   `Repository::add_raw` → `mst::add`, and `mst::add` **refuses an existing
   key** (`atrium-repo` `mst.rs`, `Error::KeyAlreadyExists`) — so an update
   through either endpoint fails with a generic 400, no swap parameters are
   read anywhere, and the lexicon's own error shape (`InvalidSwap`) is never
   produced. (`update_raw` exists in atrium-repo and is never called.)
5. **Record keys are not TIDs, and paths are barely validated.** A record
   with no rkey gets `mint_note_id()` — the *Mastodon* status id
   (`server/src/xrpc.rs:451-453`) — not a TID. `record_path`
   (`adapters/atproto/src/repo.rs:57-69`) checks "at least three
   dot-separated segments and no slash", which is not the NSID grammar, and
   the rkey half gets "non-empty, no slash" where the grammar is
   `^[a-zA-Z0-9.\-_:~]{1,512}$` minus `.` and `..`. atrium-api ships both
   validators (`types::string::Nsid`, `types::string::RecordKey`); neither
   is used.
6. **Head updates check nothing.** `state::advance` is an unconditional
   `UPDATE … SET root_cid = $2` on `user_id` alone
   (`adapters/atproto/src/state.rs:49-61`). Two concurrent writes both open
   the same root, both commit, and the second `advance` overwrites the
   first — one signed commit is orphaned, and a consumer that already
   accepted it now sees a history that never happened.
7. **Only `#commit` events exist.** The log's row shape
   (`atproto_firehose` columns) can hold nothing else, and nothing emits
   `#identity` (identity change), `#account` (hosting status change), or
   `#info` (cursor advice) — all defined by the same stream, all consumed by
   the reference relay.
8. **The backfill race is open.** `stream_commits`
   (`server/src/xrpc.rs:694-749`) drains the table to its end, *then*
   subscribes to the in-process broadcast (`xrpc.rs:734`). An event
   committed between the last page and the `subscribe()` call is in neither
   — delivered to nobody. The seq-dedupe at `xrpc.rs:736` catches the
   overlap case; the gap case is the race.
9. **Events from another process reach no one.** The broadcast channel
   (`state.commits`) is a `tokio::sync::broadcast` in this process's memory.
   A `brolly-admin` one-off, a second server process, or a future worker
   writes an event row that no live subscriber will ever hear about.

## Goals

- **`rev` is a TID**, stored and emitted as one, monotonic per repo across
  clock skew and restarts.
- **A frame our own encoder is not the only decoder for:** CIDs as links,
  `blocks` as a real CAR diff slice within the spec's limits, and
  `since`/`time`/`prevData`/per-op `prev` per the Sync spec — decodable by
  atrium's own firehose types, and invertible (D below).
- **The write path is the lexicon's:** `createRecord` creates, `putRecord`
  upserts, both validate NSID and rkey, TID rkeys by default, `applyWrites`
  batches into one commit, and `swapRecord`/`swapCommit` express
  compare-and-set with the lexicon's `InvalidSwap`.
- **Concurrent writes cannot drop each other.** The head moves only from
  the commit it was read at; a raced write is retried server-side for the
  plain writes, refused with `InvalidSwap` where a swap was named.
- **The other events exist** — `#identity`, `#account`, `#info` — and are
  emitted at the transitions that define them.
- **A subscriber cannot miss an event**: live attachment precedes backfill,
  and events written by any process reach live subscribers.
- **Blob refs in records are real CID links** in the repo block — the seam
  stage 4's `uploadBlob` lands on.

## Non-goals

- **The PDS read surface** — `sync.listRepos`, `getRepoStatus`,
  `getLatestCommit`, `getBlocks`, `getRepo`, `/.well-known/atproto-did`,
  `identity.resolveHandle`, `requestCrawl`. Stage 3
  (`docs/specs/2026-09-17-interop-roadmap.md`, stage 3 row), building on
  this stage's storage.
- **Legacy sessions and OAuth completion** — stage 2. The write endpoints
  keep the caller authentication they have today.
- **`uploadBlob`/`getBlob`/`listBlobs`** — stage 4's remainder. This stage
  defines how a *record* carries a blob ref; it does not mint any.
- **Repo import/transfer** (`importRepo`, `#sync` emission). The frame type
  is built; nothing emits it. It belongs to the paused migration spec
  (`docs/specs/2026-09-16-mycorhizza-migration.md`).
- **Event retention policy.** The log grows; pruning it is an operational
  decision with its own spec when it needs making. `#info` is the mechanism
  that makes pruning safe later.

## Design

### A. `rev` becomes a TID

**Storage.** `atproto_repos.rev` and `atproto_firehose.rev` become `TEXT`
holding the 13-character base32 TID. A TID is 64 bits — it fits a `BIGINT` —
but it travels as a string in every wire format that mentions it, and
storing the wire form means no re-encoding on the hot path and no
endianness/decoding bugs at the frame builder. Ordering still works: the
encoding is order-preserving, so lexicographic order on the text is
numeric order on the TID, and `ORDER BY rev` / `rev > $1` stay correct.

**Generation.** Atrium-api ships the type and the mint
(`types::string::Tid`, including construction from wall time with clock-id
bits). The Sync spec's own guidance is the rule: use current wall time as
the TID, and *check that the new revision is higher than the previous* —
which is exactly the `rev < $new` guard in the head update (C). Monotonicity
is enforced at the head, not at the mint, which is what makes clock skew, a
retry, and two writes in the same millisecond all correct without a lock.

**Emission.** The frame's `rev` is the TID; `since` is the previous rev
(null on a repo's first commit) — not, as today, the previous commit's CID.
`prevData` (D) is the previous MST root: the `data` field of the previous
commit object, *not* the previous commit's own CID. The commit object's
`prev` field stays `null` — in v3 repos it "must exist … but is virtually
always `null`", and the history chain is carried by `since`/`prevData` in
events instead. Nothing here should "fix" `commit.prev`.

### B. The write path is the lexicon's

All of this lands in `adapters/atproto/src/repo.rs` and the
`server/src/xrpc.rs` handlers, replacing the `create_record` handler that
both routes share today (`server/src/xrpc.rs:767-768`).

- **Validation first.** `record_path` is replaced by atrium's own grammars:
  `types::string::Nsid` for the collection, `types::string::RecordKey` for
  the rkey (`^[a-zA-Z0-9.\-_:~]{1,512}$`, minus `.` and `..`). Refused with
  `InvalidRequest` before any block is written.
- **`createRecord`** mints a TID rkey when the caller supplies none — a
  *TID*, not `mint_note_id()`; a supplied rkey is validated. If the path
  already exists, the call fails `InvalidSwap`-style *before signing*, so a
  failed create leaves no orphan blocks. (The refusal itself is not new —
  `mst::add`'s `KeyAlreadyExists` does it today — what is new is the
  lexicon-shaped error and no side effects.)
- **`putRecord`** is upsert, as the lexicon defines it: absent →
  `add_raw`, existing → `update_raw` (which atrium-repo ships and brolly
  has never called). Its `swapRecordCid`/`swapCommitCid` parameters express
  compare-and-set — `swapRecordCid: null` means "must not exist", a CID
  means "must be at exactly this" (the lexicon marks the field nullable
  *and* optional, deliberately).
- **`applyWrites`** takes a batch of creates/updates/deletes and applies
  them **in one commit** — one MST revision, one signature, one event row
  with one op per write, one CAR slice. A batch is atomic: any invalid op
  refuses the whole batch before anything is signed. **atrium-repo 0.1.8
  cannot build this commit**: `CommitBuilder::new` and the commit `schema`
  module are private, and each of `add_raw`/`update_raw`/`delete_raw`
  stages a single op from `latest_commit`. So brolly gains one commit
  envelope builder of its own — the unsigned commit is six fields
  (`did`, `version: 3`, `data`, `rev`, `prev: null`, then `sig`), built and
  signed through the same path atrium uses (serialize unsigned, sign, write
  the signed block), and used by *every* write — single-op and multi-op
  alike, one code path, no divergence. atrium keeps the MST, the block
  store, and CAR framing (D14); the envelope is not an MST. The tests (see
  Testing) hold the envelope to atrium's bytes, and hold every commit to
  atrium's own verifier.
- **The spec's write limits are enforced at the write, not the firehose**:
  a record block over 1,000,000 bytes and a batch over 200 ops are refused
  (`PayloadTooLarge` / `InvalidRequest`), and a commit whose CAR slice
  would exceed 2,000,000 bytes is refused rather than emitted with
  `tooBig` — the Sync spec deprecates `tooBig` ("producers should always
  set it to `false`"), so the limit has to bite somewhere, and the write is
  where.
- **`swapRecord`** gets its own route, both swap parameters required.
- **`swapCommit`** takes `commitCid` and writes against the head *only if*
  the head is exactly that commit — the surface C's compare-and-set needs
  to be reachable by a client that has synced the repo.

### C. Head updates compare and set; plain writes retry, swaps refuse

`state::advance` becomes:

```sql
UPDATE atproto_repos
   SET root_cid = $new, rev = $new_rev, updated_at = now()
 WHERE user_id = $1 AND root_cid = $expected AND rev < $new_rev
RETURNING rev
```

Zero rows is a **conflict**. What happens next is the decision the first
draft of this spec got wrong:

- **Plain writes (`createRecord`, `putRecord`, `applyWrites` without
  `swapCommit`): the server retries the whole write** — re-read the head,
  re-apply the ops to the new root, re-sign, re-compare-and-set — a small
  bounded number of times (start: 3). This is optimistic concurrency, it
  is what the reference PDS does, and a hard error here would surface as a
  spurious failure in bsky.app whenever two tabs write at once. A retry
  re-signs against a root the client never saw, but the client never
  *named* a root — it asked for a write, and got the commit that landed.
- **Swap writes (`swapRecord`/`swapCommit`/`swapCommitCid`): no retry,
  ever.** The client named the exact prior state; a mismatch is the
  answer `InvalidSwap`, the lexicon's own error (defined in the
  `putRecord`/`applyWrites` lexicons, verified in atrium-api's generated
  types).

The write path's `open_repo` → `advance` window is the whole race window;
closing it at the `UPDATE` closes it everywhere, because nothing else moves
the head.

### D. Frames follow the Sync spec

`firehose::frame` is rebuilt on IPLD values, not JSON:

- **CIDs are links.** The frame is built as `ipld_core::ipld::Ipld` with
  `Link` values for `commit` and each op's `cid`, so DAG-CBOR encodes them
  as tag-42 links. This is the single biggest correctness fix: the current
  builder cannot express a link, because JSON cannot.
- **`blocks` is a CAR *diff slice***, per the Repository spec's definition:
  the new commit block first (and first in the CAR `roots`), every MST node
  of the new revision that did not exist in the previous one, the
  contextual MST nodes operation inversion needs (adjacent in key order),
  and the created/updated records' new values — never a deleted record's
  old value. Built with the same atrium CAR writer `export_car` uses.
  Limits per the Sync spec: `blocks` ≤ 2,000,000 bytes (enforced at the
  write, B), the whole frame ≤ 5 MB.
- **Deprecated fields are emitted at their fixed values, not used as
  mechanisms:** `tooBig` is always `false`, the top-level `blobs` array is
  always empty. (The first draft of this spec had both as live mechanics;
  the Sync spec deprecates them.)
- **`since`** is the previous rev (A); **`prevData`** is the previous MST
  root — "effectively required for MST inversion", so it is emitted, from
  the previous commit's `data` field; **`time`** is the event's timestamp;
  **`rebase`** is `false`.
- **Per-op `prev`**: for updates and deletes, the *previous record CID* —
  required by inductive consumers; undefined for creates. The write path
  captures it when it applies the op (it has the old MST open), and the
  firehose row carries it. (Ops have no `blobs` field; blob CIDs live only
  inside the record blocks — H.)
- **Header unchanged:** two concatenated DAG-CBOR objects, `op: 1` and the
  type tag. That part is already right.

### E. The other events

The `atproto_firehose` table grows a `kind` column (`commit`, `identity`,
`account`); the commit-specific columns on the event row (`commit_cid`,
`rev`) become nullable, and a non-commit row carries none of the commit
columns — a CHECK, not a promise. (`prev_cid`, `since_rev` and `prev_data`
were nullable already; `action`, `path` and `record_cid` live on the op
rows, where they stay required — an op row exists only where a commit
does.) New columns: `handle` (`#identity`), `active`/`status` (`#account`).

- **`#identity`** is emitted when a member's identity changes — handle
  rename, key rotation. DID and the new handle on the wire; the handle is
  optional per the spec and best-effort, which a first-party PDS's is not.
- **`#account`** is emitted on hosting-status transitions: suspension,
  reinstatement, deactivation, deletion — `active` plus a `status` of
  `takendown`/`suspended`/`deleted`/`deactivated` (the spec's known
  values).
- **`#info`** is **synthesized, never logged** — it is advice to one
  connection about *its* cursor, not an event in the stream. A subscriber
  whose cursor precedes the log's oldest row (F) gets
  `#info {name: "OutdatedCursor"}` and the stream continues from the
  oldest row.
- **`#sync`** exists as a frame type and is emitted by nothing (non-goal:
  repo transfer). The Sync spec reserves it for state resets.

### F. The cursor and the backfill race

The race in `stream_commits` (`server/src/xrpc.rs:694-749`) is closed by
ordering: **attach live first, backfill second.**

1. Subscribe to the live feed *before* reading the table, into a bounded
   buffer.
2. Backfill from the cursor in pages, by `seq`, to the end of the table.
3. Drain the buffer, skipping any `seq` already sent, then stream live.

The buffer is bounded because a slow backfill must not hold unbounded
memory — and the lexicon already defines what overflow means: the stream
error `ConsumerTooSlow`, sent as an error frame followed by a close. The
consumer reconnects with its cursor; that is the designed recovery. The
seq-dedupe the handler already does (`xrpc.rs:736`) is kept — with the
ordering fixed there is no gap left for it to miss, only the overlap to
absorb.

**Cursor rules.** Absent cursor → live only (today's behaviour, correct).
A cursor before the oldest retained row → `#info` `OutdatedCursor` (E),
then oldest-first from the oldest row. A cursor *ahead of the head* → the
lexicon's `FutureCursor` stream error, then a close: a client asking for
events that do not exist yet is a client bug the stream names rather than
absorbs. The cursor is the `seq` of the last event processed, exclusive,
as today.

### G. Any process's events reach live subscribers

The in-process broadcast stays as the fast path, but it stops being the
correctness mechanism. After the event row commits, the writer issues
`SELECT pg_notify('atproto_events', $seq::text)` in the same transaction —
transactional, so a rolled-back write notifies no one. Live subscribers
get correctness from a **shared listener task**: one dedicated connection
per server process that `LISTEN`s on `atproto_events`, and on each
notification reads the new rows past its high-water mark and re-broadcasts
them on the in-process channel. This replaces per-connection polling,
keeps one Postgres connection per process rather than per subscriber, and
means an event written by `brolly-admin`, a worker, or a second server
process reaches every live subscriber. The notification carries only the
`seq`; the row is the truth — a lost notification is repaired by the next
one or by the subscriber's next table read, never by trusting payload over
table.

### H. Blob refs are real CID links

Today a record's `$blob`-typed value goes through `add_raw` and lands as
whatever JSON the caller sent. After this stage, a record value of
`{"$type": "blob", "ref": …}` is stored with `ref` as a **CID link** in
the record's DAG-CBOR block. That is the whole of it: the deprecated
top-level `blobs` array stays empty (D), ops carry no blob list, and the
blob *bytes* are stage 4's `uploadBlob`. A record referencing a blob CID
that has no bytes in the store is accepted — the repo is a pointer set,
not an oracle, and `getBlob` is stage 4's problem.

## Testing

- **Frame conformance, against a foreign decoder.** Every frame test
  decodes with atrium-api's own `subscribeRepos` types — not our `frame`
  function's inverse. The wire body carries no `$type` tag (the type lives
  in the header), so the tests dispatch on the header then decode the body
  as the matching `CommitData`/`IdentityData`/`AccountData`/`InfoData`.
  A frame that our encoder and their decoder disagree on is a bug in our
  encoder, full stop.
- **Operation inversion** — the Sync spec's own validation, as our test:
  parse our `blocks` as a partial MST, apply the ops *in reverse*, recompute
  the root, and require it to equal `prevData`. A commit whose diff cannot
  be inverted is not a diff, whatever our encoder believes.
- **The envelope is atrium's bytes.** A single-op commit built through
  brolly's envelope builder must be byte-identical to one built through
  atrium's `add_raw` path (same ops, same key, same rev), and every commit
  must verify under `atrium-crypto`'s `Verifier`.
- **TID properties.** Monotonic across same-millisecond mints (clock id
  bits), across a clock step backwards (the `rev <` guard refuses, the
  retry succeeds), and lexicographic == numeric ordering over a generated
  corpus.
- **Write-path semantics.** `createRecord` on an existing path refuses
  with no blocks written; `putRecord` creates and replaces; `swapRecord`
  with a stale CID refuses `InvalidSwap`; `applyWrites` is one commit, one
  event, `n` ops, and an invalid op refuses the batch unsigned; records
  over 1 MB and batches over 200 ops are refused.
- **The lost-update race.** Two concurrent `putRecord`s from the same root:
  both succeed (one by retry), the head's history is linear (`since`/`
  prevData` chain with no orphan), and no event is missing.
- **The backfill race.** An event committed between backfill drain and
  live attach is delivered exactly once — the test drives the sequence
  deterministically with a paused writer. A subscriber slower than the
  buffer gets `ConsumerTooSlow` and a close; a future cursor gets
  `FutureCursor`.
- **LISTEN/NOTIFY.** A second pool (a stand-in for a second process) writes
  an event; a subscriber attached through the shared listener receives it.
- **`#info` advice.** A cursor older than the log's oldest row gets
  `OutdatedCursor` and then the oldest row.

## Rollout

- **Migration:** `rev` columns become `TEXT`; existing rows are converted
  by deriving a TID from each row's `created_at`/`updated_at`, minted in
  `seq` order per repo — incrementing past a collision where two rows
  share a millisecond — so the derived revs stay strictly monotonic. The
  deployed test instance (`test.brolly.cc`) holds a handful of rows;
  production instances do not exist yet. The conversion runs in the
  migration, not at first boot, so a rollback of the binary does not see a
  half-TID table.
- **Wire-breaking, deliberately.** The frame shape changes; any consumer of
  the old frames (none known — the frames were not decodable by the
  reference stack) must resync from cursor 0.
- **Stages 2–3 build on this:** `createSession`'s callers need the TID rev,
  and stage 3's `getLatestCommit`/`getBlocks` read the storage this stage
  shapes.

## Chunks

Five, one commit each:

1. **TID revs and the compare-and-set head.** The `tid` use of
   atrium-api's type, the migration (`rev` → TID text in both tables, plus
   `since_rev`/`prev_data` columns, derived-TID conversion), `advance` as a
   CAS on `root_cid` with the `rev <` monotonic guard, the conflict error
   and its handler mapping. *First because everything else writes through
   it: the frame builder needs a TID `rev` to emit, the write-path
   semantics need the CAS to refuse on, and the swap endpoints are the CAS
   made client-visible. It also carries the only schema change other
   chunks depend on.*
2. **The write path is the lexicon's.** NSID/rkey grammars, TID rkeys, the
   `createRecord`/`putRecord` split (`add_raw`/`update_raw`), the brolly
   commit envelope (single code path for single- and multi-op), the write
   limits (1 MB record, 2 MB slice, 200 ops), `swapRecord`, `applyWrites`,
   `swapCommit`, the un-aliasing of the routes, and the server-side retry.
   *Second because it is the biggest consumer of chunk 1's CAS and the
   largest single surface, and because its events (multi-op, both actions,
   per-op `prev`) are the fixture the frame work needs to test against.*
3. **Frames on IPLD.** The frame builder rebuilt on `Ipld`/`Link`, `blocks`
   as a CAR diff slice, `since`/`prevData`/`time`, the fixed deprecated
   fields, per-op `prev` on the wire, and the atrium-decoder and
   operation-inversion tests. *Third because it is pure output — nothing
   upstream of it changes — and because testing it well needs the multi-op
   events chunk 2 produces.*
4. **The other events and the log's shape.** The `kind` column and
   nullable commit columns, `#identity` at identity change, `#account` at
   status transitions, `#sync` typed but unemitted. *Fourth because it is
   small, touches the same migration-adjacent surface as chunk 1 without
   overlapping it, and its emissions come from transitions the identity
   and admin layers already own.*
5. **Subscribers cannot miss.** Live-attach-before-backfill with the
   bounded buffer, `OutdatedCursor`/`FutureCursor`/`ConsumerTooSlow`,
   `pg_notify` on write, the shared `LISTEN` task feeding the broadcast
   channel, and the second-pool delivery test. *Last because it is the
   only chunk that changes runtime topology (a background task, a
   dedicated connection), and everything it serves is by then worth
   delivering.*

Blob refs (H) are not a chunk: they land inside chunk 2 (the record write
holds the link) and the inversion tests of chunk 3 (a blob link in a
record block inverts like any other), which is where the seam is. Nothing
else needs them until stage 4.

## Decisions

| # | Decision | Why |
|---|---|---|
| A | `rev` stored as 13-char base32 TID text in both tables; wall-time TIDs; monotonicity enforced by `rev <` in the CAS update, not at mint | The Sync spec's own guidance is "use wall time as TID, and check it is higher" — the check belongs where the head moves, because that is the one place all writes pass through, and mint-time enforcement cannot survive clock skew. Text storage removes an encode/decode step from the hot path; order-preserving encoding keeps `ORDER BY`/`>` correct. |
| B | atrium's NSID/RecordKey validators; TID rkeys by default; `createRecord` creates, `putRecord` upserts via `update_raw`; `applyWrites` is one commit through a brolly-built envelope used by every write; spec limits (1 MB/2 MB/200 ops) enforced at the write | The lexicon's semantics are the contract bsky.app codes against, and atrium ships the validators — hand-rolled approximations already exist and already accept what the network rejects. atrium-repo 0.1.8 cannot stage multi-op commits (private builder/schema), and two commit paths would diverge; one envelope, byte-held to atrium's and verified by atrium's `Verifier`, keeps D14's spirit (no hand-rolled *MST*). `tooBig` is deprecated, so the size limits must bite at the write. |
| C | CAS on `root_cid` + `rev <`; plain writes retry the whole write server-side (bounded), swap writes never retry and answer `InvalidSwap` | An unconditional UPDATE makes two concurrent writes a coin flip on which history survives. But a hard error on every race is a spurious failure in bsky.app's language — the reference PDS retries, and the client that never named a root has no reason to see one. A client that *did* name a root (`swapCommitCid`) bought exactly that answer. |
| D | Frames on IPLD with `Link` values; `blocks` as a CAR diff slice (commit block first, new MST nodes, inversion context, new record values); `since` = previous rev; `prevData` = previous MST root; `time` emitted; deprecated fields fixed (`tooBig: false`, `blobs: []`); per-op `prev` for update/delete | JSON cannot express a CID link, so the current builder is structurally incapable of a conforming frame. `prevData` is "effectively required" for MST inversion — omitting it (the first draft's position) excludes every inductive consumer. The diff's contents are the Repository spec's definition, not ours; the inversion test holds us to it. |
| E | `kind` column; `#identity`/`#account` logged and emitted at their transitions; `#info` synthesized per connection, never logged; `#sync` typed but unemitted | The stream defines all of these; the relay consumes at least three. `#info` is about a connection's cursor, not the stream — logging it would replay advice at whoever reconnects. `#sync` is for state resets, which a first-party PDS performing ordinary writes does not have. |
| F | Live attach before backfill, bounded buffer with `ConsumerTooSlow` on overflow; `OutdatedCursor` below the log's oldest row; `FutureCursor` ahead of the head | The current order has a gap an event fits through exactly once per connection; attach-then-backfill makes the gap structurally impossible. The lexicon already names both slow-consumer and future-cursor outcomes — inventing different ones (the first draft's table re-pass) is protocol fork. |
| G | `pg_notify` in the write transaction + one shared `LISTEN` task per process feeding the existing broadcast channel | The broadcast channel is process-local by nature; the log is the truth and Postgres already has a fan-out mechanism. One listener per process, not per connection, keeps the connection count flat; transactional notify means no false signals for rolled-back writes. |
| H | `$blob` refs stored as CID links in the record block; deprecated `blobs` array stays empty; bytes and `uploadBlob` stay stage 4 | Stage 4 needs the repo to hold the reference; this stage is where references are shaped. The Sync spec deprecated the blobs-in-event mechanisms, so the record block is the only place the reference lives. |
| I | atrium-repo is vendored (0.1.8 plus one fix) until upstream releases the fix; the patch is marked in `vendor/atrium-repo/src/mst.rs` and carries its own regression test | 0.1.8's `split_subtree` drops a parent node's entries when the level below splits with one side empty — silent record loss on `Tree::add` (a delete/re-add round trip makes whole key ranges unfindable), which the inversion test is the first thing to exercise and a write path would eventually hit. No released version fixes it (mst.rs is unchanged since the crate landed); a vendored one-function fix beats either a fork of every write around a broken MST or hand-rolling our own. |
