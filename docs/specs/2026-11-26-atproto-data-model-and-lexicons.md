# Stage 4a: the data model, held

<!-- doc-paths: skip -->
<!-- The spec names files this part creates (the lexicon module, the vendored
     lexicon tree, the spike), so not every path it cites resolves until it
     lands. -->

**Status:** Chunk 1 (the spike) done 2026-11-26: the validator is written,
not adopted (Decision D, `spikes/lexicon-validation/RESULT.md`). Chunk 2
(the data model and the envelope) landed 2026-11-27; review tightened H1
beyond the table below — blobs carry exactly their four fields with a
32-byte digest, a `$link` must be the canonical CIDv1 base32 string (so it
reads back byte-identical), and error paths are built only on error,
JSON-Pointer escaped, with long keys and deep paths truncated. Drafted
2026-11-26; revised twice after adversarial reviews
against the tree, the ATProto data-model and lexicon specs, and the
reference PDS's `packages/pds/src/repo/prepare.ts`.
**Roadmap:** `docs/specs/2026-09-17-interop-roadmap.md`, stage 4's ATProto
half, part a — the first of five (a–e), and the gate every later part
writes through.
**Depends on:** ADR 0022 (the pod is the core; protocol rules plug into
protocol-neutral hooks), ADR 0002 (adopt over hand-roll), stage 1
(`docs/specs/2026-10-06-atproto-repo-firehose.md` — the write plan this
gate sits in front of), D9 (publication = shape + location).
**Supersedes:** stage 1's decision H in part — a blob `ref` no longer reads
back as a bare CID string, and a bare string is no longer accepted on write
(H1).

## Problem

Every write that reaches the repo is held to some of ATProto's rules and
silently let past the rest. Each item is checked against the tree and the
reference PDS:

1. **CID links exist only inside a blob's `ref`.** `record_ipld`
   (`adapters/atproto/src/repo.rs:257-263`) makes `ref` a link when the
   object is `$type: blob`, and nowhere else. A `{"$link": "…"}` anywhere
   else is stored as a one-key map, so the block — and its CID — differ from
   what every other implementation computes for the same JSON.
2. **Links and bytes read back in the wrong form.** `ipld_to_json` renders a
   link as a bare string (`repo.rs:314`) and bytes as `null` (`repo.rs:306`).
   The JSON data model is `{"$link": "<cid>"}` and `{"$bytes": "<base64>"}`.
   A client that reads a profile with `getRecord` and writes it back —
   bsky.app's profile editor — gets a blob whose `ref` is a string.
3. **Floats are stored.** A JSON fraction becomes `Ipld::Float`
   (`repo.rs:244`). The data model has none ("not allowed in atproto").
4. **A mismatched `$type` is accepted, and the fill is copied six times.**
   Every write handler fills a missing `$type` itself
   (`server/src/xrpc.rs:1509`, `1628`, `1721`, `1806`, `1922`, `1934`) and
   none refuses a different one. The reference refuses it — `Invalid $type:
   expected {collection}, got {type}` — even under `validate: false`. The
   fill also indexes the record as an object, so a record that is a string,
   number or array **panics the handler** (serde_json's `IndexMut`), and
   `null` silently becomes `{"$type": collection}`.
5. **No lexicon is ever checked.** A post with no `createdAt`, 3 000
   graphemes of text, or a reply whose `root` is not a strong ref is
   committed, signed and announced. The reference validates every lexicon it
   knows, including the rkey against the lexicon's `key` type, and answers
   `validationStatus`.
6. **No `validate`, no `validationStatus`** — on any write verb.
7. **Legacy blob refs** (`{"cid", "mimeType"}`, no `$type`) are stored when
   sent. The data model: implementations "should never write them"; the
   reference refuses them.
8. **`applyWrites` results are malformed.** The results map
   (`xrpc.rs:1960-1972`) emits `{uri, cid}` for every op, with no `$type` and
   `cid: null` for a delete. In the lexicon the results are a union of
   `#createResult`, `#updateResult` and `#deleteResult` (which has no
   fields), and union members carry `$type`.

Under ADR 0022 these are not XRPC bugs. They are the shape the core must
hold every record to, whichever surface the write came through.

## Goals

- A record is held to the ATProto data model on every write; reads emit the
  data model's own JSON form.
- **Full lexicon validation** of every record whose lexicon this server
  knows — `com.atproto.*` and `app.bsky.*`, vendored and pinned — against
  every constraint the lexicon language has. Unknown lexicons are accepted as
  `"unknown"`, as the reference does.
- `validate` honoured and `validationStatus` answered on every write verb.
- One gate, in one place, that owns everything between "a JSON value arrived"
  and "this is the IPLD to commit" — and is shaped so part c can put a
  protocol-neutral core hook in front of it with a thin wrapper.

## Non-goals

- **Lexicon resolution** (fetching unknown schemas). The reference doesn't
  either. Unknown is `"unknown"`.
- **Rewriting committed records.** A repo's history is signed. Existing
  floats, legacy blobs and plain-map `$link`s stay as they are; only new
  writes are held, and the round-trip guarantee (H1) covers records written
  after this part.
- **Slur filtering of record keys** (the reference's `hasExplicitSlur`): a
  moderation policy, not the data model. Recorded, not adopted.
- **Mounting the gate for Solid writes.** Part c. This part fixes the gate's
  shape and the wrapper's contract (H5).

## Design

### H1. JSON ⇄ the data model, both ways

`record_ipld` and `ipld_to_json` become the data model's own JSON mapping.
**On write**, at any depth:

| JSON | Result |
|---|---|
| an object whose keys are exactly `$link` | a link if the value is a string that parses as a CID; **refused** otherwise (number, bogus CID) |
| an object with `$link` and any other key | **refused** |
| an object whose keys are exactly `$bytes` | bytes if the value is a base64 string (RFC 4648 §4 alphabet, padding optional); **refused** otherwise |
| an object with `$bytes` and any other key | **refused** |
| a `$type` key whose value is not a non-empty string | **refused** — `null`, a number, `""`, at any depth |
| an integer within i64 | integer |
| a number with a zero fraction within i64 (`1.0`, `1e3`) | that integer — a JavaScript client's `JSON.parse` yields the same integer, so the reference accepts it |
| any other number (`1.5`, past i64) | **refused**: no floats |
| an object with `$type: "blob"` | a blob: `ref` must be a `$link` to a CIDv1 with codec raw (`0x55`) and sha-256; `mimeType` a non-empty string; `size` a non-negative integer; a missing field **refused** |
| an object with string `cid`, string `mimeType` and no `$type` (the legacy blob) | **refused** on write — the reference's own detection, which also catches an unknown lexicon's object that happens to use those names (the reference accepts that cost) |

A bare-string blob `ref` — today's "what brolly's own clients send" —
is no longer accepted: no client outside this repo's tests sends one, and
the data model has no such form.

**On read**, links emit `{"$link": "<CIDv1 base32>"}` and bytes emit
`{"$bytes": "<base64, no padding>"}`. A stored `Ipld::Float` from before
this part still emits a JSON number, so old records stay readable.

**The pod copy** (D7's faithful layer) is written from `ipld_to_json` of
what was committed — carried on `AppliedOp` as the committed record — not
from the request body (`ingest_written`, `xrpc.rs:1406`, takes it from
there). The pod and the repo never describe different JSON for one record.

### H2. The record envelope

In the gate, before anything else, in this order:

1. The record must be a JSON object → otherwise `InvalidRequest`
   (`record must be an object`). This replaces the panicking fill.
2. `$type` missing → filled with the collection. Present and not equal to
   the collection → `InvalidRequest`, `Invalid $type: expected
   {collection}, got {type}` — under any `validate`, as the reference does.
   **The six handler fills are deleted**; the gate is the only place.
3. H1's conversion.
4. Lexicon validation (H4), as `validate` directs (H5).

The 1 MB block cap stays where it is, in `apply` after encoding
(`repo.rs:557`). A record that is too large *and* breaks its lexicon is
refused by the lexicon first; the size tests move to an unknown collection
(Testing).

### H3. Vendored lexicons

- `vendor/lexicons/` holds lexicon JSON exactly as published:
  `com/atproto/**` from `bluesky-social/atproto` and `app/bsky/**` from
  `bluesky-social/bsky`, the canonical home of `app.bsky.*` per the atproto
  README. Any other file a vendored lexicon refers to by `ref` (a
  `chat.bsky.*` or `tools.ozone.*` def, should one exist) is vendored with
  it — the closure, not a hand-picked list.
- `vendor/lexicons/SOURCES.md` pins **two** commits, one per repo, beside
  both repos' MIT/Apache-2.0 notice. `tools/refresh-lexicons.sh <atproto-sha>
  <bsky-sha>` re-fetches both trees and their ref closure and rewrites
  `SOURCES.md`. A refresh is its own commit.
- **Embedding:** the `include_dir` crate (MIT) embeds the tree in
  the `brolly-atproto` crate — no build script to maintain. The registry
  parses it once, on first use (`LazyLock`), and the server forces that load
  at startup, so malformed vendored JSON stops the boot rather than the first
  write. A unit test loads every file and resolves every `ref` from every
  record lexicon, transitively; a dangling one fails CI.
- **Staleness is safe** by the lexicon evolution rules: new fields must be
  optional and unexpected fields are ignored, so a newer client's record
  validates against an older pin. A new variant in a *closed* union is the
  one break, and the rules forbid it without a new NSID.

### H4. The validator — a spike decides adopt or write (ADR 0002)

**The bar is a corpus, written first.** Chunk 1 writes
`spikes/lexicon-validation/corpus/`: for each item below, at least one
record that must pass and one that must fail, as JSON files named for the
rule, drawn from real `app.bsky.*` and `com.atproto.*` types. That corpus
is the acceptance test for whichever validator ships, and it moves into the
adapter's tests in chunk 3.

The lexicon language the corpus covers:

- **Types:** `null`, `boolean`, `integer`, `string`, `bytes`, `cid-link`,
  `blob`, `array`, `object`, `ref`, `union`, `unknown`, `token`, `record`.
- **Objects:** `required` present; `nullable` — `null` only where listed,
  and null and absent are distinct; unexpected fields **ignored**.
- **Strings:** `minLength`/`maxLength` in UTF-8 bytes;
  `minGraphemes`/`maxGraphemes` in extended grapheme clusters (UAX #29);
  `enum` (closed); `knownValues` (open — not checked); `const`; and every
  `format`: `at-identifier`, `at-uri`, `cid`, `datetime` (RFC 3339 ∩ ISO
  8601: uppercase `T`, a timezone with `Z` preferred and `-00:00` refused,
  seconds required, any number of fractional digits), `did`, `handle`,
  `nsid`, `tid`, `record-key`, `uri`, `language` (BCP 47 well-formed).
  Identifier formats accept the most expansive syntax.
- **Booleans:** `const`. **Integers:** `minimum`, `maximum`, `enum`,
  `const`. **Arrays:** `minLength`, `maxLength`, items. **Bytes:**
  `minLength`, `maxLength`.
- **Blobs:** `accept` (exact types, `type/*`, `*/*`; nothing else is a
  glob), `maxSize`.
- **Unions:** every member must carry `$type`, open or closed; `$type`
  `nsid` matches a ref to `nsid#main`; **open** unions accept an unknown
  `$type`, **closed** unions refuse one.
- **`unknown`:** must be an object, and not a blob.
- **Refs:** local (`#def`) and cross-document (`nsid#def`).
- **Records:** the rkey against the lexicon's `key` (`tid`, `nsid`,
  `literal:<value>`, `any`).

**The candidates:** `atproto-lexicon` (atproto-crates, MIT) and
`proto-blue-lexicon` (MIT/Apache-2.0). A candidate **passes** when it:

1. passes the whole corpus;
2. validates against **our** vendored JSON, not lexicons it bundles;
3. takes a `serde_json::Value` (or a conversion we already have), and
   reports a failure's path, so we can produce the reference's message
   shape ourselves;
4. passes `cargo deny check` on its full transitive tree, and pulls in no
   HTTP or DNS client — or lets us switch resolution off by feature flag.

The rkey `key`-type check may be ours whatever is adopted; it is twenty
lines. If both pass, the smaller transitive tree wins; then the more
recently maintained. If neither passes, we write the validator in
`adapters/atproto/src/lexicon/` on the vendored JSON, with
`unicode-segmentation` for graphemes. The spike's result, and the reason,
are written into this spec's Decisions before chunk 3 starts.

### H5. The gate

In `adapters/atproto/src/lexicon/` (or `record.rs`):

```rust
/// What the write asked for, as the lexicons define `validate`.
pub enum Validate { Required, Skip, Optimistic }   // true, false, absent

pub enum Status { Valid, Unknown }

/// Why a record is refused — a message in the reference's shape, e.g.
/// `Invalid app.bsky.feed.post record: record/text must not be longer than
/// 300 graphemes`.
pub struct Invalid(pub String);

/// H2 steps 1–4: envelope, conversion, lexicon. Returns the IPLD to commit
/// and the status. `rkey` is `None` for a create that has not minted one.
pub fn check_record(collection: &Nsid, rkey: Option<&RecordKey>,
                    record: &Value, validate: Validate)
    -> Result<(Ipld, Status), Invalid>;

/// The lexicon's `key` type against an rkey — run by `check_record` when the
/// rkey is known, and by `apply` right after it mints one.
pub fn check_key(collection: &Nsid, rkey: &RecordKey) -> Result<(), Invalid>;
```

- **`PlannedWrite::{create, put, update}` gain a `validate: Validate`
  argument**, call `check_record`, and store the returned `Ipld` and
  `Status`. A create with no rkey runs `check_key` in `apply` immediately
  after minting the TID, so `createRecord` into `app.bsky.actor.profile`
  with no rkey is refused (its key is `literal:self`) rather than committed
  under a TID.
- `Invalid` becomes `RepoError::InvalidRecord(String)`, which
  `write_refused` (`xrpc.rs:1335`) answers as `400 InvalidRequest` with the
  message verbatim.
- `Status` rides `AppliedOp` (beside the committed record H1 adds) to the
  handlers, which put it in the response.

**`validate: false` cannot skip a known lexicon.** The reference skips
validation entirely when asked. Here a known lexicon is the collection
container's shape (D9, ADR 0022), and no interface may write a member
resource the core's shape refuses:

| `validate` | Known lexicon | Unknown lexicon |
|---|---|---|
| absent | validated → `"valid"` | accepted → `"unknown"` |
| `true` | validated → `"valid"` | refused: `Unknown lexicon type: {type}` |
| `false` | **validated** → `"valid"` | accepted → `"unknown"` |

H1 and H2 apply whatever `validate` says, as the data model requires.

**The wrapper part c will write.** ADR 0022's core never learns what a
lexicon is, so part c defines a protocol-neutral container hook, shaped
roughly `(container, resource name, &Value) → Result<Value, Refusal>`,
returning the normalised record. The ATProto adapter implements it by
calling `check_record` with `Validate::Optimistic` and returning
`ipld_to_json` of the IPLD. Nothing in this part's interface needs to change
for that, and nothing ATProto-typed crosses into the core.

### H6. The wire

- `createRecord`, `putRecord`, `applyWrites` **and brolly's two strict
  routes, `swapRecord` and `swapCommit`** (`xrpc.rs:1681`, `1771`) read
  `validate` and answer `validationStatus`.
- `applyWrites` results become the lexicon's union:
  `{"$type": "com.atproto.repo.applyWrites#createResult", uri, cid,
  validationStatus}`, `#updateResult` likewise, and
  `{"$type": "com.atproto.repo.applyWrites#deleteResult"}` with no other
  fields.
- A refusal is `400 InvalidRequest` with the gate's message. In a batch, the
  first invalid op refuses the whole batch and commits nothing, as today.

## Testing

- **Data model (H1):** the atproto-interop-tests data-model vectors, valid
  and invalid, as unit tests. Plus: `$link`/`$bytes` round-trip at depth;
  `1.0` and `1e3` land as integers; `1.5` and an integer past i64 are
  refused; a legacy blob is refused; a blob with a dag-cbor `ref`, or
  missing any field, is refused; a bare-string `ref` is refused.
- **Round trip:** an avatar-bearing profile written in data-model form, read
  with `getRecord`, written back with `putRecord`: the record CID is
  unchanged, and the new commit's MST root equals the old one.
- **Envelope (H2):** a string, number, array and `null` record → 400, never
  a panic; missing `$type` filled; mismatched refused under every
  `validate`.
- **Lexicons (H4):** the corpus, in full. Every vendored file loads; every
  ref from a record lexicon resolves.
- **Keys (H5):** `createRecord` into `app.bsky.actor.profile` with no rkey
  is refused; with `self` it lands; a `tid`-keyed collection refuses a
  non-TID rkey.
- **`validate` (H5):** the table, cell by cell, on `createRecord` and
  `applyWrites`.
- **Wire (H6):** `validationStatus` on all five verbs; `applyWrites`
  results carry `$type` and a delete's is otherwise empty; an invalid op
  refuses its batch.
- **Pod copy:** the faithful copy equals `getRecord`'s value, not the
  request body.

**Existing tests this part changes, by name, so chunk 2–4 commits carry
them rather than discover them:**

- About 150 post fixtures across `server/tests/xrpc.rs`,
  `adapters/atproto/src/repo.rs` (the `a_put` helper, `repo.rs:1289`),
  `adapters/atproto/tests/firehose.rs`, `car_export.rs` and the three
  migration tests write `app.bsky.feed.post` without `createdAt`. They move
  to one helper per crate that builds a **valid** post, and tests that are
  not about posts use `com.example.*` (unknown, so unvalidated).
- Posts written under rkeys that are not TIDs (`app.bsky.feed.post` is
  `key: tid`) fail H5's key check in the constructor: the generated rkeys
  in `a_long_historys_commits_each_invert`
  (`adapters/atproto/tests/firehose.rs:1044`, `1064`), the batch-cap test
  (`adapters/atproto/src/repo.rs:2108`), and `server/tests/xrpc.rs:1045`,
  `2812`, `2895`, `3297`. They take a TID helper (`Tid::now` or a
  deterministic sequence of valid TIDs), or move to `com.example.*` where
  the test is not about posts.
- The size tests — `a_record_over_a_megabyte_is_refused` (`repo.rs:2052`),
  `a_commit_whose_diff_would_exceed_two_megabytes_is_refused`
  (`repo.rs:2075`), and `server/tests/xrpc.rs:1082-1089` — move their
  oversized text to `com.example.big`, so they still test the size cap and
  not `maxGraphemes`.
- The blob-ref tests that send or expect a bare string —
  `a_blob_ref_lands_as_a_cid_link_and_round_trips` (`repo.rs:2118`),
  `a_blob_ref_in_atriums_link_form_round_trips_too` (`repo.rs:2195`),
  `a_blob_ref_round_trips_through_the_handler`
  (`server/tests/xrpc.rs:1180`), and `a_blob_link_rides_the_diff_and_inverts`
  (`adapters/atproto/tests/firehose.rs:956`, which sends one at `:971`) —
  send and assert `{"$link": …}`.

## Rollout

- No migration, no configuration.
- **Where brolly is stricter than the reference, on purpose:** a known
  lexicon is validated even under `validate: false` (H5). A non-integral
  number is refused because the data model forbids floats; whether the
  reference's encoder refuses one too is **not verified** — `prepare.ts`
  has no float check of its own — so this is listed as a possible
  divergence. The reference verifiably makes H2's `$type` mismatch, the
  legacy-blob and H4's lexicon refusals too (`prepare.ts`).
- **H1's strictness is also beyond the reference's (the spike checked it):**
  the reference PDS converts request bodies with `jsonToLex` in its default
  non-strict mode (`packages/xrpc-server/src/util.ts`), which keeps a
  malformed `$link` or `$bytes` object, a nested `$type` that is not a
  non-empty string, and a blob with a bare-string `ref` as plain maps
  rather than refusing them. brolly refuses all of them, as the
  atproto-interop-tests invalid vectors and the reference's own strict mode
  do — one model, held to the data model (ADR 0022). The line-cited table is
  in `spikes/lexicon-validation/RESULT.md`.
- `getRecord`, `listRecords` and the pod's faithful copy now say `$link` and
  `$bytes` for records with links or bytes. No front-end in this repo reads
  `ref`; any brolly front-end in another repo that does should read
  `ref.$link`, as every ATProto client already does.

## Chunks

1. **The spike (H4).** The corpus first, then both candidates against it
   and the four-point bar, in `spikes/lexicon-validation/`. The result goes
   into Decisions. *First because it decides chunk 3's size.*
2. **The data model and the envelope (H1, H2).** Conversion both ways, the
   envelope in one place (the six fills deleted), the committed record on
   `AppliedOp` and the pod copy from it, the interop vectors, and the
   blob-ref test updates. *Independent of the validator, and it fixes the
   bsky.app round trip on its own.*
3. **Vendored lexicons and the validator (H3, H4).** The tree, the refresh
   tool, the embedded registry and its startup load, the validator, the
   corpus as the adapter's tests.
4. **The gate and the wire (H5, H6).** `check_record`/`check_key`,
   `PlannedWrite` through them with `validate`, `RepoError::InvalidRecord`,
   `validationStatus` on all five verbs, the `applyWrites` union, and the
   fixture moves (valid-post helpers, `com.example.*`).

## Decisions

| # | Decision | Why |
|---|---|---|
| A | `$link`/`$bytes` anywhere, strictly formed, emitted on read; non-integral numbers and integers past i64 refused, integral ones (`1.0`) accepted as integers; legacy blobs and bare-string refs refused on write | The data model's own JSON mapping, held to its interop vectors; integral numbers are integers to every JSON client, including the reference's |
| B | `$type` must equal the collection, under any `validate`; missing → filled; filled in the gate only | The reference's rule; one place, so every surface gets the same fill |
| C | Lexicons vendored and pinned per source repo (`com.atproto.*` from atproto, `app.bsky.*` from bsky, plus their ref closure), embedded with `include_dir`, parsed once and forced at startup | Deterministic validation with no runtime fetch; a bad pin stops the boot, not a write; the evolution rules make a stale pin safe |
| D | The validator is **written**, in `adapters/atproto/src/lexicon/` on the vendored lexicons (spike, 2026-11-26). Neither candidate passed: `atproto-lexicon` 0.14.5 24/107 (no `null` type; 99/107 with it stripped — unpadded `$bytes`, `*/*`, `unknown`, `-00:00` and untyped union members wrong; an HTTP/DNS stack no feature removes; 17 unfixable advisories), `proto-blue-lexicon` 0.3.3 24/107 (no `null` type; 103/107 with it stripped — `unknown` and `*/*` wrong) | ADR 0002's preference, held to an explicit bar rather than a crate's own claims. `proto-blue-lexicon` is the one to re-check if it gains `null`, `unknown` and `*/*` upstream; adopting it now would mean carrying a fork |
| E | `validate: false` cannot skip a known lexicon | The known lexicon is the container's shape; an interface that could skip it would let XRPC write what a Solid write may not (ADR 0022). A deliberate deviation from the reference |
| F | One gate returns the IPLD it validated; the key check reruns after minting; part c wraps it, it does not register it | One conversion and one validation, so the committed block and the checked record cannot drift; ATProto types stay in the adapter |
| G | `applyWrites` results carry their union `$type` | The lexicon's shape; a client reading `validationStatus` needs to know which result it holds |
