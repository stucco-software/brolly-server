# Spike result: the lexicon validator (stage 4a, H4)

**Decision: write our own** validator in `adapters/atproto/src/lexicon/`, on
the vendored lexicons, with `unicode-segmentation` for graphemes. Neither
candidate passes the bar. `proto-blue-lexicon` came closest and is the one to
re-check if it gains the missing pieces upstream.

The corpus moved to the adapter's tests in stage 4a chunk 3; the spike reads it from there.

Measured 2026-11-26 against the corpus (`adapters/atproto/tests/fixtures/lexicon-corpus/cases.json`, 107 cases: 47
valid, 59 invalid, 1 unknown) and the vendored lexicons (`vendor/lexicons/`,
274 files, pinned in `vendor/lexicons/SOURCES.md`).

## Candidates

| | `atproto-lexicon` 0.14.5 (MIT) | `proto-blue-lexicon` 0.3.3 (MIT/Apache-2.0) |
|---|---|---|
| Corpus, as written | **24 / 107** — refuses to load `com.example.corpus.thing` (no `null` type), so 83 of its 84 cases read as unknown | **24 / 107** — the same: no `null` type |
| Corpus, `null` properties stripped in memory (diagnostic only) | 99 / 107 | 103 / 107 |
| Rules it gets wrong (diagnostic run) | unpadded `$bytes` rejected (`bytes-ok`, `bytes-min-ok`; `bytes-max`/`bytes-min-short` "pass" only because every unpadded value fails); `*/*` accept unsupported (`accept-any`); `unknown` not checked (`unknown-not-object`, `unknown-blob-shaped`); `-00:00` accepted (`datetime-minus-zero`); a union member with no `$type` accepted (`union-no-type`) | `unknown` not checked (`unknown-not-object`, `unknown-blob-shaped`); `*/*` accept unsupported (`accept-any`); `null` unsupported (`null-not-null`, and the parse failure above) |
| Takes our documents (bar 2) | yes — `SchemaFile::from_value` into a `BaseCatalog` | yes — `LexiconDoc` into `Lexicons` |
| Path in messages (bar 3) | partly — structural errors yes (`at /reply/root`), string-format errors no | yes, on every failure (`record/reply/root/cid: Required field missing: cid`) |
| HTTP/DNS client (bar 4) | yes — `reqwest` (non-optional), `hyper`, `hickory-resolver`; no feature removes them | none by default (`reqwest` behind `proto-blue-common`'s off-by-default `fetch-reqwest`) |
| `cargo deny check` (bar 4) | fails — 17 advisories on `hickory-proto`/`hickory-resolver` 0.25.2 (12 with no fixed version), chrono unmaintained | fails — chrono unmaintained (RUSTSEC-2026-0543) only; chrono is already in the server's own tree |
| Transitive crates | 227 | 102 |
| **Passes the bar** | **no** — points 1, 3, 4 | **no** — point 1 |

`proto-blue-lexicon`'s gaps are the `null` type (a schema-parse failure, so not
wrappable without a fork), the `unknown` checks, and `*/*`. Adopting it would
mean carrying a fork; writing our own costs more up front but holds every
rule in our own tests. The corpus becomes the validator's acceptance test
either way, and each rule a candidate got wrong above is a named case in it.

## Reference conversion (Task 1.6)

The reference PDS converts XRPC request bodies with `jsonToLex` from
`@atproto/lex-json` in its default, **non-strict** mode
(`packages/xrpc-server/src/util.ts:11,347` at atproto `665c90c8`;
`lex-json.ts:160-183`, `parseSpecialJsonObject` at `:323-359`). Strict mode
(`{strict: true}`) throws on each row below; non-strict returns `undefined`
from the special-object parser and the object falls through to an ordinary
map (`jsonObjectToLexMap`).

| Input | Reference (non-strict, as the PDS runs it) | brolly (stage 4a H1) |
|---|---|---|
| `{"$link": 1234}` | plain map (`link.ts:30`: non-string → `undefined`) | refused |
| `{"$link": "."}` | plain map (`link.ts:42-46`: `parseCid` throws, caught → `undefined`) | refused |
| `{"$link": "<cid>", "other": 1}` | plain map (`link.ts:22-26`: extra key → `undefined`) | refused |
| `{"$bytes": [1]}` | plain map (`bytes.ts`: non-string → `undefined`) | refused |
| `{"$bytes": "<b64>", "other": 1}` | plain map (`bytes.ts`: extra key → `undefined`) | refused |
| nested `{"$type": ""}` | kept as is (the `$type` checks run only `if (options.strict)`, `lex-json.ts:344-353`) | refused |
| blob with a bare-string `ref` | plain map (blobs are parsed only in strict mode, `:340-349`); a *known* lexicon's `blob` field then fails lexicon validation, an unknown lexicon's record stores the map | refused |

A non-integer number also passes the reference's JSON conversion in
non-strict mode (`lex-json.ts:174-176`); whether its CBOR encoder then
refuses the float was not traced.

**Reading:** on every row brolly is stricter than the reference PDS, and in
line with the atproto-interop-tests invalid vectors and the reference's own
strict mode. These are deliberate divergences under ADR 0022 (one model, held
to the data model) and are listed in the spec's Rollout.

## Also found

`cargo deny check advisories` fails on the **server workspace today**,
independent of this spike: chrono and `astral-tokio-tar` unmaintained, and
several new advisories in the HTTP stack. Not this stage's work; recorded so
it is not mistaken for a spike side effect.

## Running it

```
cd spikes/lexicon-validation
cargo run -- atproto-lexicon          # the measurement
cargo run -- proto-blue-lexicon
cargo run -- proto-blue-lexicon:diag-no-null   # diagnostic: null properties stripped
```
