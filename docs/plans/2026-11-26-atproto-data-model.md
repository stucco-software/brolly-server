# Stage 4a — The Data Model, Held: Implementation Plan (chunks 1–2)

<!-- doc-paths: skip -->
<!-- The plan names files it creates (the data-model module, the spike, the
     vendored trees), so not every path it cites resolves until it lands. -->

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decide the lexicon validator by evidence (chunk 1), and hold every record to the ATProto data model's JSON mapping in both directions, through one envelope, with the pod copy taken from what was committed (chunk 2).

**Architecture:** A new `adapters/atproto/src/data_model.rs` owns JSON ⇄ IPLD (`$link`, `$bytes`, blobs, no floats, `$type` well-formed at any depth). A new `adapters/atproto/src/record.rs` owns the record envelope (object check, `$type` fill or refusal) and is the only thing `PlannedWrite`'s constructors call; it is the seed of chunk 4's `check_record`. `AppliedOp` carries the committed record so the pod copy is written from it. The spike lives outside the workspace and never touches the server's build.

**Tech Stack:** Rust 2024, `serde_json`, `ipld-core` 0.4 (`Ipld`, `cid::Cid`), `serde_ipld_dagcbor` 0.6, `base64` 0.23, axum 0.8. Tests: `cargo test`, which provisions Postgres via testcontainers.

**Spec:** `docs/specs/2026-11-26-atproto-data-model-and-lexicons.md` — read it first; H-numbers and Decisions below refer to it. ADR 0022 is the principle behind it.

**Scope of this plan:** chunks 1 and 2 of the spec. Chunks 3 (vendored lexicons and the validator) and 4 (the gate and the wire) are planned *after* chunk 1 records its result, because the spike decides whether chunk 3 adopts a crate or writes a validator. One deliberate reordering from the spec: the vendored lexicon tree and its refresh tool (H3) land in chunk 1, because the spike must validate against *our* vendored JSON (H4's bar, point 2). It is data only and changes no build.

**House rules that bite here:**
- Library crates deny `unwrap`/`expect`/`panic`/`println!` (workspace clippy lints). Integration test files carry `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` at the top; a library crate's in-file `mod tests` is covered by the crate-level `#![cfg_attr(test, allow(…))]` in its `lib.rs` (`adapters/atproto/src/lib.rs:7`) — do not add a second attribute.
- Trunk-based: commit straight to `main`, **push after every commit** (`git push`), every commit green and deployable. No branches, no PRs.
- Pre-commit (lefthook) runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `./tools/check-doc-paths.sh`. Run them yourself before `git commit`.
- **Database tests need OrbStack's socket.** Prefix every `cargo test` that touches Postgres with `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock`. Run the full suite with `--no-fail-fast`. Two known flakes, not regressions: `connect to test postgres: PoolTimedOut` in a random test, and `store/tests/blobs.rs::blob_bytes_count_towards_the_pod_quota`. Re-run the single test to confirm before treating either as real.
- Gate shell chains on cargo's own exit status: `cargo test … > /tmp/x.log 2>&1; echo exit=$?`, never `cargo test … | grep …` as a pass/fail signal.
- Stage only the files each task names. Never `git add -A` / `git add .`.
- Commit messages: a conventional prefix, a body that says why, and the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

---

## Chunk 1: The spike (H3's tree, H4's bar)

Outcome: `vendor/lexicons/` pinned and committed; `spikes/lexicon-validation/` holds the corpus and a harness that runs each candidate against it; the spec's Decision D records which validator chunk 3 uses, and why.

### Task 1.1: Vendor the lexicons and the refresh tool

**Files:**
- Create: `tools/refresh-lexicons.sh`
- Create: `vendor/lexicons/SOURCES.md` (written by the script)
- Create: `vendor/lexicons/com/atproto/**`, `vendor/lexicons/app/bsky/**` (fetched by the script)

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Re-vendor the ATProto lexicons at two pinned commits (stage 4a, H3).
#
#   tools/refresh-lexicons.sh <atproto-sha> <bsky-sha>
#
# com/atproto/** comes from bluesky-social/atproto; app/bsky/** from
# bluesky-social/bsky, where app.bsky.* is maintained. Anything a vendored
# lexicon names by `ref` outside those two trees (chat.bsky.*, tools.ozone.*)
# is fetched too, until the closure is complete. A refresh is its own commit.
set -euo pipefail

atproto_sha="${1:?usage: refresh-lexicons.sh <atproto-sha> <bsky-sha>}"
bsky_sha="${2:?usage: refresh-lexicons.sh <atproto-sha> <bsky-sha>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/vendor/lexicons"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# GNU tar needs --wildcards to match a pattern; bsdtar (macOS) refuses the flag
# and matches patterns anyway.
wild=""; tar --version 2>/dev/null | grep -q GNU && wild="--wildcards"

fetch_tree() { # repo sha subdir
  curl -fsSL "https://codeload.github.com/bluesky-social/$1/tar.gz/$2" \
    | tar -xz -C "$work" --strip-components=1 $wild "*/lexicons/$3/*" "*/LICENSE-MIT.txt"
  cp "$work/LICENSE-MIT.txt" "$out/LICENSE-MIT-$1.txt"
}

rm -rf "$out"
mkdir -p "$out"
fetch_tree atproto "$atproto_sha" com/atproto
mkdir -p "$out/com" && cp -R "$work/lexicons/com/atproto" "$out/com/"
rm -rf "$work/lexicons"
fetch_tree bsky "$bsky_sha" app/bsky
mkdir -p "$out/app" && cp -R "$work/lexicons/app/bsky" "$out/app/"

# The ref closure: any `ref`/`refs` NSID outside the vendored trees.
while :; do
  missing="$(python3 - "$out" <<'PY'
import json, os, sys
root = sys.argv[1]
have = set()
for d, _, fs in os.walk(root):
    for f in fs:
        if f.endswith(".json"):
            have.add(json.load(open(os.path.join(d, f)))["id"])
want = set()
def walk(v):
    if isinstance(v, dict):
        for k, x in v.items():
            if k == "ref" and isinstance(x, str) and not x.startswith("#"):
                want.add(x.split("#")[0])
            elif k == "refs" and isinstance(x, list):
                want.update(r.split("#")[0] for r in x if not r.startswith("#"))
            else:
                walk(x)
    elif isinstance(v, list):
        for x in v: walk(x)
for d, _, fs in os.walk(root):
    for f in fs:
        if f.endswith(".json"):
            walk(json.load(open(os.path.join(d, f))))
print("\n".join(sorted(want - have)))
PY
)"
  [ -z "$missing" ] && break
  for nsid in $missing; do
    path="lexicons/$(echo "$nsid" | tr . /).json"
    case "$nsid" in
      com.atproto.*|tools.ozone.*) repo=atproto sha="$atproto_sha" ;;
      *) repo=bsky sha="$bsky_sha" ;;
    esac
    mkdir -p "$out/$(dirname "${path#lexicons/}")"
    curl -fsSL "https://raw.githubusercontent.com/bluesky-social/$repo/$sha/$path" \
      -o "$out/${path#lexicons/}"
  done
done

cat > "$out/SOURCES.md" <<EOF
# Vendored lexicons

Fetched by \`tools/refresh-lexicons.sh\` — do not edit by hand.

| Tree | Source | Commit |
|---|---|---|
| \`com/atproto/**\` (and \`tools/ozone/**\` if present) | https://github.com/bluesky-social/atproto | \`$atproto_sha\` |
| \`app/bsky/**\` (and \`chat/bsky/**\` if present) | https://github.com/bluesky-social/bsky | \`$bsky_sha\` |

Both repositories are dual-licensed MIT / Apache-2.0
(Copyright (c) 2022-2026 Bluesky Social PBC, and Contributors); their MIT
notices are beside this file as \`LICENSE-MIT-atproto.txt\` and
\`LICENSE-MIT-bsky.txt\`.
EOF
echo "vendored $(find "$out" -name '*.json' | wc -l | tr -d ' ') lexicons"
```

- [ ] **Step 2: Run it at today's pins**

```bash
chmod +x tools/refresh-lexicons.sh
tools/refresh-lexicons.sh 665c90c82545af323d9334a480074b31eb5d51d7 d92c6fe74100d33b5250f076b767e6bb8cea9026
```
Expected: `vendored 274 lexicons` (the closure is already complete at these pins — no `chat/` or `tools/` files); `vendor/lexicons/app/bsky/feed/post.json`, `vendor/lexicons/com/atproto/repo/strongRef.json` and both `LICENSE-MIT-*.txt` exist; `SOURCES.md` names both SHAs.

- [ ] **Step 3: Sanity-check the closure**

```bash
python3 -c "import json,glob; [json.load(open(f)) for f in glob.glob('vendor/lexicons/**/*.json', recursive=True)]; print('all parse')"
```
Expected: `all parse`.

- [ ] **Step 4: Commit**

```bash
git add tools/refresh-lexicons.sh vendor/lexicons
git commit -m "vendor: ATProto lexicons, pinned per source repo (stage 4a, H3)" -m "com.atproto.* from bluesky-social/atproto and app.bsky.* from bluesky-social/bsky (where it is maintained now), plus their ref closure, pinned in SOURCES.md. Data only: nothing builds from it until the validator lands. Vendored in chunk 1 rather than 3 because the spike validates against our copy, not a crate's bundled one.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

### Task 1.2: The corpus

**Files:**
- Create: `spikes/lexicon-validation/corpus/lexicons/com/example/corpus/thing.json`
- Create: `spikes/lexicon-validation/corpus/lexicons/com/example/corpus/selfkey.json`
- Create: `spikes/lexicon-validation/corpus/lexicons/com/example/corpus/tidkey.json`
- Create: `spikes/lexicon-validation/corpus/lexicons/com/example/corpus/nsidkey.json`
- Create: `spikes/lexicon-validation/corpus/lexicons/com/example/corpus/nullable.json`
- Create: `spikes/lexicon-validation/corpus/cases.json`

Real lexicons exercise few constraints (no record lexicon uses `enum`, `const` or a closed union), so five synthetic lexicons under `com.example.corpus.*` cover the language, and real `app.bsky.*` cases keep it honest.

- [ ] **Step 1: The synthetic lexicons**

`thing.json`:
```json
{
  "lexicon": 1,
  "id": "com.example.corpus.thing",
  "defs": {
    "main": {
      "type": "record",
      "key": "any",
      "record": {
        "type": "object",
        "required": ["str"],
        "nullable": ["maybe"],
        "properties": {
          "str": {"type": "string", "minLength": 2, "maxLength": 10, "maxGraphemes": 3},
          "choice": {"type": "string", "enum": ["a", "b"]},
          "fixed": {"type": "string", "const": "x"},
          "known": {"type": "string", "knownValues": ["k1"]},
          "count": {"type": "integer", "minimum": 1, "maximum": 5},
          "flag": {"type": "boolean", "const": true},
          "items": {"type": "array", "minLength": 1, "maxLength": 2, "items": {"type": "integer"}},
          "raw": {"type": "bytes", "maxLength": 4},
          "link": {"type": "cid-link"},
          "maybe": {"type": "string"},
          "anything": {"type": "unknown"},
          "pic": {"type": "blob", "accept": ["image/*"], "maxSize": 100},
          "when": {"type": "string", "format": "datetime"},
          "who": {"type": "string", "format": "did"},
          "lang": {"type": "string", "format": "language"},
          "open": {"type": "union", "refs": ["#a", "#b"]},
          "shut": {"type": "union", "refs": ["#a", "#b"], "closed": true},
          "local": {"type": "ref", "ref": "#a"},
          "remote": {"type": "ref", "ref": "com.atproto.repo.strongRef"},
          "nothing": {"type": "null"},
          "short": {"type": "string", "minGraphemes": 2},
          "ichoice": {"type": "integer", "enum": [1, 2]},
          "ifixed": {"type": "integer", "const": 7},
          "rawmin": {"type": "bytes", "minLength": 2},
          "tokened": {"type": "string", "knownValues": ["com.example.corpus.thing#tok"]},
          "atid": {"type": "string", "format": "at-identifier"},
          "hdl": {"type": "string", "format": "handle"},
          "ns": {"type": "string", "format": "nsid"},
          "t": {"type": "string", "format": "tid"},
          "rk": {"type": "string", "format": "record-key"},
          "u": {"type": "string", "format": "uri"},
          "au": {"type": "string", "format": "at-uri"},
          "c": {"type": "string", "format": "cid"},
          "anyfile": {"type": "blob", "accept": ["*/*"]},
          "globbed": {"type": "blob", "accept": ["image/pn*"]}
        }
      }
    },
    "a": {"type": "object", "required": ["n"], "properties": {"n": {"type": "integer"}}},
    "b": {"type": "object", "properties": {"s": {"type": "string"}}},
    "tok": {"type": "token", "description": "A token: only ever a value, so it has no failing case."}
  }
}
```

`nullable.json` — required **and** nullable, so null and absent are distinct:
```json
{
  "lexicon": 1,
  "id": "com.example.corpus.nullable",
  "defs": {"main": {"type": "record", "key": "any",
    "record": {"type": "object", "required": ["v"], "nullable": ["v"],
      "properties": {"v": {"type": "string"}}}}}
}
```

`selfkey.json`, `tidkey.json`, `nsidkey.json` — each the same minimal shape, with `key` `literal:self`, `tid` and `nsid` respectively:
```json
{
  "lexicon": 1,
  "id": "com.example.corpus.selfkey",
  "defs": {"main": {"type": "record", "key": "literal:self",
    "record": {"type": "object", "properties": {"s": {"type": "string"}}}}}
}
```
(Change `id` and `key` for the other two.)

- [ ] **Step 2: The cases**

`cases.json` is an array of `{"name", "collection", "rkey", "record", "expect"}`, where `expect` is `"valid"`, `"invalid"` or `"unknown"` (an unknown lexicon, accepted unvalidated). `T` below abbreviates `"$type": "com.example.corpus.thing"`; write it out in full in the file. Every `thing` case uses rkey `"r"` and collection `com.example.corpus.thing`.

| name | record (besides `T`) | expect |
|---|---|---|
| minimal | `"str": "abc"` | valid |
| required-missing | (nothing) | invalid |
| minLength | `"str": "a"` | invalid |
| maxLength-bytes | `"str": "😀😀😀"` (3 graphemes, 12 bytes) | invalid |
| maxGraphemes | `"str": "abcd"` | invalid |
| graphemes-combining | `"str": "e\u0301e\u0301e\u0301"` — write these **escapes** into `cases.json`, never pasted accented letters (a pasted é is precomposed and 2 bytes): 3 graphemes, 9 bytes | valid |
| enum-in | `"str": "abc", "choice": "a"` | valid |
| enum-out | `"str": "abc", "choice": "c"` | invalid |
| const-right | `"str": "abc", "fixed": "x"` | valid |
| const-wrong | `"str": "abc", "fixed": "y"` | invalid |
| knownValues-open | `"str": "abc", "known": "other"` | valid |
| integer-min | `"str": "abc", "count": 0` | invalid |
| integer-max | `"str": "abc", "count": 6` | invalid |
| integer-ok | `"str": "abc", "count": 3` | valid |
| boolean-const-right | `"str": "abc", "flag": true` | valid |
| boolean-const | `"str": "abc", "flag": false` | invalid |
| array-min | `"str": "abc", "items": []` | invalid |
| array-max | `"str": "abc", "items": [1, 2, 3]` | invalid |
| array-item-type | `"str": "abc", "items": ["x"]` | invalid |
| bytes-max | `"str": "abc", "raw": {"$bytes": "AQIDBAU"}` (5 bytes) | invalid |
| bytes-ok | `"str": "abc", "raw": {"$bytes": "AQIDBA"}` (4 bytes) | valid |
| cid-link-ok | `"str": "abc", "link": {"$link": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"}` | valid |
| cid-link-string | `"str": "abc", "link": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"` | invalid |
| nullable-null | `"str": "abc", "maybe": null` | valid |
| not-nullable-null | `"str": "abc", "known": null` | invalid |
| unknown-object | `"str": "abc", "anything": {"x": 1}` | valid |
| unknown-not-object | `"str": "abc", "anything": "x"` | invalid |
| unknown-blob-shaped | `"str": "abc", "anything": {"$type": "blob", "ref": {"$link": "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"}, "mimeType": "image/png", "size": 1}` | invalid |
| blob-ok | `"str": "abc", "pic": {"$type": "blob", "ref": {"$link": "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"}, "mimeType": "image/png", "size": 50}` | valid |
| blob-too-big | as blob-ok with `"size": 101` | invalid |
| blob-wrong-type | as blob-ok with `"mimeType": "text/plain"` | invalid |
| datetime-ok | `"str": "abc", "when": "2026-11-26T12:00:00Z"` | valid |
| datetime-fraction | `"str": "abc", "when": "2026-11-26T12:00:00.123456Z"` | valid |
| datetime-lower-t | `"str": "abc", "when": "2026-11-26t12:00:00Z"` | invalid |
| datetime-minus-zero | `"str": "abc", "when": "2026-11-26T12:00:00-00:00"` | invalid |
| datetime-no-seconds | `"str": "abc", "when": "2026-11-26T12:00Z"` | invalid |
| datetime-no-zone | `"str": "abc", "when": "2026-11-26T12:00:00"` | invalid |
| did-ok | `"str": "abc", "who": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"` | valid |
| did-unknown-method | `"str": "abc", "who": "did:example:xyz"` | valid |
| did-bad | `"str": "abc", "who": "notadid"` | invalid |
| language-ok | `"str": "abc", "lang": "en-US"` | valid |
| language-bad | `"str": "abc", "lang": "not a tag!"` | invalid |
| open-union-known | `"str": "abc", "open": {"$type": "com.example.corpus.thing#a", "n": 1}` | valid |
| open-union-unknown | `"str": "abc", "open": {"$type": "com.example.other#x"}` | valid |
| union-no-type | `"str": "abc", "open": {"n": 1}` | invalid |
| union-member-invalid | `"str": "abc", "open": {"$type": "com.example.corpus.thing#a"}` | invalid |
| closed-union-unknown | `"str": "abc", "shut": {"$type": "com.example.other#x"}` | invalid |
| closed-union-known | `"str": "abc", "shut": {"$type": "com.example.corpus.thing#b", "s": "y"}` | valid |
| ref-local | `"str": "abc", "local": {"n": 1}` | valid |
| ref-local-invalid | `"str": "abc", "local": {"n": "x"}` | invalid |
| ref-remote | `"str": "abc", "remote": {"uri": "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kaaaaaaaaaab", "cid": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"}` | valid |
| ref-remote-missing | `"str": "abc", "remote": {"uri": "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kaaaaaaaaaab"}` | invalid |
| extra-field-ignored | `"str": "abc", "zzz": 1` | valid |
| null-ok | `"str": "abc", "nothing": null` | valid |
| null-not-null | `"str": "abc", "nothing": 0` | invalid |
| minGraphemes-ok | `"str": "abc", "short": "ab"` | valid |
| minGraphemes-short | `"str": "abc", "short": "a"` | invalid |
| int-enum-in | `"str": "abc", "ichoice": 2` | valid |
| int-enum-out | `"str": "abc", "ichoice": 3` | invalid |
| int-const-right | `"str": "abc", "ifixed": 7` | valid |
| int-const-wrong | `"str": "abc", "ifixed": 8` | invalid |
| bytes-min-ok | `"str": "abc", "rawmin": {"$bytes": "AQI"}` (2 bytes) | valid |
| bytes-min-short | `"str": "abc", "rawmin": {"$bytes": "AQ"}` (1 byte) | invalid |
| token-value | `"str": "abc", "tokened": "com.example.corpus.thing#tok"` | valid |
| at-identifier-handle | `"str": "abc", "atid": "alice.example.com"` | valid |
| at-identifier-did | `"str": "abc", "atid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"` | valid |
| at-identifier-bad | `"str": "abc", "atid": "not an identifier"` | invalid |
| handle-ok | `"str": "abc", "hdl": "alice.example.com"` | valid |
| handle-bad | `"str": "abc", "hdl": "alice"` | invalid |
| nsid-ok | `"str": "abc", "ns": "com.example.thing"` | valid |
| nsid-bad | `"str": "abc", "ns": "com.example"` | invalid |
| tid-ok | `"str": "abc", "t": "3kaaaaaaaaaab"` | valid |
| tid-bad | `"str": "abc", "t": "3kaaaaaaaaaa0"` | invalid |
| record-key-ok | `"str": "abc", "rk": "self"` | valid |
| record-key-bad | `"str": "abc", "rk": ".."` | invalid |
| uri-ok | `"str": "abc", "u": "https://example.com/x"` | valid |
| uri-bad | `"str": "abc", "u": "not a uri"` | invalid |
| at-uri-ok | `"str": "abc", "au": "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kaaaaaaaaaab"` | valid |
| at-uri-bad | `"str": "abc", "au": "https://example.com"` | invalid |
| cid-ok | `"str": "abc", "c": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"` | valid |
| cid-bad | `"str": "abc", "c": "not-a-cid"` | invalid |
| accept-any | `"str": "abc", "anyfile": <blob-ok's blob with "mimeType": "application/zip">` | valid |
| accept-partial-glob | `"str": "abc", "globbed": <blob-ok's blob, "mimeType": "image/png">` — a partial glob is not a glob | invalid |

Key cases (record `{"$type": <collection>}`):

| name | collection | rkey | expect |
|---|---|---|---|
| key-self-ok | `com.example.corpus.selfkey` | `self` | valid |
| key-self-other | `com.example.corpus.selfkey` | `other` | invalid |
| key-tid-ok | `com.example.corpus.tidkey` | `3kaaaaaaaaaab` | valid |
| key-tid-bad | `com.example.corpus.tidkey` | `nottid` | invalid |
| key-nsid-ok | `com.example.corpus.nsidkey` | `com.example.thing` | valid |
| key-nsid-bad | `com.example.corpus.nsidkey` | `nope` | invalid |

Nullable-and-required cases (collection `com.example.corpus.nullable`, rkey `r`):

| name | record | expect |
|---|---|---|
| required-nullable-null | `{"$type": "com.example.corpus.nullable", "v": null}` | valid |
| required-nullable-absent | `{"$type": "com.example.corpus.nullable"}` | invalid |

Real lexicons (rkey `3kaaaaaaaaaab` unless noted; `D` = `"2026-11-26T12:00:00Z"`). Every invalid case is **one change from a valid record**, so a validator can only get it right by checking the one rule it names — "post-ok's record plus X" means exactly that:

| name | collection | record | expect |
|---|---|---|---|
| post-ok | `app.bsky.feed.post` | `{"$type": "app.bsky.feed.post", "text": "hi", "createdAt": D}` | valid |
| post-no-createdAt | `app.bsky.feed.post` | `{"$type": "app.bsky.feed.post", "text": "hi"}` | invalid |
| post-301-graphemes | `app.bsky.feed.post` | post-ok's record with `text` = `"a"` × 301 | invalid |
| post-four-langs | `app.bsky.feed.post` | post-ok's record plus `"langs": ["en", "fr", "de", "es"]` | invalid |
| post-reply-no-cid | `app.bsky.feed.post` | post-ok's record plus `"reply": {"root": {"uri": "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kaaaaaaaaaab"}, "parent": <ref-remote's strongRef>}` | invalid |
| post-image-embed | `app.bsky.feed.post` | post-ok's record plus `"embed": {"$type": "app.bsky.embed.images", "images": [{"alt": "x", "image": <blob-ok's blob with "mimeType": "image/jpeg">}]}` | valid |
| profile-avatar-ok | `app.bsky.actor.profile`, rkey `self` | `{"$type": "app.bsky.actor.profile", "avatar": {blob, "image/jpeg", "size": 500000}}` | valid |
| profile-avatar-too-big | as above, `"size": 2000000` | — | invalid |
| profile-avatar-webp | as above, `"mimeType": "image/webp"` | — | invalid |
| profile-name-65 | `app.bsky.actor.profile`, rkey `self` | `"displayName"` = `"a"` × 65 | invalid |
| profile-wrong-rkey | `app.bsky.actor.profile`, rkey `3kaaaaaaaaaab` | `{"$type": "app.bsky.actor.profile"}` | invalid |
| like-ok | `app.bsky.feed.like` | `{"$type": "app.bsky.feed.like", "subject": <ref-remote's strongRef>, "createdAt": D}` | valid |
| like-no-subject | `app.bsky.feed.like` | `{"$type": "app.bsky.feed.like", "createdAt": D}` | invalid |
| follow-bad-did | `app.bsky.graph.follow` | `{"$type": "app.bsky.graph.follow", "subject": "notadid", "createdAt": D}` | invalid |
| post-bad-rkey | `app.bsky.feed.post`, rkey `nottid` | post-ok's record | invalid |
| unknown-lexicon | `com.example.nobody.knows` | `{"$type": "com.example.nobody.knows", "anything": 1}` | unknown |

- [ ] **Step 3: Check the file parses and counts**

```bash
python3 -c "import json; c=json.load(open('spikes/lexicon-validation/corpus/cases.json')); print(len(c), {e: sum(1 for x in c if x['expect']==e) for e in ('valid','invalid','unknown')})"
```
Expected: `107 {'valid': 47, 'invalid': 59, 'unknown': 1}` — the tables above, row for row (re-count with `grep -cE '^\| [A-Za-z0-9-]+ \|.*\| (valid|invalid|unknown) \|$'` over this plan if you change them). Every rule H4 lists has at least one valid and one invalid case, except `token` (a token is only ever a value) and `knownValues` (open, so nothing fails it).

### Task 1.3: The harness

**Files:**
- Create: `spikes/lexicon-validation/Cargo.toml`
- Create: `spikes/lexicon-validation/src/main.rs`
- Create: `spikes/lexicon-validation/.gitignore` (`target/`)

The spike is its **own workspace** (an empty `[workspace]` table), so its candidate crates never enter the server's `Cargo.lock`, `cargo deny` run or image.

- [ ] **Step 1: `Cargo.toml`**

```toml
[package]
name = "spike-lexicon-validation"
version = "0.0.0"
edition = "2024"
publish = false
license = "AGPL-3.0-or-later"
description = "THROWAWAY. Decides stage 4a's validator: each candidate against the corpus (spec H4). Delete once chunk 3 lands."

# Its own workspace: candidate crates stay out of the server's lockfile.
[workspace]

[dependencies]
serde_json = "1"
anyhow = "1"
# Candidates — added in Tasks 1.4 and 1.5.
```

- [ ] **Step 2: `main.rs` — load lexicons, run every candidate, print a table**

```rust
//! Run each lexicon-validation candidate against the corpus (stage 4a, H4).
//!
//! `cargo run -- <candidate>` prints one line per case and a summary; the
//! exit code is non-zero if any case disagrees with its `expect`.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::Value;

/// What a candidate says about one record.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    Invalid(String),
    /// The lexicon is not in the registry: accepted unvalidated.
    Unknown,
}

/// A candidate validator, loaded from a set of lexicon documents.
pub trait Candidate {
    fn name(&self) -> &'static str;
    fn check(&self, collection: &str, rkey: &str, record: &Value) -> Verdict;
}

mod candidates;

fn lexicon_files(dirs: &[PathBuf]) -> anyhow::Result<Vec<Value>> {
    let mut docs = Vec::new();
    for dir in dirs {
        let mut stack = vec![dir.clone()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).with_context(|| format!("{d:?}"))? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "json") {
                    docs.push(serde_json::from_str(&std::fs::read_to_string(&path)?)?);
                }
            }
        }
    }
    Ok(docs)
}

fn main() -> anyhow::Result<()> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = lexicon_files(&[
        here.join("../../vendor/lexicons"),
        here.join("corpus/lexicons"),
    ])?;
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(here.join("corpus/cases.json"))?)?;

    let which = std::env::args().nth(1).context("usage: <candidate>")?;
    let candidate = candidates::load(&which, &docs)?;

    let mut wrong = 0;
    for case in &cases {
        let name = case["name"].as_str().unwrap_or("?");
        let expect = case["expect"].as_str().unwrap_or("?");
        let verdict = candidate.check(
            case["collection"].as_str().unwrap_or_default(),
            case["rkey"].as_str().unwrap_or_default(),
            &case["record"],
        );
        let got = match &verdict {
            Verdict::Valid => "valid",
            Verdict::Invalid(_) => "invalid",
            Verdict::Unknown => "unknown",
        };
        let ok = got == expect;
        if !ok {
            wrong += 1;
        }
        let detail = match &verdict {
            Verdict::Invalid(why) => why.as_str(),
            _ => "",
        };
        println!("{} {name:28} expect {expect:8} got {got:8} {detail}", if ok { "ok  " } else { "FAIL" });
    }
    println!("{}: {} of {} agree", candidate.name(), cases.len() - wrong, cases.len());
    if wrong > 0 {
        std::process::exit(1);
    }
    Ok(())
}
```

`src/candidates.rs` starts as:
```rust
use serde_json::Value;

use crate::Candidate;

pub fn load(which: &str, docs: &[Value]) -> anyhow::Result<Box<dyn Candidate>> {
    match which {
        other => anyhow::bail!("no candidate named {other}"),
    }
}
```

- [ ] **Step 3: It builds**

Run: `cd spikes/lexicon-validation && cargo build`
Expected: builds (one unused-variable warning for `docs` is fine for now).

### Task 1.4: Candidate A — `atproto-lexicon`

**Files:**
- Modify: `spikes/lexicon-validation/Cargo.toml` (add the crate)
- Modify: `spikes/lexicon-validation/src/candidates.rs`

- [ ] **Step 1: Add it and read its API**

```bash
cd spikes/lexicon-validation && cargo add atproto-lexicon && cargo doc -p atproto-lexicon --no-deps
```
Read the generated docs (or its source under `~/.cargo/registry/src/*/atproto-lexicon-*/src/`) for: how to build a registry or resolver from **our** documents (`serde_json::Value` lexicon docs, not its bundled set or a network resolver), and the entry point that validates a record value against an NSID. Note in a comment at the top of the adapter which types and functions you used.

- [ ] **Step 2: Write the adapter**

In `candidates.rs`, add a `struct AtprotoLexicon { … }` implementing `Candidate`:
- `name()` returns `"atproto-lexicon"`.
- Construction loads every document in `docs` into the crate's registry. If the crate cannot take caller-supplied documents, the candidate **fails bar point 2**: record that and stop here.
- `check()` returns `Verdict::Unknown` when the collection's NSID is not in the registry; otherwise runs the crate's record validation and maps success to `Valid` and failure to `Invalid(<its message, including the path if it gives one>)`.
- The rkey `key`-type check is **not** the crate's job (spec H4: it may be ours). Implement it once, in `main.rs`, as `pub fn key_ok(key: &str, rkey: &str) -> bool` (`"tid"` → 13 chars of `234567abcdefghijklmnopqrstuvwxyz` with the first in `234567abcdefghij`; `"nsid"` → at least three dot-separated segments; `literal:X` → equals `X`; `"any"` → true) plus `pub fn key_of(docs: &[Value], nsid: &str) -> Option<String>`, and have each adapter apply it before the crate. Task 1.5 reuses both.

Wire it into `load`: `"atproto-lexicon" => Ok(Box::new(AtprotoLexicon::new(docs)?)),`.

- [ ] **Step 3: Run it**

Run: `cargo run -- atproto-lexicon > /tmp/spike-a.txt 2>&1; echo exit=$?`
Expected: a table and `atproto-lexicon: K of 107 agree`. Keep `/tmp/spike-a.txt`.

- [ ] **Step 4: The bar's other points**

```bash
cargo tree -e normal -p atproto-lexicon | grep -E -i "reqwest|hyper|hickory|trust-dns|isahc|ureq|surf" || echo "no http/dns client"
cargo deny --version || cargo install cargo-deny --locked
cargo deny --manifest-path Cargo.toml check --config ../../deny.toml > /tmp/spike-a-deny.txt 2>&1; echo deny-exit=$?
cargo tree -e normal -p atproto-lexicon --prefix none | sort -u | wc -l
```
Record: HTTP/DNS clients present (and whether a feature flag turns them off — check `cargo info atproto-lexicon` for features), `deny` exit status, and the transitive crate count.

### Task 1.5: Candidate B — `proto-blue-lexicon`

Same as Task 1.4 with `proto-blue-lexicon`, struct `ProtoBlueLexicon`, name `"proto-blue-lexicon"`, results to `/tmp/spike-b.txt` and `/tmp/spike-b-deny.txt`.

### Task 1.6: What the reference keeps as a plain map

The spec's Rollout promises the spike checks whether the reference's JSON-to-data-model conversion keeps a malformed `$link`, `$bytes` or `$type`, or a bare-string blob `ref`, as a plain map instead of refusing it.

- [ ] **Step 1: Read the reference's conversion**

```bash
ref=665c90c82545af323d9334a480074b31eb5d51d7   # the pinned atproto commit
for f in lex-json.ts lex-json.test.ts link.ts bytes.ts blob.ts; do
  gh api "repos/bluesky-social/atproto/contents/packages/lex/lex-json/src/$f?ref=$ref" --jq .content | base64 -d > "/tmp/$f" || echo "no $f"
done
grep -n '\$link\|\$bytes\|\$type\|blob' /tmp/lex-json.ts /tmp/link.ts /tmp/bytes.ts /tmp/blob.ts | head -80
```
For each of: `{"$link": 1234}`, `{"$link": "."}`, `{"$link": "<cid>", "other": 1}`, `{"$bytes": [1]}`, `{"$bytes": "<b64>", "other": 1}`, a nested `{"$type": ""}`, and a blob with a bare-string `ref` — write down whether the reference throws or keeps the object as a plain map, citing the line. The test file usually states it outright.

- [ ] **Step 2: Record it**

Add a "Reference conversion" table to `RESULT.md` with those seven rows. Where the reference keeps a plain map and we refuse, that row is a deliberate divergence: add it to the spec's Rollout list of "where brolly is stricter", replacing the "not verified … the spike checks it" sentence with what was found.

### Task 1.7: Decide, record, commit

**Files:**
- Create: `spikes/lexicon-validation/RESULT.md`
- Modify: `docs/specs/2026-11-26-atproto-data-model-and-lexicons.md` (Decisions, row D)

- [ ] **Step 1: Write `RESULT.md`**

One table, one row per candidate: cases agreeing (of the corpus's total), the failing case names, own-documents yes/no, path in messages yes/no, HTTP/DNS client yes/no (feature-gatable?), `cargo deny` pass/fail, transitive crate count. Then the decision under spec H4's rule: **a candidate passes only if** it agrees on every case, takes our documents, reports a path, passes `deny` and brings no HTTP/DNS client (or can switch it off). If both pass, the smaller transitive tree wins, then the more recently released. If neither passes, the decision is "write our own" and `RESULT.md` lists which constraints each candidate got wrong — chunk 3's validator gets a test for each.

- [ ] **Step 2: Record it in the spec**

Replace Decision D's row text with the outcome, e.g. `| D | The validator is **<crate> <version>** (spike, 2026-11-xx: N/N, …) | … |` or `| D | The validator is **written** in adapters/atproto/src/lexicon/ (spike, 2026-11-xx: <crate A> K/107 — <what failed>; <crate B> …) | … |`, and the spec's Status line: `… chunk 1 (the spike) done <date>`.

- [ ] **Step 3: Commit**

```bash
git add spikes/lexicon-validation docs/specs/2026-11-26-atproto-data-model-and-lexicons.md
git status --short | grep deny.toml && echo "STOP: a copied deny.toml is staged" || true
git status --short spikes/lexicon-validation | grep target && echo "STOP: target/ staged" || true
git commit -m "spike(stage 4a): the lexicon validator, decided by the corpus" -m "<one line: the decision and the headline numbers from RESULT.md>

The corpus covers the whole lexicon language (synthetic com.example.corpus.* lexicons) plus real app.bsky.* records; it becomes the adapter's acceptance test in chunk 3. The spike is its own workspace, so no candidate crate entered the server's lockfile.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

- [ ] **Step 4: Stop and report**

Chunk 1 ends here. Report the decision to the human; chunks 3–4 are planned from it.

---

## Chunk 2: The data model and the envelope (H1, H2)

Outcome: records convert JSON ⇄ IPLD by the data model's own rules, pass the atproto-interop-tests vectors, and read back with `$link`/`$bytes`; the envelope (object check, `$type` fill or refusal) lives in one place; the pod's faithful copy is written from the committed record. Independent of the validator; it fixes the bsky.app profile round trip by itself.

### Task 2.1: Vendor the interop data-model vectors

**Files:**
- Create: `adapters/atproto/tests/fixtures/interop/data-model/data-model-valid.json`
- Create: `adapters/atproto/tests/fixtures/interop/data-model/data-model-invalid.json`
- Create: `adapters/atproto/tests/fixtures/interop/data-model/data-model-fixtures.json`
- Create: `adapters/atproto/tests/fixtures/interop/SOURCE.md`

- [ ] **Step 1: Fetch at a pinned commit**

```bash
sha=056e5741bb330757205d6b16db5266fffcae937b
d=adapters/atproto/tests/fixtures/interop/data-model
mkdir -p $d
for f in data-model-valid.json data-model-invalid.json data-model-fixtures.json; do
  curl -fsSL "https://raw.githubusercontent.com/bluesky-social/atproto-interop-tests/$sha/data-model/$f" -o "$d/$f"
done
```

- [ ] **Step 2: `SOURCE.md`**

```markdown
# atproto-interop-tests vectors

From https://github.com/bluesky-social/atproto-interop-tests at
`056e5741bb330757205d6b16db5266fffcae937b`, `data-model/`. CC0-1.0.
Used by `adapters/atproto/tests/data_model_vectors.rs` (stage 4a, H1).
```

### Task 2.2: `data_model.rs` — JSON ⇄ IPLD (H1)

**Files:**
- Create: `adapters/atproto/src/data_model.rs`
- Modify: `adapters/atproto/src/lib.rs` (add `pub mod data_model;` in alphabetical order)
- Create: `adapters/atproto/tests/data_model_vectors.rs`

- [ ] **Step 1: Write the failing vector tests**

`adapters/atproto/tests/data_model_vectors.rs`:
```rust
//! The atproto-interop-tests data-model vectors (stage 4a, H1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD_INDIFFERENT;
use brolly_atproto::data_model;
use serde_json::Value;

fn vectors(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/tests/fixtures/interop/data-model/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_valid_vector_converts() {
    for v in vectors("data-model-valid.json") {
        data_model::record_from_json(&v["json"])
            .unwrap_or_else(|e| panic!("{}: {e}", v["note"]));
    }
}

#[test]
fn every_invalid_vector_is_refused() {
    for v in vectors("data-model-invalid.json") {
        assert!(
            data_model::record_from_json(&v["json"]).is_err(),
            "{} was accepted",
            v["note"]
        );
    }
}

#[test]
fn every_fixture_encodes_to_its_bytes_and_cid_and_reads_back() {
    for v in vectors("data-model-fixtures.json") {
        let ipld = data_model::record_from_json(&v["json"]).unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&ipld).unwrap();
        let expected = STANDARD_NO_PAD_INDIFFERENT
            .decode(v["cbor_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, expected, "CBOR for {}", v["json"]);
        assert_eq!(
            data_model::cid_for_cbor(&bytes).to_string(),
            v["cid"].as_str().unwrap()
        );
        assert_eq!(data_model::to_json(&ipld), v["json"], "read-back");
    }
}
```
(`base64` and `serde_ipld_dagcbor` are already `[dependencies]` of `brolly-atproto`, so integration tests can use them.)

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p brolly-atproto --test data_model_vectors > /tmp/dm.log 2>&1; echo exit=$?; tail -5 /tmp/dm.log`
Expected: compile error, `could not find data_model in brolly_atproto`.

- [ ] **Step 3: Write `data_model.rs`**

```rust
//! The ATProto data model's JSON mapping, both ways (stage 4a, H1).
//!
//! One place turns wire JSON into the IPLD a record block is made of, and
//! back. The rules are the data model's own, held to the atproto-interop-tests
//! vectors (`tests/data_model_vectors.rs`):
//!
//! * `{"$link": "<cid>"}` is a CID link and `{"$bytes": "<base64>"}` is bytes,
//!   anywhere in a record; either with any other key, or a value of the wrong
//!   kind, is refused.
//! * There are no floats. A number with a zero fraction inside i64 (`123.0`,
//!   `1e3`) is that integer — every JSON client reads it so, and the vectors
//!   call it valid; anything else is refused.
//! * `$type`, wherever it appears, is a non-empty string.
//! * A blob is `{"$type": "blob", "ref": {"$link"}, "mimeType", "size"}`, its
//!   `ref` a raw sha-256 CIDv1. The legacy `{"cid", "mimeType"}` form is never
//!   written.
//!
//! Reads emit `$link` and `$bytes` (base64, no padding). A float stored before
//! these rules still reads back as a JSON number.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, STANDARD_NO_PAD_INDIFFERENT};
use ipld_core::cid::{Cid, Version};
use ipld_core::ipld::Ipld;
use serde_json::{Map, Number, Value};
use sha2::Digest;

/// The multicodec for raw bytes: what a blob's CID names.
const RAW: u64 = 0x55;
/// The multicodec for DAG-CBOR: what a record block's CID names.
const DAG_CBOR: u64 = 0x71;
/// The multihash code for sha-256.
const SHA2_256: u64 = 0x12;

/// Why a value is not in the data model: the path to it, and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataModelError(pub String);

impl std::fmt::Display for DataModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DataModelError {}

fn refuse(path: &str, why: &str) -> DataModelError {
    DataModelError(format!("{path}: {why}"))
}

/// A record: the data model, and an object at the top.
pub fn record_from_json(value: &Value) -> Result<Ipld, DataModelError> {
    if !value.is_object() {
        return Err(DataModelError("record must be an object".into()));
    }
    convert(value, "record")
}

/// Any value in the data model.
pub fn from_json(value: &Value) -> Result<Ipld, DataModelError> {
    convert(value, "record")
}

fn convert(value: &Value, path: &str) -> Result<Ipld, DataModelError> {
    match value {
        Value::Null => Ok(Ipld::Null),
        Value::Bool(b) => Ok(Ipld::Bool(*b)),
        Value::Number(n) => number(n, path),
        Value::String(s) => Ok(Ipld::String(s.clone())),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| convert(item, &format!("{path}/{i}")))
            .collect::<Result<Vec<_>, _>>()
            .map(Ipld::List),
        Value::Object(fields) => object(fields, path),
    }
}

fn number(n: &Number, path: &str) -> Result<Ipld, DataModelError> {
    if let Some(i) = n.as_i64() {
        return Ok(Ipld::Integer(i.into()));
    }
    if n.as_u64().is_some() {
        return Err(refuse(path, "integers are limited to 64-bit signed"));
    }
    match n.as_f64() {
        // `i64::MAX as f64` is 2^63, one past the largest i64, so `<` is exact.
        Some(f) if f.fract() == 0.0 && f >= i64::MIN as f64 && f < i64::MAX as f64 => {
            Ok(Ipld::Integer((f as i64).into()))
        }
        _ => Err(refuse(path, "floats are not allowed")),
    }
}

fn object(fields: &Map<String, Value>, path: &str) -> Result<Ipld, DataModelError> {
    if let Some(link) = fields.get("$link") {
        if fields.len() != 1 {
            return Err(refuse(path, "$link must be the only key"));
        }
        return link_of(link, path).map(Ipld::Link);
    }
    if let Some(bytes) = fields.get("$bytes") {
        if fields.len() != 1 {
            return Err(refuse(path, "$bytes must be the only key"));
        }
        let Value::String(text) = bytes else {
            return Err(refuse(path, "$bytes must be a base64 string"));
        };
        return STANDARD_NO_PAD_INDIFFERENT
            .decode(text)
            .map(Ipld::Bytes)
            .map_err(|_| refuse(path, "$bytes is not base64"));
    }
    match fields.get("$type") {
        None if is_legacy_blob(fields) => {
            return Err(refuse(path, "legacy blob refs are not allowed"));
        }
        None => {}
        Some(Value::String(t)) if t == "blob" => return blob(fields, path),
        Some(Value::String(t)) if !t.is_empty() => {}
        Some(_) => return Err(refuse(path, "$type must be a non-empty string")),
    }
    let mut out = BTreeMap::new();
    for (name, field) in fields {
        out.insert(name.clone(), convert(field, &format!("{path}/{name}"))?);
    }
    Ok(Ipld::Map(out))
}

fn link_of(value: &Value, path: &str) -> Result<Cid, DataModelError> {
    let Value::String(text) = value else {
        return Err(refuse(path, "$link must be a CID string"));
    };
    text.parse::<Cid>()
        .map_err(|_| refuse(path, "$link is not a CID"))
}

/// The reference's detection: string `cid`, string `mimeType`, no `$type`.
fn is_legacy_blob(fields: &Map<String, Value>) -> bool {
    fields.get("cid").is_some_and(Value::is_string)
        && fields.get("mimeType").is_some_and(Value::is_string)
}

fn blob(fields: &Map<String, Value>, path: &str) -> Result<Ipld, DataModelError> {
    let reference = match fields.get("ref") {
        Some(Value::Object(r)) if r.len() == 1 => r.get("$link"),
        Some(_) => return Err(refuse(path, "a blob's ref must be a $link")),
        None => return Err(refuse(path, "a blob needs a ref")),
    };
    let Some(reference) = reference else {
        return Err(refuse(path, "a blob's ref must be a $link"));
    };
    let cid = link_of(reference, &format!("{path}/ref"))?;
    if cid.version() != Version::V1 || cid.codec() != RAW || cid.hash().code() != SHA2_256 {
        return Err(refuse(path, "a blob's ref must be a raw sha-256 CIDv1"));
    }
    let Some(Value::String(mime)) = fields.get("mimeType").filter(|m| m.as_str().is_some_and(|s| !s.is_empty())) else {
        return Err(refuse(path, "a blob needs a non-empty mimeType"));
    };
    // Through `number`, so a size of `10000.0` is the integer it is, as any
    // other integral number is.
    let size = match fields.get("size") {
        Some(Value::Number(n)) => match number(n, &format!("{path}/size"))? {
            Ipld::Integer(i) if i >= 0 => i,
            _ => return Err(refuse(path, "a blob's size must be a non-negative integer")),
        },
        _ => return Err(refuse(path, "a blob's size must be a non-negative integer")),
    };
    let mut out = BTreeMap::new();
    for (name, field) in fields {
        let value = match name.as_str() {
            "$type" => Ipld::String("blob".into()),
            "ref" => Ipld::Link(cid),
            "mimeType" => Ipld::String(mime.clone()),
            "size" => Ipld::Integer(size),
            _ => convert(field, &format!("{path}/{name}"))?,
        };
        out.insert(name.clone(), value);
    }
    Ok(Ipld::Map(out))
}

/// A stored record as the wire sees it.
pub fn to_json(ipld: &Ipld) -> Value {
    match ipld {
        Ipld::Null => Value::Null,
        Ipld::Bool(b) => Value::Bool(*b),
        Ipld::Integer(i) => i64::try_from(*i)
            .ok()
            .map(Number::from)
            .or_else(|| u64::try_from(*i).ok().map(Number::from))
            .map(Value::Number)
            .unwrap_or(Value::Null),
        // Only records committed before these rules hold one.
        Ipld::Float(f) => Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
        Ipld::String(s) => Value::String(s.clone()),
        Ipld::Bytes(b) => serde_json::json!({ "$bytes": STANDARD_NO_PAD.encode(b) }),
        Ipld::List(items) => Value::Array(items.iter().map(to_json).collect()),
        Ipld::Map(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, field)| (name.clone(), to_json(field)))
                .collect(),
        ),
        Ipld::Link(cid) => serde_json::json!({ "$link": cid.to_string() }),
    }
}

/// The CID of a DAG-CBOR block: CIDv1, dag-cbor, sha-256.
pub fn cid_for_cbor(bytes: &[u8]) -> Cid {
    let digest = sha2::Sha256::digest(bytes);
    // A sha-256 digest is 32 bytes, always within a 64-byte multihash.
    let hash = ipld_core::cid::multihash::Multihash::<64>::wrap(SHA2_256, &digest)
        .unwrap_or_default();
    Cid::new_v1(DAG_CBOR, hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RAW_CID: &str = "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity";
    const CBOR_CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";

    fn blob_with(reference: Value) -> Value {
        json!({"$type": "blob", "ref": reference, "mimeType": "image/png", "size": 4})
    }

    #[test]
    fn integral_numbers_are_integers_and_fractions_are_refused() {
        assert_eq!(from_json(&json!(1e3)), Ok(Ipld::Integer(1000)));
        assert_eq!(from_json(&json!(123.0)), Ok(Ipld::Integer(123)));
        assert!(from_json(&json!(1.5)).is_err());
        assert!(from_json(&json!(u64::MAX)).is_err());
    }

    #[test]
    fn links_and_bytes_round_trip_at_depth() {
        let value = json!({"a": [{"b": {"$link": CBOR_CID}}, {"c": {"$bytes": "AQID"}}]});
        assert_eq!(to_json(&from_json(&value).unwrap()), value);
    }

    #[test]
    fn padded_bytes_are_accepted_and_read_back_unpadded() {
        let ipld = from_json(&json!({"$bytes": "AQI="})).unwrap();
        assert_eq!(to_json(&ipld), json!({"$bytes": "AQI"}));
    }

    #[test]
    fn a_blob_needs_a_raw_link_ref() {
        assert!(from_json(&blob_with(json!({"$link": RAW_CID}))).is_ok());
        // dag-cbor codec, not raw.
        assert!(from_json(&blob_with(json!({"$link": CBOR_CID}))).is_err());
        // The bare-string form is no longer accepted (stage 1's H, superseded).
        assert!(from_json(&blob_with(json!(RAW_CID))).is_err());
    }

    #[test]
    fn a_blob_missing_a_field_is_refused() {
        let mut no_mime = blob_with(json!({"$link": RAW_CID}));
        no_mime.as_object_mut().unwrap().remove("mimeType");
        assert!(from_json(&no_mime).is_err());
        let mut no_size = blob_with(json!({"$link": RAW_CID}));
        no_size.as_object_mut().unwrap().remove("size");
        assert!(from_json(&no_size).is_err());
    }

    #[test]
    fn a_legacy_blob_is_refused() {
        assert!(from_json(&json!({"cid": RAW_CID, "mimeType": "image/png"})).is_err());
    }

    #[test]
    fn a_nested_type_must_be_a_non_empty_string() {
        assert!(from_json(&json!({"x": {"$type": ""}})).is_err());
        assert!(from_json(&json!({"x": {"$type": 1}})).is_err());
        assert!(from_json(&json!({"x": {"$type": "com.example.y"}})).is_ok());
    }
}
```

If `Multihash::<64>::wrap(...).unwrap_or_default()` does not compile against `ipld-core` 0.4's re-export, use the path `atrium_repo::Multihash::wrap(atrium_repo::blockstore::SHA2_256, &digest)` the way `firehose.rs:947` already does, and `atrium_repo::Cid::new_v1(atrium_repo::blockstore::DAG_CBOR, mh)`; keep the `unwrap_or_default` (library code may not `expect`). Clippy may flag `f as i64` (`cast_possible_truncation`) — the range check above it makes it exact; add `#[allow(clippy::cast_possible_truncation)]` on `number` with that reason in a comment only if clippy asks.

- [ ] **Step 4: Run the vectors and the unit tests**

Run: `cargo test -p brolly-atproto --test data_model_vectors > /tmp/dm.log 2>&1; echo exit=$?; grep "test result" /tmp/dm.log`
Expected: `exit=0`, 3 passed.
Run: `cargo test -p brolly-atproto --lib data_model > /tmp/dmu.log 2>&1; echo exit=$?; grep "test result" /tmp/dmu.log`
Expected: `exit=0`, 7 passed.

### Task 2.3: The envelope in one place (H2), and the old conversion retired

**Files:**
- Create: `adapters/atproto/src/record.rs`
- Modify: `adapters/atproto/src/lib.rs` (`pub mod record;`)
- Modify: `adapters/atproto/src/repo.rs` — `RepoError` (add `InvalidRecord`), `PlannedWrite::{create, put, update}` (lines ~379-416), delete `record_ipld`/`blob_ref`/`ipld_to_json` (lines ~228-316) and point their callers at `data_model`
- Modify: `server/src/xrpc.rs` — delete the six `$type` fills (`:1509`, `:1628`, `:1721`, `:1806`, `:1922`, `:1934` — re-locate by searching `record["$type"] = json!`)

- [ ] **Step 1: Write the failing envelope tests**

Add `pub mod record;` to `adapters/atproto/src/lib.rs` now (alphabetical order), so the tests below fail to compile rather than silently not run. Then `adapters/atproto/src/record.rs` — tests first, at the bottom:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn post() -> Nsid {
        Nsid::new("app.bsky.feed.post".into()).unwrap()
    }

    #[test]
    fn a_record_that_is_not_an_object_is_refused_not_panicked() {
        for value in [json!("blah"), json!(1), json!([1]), json!(null), json!(true)] {
            assert!(prepare(&post(), &value).is_err(), "{value}");
        }
    }

    #[test]
    fn a_missing_type_is_filled_with_the_collection() {
        let ipld = prepare(&post(), &json!({"text": "hi"})).unwrap();
        assert_eq!(
            crate::data_model::to_json(&ipld)["$type"],
            "app.bsky.feed.post"
        );
    }

    #[test]
    fn a_different_type_is_refused_with_the_references_message() {
        let err = prepare(&post(), &json!({"$type": "app.bsky.feed.like"})).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid $type: expected app.bsky.feed.post, got app.bsky.feed.like"
        );
    }

    #[test]
    fn the_data_model_applies_inside() {
        assert!(prepare(&post(), &json!({"n": 1.5})).is_err());
    }
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test -p brolly-atproto --lib record:: > /tmp/rec.log 2>&1; echo exit=$?; tail -3 /tmp/rec.log`
Expected: compile failure (`prepare` not found).

- [ ] **Step 3: Write `prepare` above the tests**

```rust
//! The record envelope (stage 4a, H2): what every write's record passes
//! through before a block is made of it — the seed of chunk 4's gate.
//!
//! In order: the record is an object; `$type` is filled with the collection
//! when missing and refused when it names another (the reference's rule,
//! under any `validate`); then the data model (`data_model`). This is the only
//! place a `$type` is filled — the write handlers no longer do it.

use atrium_api::types::string::Nsid;
use ipld_core::ipld::Ipld;
use serde_json::Value;

use crate::data_model;
use crate::repo::RepoError;

/// Hold `record` to the envelope and the data model; the IPLD to commit.
pub fn prepare(collection: &Nsid, record: &Value) -> Result<Ipld, RepoError> {
    let Value::Object(fields) = record else {
        return Err(RepoError::InvalidRecord("record must be an object".into()));
    };
    let mut fields = fields.clone();
    match fields.get("$type") {
        None => {
            fields.insert("$type".into(), Value::String(collection.as_str().into()));
        }
        Some(Value::String(t)) if t == collection.as_str() => {}
        Some(Value::String(t)) => {
            return Err(RepoError::InvalidRecord(format!(
                "Invalid $type: expected {}, got {t}",
                collection.as_str()
            )));
        }
        Some(_) => {
            return Err(RepoError::InvalidRecord(
                "record/$type: $type must be a non-empty string".into(),
            ));
        }
    }
    data_model::record_from_json(&Value::Object(fields))
        .map_err(|e| RepoError::InvalidRecord(e.to_string()))
}
```

In `repo.rs`, add the variant to `RepoError` (after `BadPath`):
```rust
    /// A record the data model or its envelope refuses (stage 4a, H1, H2):
    /// the message is the client's, verbatim.
    InvalidRecord(String),
```
and its `Display` arm: `RepoError::InvalidRecord(m) => f.write_str(m),`. `write_refused` (`server/src/xrpc.rs:1335`) already answers every unlisted variant as `400 InvalidRequest` with `e.to_string()` — no change there.

In `PlannedWrite::create`, `put` and `update`, parse the collection once and pass it to `prepare`:
```rust
    pub fn create(collection: &str, rkey: Option<&str>, record: &Value) -> Result<Self, RepoError> {
        let collection = parse_nsid(collection)?;
        let record = crate::record::prepare(&collection, record)?;
        Ok(PlannedWrite {
            action: WriteAction::Create,
            collection,
            rkey: parse_rkey(rkey)?,
            record: Some(record),
            swap: RecordSwap::Any,
        })
    }
```
(and the same shape for `put` and `update`).

Delete `record_ipld`, `blob_ref` and `ipld_to_json` from `repo.rs`. Replace the two `ipld_to_json` uses (`get_record_entry` ~`:813`, `list_records` ~`:897`) with `crate::data_model::to_json`. Then `cargo build -p brolly-atproto -p brolly-server 2>&1 | grep -E "^error" -A6` and fix any remaining caller the compiler names (there should be none outside `repo.rs`).

- [ ] **Step 4: Delete the six fills in `server/src/xrpc.rs`**

Each is:
```rust
    let mut record = input.record;
    if record.get("$type").is_none() {
        record["$type"] = json!(input.collection);
    }
```
(or the `value.clone()` form inside `applyWrites`). Replace with `let record = input.record;` (or `let record = value.clone();`). The record still goes to `commit_write` for now; Task 2.4 removes that, after which pass `value` / `&input.record` to the constructors directly and drop the `let record` bindings. Update the `applyWrites` comment that says a value "is given its collection's" `$type` — the envelope does that now.

- [ ] **Step 5: Run the adapter's tests**

Run: `cargo test -p brolly-atproto --lib > /tmp/lib.log 2>&1; echo exit=$?; grep -E "test result|FAILED|panicked" /tmp/lib.log | head -20`
Expected: `record::` tests pass. **Expect failures** in the blob-ref tests that send a bare string — they are Task 2.5's. Anything else failing is a real regression: stop and investigate.

### Task 2.4: The pod copy from what was committed

**Files:**
- Modify: `adapters/atproto/src/repo.rs` — `AppliedOp` (`:466`), its one construction (`:646`)
- Modify: `server/src/xrpc.rs` — `ingest_written` (`:1406`), `commit_write` (`:1439`) and its six callers (`:1527`, `:1652`, `:1739`, `:1820`, `:1955`, `:2034`)
- Test: `server/tests/xrpc.rs`

- [ ] **Step 1: Write the failing test**

Append to `server/tests/xrpc.rs` (in the "the assertion that matters" section's spirit — near `a_write_lands_in_both_the_repo_and_the_pod`):
```rust
#[tokio::test]
async fn the_pod_copy_is_what_was_committed_not_the_request() {
    // H1/H2: the request leaves $type out and writes 1e3 for an integer; the
    // commit fills one and normalises the other, and the pod must say what
    // the repo says, not what the client sent.
    let h = harness().await;
    let (user_id, cookie) = a_member(&h, "alice").await;
    let created = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "collection": "com.example.thing",
            "rkey": "3kaaaaaaaaaab",
            "record": {"n": 1e3},
        }),
        Some(&cookie),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text());

    let fetched = get(
        &h,
        &format!("/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=com.example.thing&rkey=3kaaaaaaaaaab"),
    )
    .await
    .json();
    let pod = h.stores.pod(user_id).unwrap();
    let uri = created.json()["uri"].as_str().unwrap().to_string();
    let stored = brolly_atproto::ingest::read(&pod.read_store(), &uri).expect("the pod copy");
    assert_eq!(stored, fetched["value"]);
    assert_eq!(stored["n"], 1000);
    assert_eq!(stored["$type"], "com.example.thing");
}
```

- [ ] **Step 2: Run it**

Run: `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test -p brolly-server --test xrpc -- the_pod_copy_is_what_was_committed > /tmp/pc.log 2>&1; echo exit=$?; grep -E "panicked|left|right" -A2 /tmp/pc.log | head`
Expected: FAIL, panicking at `expect("the pod copy")`: the handler fill is gone (Task 2.3), so the pod is still handed the request body, which has no `$type`; `ingest::ingest` refuses it with `NoType` and nothing is stored.

- [ ] **Step 3: Carry the committed record on `AppliedOp`**

In `repo.rs`, add to `AppliedOp`:
```rust
    /// The record as committed — the IPLD its block was made of; absent for
    /// a delete. What the pod's faithful copy is written from (stage 4a, H1),
    /// so the pod and the repo never describe different JSON.
    pub record: Option<Ipld>,
```
and at the construction (`ops.push(AppliedOp { … })`, ~`:646`) add `record: write.record.clone(),`.

- [ ] **Step 4: Write the pod copy from it**

In `server/src/xrpc.rs`, change `ingest_written` to take no `records` and read each op's own:
```rust
async fn ingest_written(state: &AppState, user: &User, ops: &[brolly_atproto::repo::AppliedOp]) {
    // … unchanged setup (pod, did, webid, document) …
    for op in ops {
        let Some(committed) = op.record.as_ref() else {
            continue; // a delete leaves the pod copy alone, as always
        };
        let record = brolly_atproto::data_model::to_json(committed);
        let Some((collection, rkey)) = op.path.split_once('/') else {
            continue;
        };
        let uri = ingest::at_uri(&did, collection, rkey);
        if let Err(e) = pod
            .write(|w| Ok(ingest::ingest(w, &record, &uri, &webid, &document)))
            .map_err(ingest::IngestError::from)
            .flatten()
        {
            tracing::error!(error = %e, "faithful ingest failed after a repo write");
        }
    }
}
```
Update its doc comment: "paired with the record the caller asked for" becomes "the record as committed (stage 4a, H1)". Drop the `records` parameter from `commit_write` and the `ingest_written` call inside it, and from its six callers (`vec![record]`, `records`, `Vec::new()` arguments go away; in `applyWrites` delete the `records` vector and its pushes).

- [ ] **Step 5: Run the test and the build**

Run: `DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test -p brolly-server --test xrpc -- the_pod_copy_is_what_was_committed a_write_lands_in_both > /tmp/pc.log 2>&1; echo exit=$?; grep "test result" /tmp/pc.log`
Expected: `exit=0`, 2 passed.

### Task 2.5: The tests that encoded the old form

**Files:**
- Modify: `adapters/atproto/src/repo.rs` — `a_blob_ref_lands_as_a_cid_link_and_round_trips` (`:2118`), `a_blob_ref_in_atriums_link_form_round_trips_too` (`:2195`)
- Modify: `server/tests/xrpc.rs` — `a_blob_ref_round_trips_through_the_handler` (`:1180`)
- Modify: `adapters/atproto/tests/firehose.rs` — `a_blob_link_rides_the_diff_and_inverts` (`:956`, the bare-string `ref` at `:971`)

- [ ] **Step 1: Send and expect `{"$link": …}`**

In each, the blob's `ref` becomes `{"$link": "<cid>"}` where it is sent, and the read-back assertion compares against `json!({"$link": "<cid>"})` instead of the bare string. The two `repo.rs` tests merge naturally: rename `a_blob_ref_in_atriums_link_form_round_trips_too` to `a_bare_string_blob_ref_is_refused` and make it assert that `PlannedWrite::create` with a bare-string `ref` — in an otherwise complete blob (`$type`, `mimeType`, `size` all present) — returns `Err(RepoError::InvalidRecord(_))`. In `a_blob_ref_round_trips_through_the_handler`, also change the assertion message ("must read back as the CID string that named it" → "must read back as the $link that named it").

- [ ] **Step 2: Add the round-trip test the spec names**

Append to `server/tests/xrpc.rs`:
```rust
#[tokio::test]
async fn a_profile_read_and_written_back_commits_the_same_record() {
    // H1: bsky.app's profile editor reads the record and writes it back. The
    // record CID must not move: the rewrite is an update to the same CID.
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    let put = |record: serde_json::Value| {
        let h = &h;
        let cookie = cookie.clone();
        async move {
            post_json(
                h,
                "/xrpc/com.atproto.repo.putRecord",
                json!({"collection": "app.bsky.actor.profile", "rkey": "self", "record": record}),
                Some(&cookie),
            )
            .await
        }
    };
    let link = json!({"$link": "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"});
    let first = put(json!({
        "$type": "app.bsky.actor.profile",
        "displayName": "Alice",
        "avatar": {"$type": "blob", "ref": link, "mimeType": "image/jpeg", "size": 10000},
    }))
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());

    let read = get(
        &h,
        &format!("/xrpc/com.atproto.repo.getRecord?repo=alice.{BASE}&collection=app.bsky.actor.profile&rkey=self"),
    )
    .await
    .json();
    assert_eq!(read["value"]["avatar"]["ref"], link);

    let second = put(read["value"].clone()).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text());
    assert_eq!(second.json()["cid"], first.json()["cid"], "the record CID moved");

    // On the firehose the rewrite is one update whose new CID is its old one.
    let last = commits(&h.db.pool).await.pop().expect("the rewrite's commit");
    assert_eq!(last.ops.len(), 1);
    assert_eq!(last.ops[0].record_cid, last.ops[0].prev_cid);
}
```

- [ ] **Step 3: The envelope at the endpoint**

Append to `server/tests/xrpc.rs` — the spec's "400, never a panic":
```rust
#[tokio::test]
async fn a_record_that_is_not_an_object_is_a_400_at_every_write_verb() {
    let h = harness().await;
    let (_, cookie) = a_member(&h, "alice").await;
    for record in [json!("blah"), json!(1), json!([1]), json!(null)] {
        let create = post_json(
            &h,
            "/xrpc/com.atproto.repo.createRecord",
            json!({"collection": "com.example.thing", "record": record}),
            Some(&cookie),
        )
        .await;
        assert_eq!(create.status, StatusCode::BAD_REQUEST, "create {record}");
        assert_eq!(create.json()["error"], "InvalidRequest");

        let batch = post_json(
            &h,
            "/xrpc/com.atproto.repo.applyWrites",
            json!({"repo": format!("alice.{BASE}"), "writes": [{
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "com.example.thing",
                "value": record,
            }]}),
            Some(&cookie),
        )
        .await;
        assert_eq!(batch.status, StatusCode::BAD_REQUEST, "applyWrites {record}");
    }

    let mismatched = post_json(
        &h,
        "/xrpc/com.atproto.repo.createRecord",
        json!({"collection": "com.example.thing", "record": {"$type": "com.example.other"}}),
        Some(&cookie),
    )
    .await;
    assert_eq!(mismatched.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        mismatched.json()["message"],
        "Invalid $type: expected com.example.thing, got com.example.other"
    );
}
```
Check `ApplyWrite`'s serde shape in `server/src/xrpc.rs` (`struct ApplyWrites`, `enum ApplyWrite`) and match its tag spelling.

- [ ] **Step 4: Run what changed**

```bash
DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test -p brolly-atproto > /tmp/at.log 2>&1; echo exit=$?; grep -E "test result|FAILED" /tmp/at.log
DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test -p brolly-server --test xrpc > /tmp/x.log 2>&1; echo exit=$?; grep -E "test result|FAILED" /tmp/x.log
```
Expected: `exit=0` for both. A failure that is not about a blob `ref` or the pod copy is a real regression — investigate before going on.

### Task 2.6: The whole suite, and commit

- [ ] **Step 1: Lints**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings > /tmp/clippy.log 2>&1; echo exit=$?; grep -E "^(error|warning)" -A6 /tmp/clippy.log | head -30
./tools/check-doc-paths.sh | tail -1
```
Expected: `exit=0`; `doc paths ok`.

- [ ] **Step 2: Full suite**

```bash
DOCKER_HOST=unix:///Users/nk/.orbstack/run/docker.sock cargo test --workspace --no-fail-fast > /tmp/full.log 2>&1; echo exit=$?; grep -E "^test .*FAILED" /tmp/full.log
```
Expected: `exit=0`. If the only failures are the two known flakes, re-run each alone and confirm they pass.

- [ ] **Step 3: Mark the spec**

In `docs/specs/2026-11-26-atproto-data-model-and-lexicons.md`, extend the Status line: `Chunk 2 (the data model and the envelope) landed <date>.`

- [ ] **Step 4: Commit and push**

```bash
git add adapters/atproto/src/data_model.rs adapters/atproto/src/record.rs adapters/atproto/src/lib.rs adapters/atproto/src/repo.rs adapters/atproto/tests/data_model_vectors.rs adapters/atproto/tests/fixtures/interop adapters/atproto/tests/firehose.rs server/src/xrpc.rs server/tests/xrpc.rs docs/specs/2026-11-26-atproto-data-model-and-lexicons.md
git commit -m "Stage 4a, chunk 2: the data model, held (H1, H2)" -m "Records convert JSON <-> IPLD by the data model's own rules, held to the atproto-interop-tests vectors: \$link and \$bytes anywhere, no floats (integral numbers are integers), \$type a non-empty string at any depth, blobs strictly formed, legacy blobs refused. Reads emit \$link/\$bytes, which fixes bsky.app's read-and-write-back of a profile.

The envelope is one function: a record must be an object (the old fill panicked on anything else), a missing \$type is filled and a different one refused with the reference's message. The six handler fills are gone. The pod's faithful copy is written from the committed record, so the pod and the repo never disagree.

Supersedes stage 1's decision H: a bare-string blob ref is no longer accepted or emitted.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```
