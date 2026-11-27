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
# include_dir cannot tell cargo the tree changed on stable Rust; touching the
# module that embeds it forces the rebuild.
touch "$root/adapters/atproto/src/lexicon/mod.rs"
echo "vendored $(find "$out" -name '*.json' | wc -l | tr -d ' ') lexicons"
