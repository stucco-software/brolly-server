#!/usr/bin/env bash
# Regenerate server/static/tokens.css from batklubb.config.js.
#
# Node is required to AUTHOR tokens. It is deliberately NOT required to build or
# run the server: the generated CSS is committed, so the Docker image stays a
# single Rust binary plus static files (decision D1).
#
# Run after editing batklubb.config.js. Fails if any colour pair misses WCAG AA.
set -euo pipefail
cd "$(dirname "$0")/.."

BATKLUBB="${BATKLUBB_HOME:-$HOME/Research/robot/båtklubb}/packages/cli/bin/batklubb.js"
[ -f "$BATKLUBB" ] || { echo "batklubb CLI not found at $BATKLUBB (set BATKLUBB_HOME)"; exit 1; }

# The CLI assumes a SvelteKit shape and writes src/lib/tokens.css.
node "$BATKLUBB" tokens
RAW=src/lib/tokens.css
[ -f "$RAW" ] || { echo "expected $RAW to be generated"; exit 1; }

# batklubb emits themes only as [data-theme="..."]. We are server-rendered with
# no JavaScript, so an anonymous visitor never gets that attribute set. Re-emit
# the night theme under a colour-scheme media query, scoped so an explicit
# data-theme always wins.
python3 - "$RAW" server/static/tokens.css <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
css = open(src).read()

m = re.search(r'\[data-theme="natt"\]\s*\{(.*?)\n\}', css, re.S)
if not m:
    sys.exit('could not find the natt theme block')

bridge = (
    '\n/* OS colour-scheme bridge — appended by tools/gen-tokens.sh.\n'
    ' * batklubb emits [data-theme] blocks only; this applies the night theme\n'
    ' * when the visitor prefers dark and has not chosen explicitly. An explicit\n'
    ' * data-theme always wins. */\n'
    '@media (prefers-color-scheme: dark) {\n'
    '  :root:not([data-theme="dag"]) {' + m.group(1) + '\n  }\n}\n'
)

header = (
    '/* GENERATED FILE — DO NOT EDIT.\n'
    ' * Source: batklubb.config.js. Regenerate with tools/gen-tokens.sh.\n'
    ' * Edits here are overwritten and will not survive review. */\n\n'
)
open(dst, 'w').write(header + css + bridge)
print(f'wrote {dst}')
PY

rm -rf src
echo "tokens regenerated"
