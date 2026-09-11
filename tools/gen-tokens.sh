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

def theme(name):
    m = re.search(r'\[data-theme="%s"\]\s*\{(.*?)\n\}' % name, css, re.S)
    if not m:
        sys.exit(f'could not find the {name} theme block')
    return m.group(1)

# batklubb emits themes ONLY as [data-theme="..."]. We are server-rendered with
# no JavaScript and no theme switcher, so the html element carries no such
# attribute and *neither* theme would apply — every semantic var would be
# unset and every component would fall back to the browser default. Both
# blocks below close that gap.
#
# :not([data-theme]) is (0,2,0) — above the (0,1,0) [data-theme] blocks above
# it — so these apply only in the absence of an explicit choice, and an
# explicit choice always wins regardless of source order. The night bridge is
# last, so between two equally specific matches in dark mode it takes it.
bridge = (
    '\n/* Default theme — appended by tools/gen-tokens.sh.\n'
    ' * batklubb emits [data-theme] blocks only, and nothing sets that\n'
    ' * attribute server-side. Without this, a visitor who has expressed no\n'
    ' * preference gets no theme at all. */\n'
    ':root:not([data-theme]) {' + theme('dag') + '\n}\n'
    '\n/* OS colour-scheme bridge — appended by tools/gen-tokens.sh.\n'
    ' * Applies the night theme when the visitor prefers dark and has not\n'
    ' * chosen explicitly. An explicit data-theme always wins. */\n'
    '@media (prefers-color-scheme: dark) {\n'
    '  :root:not([data-theme="dag"]) {' + theme('natt') + '\n  }\n}\n'
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
