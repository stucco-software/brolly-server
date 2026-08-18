#!/usr/bin/env bash
# Every filesystem path cited in docs/ must resolve.
#
# The predecessor had ADRs pointing at mycorriza-core/migrations/ months after
# that directory moved. Docs decay silently; this makes it loud.
#
# Two escapes, both deliberate:
#   * A file containing "<!-- doc-paths: skip -->" is exempt. Use it for
#     retrospectives that cite a different repository.
#   * Paths under the historical prefixes below are ignored, since documents
#     about the predecessor legitimately reference files that never existed here.
set -euo pipefail
cd "$(dirname "$0")/.."

HISTORICAL='^(mycorriza|docs/plans/|docs/superpowers/)'

fail=0
checked=0
while IFS= read -r doc; do
  grep -q '<!-- doc-paths: skip -->' "$doc" && continue
  while IFS= read -r path; do
    [[ "$path" =~ $HISTORICAL ]] && continue
    checked=$((checked + 1))
    # Resolve against the repo root, then against the citing document's own
    # directory, so relative cross-links are validated too.
    if [ ! -e "$path" ] && [ ! -e "$(dirname "$doc")/$path" ]; then
      echo "broken doc path: $doc -> $path"
      fail=1
    fi
  done < <(
    grep -oE '`[a-zA-Z0-9_./-]+/[a-zA-Z0-9_./-]+\.(rs|toml|sql|md|css|html|sh|yml)`' "$doc" \
      | tr -d '`' | sort -u
  )
  while IFS= read -r path; do
    [[ "$path" =~ $HISTORICAL ]] && continue
    checked=$((checked + 1))
    if [ ! -e "$path" ] && [ ! -e "$(dirname "$doc")/$path" ]; then
      echo "broken doc link: $doc -> $path"
      fail=1
    fi
  done < <(
    grep -oE '\]\([a-zA-Z0-9_./-]+\)' "$doc" | sed -E 's/^\]\(//; s/\)$//' \
      | grep -vE '^https?:' | sort -u
  )
done < <(find docs -name '*.md')

if [ "$fail" -eq 0 ]; then echo "doc paths ok ($checked checked)"; fi
exit "$fail"
