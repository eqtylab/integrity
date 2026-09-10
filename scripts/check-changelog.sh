#!/usr/bin/env bash
# Run from the repository root.
set -euo pipefail

tag=${1:?Usage: ./scripts/check-changelog.sh vX.Y.Z}

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Skipping changelog check for candidate or unofficial tag $tag."
    exit 0
fi

if ! awk -v version="${tag#v}" '
    $1 == "##" && $2 == "[" version "]" { found = 1 }
    END { exit !found }
' CHANGELOG.md; then
    echo "Changelog check failed: add a ## [${tag#v}] release heading to CHANGELOG.md." >&2
    exit 1
fi

echo "Changelog contains $tag."
