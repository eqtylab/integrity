#!/usr/bin/env bash
#
# Vendor JSON-LD context documents from the eqtylab/credentials repo into
# integrity-jsonld so they can be resolved offline, by URL, during JSON-LD
# expansion.
#
# The contexts are published (conceptually) at:
#
#   https://eqtylab.io/contexts/<name>.jsonld
#
# and are mirrored on disk under a directory whose path reconstructs that URL:
#
#   integrity-jsonld/static_contexts/https/eqtylab.io/contexts/<name>.jsonld
#
# integrity-jsonld/src/loader.rs embeds that whole tree with include_dir! and
# derives the lookup URI from each file's path, so vendoring a new context here
# requires no Rust changes.
#
# eqtylab/credentials is private, so the contexts are fetched with authentication:
#   - `gh` (GitHub CLI) if available — uses your existing `gh auth` locally, or
#     $GH_TOKEN in CI. This is the default.
#   - otherwise a shallow, sparse `git clone` fallback (uses your git credentials).
#
# The directory is enumerated remotely, so newly added upstream contexts are
# picked up automatically. This only adds/overwrites files, never deletes — old
# context URLs are kept so previously-issued credentials continue to verify.
#
# Usage:
#   scripts/sync-credential-contexts.sh
#
# Environment:
#   CREDENTIALS_REF   git ref (branch/tag; also a commit SHA when using gh) to
#                     fetch from. Defaults to "main". The git clone fallback only
#                     supports a branch or tag.

set -euo pipefail

owner_repo="eqtylab/credentials"
src_subdir="vc-schema/contexts"
ref="${CREDENTIALS_REF:-main}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dst_dir="${repo_root}/integrity-jsonld/static_contexts/https/eqtylab.io/contexts"

staging="$(mktemp -d)"
cleanup() { rm -rf "${staging}"; }
trap cleanup EXIT

# Directory the fetched *.jsonld files end up in (set by whichever method runs).
fetched_dir=""

if command -v gh >/dev/null 2>&1; then
    echo "fetching ${owner_repo}/${src_subdir}@${ref} via gh api..."
    listing="$(gh api "repos/${owner_repo}/contents/${src_subdir}?ref=${ref}" \
        --jq '.[] | select(.name | endswith(".jsonld")) | .name')"
    names=()
    while IFS= read -r name; do
        [ -n "${name}" ] && names+=("${name}")
    done <<<"${listing}"

    if [ ${#names[@]} -eq 0 ]; then
        echo "error: no .jsonld files found in ${owner_repo}/${src_subdir}@${ref}" >&2
        exit 1
    fi
    for name in "${names[@]}"; do
        gh api "repos/${owner_repo}/contents/${src_subdir}/${name}?ref=${ref}" \
            -H "Accept: application/vnd.github.raw" >"${staging}/${name}"
    done
    fetched_dir="${staging}"
elif command -v git >/dev/null 2>&1; then
    echo "gh not found; falling back to sparse git clone of ${owner_repo}@${ref}..."
    git clone --depth 1 --filter=blob:none --sparse --branch "${ref}" \
        "https://github.com/${owner_repo}.git" "${staging}/repo" >/dev/null 2>&1
    git -C "${staging}/repo" sparse-checkout set "${src_subdir}" >/dev/null 2>&1
    fetched_dir="${staging}/repo/${src_subdir}"
else
    echo "error: need either 'gh' or 'git' installed to fetch contexts" >&2
    exit 1
fi

shopt -s nullglob
contexts=("${fetched_dir}"/*.jsonld)
if [ ${#contexts[@]} -eq 0 ]; then
    echo "error: no .jsonld files fetched from ${owner_repo}/${src_subdir}@${ref}" >&2
    exit 1
fi

mkdir -p "${dst_dir}"
for f in "${contexts[@]}"; do
    # Validate as JSON before vendoring so a malformed context can't land.
    if ! jq empty "${f}" >/dev/null 2>&1; then
        echo "error: $(basename "${f}") is not valid JSON" >&2
        exit 1
    fi
    cp "${f}" "${dst_dir}/"
    echo "synced $(basename "${f}")"
done

echo "done: vendored ${#contexts[@]} context(s) into ${dst_dir#"${repo_root}/"}"
