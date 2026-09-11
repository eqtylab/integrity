# Contributing to Integrity

Build prerequisites and development checks are in [README.md](README.md#development).
Maintain [CHANGELOG.md](CHANGELOG.md) as part of PR review and release preparation,
following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Pull requests

Add concise bullets under `Unreleased` for changes affecting users: Rust APIs,
feature flags, signing and verification, credential formats, JSON-LD contexts,
blob backends, FFI behavior, supported platforms, and build or packaging requirements.
Name the affected crate or interface when the change is not shared by the workspace.
Internal refactors, tests, and typo fixes generally need no entry; explain the
omission in the PR description.

Use the relevant category, creating it only when needed:

| Category | Use for |
| --- | --- |
| Added | New capabilities |
| Changed | Updates to existing behavior |
| Deprecated | Features scheduled for removal |
| Removed | Features no longer available |
| Fixed | Corrected behavior |
| Security | Security fixes |

Include a PR link once available. Mark incompatible changes with **Breaking:**
and explain the required migration. For dependency version changes, state both
versions explicitly (`from OLD to NEW`) and verify them against the Git diff.
Describe the effect on users instead of copying commit messages.

Reviewers check that notes match the final implementation and preserve other
contributors' entries. Ordinary PRs do not assign release versions or dates.

## Releases

Only plain `vX.Y.Z` tags get versioned changelog sections. Candidate and unofficial
tags (for example, `v0.0.17-rc.1` or `v0.0.17-cloud`) keep their changes under
`Unreleased`; put tag-specific notes in their GitHub releases.

For an official stable release:

1. Review `Unreleased` against changes since the previous stable tag. Move included
   changes into a new `## [X.Y.Z] - YYYY-MM-DD` section using the actual release
   date. Keep `Unreleased` at the top and releases newest first; omit empty categories.
2. Match the heading to the intended Git tag. Review `[workspace.package].version`
   in `Cargo.toml`, workspace crate versions, and `Cargo.lock` for the release.
   The native FFI ABI version is a separate compatibility contract; do not change
   it just to match a Git tag.
3. Add a comparison link from the previous stable tag to the new tag and advance
   the `Unreleased` link to compare the new tag with `main`. For example:

   ```markdown
   [Unreleased]: https://github.com/eqtylab/integrity/compare/v0.0.17...main
   [0.0.17]: https://github.com/eqtylab/integrity/compare/v0.0.16...v0.0.17
   ```

4. Run `./scripts/check-changelog.sh vX.Y.Z` and the development checks in the
   README, merge the release preparation PR, then push the tag at the intended
   commit on `main`. The [native FFI release workflow](.github/workflows/release-native-ffi.yml)
   checks for the matching `## [X.Y.Z]` heading before building, packaging, and
   publishing native artifacts. Manual runs on tags also check the heading,
   including dry runs. Branch runs and candidate or unofficial tags skip the
   check. A manual run publishes only when run on a tag with `dry_run` disabled.

The CI gate checks heading presence only. Reviewers verify dates, notes, ordering,
comparison links, and version consistency. Correct factual errors in published
entries when needed, but retain history. If a release is withdrawn, append
`[YANKED]` to its heading and explain why.
