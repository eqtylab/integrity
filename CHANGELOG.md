# Changelog

Notable changes to Integrity are recorded here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
See [CONTRIBUTING.md](CONTRIBUTING.md) for PR and release instructions.

One release section covers the Rust workspace and native FFI artifacts using
the repository's Git tag version. The FFI ABI version is independent.
Only plain `vX.Y.Z` tags receive versioned sections; candidate and unofficial
tag changes stay under `Unreleased`.

## [Unreleased]

### Added

- A changelog and contributor instructions for documenting PRs and releases.
- A release CI check requiring a matching changelog heading for stable tags
  before native FFI builds begin.

[Unreleased]: https://github.com/eqtylab/integrity/compare/v0.0.16...main
