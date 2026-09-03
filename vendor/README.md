# Vendored Rust crates

This directory contains patched copies of crates.io releases required by the
legacy Verifiable Credential (VC) verification path. The workspace overrides
the published releases through `[patch.crates-io]` in the root `Cargo.toml`.

The legacy dependency chain starts at `integrity-vc`, which keeps `ssi` 0.7
under the `ssi-legacy` alias solely to verify VCs created before the migration
to `ssi` 0.16. The old `ssi` graph cannot be upgraded piecemeal without changing
the legacy VC implementation, so the affected versions are patched locally.

## Vendored releases

| Crate | Upstream release | Purpose and reason for vendoring |
| --- | --- | --- |
| `ssi-vc` | [0.2.1](https://crates.io/crates/ssi-vc/0.2.1) | Implements VCs and Verifiable Presentations for `ssi` 0.7. It requires compatibility changes for the current HTTP dependency graph and Rust toolchain. |
| `cid` | [0.8.6](https://crates.io/crates/cid/0.8.6) | Provides content identifiers to the legacy IPLD stack. The published release depends directly on the yanked `core2` 0.4 crate. |
| `multihash` | [0.16.3](https://crates.io/crates/multihash/0.16.3) | Provides multihash support to `cid`, IPLD, and `ssi-vc`. The published release depends directly on the yanked `core2` 0.4 crate. |
| `libipld-core` | [0.14.0](https://crates.io/crates/libipld-core/0.14.0) | Provides the base IPLD traits and types used by the legacy stack. The published release depends directly on the yanked `core2` 0.4 crate and contains a call rejected by the current Rust lint set. |

Cargo patches are selected by semantic version. Consequently, the `cid` 0.8.6
and `multihash` 0.16.3 patches affect only the legacy graph; the newer versions
used elsewhere in the workspace continue to come from crates.io.

## Local modifications

Changes are intentionally limited to dependency and compiler compatibility.
No public APIs or VC verification behavior are changed.

### `ssi-vc` 0.2.1

`ssi` 0.7 requires the `ssi-vc` 0.2 API, so replacing this crate with a current
release is not possible without replacing the legacy verification path.

The local copy differs from crates.io as follows:

- `Cargo.toml`: updates `reqwest` from 0.11 to 0.13 and changes its TLS feature
  from `rustls-tls` to the corresponding `rustls` feature. This lets the crate
  share the newer HTTP stack already used by the workspace instead of adding a
  separate obsolete Hyper/Rustls stack.
- `src/lib.rs`: adds the explicit proof lifetime required by the current Rust
  compiler.
- `src/revocation.rs`: adds the explicit `IterOnes` lifetime required by the
  current Rust compiler.

### `cid` 0.8.6

- `Cargo.toml` and `Cargo.toml.orig`: replace the `core2` 0.4 dependency and
  `core2/alloc` feature with `no_std_io2` 0.8.1 equivalents.
- `src/cid.rs` and `src/error.rs`: import `no_std_io2::io` in `no_std` builds.

### `multihash` 0.16.3

- `Cargo.toml` and `Cargo.toml.orig`: replace the `core2` 0.4 dependency and
  `core2/alloc` feature with `no_std_io2` 0.8.1 equivalents.
- `src/error.rs`, `src/hasher_impl.rs`, and `src/multihash.rs`: use the
  equivalent `no_std_io2` error and I/O types in `no_std` builds.

### `libipld-core` 0.14.0

- `Cargo.toml` and `Cargo.toml.orig`: replace the `core2` 0.4 dependency with
  `no_std_io2` 0.8.1, preserving the `alloc` feature and disabled default
  features.
- `src/lib.rs`: import `no_std_io2::io` in `no_std` builds.
- `src/codec.rs`: use explicit `Encode` trait dispatch. Rust 1.89 otherwise
  reports the old double-reference method call through
  `suspicious_double_ref_op`, which becomes an error under the crate's
  `#![deny(warnings)]` policy.

`no_std_io2` provides the `core2` I/O API used by these releases, including the
`alloc` feature needed by this graph. Both standard-library and `no_std`
configurations remain supported.

Registry checksum files are omitted because modifying a vendored crate makes
the original crates.io checksum stale. Nested crate lockfiles are also omitted;
the root workspace `Cargo.lock` is authoritative.

## Maintenance

- Keep changes to vendored sources minimal and document every difference here.
- When a crate includes both `Cargo.toml` and `Cargo.toml.orig`, keep their
  dependency declarations aligned. Cargo builds the normalized `Cargo.toml`.
- Preserve the upstream version in each manifest so the root Cargo patch
  continues to select only the intended release.
- After changing a vendored dependency, regenerate the root `Cargo.lock` and
  confirm that unrelated package versions did not change.
- Compare vendored sources with the corresponding crates.io archive before
  review to ensure no undocumented files changed.

The patches can be removed when support for VCs produced by the `ssi` 0.7 stack
is retired, or when that legacy stack can be upgraded without changing accepted
VC behavior. At that point, remove the applicable `[patch.crates-io]` entries,
delete their directories here, and regenerate `Cargo.lock`.
