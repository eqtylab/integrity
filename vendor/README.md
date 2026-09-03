# Vendored Rust crates

This directory contains a self-contained island of crates.io releases required
by the legacy Verifiable Credential (VC) verification path. Every edge that
could otherwise reach one of the locally modified crates is a relative `path`
dependency. The root manifest therefore needs no `[patch.crates-io]` entries,
and a Git or local-path consumer receives the same sources automatically.

The legacy dependency chain starts at `integrity-vc`, which keeps `ssi` 0.7
under the `ssi-legacy` alias solely to verify VCs created before the migration
to `ssi` 0.16. The old `ssi` graph cannot be upgraded piecemeal without changing
the legacy VC implementation, so the affected versions are patched locally.

## Vendored releases

| Crate | Upstream release | Purpose and reason for vendoring |
| --- | --- | --- |
| `ssi` | [0.7.0](https://crates.io/crates/ssi/0.7.0) | Entry point for legacy VC parsing and verification. It is the only vendored crate referenced directly by first-party code. |
| `ssi-vc` | [0.2.1](https://crates.io/crates/ssi-vc/0.2.1) | Implements VCs and Verifiable Presentations for `ssi` 0.7. It requires compatibility changes for the current HTTP dependency graph and Rust toolchain. |
| `ssi-ucan` | [0.1.1](https://crates.io/crates/ssi-ucan/0.1.1) | An unconditional `ssi` 0.7 dependency and a second route into `libipld` 0.14. |
| `cacaos` | [0.5.1](https://crates.io/crates/cacaos/0.5.1) | An `ssi-vc` dependency and a third route into `libipld` 0.14. |
| `libipld` | [0.14.0](https://crates.io/crates/libipld/0.14.0) | Aggregates the legacy IPLD core, codecs, macros, and multihash implementation. |
| `libipld-cbor` | [0.14.0](https://crates.io/crates/libipld-cbor/0.14.0) | DAG-CBOR support enabled by all three legacy IPLD consumers. |
| `libipld-json` | [0.14.0](https://crates.io/crates/libipld-json/0.14.0) | DAG-JSON support enabled by `ssi-ucan`. |
| `libipld-macro` | [0.14.0](https://crates.io/crates/libipld-macro/0.14.0) | Macro support with a direct dependency on `libipld-core`. |
| `libipld-core` | [0.14.0](https://crates.io/crates/libipld-core/0.14.0) | Provides the base IPLD traits and types. The published release depends directly on the yanked `core2` 0.4 crate and contains a call rejected by the current Rust lint set. |
| `cid` | [0.8.6](https://crates.io/crates/cid/0.8.6) | Provides content identifiers to the legacy IPLD stack. The published release depends directly on the yanked `core2` 0.4 crate. |
| `multihash` | [0.16.3](https://crates.io/crates/multihash/0.16.3) | Provides multihash support to `cid`, IPLD, and `ssi-vc`. The published release depends directly on the yanked `core2` 0.4 crate. |

The newer `ssi`, `cid`, and multihash implementations used elsewhere in the
workspace remain normal crates.io dependencies with distinct source identities.

## Dependency topology

`integrity-vc` references `vendor/ssi-0.7.0` directly. The vendored manifests
then form this closed path-dependency graph:

```text
ssi 0.7.0
├── ssi-vc 0.2.1
│   ├── cacaos 0.5.1 ──┐
│   ├── libipld 0.14.0 ◄┘
│   └── multihash 0.16.3
└── ssi-ucan 0.1.1 ────► libipld 0.14.0
                            ├── libipld-cbor 0.14.0
                            ├── libipld-json 0.14.0
                            ├── libipld-macro 0.14.0
                            ├── libipld-core 0.14.0
                            │   ├── cid 0.8.6
                            │   └── multihash 0.16.3
                            └── multihash 0.16.3
```

The vendored packages are explicitly excluded from root workspace membership.
This keeps their upstream tests, dev-dependencies, and unused optional features
out of normal workspace resolution while still allowing them to be used as
path dependencies. The root package is an implicit workspace member; it must
not be added as `"."` to `workspace.members`, because doing so prevents Cargo
from honoring exclusions nested beneath the root package.

This layout intentionally supports Git and local-path consumption. It is not
publishable to crates.io as-is: Cargo does not package path-only dependencies.
If registry distribution becomes necessary, publish maintained forks or replace
the legacy verifier before publishing.

## Local modifications

Changes are intentionally limited to dependency and compiler compatibility.
No public APIs or VC verification behavior are changed.

### Path-only crates

The source code in `ssi` 0.7.0, `ssi-ucan` 0.1.1, `cacaos` 0.5.1, `libipld`
0.14.0, `libipld-cbor` 0.14.0, `libipld-json` 0.14.0, and `libipld-macro`
0.14.0 is unchanged from crates.io. Their normalized `Cargo.toml` files and,
where present, `Cargo.toml.orig` files differ only by relative path declarations
that connect the graph shown above. Dev-dependency edges to the same legacy
IPLD crates are also local so isolated maintenance tests use one source identity.

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

Registry checksum files are omitted because the manifest changes make the
original crates.io checksums stale. Nested crate lockfiles are also omitted;
the repository's root `Cargo.lock` is authoritative for its own builds.

## Maintenance

- Keep changes to vendored sources minimal and document every difference here.
- When a crate includes both `Cargo.toml` and `Cargo.toml.orig`, keep their
  dependency declarations aligned. Cargo builds the normalized `Cargo.toml`.
- Preserve the upstream version and relative path topology in each manifest.
- Keep vendored crates in `workspace.exclude` and do not explicitly add `"."`
  to `workspace.members`.
- After changing a vendored dependency, regenerate the root `Cargo.lock` and
  confirm that unrelated package versions did not change.
- Compare vendored sources with the corresponding crates.io archive before
  review to ensure no undocumented files changed.

The vendored island can be removed when support for VCs produced by the `ssi`
0.7 stack is retired, or when that legacy stack can be upgraded without changing
accepted VC behavior. At that point, remove the `ssi-legacy` dependency, delete
these directories, remove their workspace exclusions, and regenerate
`Cargo.lock`.

## Verification

After changing the vendored graph, run:

```sh
just fmt-check
just lint
cargo test --locked -p integrity-vc
cargo test --locked --workspace
just build
cargo tree --locked --workspace --all-features --target all -i no_std_io2
! cargo tree --locked --workspace --all-features --target all -i core2
```

The formatting recipes target first-party packages explicitly. Cargo otherwise
discovers local path dependencies beneath `vendor/` and checks upstream source
formatting even though those packages are excluded from workspace membership.

The final tree should show every legacy crate above as a local path package,
`no_std_io2` only below `cid`, `multihash`, and `libipld-core`, and no package
matching `core2`. A fresh Git consumer should also pass the same tree audit
without defining any Cargo patches.
