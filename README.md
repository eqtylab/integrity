# Overview

Library for data integrity, signing, verifiable credentials, and content-addressable storage.

This crate provides tools for creating tamper-evident data structures using cryptographic hashing, digital signatures, and W3C standards like Verifiable Credentials and JSON-LD.

## Feature Flags

Signer and blob backends are now split into dedicated workspace crates and are feature-gated.

- Blob features:
  - `blob-local`
  - `blob-memory`
  - `blob-s3`
  - `blob-gcs`
  - `blob-azure`
  - `blob-all`
- Signer features:
  - `signer-ed25519`
  - `signer-p256`
  - `signer-secp256k1`
  - `signer-auth-service`
  - `signer-vcomp-notary`
  - `signer-akv`
  - `signer-yubihsm`
  - `signer-slh-dsa`
  - `signer-all`

Default features include local blob backends (`blob-local`, `blob-memory`) and local software signers (`signer-ed25519`, `signer-p256`, `signer-secp256k1`).


## FFI (C ABI)

The workspace includes a stable C ABI surface in `ffi/src/ffi/` for SDK bindings (including the Go SDK), packaged as the dedicated `integrity-ffi` crate.

- Public header: `include/integrity_ffi.h`
- ABI version functions:
  - `ig_abi_version_major`
  - `ig_abi_version_minor`
  - `ig_abi_version_patch`
  - `ig_abi_version_string`
- Runtime and handle model:
  - Create one runtime with `ig_runtime_new`
  - Create and reuse opaque handles (signers, blob stores)
  - Release memory with `ig_string_free`, `ig_error_free`, `ig_bytes_free`
  - Release handles with their corresponding `*_free` function

The current ABI version is `0.2.0`.

### Native Artifact Releases

GitHub Actions can publish prebuilt native FFI artifacts for each supported system:

- Linux x86_64 (`libintegrity_ffi.so`)
- macOS 14 aarch64 (`libintegrity_ffi.dylib`)
- macOS 15 x86_64 (`libintegrity_ffi.dylib`)
- macOS 15 aarch64 (`libintegrity_ffi.dylib`)

Workflow: `.github/workflows/release-native-ffi.yml`

- Push a version tag like `v0.2.0` to build and attach release assets to that GitHub Release.
- Use `workflow_dispatch` to run the build matrix and collect workflow artifacts without publishing a Release.

Build native FFI artifacts locally:

```bash
cargo build -p integrity-ffi --release --locked --features "blob-all,signer-all"
```

# Development

Nix flake creates a dev environment with all the dependencies.

`prek` is used for formatting and linting.

## Just Commands

The project uses [Just](https://github.com/casey/just) for common development tasks.

```present just --list
Available recipes:
    build                  # Build the project for native target
    build-wasm             # Build WebAssembly package with wasm-pack
    ci                     # Run all CI checks (format, build, lint, test)
    fix                    # Auto-fix clippy warnings where possible
    fmt                    # Format Rust code using rustfmt
    fmt-check              # Check if code is formatted correctly without modifying files
    lint                   # Run clippy lints to check code quality
    lint-docs              # Check that all public items have documentation
    pre-commit             # Run all prek pre-commit hooks on all files
    readme-check           # Check if README.md is up to date with auto-generated content
    readme-update          # Update README.md with auto-generated content (Justfile commands, etc.)
    test                   # Run unit tests with cargo
    test-wasm              # Run WASM tests in Node.js and browsers (Chrome, Firefox) Note: for macOS test Safari with --safari
    update-static-contexts # Rebuild static JSON-LD context files
```
