# Overview

Library for data integrity, signing, verifiable credentials, and content-addressable storage.

This crate provides tools for creating tamper-evident data structures using cryptographic hashing, digital signatures, and W3C standards like Verifiable Credentials and JSON-LD.

## Static Contexts

The `static_contexts/` directory contains JSON-LD context documents that define the vocabulary and semantics for the Integrity Fabric. These contexts enable interoperable, machine-readable metadata using linked data standards.

The schema is defined in <https://github.com/eqtylab/integrity-schema>

### Structure

- **`http/`** - W3C standard contexts cached locally for offline processing:
  - W3C Verifiable Credentials v1 and v2
  - W3C DID (Decentralized Identifiers) v1
  - W3C Security vocabularies v1 and v2

- **`cid/`** - Custom Integrity Graph contexts stored by their content identifiers (CIDs):
  - Domain-specific terms for data lineage and provenance
  - Custom types like `MetadataRegistration`, `ComputeRegistration`, `DataRegistration`
  - Verifiable metadata schemas for the Integrity Fabric

### Usage

The Integrity Graph common context is referenced in code via:
```rust
use integrity::json_ld::ig_common_context_link;

let context_urn = ig_common_context_link();
// Returns: "urn:cid:bafkr4ibtc72t26blsnipjniwpoawtopufixoe7bbloqk7ko65cizgnhgnq"
```

These contexts are embedded at compile time and used by the JSON-LD processor to:
- Expand compact JSON-LD documents to their canonical form
- Resolve context references without network requests
- Ensure deterministic content addressing of linked data

### Regenerating Contexts

To update the static contexts (e.g., after schema changes):
```bash
just update-static-contexts
```

This downloads the latest W3C contexts and regenerates the CID-indexed files.

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
