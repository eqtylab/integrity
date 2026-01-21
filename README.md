# Overview

Library for data integrity, signing, verifiable credentials, and content-addressable storage.

This crate provides tools for creating tamper-evident data structures using cryptographic hashing, digital signatures, and W3C standards like Verifiable Credentials and JSON-LD.

## Main Modules

### `cid`
Content Identifier (CID) utilities for content-addressable data. Provides BLAKE3-based hashing and CID generation compatible with IPFS/IPLD standards. Includes support for:
- Raw binary data CIDs
- JSON Canonicalization Scheme (JCS) CIDs
- RDF Dataset Canonicalization (RDFC) CIDs
- Iroh protocol integration

### `json_ld`
JSON-LD processing and canonicalization. Converts JSON-LD documents to canonical N-Quads format using the URDNA2015 algorithm, enabling deterministic content addressing of linked data.

### `nquads`
N-Quads RDF format parsing and canonicalization. Implements the Universal RDF Dataset Normalization Algorithm 2015 (URDNA2015) for creating canonical representations of RDF data.

### `vc`
W3C Verifiable Credentials creation and signing. Build and sign verifiable credentials with DID-based issuers and linked data proofs. Supports various signature algorithms through the `signer` module.

### `blob_store`
Content-addressable blob storage backends:
- **Azure Blob Storage** - Cloud storage using Azure
- **AWS S3** - Cloud storage using Amazon S3
- **Local Filesystem** - File-based storage for development
- **In-Memory** - Ephemeral storage for testing

All data is indexed by CID for content-addressability.

### `signer`
Digital signature implementations for various key types:
- **ed25519** - EdDSA signatures
- **p256** - ECDSA with NIST P-256 curve
- **secp256k1** - ECDSA with secp256k1 curve (Bitcoin/Ethereum)
- **YubiKey HSM** - Hardware security module integration
- **Azure Key Vault** - Cloud-based key management

### `lineage`
Data lineage tracking and graph indexing. Record and query the provenance of data transformations and computations.

### `dsse`
Dead Simple Signing Envelope (DSSE) implementation for authenticated message signing.

### `intoto_attestation`
In-Toto attestation format support for software supply chain security.

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
use crate::json_ld::ig_common_context_link;

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
    lint-docs              # Check that all public items have documentation (warnings only for now)
    pre-commit             # Run all prek pre-commit hooks on all files
    pre-push               # Called by git pre-push hook
    readme-check           # Check if README.md is up to date with auto-generated content
    readme-update          # Update README.md with auto-generated content (Justfile commands, etc.)
    test                   # Run unit tests with cargo
    test-wasm              # Run WASM tests in Node.js and browsers (Chrome, Firefox) Note: for macOS test Safari with --safari
    update-static-contexts # Rebuild static JSON-LD context files
```
