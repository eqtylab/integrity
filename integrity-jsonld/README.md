## Static Contexts

The `static_contexts/` directory contains JSON-LD context documents that define the vocabulary and semantics for the Integrity Fabric. These contexts enable interoperable, machine-readable metadata using linked data standards.

The schema is defined in <https://github.com/eqtylab/integrity-schema>

### Structure

The whole `static_contexts/` tree is embedded at compile time (via `include_dir!` in
`src/loader.rs`), and each file's **lookup URI is derived from its path**:

- **`cid/<CID>`** — Custom Integrity Graph contexts stored by their content identifiers,
  keyed as `urn:cid:<CID>`:
  - Domain-specific terms for data lineage and provenance
  - Custom types like `MetadataRegistration`, `ComputeRegistration`, `DataRegistration`
  - Verifiable metadata schemas for the Integrity Fabric

- **`https/<host>/<path>`** — URL-addressed contexts mirrored on disk under a path that
  reconstructs their URL, keyed as `https://<host>/<path>`. For example
  `https/eqtylab.io/contexts/component-attestation.jsonld` is served (conceptually) at
  `https://eqtylab.io/contexts/component-attestation.jsonld`. These are vendored from the
  [`eqtylab/credentials`](https://github.com/eqtylab/credentials) repo (see below).

W3C standard contexts (Verifiable Credentials v1/v2, DID v1, Security v1/v2) are **not**
stored here — `ssi_json_ld`'s built-in static loader provides them at runtime.

### Usage

The Integrity Graph common context is referenced in code via:

```rust
#[cfg(feature = "jsonld")]
use integrity::json_ld::ig_common_context_link;

#[cfg(feature = "jsonld")]
let context_urn = ig_common_context_link();
// Returns: "urn:cid:bafkr4ic7ydwk3rtoltyzx4zn3vvu3r7hpzxtmbzmnksotx7k5nbnwclf6m"
```

These contexts are embedded at compile time and used by the JSON-LD processor to:

- Expand compact JSON-LD documents to their canonical form
- Resolve context references without network requests
- Ensure deterministic content addressing of linked data

### Adding or updating contexts

Because the loader derives each URI from the file path, adding a context is just dropping a
file in the right place — **no Rust changes are needed**:

- A new content-addressed context: add `static_contexts/cid/<CID>` (resolvable as
  `urn:cid:<CID>`).
- A new URL-addressed context: add `static_contexts/https/<host>/<path>.jsonld` (resolvable
  as `https://<host>/<path>.jsonld`).

The URL-addressed contexts from the `eqtylab/credentials` repo are kept in sync by fetching
them straight from that repo. Because it is private, this needs GitHub auth — `gh auth login`
locally, or `$GH_TOKEN` in CI:

```bash
# Fetch the latest contexts (uses `gh`, or falls back to a shallow `git clone`)
just sync-credential-contexts

# Pin to a specific ref instead of the default branch
CREDENTIALS_REF=some-tag just sync-credential-contexts
```

The [`sync-contexts`](../.github/workflows/sync-contexts.yml) GitHub Action also runs this
daily and commits any changes.
