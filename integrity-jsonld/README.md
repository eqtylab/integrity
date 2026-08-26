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
  reconstructs their URL, keyed as `https://<host>/<path>`. This holds exactly two documents,
  `https://eqtylab.io/contexts/{component,identity}-attestation.jsonld`, retained so that
  credentials already signed against those URLs keep verifying. They are **frozen**: no longer
  synced from anywhere, and not to be edited. Rewriting one changes the canonicalized output of
  every credential referencing it, invalidating proofs that are already in the wild.

W3C standard contexts (Verifiable Credentials v1/v2, DID v1, Security v1/v2) are **not**
stored here — `ssi_json_ld`'s built-in static loader provides them at runtime.

### Caller-supplied contexts

`loader()` takes an optional `HashMap<String, String>` of context URL to context document,
merged over the embedded set so a caller's entry wins on collision. This is where a vocabulary
that is still evolving belongs: anything vendored into `static_contexts/` is pinned to the
version of this crate you depend on, so embedding it would mean cutting a release here before a
new term could be used.

Nothing is ever fetched over the network. A context that is neither embedded nor supplied is a
hard error, which keeps canonicalization a pure function of its inputs.

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

Embed a context here only when it is genuinely immutable — a content-addressed document is,
by construction. For anything served at a URL that may still gain terms, prefer passing it to
`loader()` at call time so the two never drift.
