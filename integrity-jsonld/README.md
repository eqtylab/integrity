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

### Regenerating Contexts

To update the static contexts (e.g., after schema changes):

```bash
just update-static-contexts
```

This downloads the latest W3C contexts and regenerates the CID-indexed files.
