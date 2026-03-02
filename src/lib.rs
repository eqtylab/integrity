#![doc = include_str!("../README.md")]

/// Blob storage backends and trait abstraction.
#[cfg(feature = "blob")]
pub use integrity_blob as blob_store;
/// Content Identifier (CID) utilities and encoding
#[cfg(feature = "cid")]
pub use integrity_cid as cid;
/// Iroh protocol integration.
#[cfg(all(not(target_arch = "wasm32"), feature = "cid"))]
pub use integrity_cid::collection as iroh;
/// Dead Simple Signing Envelope (DSSE) implementation
#[cfg(all(not(target_arch = "wasm32"), feature = "dsse"))]
pub use integrity_dsse as dsse;
/// In-Toto attestation format support
#[cfg(all(not(target_arch = "wasm32"), feature = "intoto-attestation"))]
pub use integrity_intoto_attestation as intoto_attestation;
/// JSON-LD processing and canonicalization.
#[cfg(feature = "jsonld")]
pub use integrity_jsonld as json_ld;
/// N-Quads RDF format parsing
#[cfg(feature = "jsonld")]
pub use integrity_jsonld::nquads;
/// Data lineage tracking and graph indexing
#[cfg(all(not(target_arch = "wasm32"), feature = "lineage"))]
pub use integrity_lineage_models as lineage;
/// Model signing utilities
#[cfg(all(not(target_arch = "wasm32"), feature = "model-signing"))]
pub use integrity_model_signing as model_signing;
/// Digital signer implementations and trait abstraction.
#[cfg(feature = "signer")]
pub use integrity_signer as signer;
/// Sigstore bundle format support
#[cfg(all(not(target_arch = "wasm32"), feature = "sigstore"))]
pub use integrity_sigstore as sigstore_bundle;
/// Verifiable Credentials creation and proofs.
#[cfg(feature = "vc")]
pub use integrity_vc as vc;
