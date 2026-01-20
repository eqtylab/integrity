//! Library for various integrity functionality.
//!
//! This crate provides tools for data integrity, signing, verifiable credentials,
//! and content-addressable storage using CIDs (Content Identifiers).

/// Alternative signer implementations for post-quantum and advanced cryptography.
#[cfg(not(target_arch = "wasm32"))]
pub mod alt_signer;

/// Blob storage backends (Azure, S3, local filesystem, in-memory)
#[cfg(not(target_arch = "wasm32"))]
pub mod blob_store;

/// Content Identifier (CID) utilities and encoding
pub mod cid;

/// Dead Simple Signing Envelope (DSSE) implementation
#[cfg(not(target_arch = "wasm32"))]
pub mod dsse;

/// In-Toto attestation format support
#[cfg(not(target_arch = "wasm32"))]
pub mod intoto_attestation;

/// Iroh protocol integration
#[cfg(not(target_arch = "wasm32"))]
pub mod iroh;

/// JSON-LD processing and canonicalization
pub mod json_ld;

/// Data lineage tracking and graph indexing
#[cfg(not(target_arch = "wasm32"))]
pub mod lineage;

/// Model signing utilities
#[cfg(not(target_arch = "wasm32"))]
pub mod model_signing;

/// N-Quads RDF format parsing
pub mod nquads;

/// Digital signature implementations (ed25519, p256, secp256k1, YubiKey, Azure Key Vault)
#[cfg(not(target_arch = "wasm32"))]
pub mod signer;

/// Sigstore bundle format support
#[cfg(not(target_arch = "wasm32"))]
pub mod sigstore_bundle;

/// Verifiable Credentials creation and proofs
pub mod vc;
