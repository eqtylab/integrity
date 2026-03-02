//! Signer implementations for Integrity.

pub mod signer;
pub use signer::*;

#[cfg(feature = "signer-slh-dsa")]
pub mod alt_signer;

#[cfg(feature = "signer-slh-dsa")]
pub use alt_signer::AltSigner;
