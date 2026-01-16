use anyhow::Result;
use slh_dsa::{
    signature::{Keypair, Signer},
    ParameterSet, SigningKey,
};

/// Alternative signer implementations for post-quantum and advanced cryptography.
///
/// This enum provides access to signing algorithms beyond the standard ECDSA/EdDSA,
/// including post-quantum secure signature schemes.
pub enum AltSigner {
    /// SLH-DSA (SPHINCS+) post-quantum signature scheme.
    /// Contains the private key bytes for signing operations.
    SlhDsa(Vec<u8>),
}

/// Type alias for the SLH-DSA parameter set used in this implementation.
/// Currently configured to use SHAKE128f variant for optimal performance.
type SlhDsaParamSet = slh_dsa::Shake128f;

impl AltSigner {
    /// Signs a payload using the alternative signer.
    ///
    /// # Arguments
    /// * `payload` - Data bytes to sign
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - Signature bytes, or error if signing fails
    pub fn sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let sig = match self {
            AltSigner::SlhDsa(key) => {
                let sk = SigningKey::<SlhDsaParamSet>::try_from(key.as_slice())?;

                sk.sign(payload).to_vec()
            }
        };

        Ok(sig)
    }

    /// Returns the key identifier for the alternative signer.
    ///
    /// # Returns
    /// * `Result<String>` - Key identifier string, or error if key processing fails
    pub fn keyid(&self) -> Result<String> {
        let keyid = match self {
            AltSigner::SlhDsa(key) => {
                let sk = SigningKey::<SlhDsaParamSet>::try_from(key.as_slice())?;

                let vk = sk.verifying_key();
                let vk_hex = hex::encode(vk.to_bytes());

                let prefix = SlhDsaParamSet::NAME;

                format!("{prefix}:{vk_hex}")
            }
        };

        Ok(keyid)
    }
}
