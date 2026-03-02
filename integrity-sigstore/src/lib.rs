use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Sigstore bundle containing signature verification material and a DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreBundle {
    media_type: String,
    verification_material: Value,
    dsse_envelope: Value,
}

impl SigstoreBundle {
    /// Creates a new Sigstore bundle with the given verification material and DSSE envelope.
    ///
    /// # Arguments
    ///
    /// * `verification_material` - JSON value containing public key or certificate information.
    /// * `dsse_envelope` - The DSSE envelope containing the signed payload.
    ///
    /// # Returns
    ///
    /// A new `SigstoreBundle` with the standard media type.
    pub fn new(verification_material: Value, dsse_envelope: Value) -> SigstoreBundle {
        SigstoreBundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".to_owned(),
            verification_material,
            dsse_envelope,
        }
    }
}
