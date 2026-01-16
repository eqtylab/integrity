use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreBundle {
    media_type: String,
    verification_material: Value,
    dsse_envelope: Value,
}

impl SigstoreBundle {
    pub fn new(verification_material: Value, dsse_envelope: Value) -> SigstoreBundle {
        SigstoreBundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".to_owned(),
            verification_material,
            dsse_envelope,
        }
    }
}
