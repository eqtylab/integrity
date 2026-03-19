use anyhow::{anyhow, Result};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD, Engine};
use did_key::{Document, KeyFormat};
#[cfg(feature = "signer-p256")]
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::EncodedPoint;
#[cfg(feature = "signer-vcomp-notary")]
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};

#[cfg(feature = "signer-p256")]
pub(crate) fn p256_encoded_point_from_secret_key(secret_key: &[u8]) -> Result<EncodedPoint> {
    let signing_key =
        SigningKey::from_bytes(secret_key.into()).map_err(|e| anyhow!("Invalid P-256 key: {e}"))?;
    let verifying_key = VerifyingKey::from(&signing_key);

    Ok(verifying_key.to_encoded_point(false))
}

#[cfg(feature = "signer-vcomp-notary")]
pub(crate) fn p256_encoded_point_from_public_key(public_key: &[u8]) -> Result<EncodedPoint> {
    let public_key = PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| anyhow!("Invalid P-256 public key: {e}"))?;

    Ok(public_key.to_encoded_point(false))
}

pub(crate) fn fix_p256_jwk_from_encoded_point(
    did_doc: &mut Document,
    encoded_point: &EncodedPoint,
    secret_key: Option<&[u8]>,
) -> Result<()> {
    let x_bytes = encoded_point
        .x()
        .ok_or_else(|| anyhow!("Failed to get x coordinate"))?;
    let y_bytes = encoded_point
        .y()
        .ok_or_else(|| anyhow!("Failed to get y coordinate"))?;

    let x_b64 = BASE64_URL_NO_PAD.encode(x_bytes);
    let y_b64 = BASE64_URL_NO_PAD.encode(y_bytes);
    let d_b64 = secret_key.map(|secret_key| BASE64_URL_NO_PAD.encode(secret_key));

    for vm in &mut did_doc.verification_method {
        if let Some(KeyFormat::JWK(ref mut jwk)) = vm.public_key {
            jwk.x = Some(x_b64.clone());
            jwk.y = Some(y_b64.clone());
        }
        if let Some(KeyFormat::JWK(ref mut jwk)) = vm.private_key {
            jwk.x = Some(x_b64.clone());
            jwk.y = Some(y_b64.clone());
            if let Some(ref d_b64) = d_b64 {
                jwk.d = Some(d_b64.clone());
            }
        }
    }

    Ok(())
}
