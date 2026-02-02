use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, bail, Result};
use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    blob_store::BlobStore, intoto_attestation, iroh::hashmap_for_iroh_collection,
    sigstore_bundle::SigstoreBundle,
};

/// Manifest containing model signing information for integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSigningManifest {
    /// Serialization configuration used to create the manifest
    pub serialization: ModelSigningManifestSerialization,
    /// List of resources (files) with their digests
    pub resources: Vec<ModelSigningManifestResource>,
}

/// Configuration for how the model manifest was serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSigningManifestSerialization {
    /// The serialization method (e.g., "files")
    pub method: String,
    /// The hash algorithm used (e.g., "blake3")
    pub hash_type: String,
    /// Whether symlinks are allowed in the model directory
    pub allow_symlinks: bool,
    /// Paths to ignore when computing the manifest
    pub ignore_paths: Vec<String>,
}

/// A single resource entry in the model signing manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSigningManifestResource {
    /// The hash algorithm used for this resource
    pub algorithm: String,
    /// The hex-encoded digest of the resource
    pub digest: String,
    /// The relative path/name of the resource
    pub name: String,
}

/// Information about a directory for model signing.
pub enum DirectoryInfo {
    /// A map of file paths to their 32-byte hashes
    PathHashMap(HashMap<String, [u8; 32]>),
    /// An Iroh collection CID with its associated blob store
    IrohCollectionCidAndBlobStore(String, Arc<dyn BlobStore + Send + Sync>),
}

/// Creates an in-toto attestation statement for model signing.
///
/// # Arguments
///
/// * `name` - The name of the model being signed.
/// * `directory_info` - Information about the directory containing model files.
/// * `allow_symlinks` - Whether symlinks are allowed in the model directory.
/// * `ignore_paths` - Paths to ignore when computing the manifest.
///
/// # Returns
///
/// An in-toto `Statement` containing the model signing manifest as the predicate.
pub async fn create_model_signing_intoto_statement(
    name: String,
    directory_info: DirectoryInfo,
    allow_symlinks: bool,
    ignore_paths: Vec<String>,
) -> Result<intoto_attestation::Statement> {
    let path_hash_map = match directory_info {
        DirectoryInfo::PathHashMap(map) => map,
        DirectoryInfo::IrohCollectionCidAndBlobStore(collection_cid, blob_store) => {
            let hash_map_of_cids = hashmap_for_iroh_collection(&collection_cid, blob_store).await?;
            let hash_map_of_hashes = hash_map_of_cids
                .into_iter()
                .map(|(path, cid)| {
                    let cid = Cid::try_from(cid.as_str())
                        .map_err(|e| anyhow!("Failed to parse cid {cid} from collection: {}", e))?;
                    let hash = cid.hash().digest();
                    let hash_bytes: [u8; 32] = hash
                        .try_into()
                        .map_err(|e| anyhow!("Unexpected digest length for cid {cid}: {}", e))?;

                    Ok((path, hash_bytes))
                })
                .collect::<Result<HashMap<String, [u8; 32]>>>()?;

            hash_map_of_hashes
        }
    };

    let serialization = ModelSigningManifestSerialization {
        method: "files".to_owned(),
        hash_type: "blake3".to_owned(),
        allow_symlinks,
        ignore_paths,
    };

    let resources = path_hash_map
        .iter()
        .map(|(name, hash)| ModelSigningManifestResource {
            algorithm: "blake3".to_owned(),
            digest: hex::encode(hash),
            name: name.clone(),
        })
        .collect::<Vec<_>>();

    let model_signing_manifest = ModelSigningManifest {
        serialization,
        resources,
    };

    let model_signing_root_hash = {
        let mut hasher = Sha256::new();
        for (_, hash) in path_hash_map {
            hasher.update(hash);
        }
        let hash = hasher.finalize();
        hex::encode(hash)
    };

    let intoto_attestation_statement = intoto_attestation::Statement {
        subject: vec![intoto_attestation::Subject {
            name,
            digest: {
                let mut m = std::collections::HashMap::new();
                m.insert("sha256".to_owned(), model_signing_root_hash);
                m
            },
        }],
        predicate: intoto_attestation::Predicate {
            predicate_type: intoto_attestation::PredicateType::ModelSigningSignature,
            predicate: serde_json::to_value(&model_signing_manifest)?,
        },
    };

    Ok(intoto_attestation_statement)
}

/// Creates a Sigstore bundle for model signing from a DSSE envelope.
///
/// # Arguments
///
/// * `dsse` - The DSSE envelope as a JSON value.
/// * `signer_did_key` - The DID key of the signer (must be a `did:key:` URI).
///
/// # Returns
///
/// A `SigstoreBundle` containing verification material and the DSSE envelope.
pub fn create_model_signing_sigstore_bundle(
    dsse: Value,
    signer_did_key: &str,
) -> Result<SigstoreBundle> {
    let signer_pub_key_hex = {
        let multibase_str = signer_did_key
            .strip_prefix("did:key:")
            .ok_or_else(|| anyhow!("Missing 'did:key:' prefix"))?;

        // 'z' prefix means base58btc
        let b58_str = multibase_str
            .strip_prefix('z')
            .ok_or_else(|| anyhow!("Expected base58btc (z-prefix) multibase encoding"))?;

        let decoded = bs58::decode(b58_str)
            .into_vec()
            .map_err(|e| anyhow!("Failed to decode base58btc: {}", e))?;

        // first 2 bytes are multicodec for key type
        let (multicodec, pub_key_bytes) = (&decoded[0..2], &decoded[2..]);

        let pub_key_hash_hex = match multicodec {
            // secp256r1 (P-256)
            [0x80, 0x24] => {
                use p256::elliptic_curve::sec1::FromEncodedPoint;
                use pkcs8::EncodePublicKey;

                match pub_key_bytes.len() {
                    65 => {} // uncompressed point
                    33 => {} // compressed point
                    _ => {
                        bail!("Unexpected public key length: {}", pub_key_bytes.len());
                    }
                }

                let encoded_point =
                    p256::elliptic_curve::sec1::EncodedPoint::<p256::NistP256>::from_bytes(
                        pub_key_bytes,
                    )
                    .map_err(|e| anyhow!("Failed to parse public key bytes: {}", e))?;
                let pub_key = p256::PublicKey::from_encoded_point(&encoded_point).unwrap();
                let pem = pub_key
                    .to_public_key_pem(Default::default())
                    .map_err(|e| anyhow!("Failed to encode public key as PEM: {}", e))?;

                let pub_key_hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(pem.as_bytes());
                    hasher.finalize()
                };

                hex::encode(pub_key_hash)
            }
            _ => {
                bail!(
                    "Unsupported multicodec for public key: {:x} {:x}",
                    multicodec[0],
                    multicodec[1]
                );
            }
        };

        pub_key_hash_hex
    };

    let verification_material = serde_json::json!({
        "publicKey": {
            "hint": signer_pub_key_hex
        },
        "tlogEntries": []
    });

    Ok(SigstoreBundle::new(verification_material, dsse))
}
