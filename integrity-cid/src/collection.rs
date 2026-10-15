use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use cid::{multihash::Multihash as MultihashGeneric, Cid};
use integrity_blob::BlobStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

type Multihash = MultihashGeneric<64>;

/// Creates a Hashmap of <Item Name, Item CID> from the provided Iroh collection cid
pub async fn hashmap_for_iroh_collection(
    cid: &str,
    blob_store: Arc<dyn BlobStore + Send + Sync>,
) -> Result<HashMap<String, String>> {
    let (collection_blob, meta_blob) = get_iroh_collection_blobs(cid, blob_store).await?;

    hashmap_from_iroh_collection_blobs(collection_blob, meta_blob)
}

/// Creates a Json object of key=Item Name and value=Item CID from the provided Iroh collection cid
pub async fn json_for_iroh_collection(
    cid: &str,
    blob_store: Arc<dyn BlobStore + Send + Sync>,
) -> Result<Value> {
    let (collection_blob, meta_blob) = get_iroh_collection_blobs(cid, blob_store).await?;

    json_from_iroh_collection_blobs(collection_blob, meta_blob)
}

/// Pretty prints the content information of the iroh collection
pub async fn pretty_print_for_iroh_collection(
    cid: &str,
    blob_store: Arc<dyn BlobStore + Send + Sync>,
) -> Result<String> {
    let (collection_blob, meta_blob) = get_iroh_collection_blobs(cid, blob_store).await?;

    pretty_print_from_iroh_collection_blobs(collection_blob, meta_blob)
}

async fn get_iroh_collection_blobs(
    cid: &str,
    blob_store: Arc<dyn BlobStore + Send + Sync>,
) -> Result<(Bytes, Bytes)> {
    let collection_blob: Bytes = blob_store
        .get(cid)
        .await
        .map_err(|e| anyhow!("Failed to get collection blob: {e}"))?
        .ok_or_else(|| anyhow!("Collection blob not found"))?
        .into();

    if collection_blob.len() < 32 {
        log::error!("Collection '{collection_blob:?}' blob is too short to be an iroh collection.");
        return Err(anyhow!(
            "Collection blob is too short to be an iroh collection."
        ));
    }
    let meta_cid = {
        let multihash = Multihash::wrap(crate::multihash::BLAKE3, &collection_blob[0..32])
            .expect("Iroh collection '{cid}' has an invalid multihash");
        Cid::new_v1(crate::multicodec::RAW_BINARY, multihash).to_string()
    };

    let meta_blob = blob_store
        .get(&meta_cid)
        .await
        .map_err(|e| anyhow!("Failed to get meta blob: {e}"))?
        .ok_or_else(|| anyhow!("Meta blob not found"))?
        .into();

    Ok((collection_blob, meta_blob))
}

/// Creates a HashMap of <Item Name, Item CID> from the provided blobs
fn hashmap_from_iroh_collection_blobs(
    collection_blob: impl Into<Bytes>,
    meta_blob: impl Into<Bytes>,
) -> Result<HashMap<String, String>> {
    let collection_blob = collection_blob.into();
    let meta_blob = meta_blob.into();

    // A hash sequence is a concatenation of 32-byte BLAKE3 hashes; the first is the meta blob's.
    if collection_blob.len() % 32 != 0 {
        bail!("Hash sequence length is not a multiple of 32");
    }
    let mut hash_seq = collection_blob.chunks_exact(32);

    let meta_hash = hash_seq
        .next()
        .ok_or_else(|| anyhow!("No meta hash found"))?;

    let meta_blob_hash = iroh_blake3::hash(&meta_blob);

    if meta_hash != meta_blob_hash.as_bytes() {
        bail!(
            "Meta hash mismatch: {} != {}",
            iroh_blake3::Hash::from(<[u8; 32]>::try_from(meta_hash)?).to_hex(),
            meta_blob_hash.to_hex()
        );
    }

    let meta = postcard::from_bytes::<CollectionMeta>(&meta_blob)?;

    let collection_map = if meta.names.len() == hash_seq.len() {
        meta.names
            .into_iter()
            .zip(hash_seq)
            .collect::<HashMap<String, &[u8]>>()
            .into_iter()
            .map(|(k, v)| {
                let multihash = Multihash::wrap(crate::multihash::BLAKE3, v)
                    .expect("Failed to wrap the collection hash {v:?}");
                (
                    k,
                    Cid::new_v1(crate::multicodec::RAW_BINARY, multihash).to_string(),
                )
            })
            .collect::<HashMap<String, String>>()
    } else {
        bail!("Meta names and hash seq length mismatch");
    };

    Ok(collection_map)
}

/// Creates a JSON object from the Iroh Collection where the key is the item name, and the value is
/// the item CID
fn json_from_iroh_collection_blobs(
    collection_blob: impl Into<Bytes>,
    meta_blob: impl Into<Bytes>,
) -> Result<Value> {
    let mut json = json!({});

    for (k, v) in hashmap_from_iroh_collection_blobs(collection_blob, meta_blob)? {
        json[k] = Value::String(v);
    }

    Ok(json)
}

fn pretty_print_from_iroh_collection_blobs(
    collection_blob: impl Into<Bytes>,
    meta_blob: impl Into<Bytes>,
) -> Result<String> {
    let hashmap = hashmap_from_iroh_collection_blobs(collection_blob, meta_blob)?;

    let max_name_len = hashmap.keys().map(|name| name.len()).max().unwrap_or(0);

    let mut files = hashmap.into_iter().collect::<Vec<_>>();
    files.sort_by(|(name1, _), (name2, _)| name1.cmp(name2));

    let pretty = files
        .iter()
        .map(|(name, hash)| format!("{name:<max_name_len$} {hash}"))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(pretty)
}

/// Encodes an iroh collection (`CollectionV0`) as its (meta blob, hash sequence blob) pair.
///
/// The meta blob is the postcard-encoded [`CollectionMeta`]; the hash sequence is the
/// meta blob's BLAKE3 hash followed by each entry's hash, in order.
pub(crate) fn collection_blobs(entries: Vec<(String, [u8; 32])>) -> Result<(Bytes, Bytes)> {
    let (names, hashes): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
    let meta_blob = postcard::to_allocvec(&CollectionMeta {
        header: *b"CollectionV0.",
        names,
    })?;

    let mut hash_seq = Vec::with_capacity(32 * (hashes.len() + 1));
    hash_seq.extend_from_slice(iroh_blake3::hash(&meta_blob).as_bytes());
    for hash in hashes {
        hash_seq.extend_from_slice(&hash);
    }

    Ok((meta_blob.into(), hash_seq.into()))
}

/// Metadata for a collection
///
/// This is the wire format for the metadata blob, matching iroh-blobs' `CollectionV0`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
struct CollectionMeta {
    header: [u8; 13], // Must contain "CollectionV0."
    names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::iroh::{compute_dir_cid, CidIgnoreConfig, HashingConfig};

    #[tokio::test]
    async fn reads_back_the_fixture_iroh_collection() {
        let fixture_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/iroh-collection");

        let dir_result = compute_dir_cid(
            &fixture_dir,
            HashingConfig::default(),
            CidIgnoreConfig::default(),
        )
        .await
        .expect("should compute dir cid");

        let map = hashmap_from_iroh_collection_blobs(
            dir_result.collection.blob.clone(),
            dir_result.meta.blob.clone(),
        )
        .expect("should read the collection back");

        assert_eq!(
            map,
            dir_result
                .file_hashes
                .into_iter()
                .collect::<HashMap<_, _>>()
        );

        let mut wrong_meta = dir_result.meta.blob.to_vec();
        wrong_meta.push(0);
        assert!(
            hashmap_from_iroh_collection_blobs(dir_result.collection.blob.clone(), wrong_meta)
                .is_err()
        );

        let truncated = dir_result
            .collection
            .blob
            .slice(..dir_result.collection.blob.len() - 1);
        assert!(hashmap_from_iroh_collection_blobs(truncated, dir_result.meta.blob).is_err());
    }
}
