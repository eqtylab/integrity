use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use cid::{multihash::MultihashGeneric, Cid};
use iroh::{base::hash::Hash, bytes::hashseq::HashSeq};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{blob_store::BlobStore, cid::multicodec};

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
        let multihash = Multihash::wrap(0x1e, &collection_blob[0..32])
            .expect("Iroh collection '{cid}' has an invalid multihash");
        Cid::new_v1(multicodec::RAW_BINARY, multihash).to_string()
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

    let mut hash_seq = HashSeq::try_from(collection_blob)?;

    let meta_hash = hash_seq
        .pop_front()
        .ok_or_else(|| anyhow!("No meta hash found"))?;

    let meta_blob_hash = iroh_blake3::hash(&meta_blob).into();

    if meta_hash != meta_blob_hash {
        bail!("Meta hash mismatch: {meta_hash} != {meta_blob_hash}");
    }

    let meta = postcard::from_bytes::<CollectionMeta>(&meta_blob)?;

    let collection_map = if meta.names.len() == hash_seq.len() {
        meta.names
            .into_iter()
            .zip(hash_seq)
            .collect::<HashMap<String, Hash>>()
            .into_iter()
            .map(|(k, v)| {
                let multihash = Multihash::wrap(0x1e, v.as_bytes())
                    .expect("Failed to wrap the collection hash {v:?}");
                (
                    k,
                    Cid::new_v1(multicodec::RAW_BINARY, multihash).to_string(),
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

/// Metadata for a collection
///
/// This is the wire format for the metadata blob.
///
/// TODO: this is copied from iroh repo
///       try to get iroh to make this struct public and reference that instead
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
struct CollectionMeta {
    header: [u8; 13], // Must contain "CollectionV0."
    names: Vec<String>,
}
