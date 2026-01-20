/// Anchor models for recording statements on external systems
pub mod anchor;
/// Version 4 manifest format with graph support
pub mod manifest_v4;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anchor::Anchor;
use anyhow::{anyhow, Result};
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use cid::{multihash::MultihashGeneric, Cid};
use futures::{stream, stream::StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    blob_store::BlobStore,
    cid::{
        multicodec::{BLAKE3_HASHSEQ, RAW_BINARY},
        multihash::BLAKE3,
        strip_urn_cid,
    },
    iroh::hashmap_for_iroh_collection,
    lineage::models::statements::{Statement, StatementTrait},
};

/// A manifest packages statements, contexts, and blobs for distribution.
///
/// Version 3 manifest format that bundles statements with their JSON-LD contexts,
/// binary blobs, and optional anchoring information.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Manifest {
    /// Manifest format version
    pub version: String,
    /// JSON-LD context definitions embedded for self-contained processing
    pub contexts: HashMap<String, Value>,
    /// Statements included in this manifest, keyed by statement ID
    pub statements: HashMap<String, Statement>,
    /// Binary blobs referenced by statements, keyed by CID
    pub blobs: HashMap<String, String>,
    /// Optional anchor records proving statement publication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchors: Option<Vec<Anchor>>,
    /// Optional custom attributes for the manifest
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, Value>>,
}

/// Generates a version 3 manifest from statements and blobs.
///
/// # Arguments
/// * `include_context` - Whether to embed JSON-LD contexts
/// * `statements` - Statements to include in the manifest
/// * `attributes` - Optional custom attributes
/// * `blobs` - Binary blobs referenced by statements
pub async fn generate_manifest(
    include_context: bool,
    statements: Vec<Statement>,
    attributes: Option<HashMap<String, Value>>,
    blobs: HashMap<String, String>,
) -> Result<Manifest> {
    let contexts = if include_context {
        // Embed json-ld contexts to make the manifest self-contained
        get_contexts_for_manifest(&statements)?
    } else {
        HashMap::new()
    };

    let statements = statements_to_map(statements)?;
    Ok(Manifest {
        version: String::from("3"),
        statements,
        blobs,
        contexts,
        attributes,
        anchors: None,
    })
}

/// Merges two manifests into a single manifest (async version).
///
/// # Arguments
/// * `a` - First manifest to merge
/// * `b` - Second manifest to merge
///
/// # Returns
/// * `Result<Manifest>` - Merged manifest, or error if versions don't match
pub async fn merge_async(a: Manifest, b: Manifest) -> Result<Manifest> {
    if a.version != b.version {
        return Err(anyhow!("Manifests must be the same version."));
    }

    let mut contexts = a.contexts;
    contexts.extend(b.contexts);

    let mut statements = a.statements;
    statements.extend(b.statements);

    let mut blobs = a.blobs;
    blobs.extend(b.blobs);

    let attributes = match (a.attributes, b.attributes) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(mut a), Some(b)) => {
            a.extend(b);
            Some(a)
        }
    };

    let anchors = match (a.anchors, b.anchors) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(mut a), Some(b)) => {
            a.extend(b);
            Some(a)
        }
    };

    let manifest = Manifest {
        version: a.version,
        contexts,
        statements,
        blobs,
        anchors,
        attributes,
    };

    Ok(manifest)
}

/// Retrieves the blobs (as a BASE64 encoded string) that are referenced by the statements
pub async fn resolve_blobs(
    statements: &Vec<Statement>,
    blob_store: Arc<dyn BlobStore + Send + Sync>,
    concurrency_limit: usize,
) -> Result<HashMap<String, String>> {
    let mut ref_cids = Vec::new();

    for statement in statements {
        let cids = statement.referenced_cids();

        for cid in cids {
            if !ref_cids.contains(&cid) {
                ref_cids.push(cid);
            }
        }
    }

    let blobs = stream::iter(ref_cids)
        .map(|urn_cid| {
            let blob_store = blob_store.clone();
            let cid = strip_urn_cid(&urn_cid).to_owned();
            async move {
                match blob_store.get(&cid).await {
                    Ok(Some(blob)) => {
                        if Cid::try_from(cid.clone()).map(|c| c.codec()).unwrap_or(0) == BLAKE3_HASHSEQ {
                            // add iroh meta blob
                            let iroh_meta_blob_hash = blob[0..32].to_vec();
                            let iroh_meta_blob_multihash =
                                MultihashGeneric::wrap(BLAKE3, &iroh_meta_blob_hash).unwrap();
                            let iroh_meta_blob_cid =
                                Cid::new_v1(RAW_BINARY, iroh_meta_blob_multihash).to_string();

                            let mut blobs = vec![(cid.clone(), BASE64.encode(&blob))];

                            match blob_store.get(&iroh_meta_blob_cid).await {
                                Ok(Some(iroh_meta_blob)) => {
                                    blobs.push((
                                        iroh_meta_blob_cid.clone(),
                                        BASE64.encode(&iroh_meta_blob),
                                    ));
                                }
                                Ok(None) => {
                                    log::warn!(
                                        "Blob '{iroh_meta_blob_cid}' (meta blob for iroh collection '{cid}') was not found in blob store"
                                    );
                                }
                                Err(e) => {
                                    log::error!(
                                        "Error connecting to blob store to get blob '{iroh_meta_blob_cid}': {e}"
                                    );
                                }
                            }

                            // add iroh file blobs
                            let Ok(iroh_map) =
                                hashmap_for_iroh_collection(&cid, blob_store.clone()).await else {
                                    return blobs;
                                };

                            for file_cid in iroh_map.values() {
                                match blob_store.get(file_cid).await {
                                    Ok(Some(file_blob)) => {
                                        blobs.push((
                                            file_cid.clone(),
                                            BASE64.encode(&file_blob),
                                        ));
                                    }
                                    Ok(None) => {
                                        log::warn!(
                                            "Blob '{file_cid}' (file blob in iroh collection '{cid}') was not found in blob store"
                                        );
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "Error connecting to blob store to get blob '{file_cid}': {e}"
                                        );
                                    }
                                }
                            }

                            blobs
                        } else {
                            vec![(cid.clone(), BASE64.encode(&blob))]
                        }
                    }
                    Ok(None) => {
                        log::warn!("Blob '{cid}' was not found in blob store");
                        vec![]
                    }
                    Err(e) => {
                        log::error!("Error connecting to blob store to get blob '{cid}': {e}");
                        vec![]
                    }
                }
            }
        })
        .buffer_unordered(concurrency_limit)
        .collect::<Vec<Vec<_>>>()
        .await
        .into_iter()
        .flatten()
        .collect::<HashMap<String, String>>();

    log::debug!("Resolved {} blobs.", blobs.len());
    Ok(blobs)
}

fn get_contexts_for_manifest(statements: &[Statement]) -> Result<HashMap<String, Value>> {
    let static_contexts = crate::json_ld::loader::static_contexts()?;

    let required_context_links = statements
        .iter()
        .flat_map(|statement| {
            // Serialize the statement to a serde_json::Value
            let value = serde_json::to_value(statement).expect("Failed to serialize statement");
            get_jsonld_context_links_recursive(&value)
        })
        .collect::<HashSet<String>>();

    let mut included_contexts = HashMap::new();

    for context_link in required_context_links {
        if let Some(context) = static_contexts.get(&context_link) {
            process_context_document(
                &mut included_contexts,
                static_contexts,
                &context_link,
                context,
            )?;
        } else {
            log::error!("Static context not found for linked context: {context_link}");
        }
    }

    Ok(included_contexts)
}

/// Recursively extract all context links from a JSON-LD object
fn get_jsonld_context_links_recursive(obj: &Value) -> HashSet<String> {
    let mut context_links = HashSet::new();
    match obj {
        Value::Object(map) => {
            for (key, value) in map.iter() {
                match (key.as_str(), value) {
                    ("@context", Value::String(s)) => {
                        context_links.insert(s.to_owned());
                    }
                    ("@context", Value::Array(arr)) => {
                        for value in arr {
                            match value {
                                Value::String(s) => {
                                    context_links.insert(s.to_owned());
                                }
                                Value::Object(_) => {
                                    log::warn!("Embedded context objects are not currently handled for embedding static contexts in manifests.")
                                }
                                _ => {
                                    log::warn!(
                                        "Unexpected context value type encountered: {value}"
                                    );
                                }
                            }
                        }
                    }
                    ("@context", Value::Object(_)) => {
                        log::warn!("Embedded context objects are not currently handled for embedding static contexts in manifests.")
                    }
                    ("@context", _) => {
                        log::warn!("Unexpected context value type encountered: {value}");
                    }
                    (_, Value::Object(map)) => {
                        context_links.extend(get_jsonld_context_links_recursive(&Value::Object(
                            map.clone(),
                        )));
                    }
                    (_, Value::Array(arr)) => {
                        for value in arr {
                            context_links.extend(get_jsonld_context_links_recursive(value));
                        }
                    }
                    (_, _) => {}
                }
            }
        }
        Value::Array(arr) => {
            for obj in arr {
                context_links.extend(get_jsonld_context_links_recursive(obj));
            }
        }
        _ => {}
    }

    context_links
}

/// Process a context document
///
/// Adds the context to the included contexts map and processes any additional contexts embedded in the context document
fn process_context_document(
    included_contexts: &mut HashMap<String, Value>,
    static_contexts: &HashMap<String, &str>,
    context_link: &str,
    context: &str,
) -> Result<()> {
    let context = serde_json::from_str::<Value>(context)?;

    included_contexts.insert(context_link.to_owned(), context.clone());

    // Handle any additional contexts embedded in this context document
    match &context {
        Value::Object(obj) => {
            if let Some(Value::Array(arr)) = obj.get("@context") {
                for value in arr {
                    match value {
                        Value::String(s) => {
                            if let Some(context) = static_contexts.get(s) {
                                process_context_document(
                                    included_contexts,
                                    static_contexts,
                                    s,
                                    context,
                                )?;
                            }
                        }
                        Value::Object(_) => {
                            log::warn!("Embedded context objects are not currently handled for embedding static contexts in manifests.")
                        }
                        _ => {
                            log::warn!("Unexpected context value type encountered: {value}");
                        }
                    }
                }
            }
        }
        _ => {
            log::warn!("Static context is not an object.");
        }
    }

    Ok(())
}

/// helper fn to convert a Vec of statements into a HashMap where the Key is the @id field
fn statements_to_map(statements: Vec<Statement>) -> Result<HashMap<String, Statement>> {
    let mut map = HashMap::new();

    for statement in statements {
        map.insert(statement.get_id(), statement);
    }

    Ok(map)
}
