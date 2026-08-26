use std::{collections::HashMap, path::Path};

use anyhow::Result;
use include_dir::{include_dir, Dir, DirEntry};
use once_cell::sync::OnceCell;
use ssi_json_ld::ContextLoader;

type ContextMap = HashMap<String, &'static str>;

/// All static JSON-LD context documents, embedded at compile time.
///
/// The directory tree is the source of truth: each file's lookup URI is derived
/// from its path (see [`uri_for_path`]), so adding a new context is just a matter
/// of dropping a file in the right sub-directory — no Rust changes required.
///
/// - `cid/<CID>` files are keyed by `urn:cid:<CID>`.
/// - `https/<host>/<path>` files are keyed by `https://<host>/<path>`.
///
/// Everything embedded here is **frozen**, and that is the bar for adding to it:
/// a `urn:cid:` document cannot change without changing its own identifier, and
/// the two `https/eqtylab.io/contexts/` documents are retained solely so that
/// credentials already signed against those URLs keep verifying. They are no
/// longer synced from anywhere and must not be edited — rewriting one changes the
/// canonicalized output of every credential that references it, which invalidates
/// proofs that are already in the wild.
///
/// A vocabulary that is still evolving does not belong here. Pass it to [`loader`]
/// as `additional_contexts` instead, so it is not pinned to a release of this crate.
///
/// A `build.rs` emits `cargo:rerun-if-changed` for this tree so edits are picked
/// up on incremental builds.
static STATIC_CONTEXTS_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/static_contexts");

/// Get JSON-LD context loader, pre-loaded with our static contexts plus the
/// W3C contexts ssi already ships with.
///
/// Optionally provide additional runtime contexts that take precedence over
/// static contexts.
pub fn loader(additional_contexts: Option<HashMap<String, String>>) -> Result<ContextLoader> {
    let static_context_map = static_contexts()?;

    let mut combined: HashMap<String, String> = static_context_map
        .iter()
        .map(|(k, v)| (k.clone(), (*v).to_string()))
        .collect();
    if let Some(additional) = additional_contexts {
        combined.extend(additional);
    }

    let loader = ContextLoader::default()
        .with_static_loader()
        .with_context_map_from(combined)
        .map_err(|e| anyhow::anyhow!("failed to build context loader: {e}"))?;

    Ok(loader)
}

/// Get static contexts map.
///
/// These context are included in memory for commonly used JSON-LD contexts
/// to prevent frequent http and cid lookups during JSON-LD expansion.
pub fn static_contexts() -> Result<&'static ContextMap> {
    static STATIC_CONTEXTS: OnceCell<ContextMap> = OnceCell::new();

    let static_contexts = STATIC_CONTEXTS.get_or_try_init(build_static_contexts)?;

    Ok(static_contexts)
}

fn build_static_contexts() -> Result<ContextMap> {
    // The W3C/security contexts the old code shipped are provided by
    // ssi_json_ld's built-in StaticLoader (CREDENTIALS_V1, CREDENTIALS_V2,
    // SECURITY_V1, SECURITY_V2, DID_V1, ...), so they are not embedded here.
    let mut map = ContextMap::new();
    collect_contexts(&STATIC_CONTEXTS_DIR, &mut map)?;
    Ok(map)
}

/// Recursively walk the embedded context tree, mapping each context file to its
/// lookup URI.
fn collect_contexts(dir: &'static Dir<'static>, map: &mut ContextMap) -> Result<()> {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(subdir) => collect_contexts(subdir, map)?,
            DirEntry::File(file) => {
                let Some(uri) = uri_for_path(file.path()) else {
                    continue;
                };
                let json = file.contents_utf8().ok_or_else(|| {
                    anyhow::anyhow!("context file is not valid UTF-8: {}", file.path().display())
                })?;
                validate_json_string(json)?;
                map.insert(uri, json);
            }
        }
    }

    Ok(())
}

/// Derive a context's lookup URI from its path within `static_contexts/`.
///
/// - `cid/<CID>` -> `urn:cid:<CID>`
/// - `https/<host>/<path>` -> `https://<host>/<path>`
/// - anything else -> `None` (only these two families are embedded)
fn uri_for_path(path: &Path) -> Option<String> {
    // `include_dir` always uses `/` separators, regardless of platform.
    let path = path.to_str()?;

    if let Some(cid) = path.strip_prefix("cid/") {
        // CIDs live directly under cid/ and have no further path segments.
        return (!cid.contains('/')).then(|| format!("urn:cid:{cid}"));
    }

    path.strip_prefix("https/")
        .map(|rest| format!("https://{rest}"))
}

fn validate_json_string(s: &str) -> Result<()> {
    let _ = serde_json::from_str::<serde_json::Value>(s)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_cid_and_legacy_url_contexts() {
        let contexts = static_contexts().expect("static contexts build");

        // The full set of content-addressed contexts is still embedded.
        assert_eq!(
            contexts
                .keys()
                .filter(|k| k.starts_with("urn:cid:"))
                .count(),
            25,
            "expected all 25 urn:cid: contexts to be embedded"
        );

        // A representative CID context (also returned by `ig_common_context_link`).
        assert!(contexts
            .contains_key("urn:cid:bafkr4icploa577ziqnb57jlpoj7l2hi5kgt3knxpdtunlttjd3q33zeqpy"));

        // Retained so credentials signed against these URLs keep verifying. New
        // contexts are supplied by the caller, so this set should not grow.
        assert!(contexts.contains_key("https://eqtylab.io/contexts/component-attestation.jsonld"));
        assert!(contexts.contains_key("https://eqtylab.io/contexts/identity-attestation.jsonld"));
        assert_eq!(
            contexts
                .keys()
                .filter(|k| !k.starts_with("urn:cid:"))
                .count(),
            2,
            "only the two legacy eqtylab.io contexts should be embedded by URL"
        );
    }

    #[test]
    fn derives_uris_from_paths() {
        assert_eq!(
            uri_for_path(Path::new("cid/bafkr4iabc")).as_deref(),
            Some("urn:cid:bafkr4iabc")
        );
        assert_eq!(
            uri_for_path(Path::new("https/eqtylab.io/contexts/foo.jsonld")).as_deref(),
            Some("https://eqtylab.io/contexts/foo.jsonld")
        );
        // Non-context paths are ignored.
        assert_eq!(uri_for_path(Path::new("cid/nested/file")), None);
        assert_eq!(uri_for_path(Path::new("README.md")), None);
    }
}
