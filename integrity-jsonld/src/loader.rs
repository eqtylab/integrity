use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::Result;
use include_dir::{include_dir, Dir, DirEntry};
use iref::{Iri, IriBuf};
use json_ld::{LoadError, Loader, RemoteDocument};
use json_syntax::Parse;
use once_cell::sync::OnceCell;
use ssi_json_ld::{StaticLoader, UnknownContext};

type ContextMap = HashMap<String, &'static str>;
type ParsedContextMap = HashMap<IriBuf, RemoteDocument>;

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

/// JSON-LD context loader returned by [`loader`].
///
/// Lookup order: the W3C contexts ssi ships with, then caller-supplied
/// contexts, then our static contexts. The static contexts are parsed once per
/// process and shared, so constructing a loader is cheap.
#[derive(Clone)]
pub struct IntegrityLoader {
    additional: Arc<ParsedContextMap>,
    statics: Arc<ParsedContextMap>,
}

impl std::fmt::Debug for IntegrityLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrityLoader").finish_non_exhaustive()
    }
}

impl Loader for IntegrityLoader {
    async fn load(&self, url: &Iri) -> json_ld::LoadingResult {
        if let Ok(doc) = StaticLoader.load(url).await {
            return Ok(doc);
        }

        self.additional
            .get(url)
            .or_else(|| self.statics.get(url))
            .cloned()
            .ok_or_else(|| LoadError::new(url.to_owned(), UnknownContext))
    }
}

/// Get JSON-LD context loader, pre-loaded with our static contexts plus the
/// W3C contexts ssi already ships with.
///
/// Optionally provide additional runtime contexts. These take precedence over
/// our embedded static contexts, but not over ssi's built-in W3C contexts: a
/// W3C context URL passed here is ignored.
pub fn loader(additional_contexts: Option<HashMap<String, String>>) -> Result<IntegrityLoader> {
    let additional = match additional_contexts {
        Some(contexts) => parse_context_map(contexts)?,
        None => ParsedContextMap::new(),
    };

    Ok(IntegrityLoader {
        additional: Arc::new(additional),
        statics: Arc::clone(parsed_static_contexts()?),
    })
}

/// Get the static contexts, parsed into JSON-LD documents.
fn parsed_static_contexts() -> Result<&'static Arc<ParsedContextMap>> {
    static PARSED_STATIC_CONTEXTS: OnceCell<Arc<ParsedContextMap>> = OnceCell::new();

    PARSED_STATIC_CONTEXTS.get_or_try_init(|| {
        let contexts = static_contexts()?
            .iter()
            .map(|(k, v)| (k.clone(), (*v).to_string()));

        Ok(Arc::new(parse_context_map(contexts)?))
    })
}

/// Parse a map of context URL to JSON content, the same way
/// `ssi_json_ld::ContextLoader::with_context_map_from` does.
fn parse_context_map(
    contexts: impl IntoIterator<Item = (String, String)>,
) -> Result<ParsedContextMap> {
    contexts
        .into_iter()
        .map(|(url, json)| {
            let (doc, _) = json_syntax::Value::parse_str(&json)
                .map_err(|e| anyhow::anyhow!("failed to parse context {url}: {e}"))?;
            let iri = IriBuf::new(url)
                .map_err(|e| anyhow::anyhow!("invalid context IRI {}: {e}", e.0))?;
            let remote_doc = RemoteDocument::new(
                Some(iri.clone()),
                Some("application/ld+json".parse().unwrap()),
                doc,
            );

            Ok((iri, remote_doc))
        })
        .collect()
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
    use futures::executor::block_on;

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
    fn static_contexts_are_parsed_once() {
        let a = loader(None).expect("loader builds");
        let b = loader(None).expect("loader builds");

        assert!(Arc::ptr_eq(&a.statics, &b.statics));
    }

    #[test]
    fn additional_contexts_take_precedence_over_static() {
        let url = "https://eqtylab.io/contexts/component-attestation.jsonld";
        let override_json = r#"{"@context": {"overridden": "https://example.com/overridden"}}"#;
        let loader = loader(Some(HashMap::from([(
            url.to_string(),
            override_json.to_string(),
        )])))
        .expect("loader builds");

        let iri = Iri::new(url).unwrap();
        let doc = block_on(loader.load(iri)).expect("context loads");
        let (expected, _) = json_syntax::Value::parse_str(override_json).unwrap();
        assert_eq!(doc.document(), &expected);

        // Static contexts not shadowed by the caller still resolve.
        let other = Iri::new("https://eqtylab.io/contexts/identity-attestation.jsonld").unwrap();
        assert!(block_on(loader.load(other)).is_ok());
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
