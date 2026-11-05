//! Checks that the contexts generated from `schema/` are the ones embedded in
//! `static_contexts/cid/`, and that `ig_common_context_link` points at the
//! current common context.
//!
//! Run with `INTEGRITY_SCHEMA_REGENERATE=1` to write the generated contexts
//! into `static_contexts/cid/` instead of failing on a mismatch.

use std::path::{Path, PathBuf};

use cid::{multihash::Multihash, Cid};

const RAW_BINARY: u64 = 0x55;
const BLAKE3: u64 = 0x1e;

const VCOMP_CID_PLACEHOLDER: &str = "{{VCOMP_JSONLD_CID}}";

fn raw_blake3_cid(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    let multihash = Multihash::<64>::wrap(BLAKE3, hash.as_bytes()).unwrap();
    Cid::new_v1(RAW_BINARY, multihash).to_string()
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Ensure `contents` is embedded as `static_contexts/cid/<CID>`, writing it
/// when regenerating. Returns the CID.
fn check_embedded(name: &str, contents: &str, regenerate: bool) -> String {
    let cid = raw_blake3_cid(contents.as_bytes());
    let path = crate_dir().join("static_contexts/cid").join(&cid);

    if regenerate {
        std::fs::write(&path, contents).unwrap();
    } else {
        assert!(
            path.exists(),
            "{name} has changed and is not embedded as static_contexts/cid/{cid}; \
             rerun with INTEGRITY_SCHEMA_REGENERATE=1"
        );
        assert_eq!(read(&path), contents, "{} differs", path.display());
    }

    cid
}

#[test]
fn schema_contexts_are_embedded() {
    let regenerate = std::env::var_os("INTEGRITY_SCHEMA_REGENERATE").is_some();
    let schema = crate_dir().join("schema");

    let vcomp = read(&schema.join("vcomp.jsonld"));
    let vcomp_cid = check_embedded("vcomp.jsonld", &vcomp, regenerate);

    let template = read(&schema.join("common-context.jsonld.template"));
    assert!(template.contains(VCOMP_CID_PLACEHOLDER));
    let common = template.replace(VCOMP_CID_PLACEHOLDER, &vcomp_cid);
    let common_cid = check_embedded("common-context.jsonld", &common, regenerate);

    assert_eq!(
        integrity_jsonld::ig_common_context_link(),
        format!("urn:cid:{common_cid}"),
        "update ig_common_context_link to the new common context CID"
    );
}
