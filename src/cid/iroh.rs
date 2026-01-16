use std::{fs, io::Read, path::PathBuf};

use anyhow::{bail, Result};
use bytes::Bytes;
use cid::{multihash::MultihashGeneric, Cid};
use iroh::{bytes::format::collection::Collection, util::fs::DataSource};
use log::{debug, trace};
use serde::{Deserialize, Serialize};

use crate::cid::{multicodec, multihash};

/// Configuration for hashing algorithms and performance optimizations.
///
/// Controls how file hashing is performed, including multi-threading
/// and memory mapping optimizations for large files.
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct HashingConfig {
    #[serde(default)]
    pub multithread: bool,
    #[serde(default)]
    pub memory_map: bool,
}

/// Configuration for filtering files during CID computation.
///
/// Determines which files should be included or excluded when computing
/// directory CIDs, similar to .gitignore functionality.
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct CidIgnoreConfig {
    #[serde(default)]
    pub include_hidden_files: bool,
    #[serde(default)]
    pub gitignore: bool,
    #[serde(default)]
    pub include_symlinks: bool,
}

/// Type alias for 64-byte multihash used in CID operations.
type Multihash = MultihashGeneric<64>;

#[derive(Debug, Clone)]
pub struct DirCidResult {
    pub collection: CidResult,
    pub meta: CidResult,
    pub file_hashes: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct CidResult {
    pub cid: String,
    pub blob: Bytes,
}

/// Computes a CID for a directory by hashing all contained files.
///
/// # Arguments
/// * `path` - Directory path to compute CID for
///
/// # Returns
/// * `Result<DirCidResult>` - Struct of the collection and meta blobs and their corresponding CIDs
pub async fn compute_dir_cid(
    path: impl Into<PathBuf>,
    hash_config: HashingConfig,
    cid_ignore: CidIgnoreConfig,
) -> Result<DirCidResult> {
    let path = path.into();

    debug!("computing cid for dir {path:?}");

    if !path.is_dir() {
        bail!(
            "The provided path ({:?}) is not a directory",
            path.display()
        );
    };

    let path_hash_map = {
        let mut bs = vec![];

        let ordered_paths =
            sort_data_sources(files_for_dir_cid(path.canonicalize()?, cid_ignore.clone())?);

        for data_source in ordered_paths {
            let name = data_source.name().to_string();
            trace!("computing cid for file {name}");
            let hash = compute_hash_for_file(
                data_source.path().to_path_buf(),
                hash_config.multithread,
                hash_config.memory_map,
            )?;

            bs.push((name, hash));
        }

        bs
    };

    let collection = Collection::from_iter(path_hash_map.clone().into_iter());

    let (meta_blob, collection_blob) = match collection.to_blobs().collect::<Vec<_>>().as_slice() {
        [meta_blob, collection_blob] => (meta_blob.clone(), collection_blob.clone()),
        bs => bail!("Expected two blobs, found {}.", bs.len()),
    };

    let meta_blob_cid = compute_blob_cid(&meta_blob, multicodec::RAW_BINARY).await?;
    let collection_cid = compute_blob_cid(&collection_blob, multicodec::BLAKE3_HASHSEQ).await?;

    let mut file_hashes: Vec<(String, String)> = vec![]; // <File Name, CID>
    for (name, hash) in &path_hash_map {
        let multihash = Multihash::wrap(multihash::BLAKE3, hash)?;
        let cid = Cid::new_v1(multicodec::RAW_BINARY, multihash).to_string();
        file_hashes.push((name.clone(), cid));
    }

    Ok(DirCidResult {
        collection: CidResult {
            cid: collection_cid,
            blob: collection_blob,
        },
        meta: CidResult {
            cid: meta_blob_cid,
            blob: meta_blob,
        },
        file_hashes,
    })
}

/// Gets the list of files ignored when computing a directory CID.
///
/// # Arguments
/// * `path` - Directory path to check for ignored files
///
/// # Returns
/// * `Result<Vec<String>>` - List of ignored file names, or error if directory access fails
pub fn get_ignored_files_for_dir_cid(
    path: impl Into<PathBuf>,
    cid_ignore: CidIgnoreConfig,
) -> Result<Vec<String>> {
    let ignored_files = sort_data_sources(ignored_files_for_dir_cid(path, cid_ignore)?)
        .into_iter()
        .map(|d| d.name().to_string())
        .collect::<Vec<_>>();

    Ok(ignored_files)
}

/// Computes a CID for a single file.
///
/// # Arguments
/// * `path` - File path to compute CID for
///
/// # Returns
/// * `Result<CidResult>` - The CID and hashed file blob, or error if not a file or computation fails
pub async fn compute_file_cid(
    path: impl Into<PathBuf>,
    hash_config: HashingConfig,
) -> Result<CidResult> {
    let path = path.into();
    trace!("computing cid for file {path:?}");

    if !path.is_file() {
        bail!("The provided path ({:?}) is not a file", path.display());
    };

    let blob = compute_hash_for_file(
        path.clone(),
        hash_config.multithread,
        hash_config.memory_map,
    )?;

    let multihash = Multihash::wrap(multihash::BLAKE3, &blob)?;
    let cid = Cid::new_v1(multicodec::RAW_BINARY, multihash).to_string();

    Ok(CidResult {
        cid,
        blob: Bytes::from(blob.to_vec()),
    })
}

pub async fn compute_blob_cid(blob: impl Into<&Bytes>, multicodec: u64) -> Result<String> {
    let blob = blob.into();

    let hash = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(blob);
        hasher.finalize()
    };
    let multihash = Multihash::wrap(multihash::BLAKE3, hash.as_bytes())?;

    let cid = Cid::new_v1(multicodec, multihash).to_string();

    Ok(cid)
}

fn compute_hash_for_file(path: PathBuf, multithread: bool, memory_map: bool) -> Result<[u8; 32]> {
    let hash = match (multithread, memory_map) {
        (false, false) => {
            // Single threaded, no memory mapping
            let mut hasher = blake3::Hasher::new();
            let mut file = fs::File::open(&path)?;

            let chunk_size = 1024 * 1024 * 1024;
            let mut buf = vec![0; chunk_size];

            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }

            hasher.finalize()
        }
        (true, false) => {
            // Multithreaded, no memory mapping
            let mut hasher = blake3::Hasher::new();
            let mut file = fs::File::open(&path)?;

            let chunk_size = 1024 * 1024 * 1024;
            let mut buf = vec![0; chunk_size];

            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update_rayon(&buf[..n]);
            }

            hasher.finalize()
        }
        (false, true) => {
            // Single threaded, with memory mapping
            let mut hasher = blake3::Hasher::new();
            hasher.update_mmap(&path)?;
            hasher.finalize()
        }
        (true, true) => {
            // Multithreaded, with memory mapping
            let mut hasher = blake3::Hasher::new();
            hasher.update_mmap_rayon(&path)?;
            hasher.finalize()
        }
    };
    let hash = *hash.as_bytes();

    Ok(hash)
}

fn files_for_dir_cid(
    path: impl Into<PathBuf>,
    cid_ignore: CidIgnoreConfig,
) -> Result<Vec<DataSource>> {
    let dir_base_path = path.into();

    let CidIgnoreConfig {
        include_hidden_files,
        gitignore,
        include_symlinks,
    } = cid_ignore;

    let ordered_paths = walked_files_for_dir_cid(
        dir_base_path,
        include_hidden_files,
        gitignore,
        true,
        include_symlinks,
    )?;

    Ok(ordered_paths)
}

fn ignored_files_for_dir_cid(
    path: impl Into<PathBuf>,
    cid_ignore: CidIgnoreConfig,
) -> Result<Vec<DataSource>> {
    let dir_base_path = path.into();

    let files_all = {
        let include_hidden_files = true;
        let gitignore = false;
        let cidignore = false;
        let include_symlinks = true;

        walked_files_for_dir_cid(
            &dir_base_path,
            include_hidden_files,
            gitignore,
            cidignore,
            include_symlinks,
        )?
    };

    let files_included = files_for_dir_cid(&dir_base_path, cid_ignore)?;

    let ignored_files = files_all
        .into_iter()
        .filter(|d| !files_included.contains(d))
        .collect::<Vec<_>>();

    Ok(ignored_files)
}

fn walked_files_for_dir_cid(
    path: impl Into<PathBuf>,
    include_hidden_files: bool,
    gitignore: bool,
    cidignore: bool,
    follow_links: bool,
) -> Result<Vec<DataSource>> {
    let dir_base_path = path.into();

    let walk = {
        let mut wb = ignore::WalkBuilder::new(&dir_base_path);

        // start with no filters
        wb.standard_filters(false);
        // enable searching parent directories for ignore files (if no ignore files are enabled this has no effect)
        wb.parents(true);
        // if `include_hidden_files == true` then dot files and dot directories are included in the walk
        wb.hidden(!include_hidden_files);
        // if `gitignore == true` then .gitignore files found during the walk are respected
        wb.git_ignore(gitignore);
        // if `cidignore == true` then .cidignore files found during the walk are respected
        // and have higher precedence than .gitignore files
        if cidignore {
            wb.add_custom_ignore_filename(".cidignore");
        }

        wb.follow_links(follow_links);

        wb.build()
    };

    let files = walk
        .map(|x| x.map_err(|e| anyhow::anyhow!(e)))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|d| {
            let path = d.path();
            path.is_file() && (follow_links || !path.is_symlink())
        })
        .map(|d| {
            let path = d.path().to_path_buf();
            let name = path
                .strip_prefix(&dir_base_path)?
                .to_string_lossy()
                .to_string();
            Ok(DataSource::with_name(path, name))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(files)
}

fn sort_data_sources(ds: Vec<DataSource>) -> Vec<DataSource> {
    let mut ds = ds;
    ds.sort_by(|a, b| a.name().cmp(&b.name()));
    ds
}
