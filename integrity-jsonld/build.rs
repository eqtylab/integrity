//! Emit `cargo:rerun-if-changed` for every file under `static_contexts/`.
//!
//! `src/loader.rs` embeds that directory tree with `include_dir!`. On stable
//! Rust the macro does not track its inputs for recompilation, so without this
//! build script adding or editing a context file would not trigger a rebuild.

use std::path::Path;

fn main() {
    let dir = Path::new("static_contexts");
    emit_rerun_if_changed(dir);
}

fn emit_rerun_if_changed(path: &Path) {
    // Watching the directory itself catches added/removed files (its mtime
    // changes); recursing catches edits to existing files.
    println!("cargo:rerun-if-changed={}", path.display());

    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            emit_rerun_if_changed(&child);
        } else {
            println!("cargo:rerun-if-changed={}", child.display());
        }
    }
}
