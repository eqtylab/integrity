# List all available recipes
_:
    @just --list

# Format Rust code using rustfmt
fmt:
    cargo fmt --all --

# Check if code is formatted correctly without modifying files
fmt-check:
    cargo fmt --check

# Build the project for native target
build:
    cargo build

# Build WebAssembly package with wasm-pack
build-wasm:
    RUST_LOG=debug wasm-pack build \
        --mode no-install \
        --no-default-features

# Auto-fix clippy warnings where possible
fix:
    cargo clippy --fix --allow-dirty -- -Dwarnings --no-deps

# Run clippy lints to check code quality
lint:
  cargo clippy --workspace --all-targets -- -Dwarnings --no-deps

# Check that all public items have documentation (warnings only for now)
lint-docs:
    cargo rustdoc --lib -- -W missing_docs -D rustdoc::broken_intra_doc_links

# Run all prek pre-commit hooks on all files
pre-commit:
    prek run --all-files

# Run unit tests with cargo
test:
    cargo test

# Run WASM tests in Node.js and browsers (Chrome, Firefox) Note: for macOS test Safari with --safari
test-wasm:
    wasm-pack test \
        --release \
        --node \
        --headless \
        --chrome \
        --firefox \
        --mode no-install \
        --no-default-features

# Rebuild static JSON-LD context files
update-static-contexts:
    cd static_contexts && make clean && make all

# Update README.md with auto-generated content (Justfile commands, etc.)
readme-update:
    present --in-place README.md

# Check if README.md is up to date with auto-generated content
readme-check: _tmp
    present README.md > tmp/README.md
    diff README.md tmp/README.md

# Run all CI checks (format, build, lint, test)
ci: fmt-check readme-check build build-wasm lint lint-docs test test-wasm

# Called by git pre-push hook
pre-push: fmt-check lint lint-docs readme-check

# Create temporary directory for artifacts
_tmp:
    mkdir -p tmp
