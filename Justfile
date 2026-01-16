_:
    @just --list

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

build:
    cargo build

build-wasm:
    RUST_LOG=debug wasm-pack build \
        --mode no-install \
        --no-default-features

lint:
    cargo clippy -- -Dwarnings --no-deps

fix:
    cargo clippy --fix --allow-dirty -- -Dwarnings --no-deps

test:
    cargo test

test-wasm:
    wasm-pack test \
        --release \
        --node \
        --headless \
        --chrome \
        --firefox \
        --mode no-install \
        --no-default-features
# from macos you can also test safari with --safari

update-static-contexts:
    cd static_contexts && make clean && make all

ci: fmt-check build build-wasm lint test test-wasm

_tmp:
    mkdir -p tmp
