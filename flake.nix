{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    nixpkgs-rust.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs-rust";
    };
  };

  outputs = inputs @ { self, ...}:
    inputs.utils.lib.eachDefaultSystem (system:
      let
        pkgs = import inputs.nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage inputs.naersk { };

        pkgs-rust = import inputs.nixpkgs-rust {
          inherit system;
          overlays = [ inputs.rust-overlay.overlays.default ];
        };

       rust-config = {
          extensions = [ "rust-src" ];
          targets = [ "wasm32-unknown-unknown" ];
        };

        # rust toolchain for services
        rust = (pkgs-rust.rust-bin.fromRustupToolchainFile ./rust-toolchain).override rust-config;

        # rustfmt from rust-nightly used for advanced options in rustfmt
        rustfmt-nightly = pkgs-rust.rust-bin.nightly.latest.rustfmt;


      in
      {
        defaultPackage = naersk-lib.buildPackage ./.;
        devShell = with pkgs; mkShell {
          buildInputs = [
            cargo
            chromedriver
            geckodriver
            just
            openssl
            prek
            pkg-config
            rustfmt-nightly
            rust
            rustPackages.clippy
            wasm-pack
            wasm-bindgen-cli
          ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      }
    );
}
