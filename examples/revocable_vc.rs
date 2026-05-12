//! End-to-end manual check for `integrity::vc::issue_revocable_vc` against a
//! running vc-status-server instance.
//!
//! Two-step usage:
//!   1. `cargo run --example revocable-vc`
//!      Prints the issuer DID derived from the deterministic seed below.
//!      Mint a JWT for that DID (e.g. `vc-status-server token --issuer <DID>`).
//!   2. `cargo run --example revocable-vc -- <JWT>`
//!      Calls the status server at $VC_STATUS_URL (default
//!      http://localhost:8080) and prints the signed VC JSON.

use std::env;

use anyhow::{Context, Result};
use integrity::{
    signer::{Ed25519Signer, SignerType},
    vc,
};
use tokio::runtime::Runtime;

// Fixed 32-byte Ed25519 seed so the issuer DID is stable across runs. NOT
// FOR PRODUCTION — it's deliberately public so the JWT you mint can be
// reused on every invocation.
const SEED: [u8; 32] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];

const DEFAULT_URL: &str = "http://localhost:8080";

fn main() -> Result<()> {
    let signer = Ed25519Signer::import(&SEED).context("import Ed25519 signer from seed")?;
    let did = signer.did_doc.id.clone();
    println!("issuer DID: {did}");

    let jwt = match env::args().nth(1) {
        Some(j) => j,
        None => {
            println!();
            println!("No JWT argument supplied. Mint one for this issuer, e.g.:");
            println!("  vc-status-server token --issuer {did}");
            println!("Then re-run:");
            println!("  cargo run --example revocable-vc -- <JWT>");
            return Ok(());
        }
    };

    let url = env::var("VC_STATUS_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    println!("status server: {url}");

    let signer_type = SignerType::ED25519(signer);
    let subject = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";

    let runtime = Runtime::new().context("build Tokio runtime")?;
    let signed = runtime.block_on(vc::issue_revocable_vc(subject, signer_type, &url, &jwt))?;

    println!();
    println!("{}", serde_json::to_string_pretty(&signed)?);

    let signed_json = serde_json::to_string(&signed)?;
    println!();
    match runtime.block_on(vc::verify_vc(&signed_json)) {
        Ok(msg) => println!("verify: {msg}"),
        Err(e) => println!("verify failed: {e}"),
    }

    Ok(())
}
