//! End-to-end manual check for the revocable-VC lifecycle against a running
//! vc-status-server instance: issue → check status → revoke → check status.
//!
//! Two-step usage:
//!   1. `cargo run --example revocable-vc`
//!      Prints the issuer DID derived from the deterministic seed below.
//!      Mint a JWT for that DID (e.g. `vc-status-server token --issuer <DID>`).
//!   2. `cargo run --example revocable-vc -- <JWT>`
//!      Issues a revocable VC against the status server at $VC_STATUS_URL
//!      (default http://localhost:8080), checks its status (expected: not
//!      revoked), revokes it via `revoke_vc`, then re-checks (expected:
//!      revoked).

use std::env;

use anyhow::{bail, Context, Result};
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
    runtime.block_on(lifecycle(subject, signer_type, &url, &jwt))
}

/// Drives the full issue → check → revoke → check flow.
async fn lifecycle(subject: &str, signer: SignerType, url: &str, jwt: &str) -> Result<()> {
    // 1. Issue a revocable VC (build → allocate status → sign).
    let signed = vc::issue_revocable_vc(subject, signer, url, jwt).await?;
    let signed_json = serde_json::to_string(&signed)?;

    println!();
    println!("issued VC:");
    println!("{}", serde_json::to_string_pretty(&signed)?);

    println!();
    match vc::verify_vc(&signed_json).await {
        Ok(msg) => println!("verify: {msg}"),
        Err(e) => println!("verify failed: {e}"),
    }

    // The status server signs its status lists with its own did:key. Discover
    // that DID by fetching one of the credential's status lists and reading
    // its `issuer` — `check_credential_status` pins it to refuse a swapped
    // bitstring.
    let signer_did = status_list_signer(&signed_json).await?;
    println!("status-list signer: {signer_did}");

    // 2. Status before revocation — expected: not revoked.
    let before = vc::check_credential_status(&signed_json, &signer_did).await?;
    println!();
    println!("status before revoke: {before:?}");

    // 3. Revoke (one-way).
    let revoked = vc::revoke_vc(&signed_json, url, jwt).await?;
    println!("revoke_vc -> server-confirmed revocation bit: {revoked}");

    // 4. Status after revocation — expected: revoked.
    let after = vc::check_credential_status(&signed_json, &signer_did).await?;
    println!("status after revoke:  {after:?}");

    Ok(())
}

/// Fetches the credential's first status list and returns its issuer DID —
/// the DID `check_credential_status` should pin the list signature to.
async fn status_list_signer(vc_json: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(vc_json)?;

    // `credentialStatus` is an array for revocable VCs; tolerate a bare object.
    let cs = &v["credentialStatus"];
    let entry = cs.get(0).filter(|e| !e.is_null()).unwrap_or(cs);
    let list_url = entry["statusListCredential"]
        .as_str()
        .context("VC has no credentialStatus[..].statusListCredential")?;

    // dev-dep reqwest has no `json` feature — read text and parse with serde.
    let body = reqwest::Client::new()
        .get(list_url)
        .send()
        .await
        .with_context(|| format!("GET status list at {list_url}"))?
        .text()
        .await?;
    let list: serde_json::Value = serde_json::from_str(&body)?;

    match &list["issuer"] {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Object(o) => o["id"]
            .as_str()
            .map(str::to_string)
            .context("status list issuer object has no `id`"),
        _ => bail!("status list at {list_url} has no `issuer`"),
    }
}
