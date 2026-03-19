use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use base64::engine::{general_purpose::STANDARD as BASE64, Engine};
use clap::{Args, Parser, Subcommand};
use integrity::{
    signer::{SignerType, YubiKeySigner, YubikeyEvidenceBundle},
    vc,
};
use openssl::{
    stack::Stack,
    x509::{store::X509StoreBuilder, X509StoreContext, X509},
};
use reqwest::blocking::Client;
use tokio::runtime::Runtime;

const YUBICO_ROOT_CAS_URL: &str = "https://developers.yubico.com/PKI/yubico-ca-certs.txt";
const YUBICO_INTERMEDIATE_CAS_URL: &str =
    "https://developers.yubico.com/PKI/yubico-intermediate.pem";

#[derive(Debug, Parser)]
#[command(name = "yubikey-example")]
#[command(bin_name = "yubikey-example")]
#[command(about = "Test YubiKey signing and attestation evidence flows")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum Command {
    /// Sign a message with a YubiKey-backed PIV slot key.
    Sign(SignArgs),
    /// Generate a YubiKey evidence bundle as JSON.
    GenerateEvidence(GenerateEvidenceArgs),
    /// Verify a YubiKey evidence bundle against Yubico CA certificates.
    VerifyEvidence(VerifyEvidenceArgs),
    /// Issue and sign a Verifiable Credential with the YubiKey signer.
    SignVc(SignVcArgs),
    /// Verify a Verifiable Credential JSON document.
    VerifyVc(VerifyVcArgs),
}

#[derive(Debug, Clone, Args)]
struct YubiKeyArgs {
    /// Optional YubiKey serial number when multiple keys are connected.
    #[arg(long)]
    serial: Option<u32>,
    /// PIV slot: signature|authentication|key-management|card-authentication or raw hex (for example 9c).
    #[arg(long, default_value = "signature", value_parser = parse_slot)]
    slot: u8,
    /// Optional YubiKey PIN.
    #[arg(long)]
    pin: Option<String>,
}

#[derive(Debug, Args)]
struct SignArgs {
    #[command(flatten)]
    yubikey: YubiKeyArgs,
    /// Message to sign.
    #[arg(long, default_value = "integrity yubikey signer test")]
    message: String,
}

#[derive(Debug, Args)]
struct GenerateEvidenceArgs {
    #[command(flatten)]
    yubikey: YubiKeyArgs,
    /// Optional output file for the generated JSON.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct VerifyEvidenceArgs {
    /// Evidence bundle JSON file. If omitted, JSON is read from stdin.
    #[arg(long)]
    evidence: Option<PathBuf>,
    /// URL for Yubico root CA certificates (PEM bundle).
    #[arg(long, default_value = YUBICO_ROOT_CAS_URL)]
    roots_url: String,
    /// URL for Yubico intermediate certificates (PEM bundle).
    #[arg(long, default_value = YUBICO_INTERMEDIATE_CAS_URL)]
    intermediates_url: String,
}

#[derive(Debug, Args)]
struct SignVcArgs {
    #[command(flatten)]
    yubikey: YubiKeyArgs,
    /// VC credential subject identifier (for example a DID).
    #[arg(long)]
    subject: String,
    /// Optional output file for the signed VC JSON.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct VerifyVcArgs {
    /// VC JSON file. If omitted, JSON is read from stdin.
    #[arg(long)]
    vc: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Sign(args) => run_sign(args),
        Command::GenerateEvidence(args) => run_generate_evidence(args),
        Command::VerifyEvidence(args) => run_verify_evidence(args),
        Command::SignVc(args) => run_sign_vc(args),
        Command::VerifyVc(args) => run_verify_vc(args),
    }
}

fn run_sign(args: SignArgs) -> Result<()> {
    let slot = args
        .yubikey
        .slot
        .try_into()
        .map_err(|_| anyhow!("invalid PIV slot identifier: 0x{:02x}", args.yubikey.slot))?;
    let signer = YubiKeySigner::create(slot, args.yubikey.serial, args.yubikey.pin)?;
    let signature = signer.sign_sync(args.message.as_bytes())?;

    println!("did: {}", signer.did_doc.id);
    println!("slot: 0x{:02x}", args.yubikey.slot);
    println!("message: {}", args.message);
    println!("signature_hex: {}", encode_hex(&signature));

    Ok(())
}

fn run_generate_evidence(args: GenerateEvidenceArgs) -> Result<()> {
    let slot = args
        .yubikey
        .slot
        .try_into()
        .map_err(|_| anyhow!("invalid PIV slot identifier: 0x{:02x}", args.yubikey.slot))?;
    let signer = YubiKeySigner::create(slot, args.yubikey.serial, args.yubikey.pin)?;
    let bundle = signer.evidence_bundle_sync()?;
    let json = serde_json::to_string_pretty(&bundle)?;

    if let Some(out) = args.out {
        fs::write(&out, json).with_context(|| format!("failed to write {}", out.display()))?;
        println!("{}", out.display());
    } else {
        println!("{json}");
    }

    Ok(())
}

fn run_verify_evidence(args: VerifyEvidenceArgs) -> Result<()> {
    let bundle = load_evidence_bundle(args.evidence.as_deref())?;
    verify_evidence_bundle(&bundle, &args.roots_url, &args.intermediates_url)?;

    println!("evidence verified");
    Ok(())
}

fn run_sign_vc(args: SignVcArgs) -> Result<()> {
    let slot = args
        .yubikey
        .slot
        .try_into()
        .map_err(|_| anyhow!("invalid PIV slot identifier: 0x{:02x}", args.yubikey.slot))?;
    let signer = YubiKeySigner::create(slot, args.yubikey.serial, args.yubikey.pin)?;
    let signer_type = SignerType::YubiKeySigner(signer);

    let runtime = build_runtime()?;
    let credential = runtime.block_on(vc::issue_vc(&args.subject, signer_type))?;
    let json = serde_json::to_string_pretty(&credential)?;

    if let Some(out) = args.out {
        fs::write(&out, json).with_context(|| format!("failed to write {}", out.display()))?;
        println!("{}", out.display());
    } else {
        println!("{json}");
    }

    Ok(())
}

fn run_verify_vc(args: VerifyVcArgs) -> Result<()> {
    let vc_json = load_json_from_file_or_stdin(
        args.vc.as_deref(),
        "VC JSON",
        "no VC JSON provided; pass --vc <file> or pipe JSON on stdin",
    )?;

    let runtime = build_runtime()?;
    let result = runtime.block_on(vc::verify_vc(&vc_json))?;
    println!("{result}");

    Ok(())
}

fn load_evidence_bundle(path: Option<&Path>) -> Result<YubikeyEvidenceBundle> {
    let json = load_json_from_file_or_stdin(
        path,
        "evidence file",
        "no evidence JSON provided; pass --evidence <file> or pipe JSON on stdin",
    )?;

    serde_json::from_str(&json).context("failed to parse YubiKey evidence bundle JSON")
}

fn load_json_from_file_or_stdin(
    path: Option<&Path>,
    file_label: &str,
    empty_error: &str,
) -> Result<String> {
    match path {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read {file_label} {}", path.display())),
        None => {
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .context("failed to read JSON from stdin")?;
            if input.trim().is_empty() {
                return Err(anyhow!(empty_error.to_owned()));
            }
            Ok(input)
        }
    }
}

fn build_runtime() -> Result<Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build Tokio runtime")
}

fn verify_evidence_bundle(
    bundle: &YubikeyEvidenceBundle,
    roots_url: &str,
    intermediates_url: &str,
) -> Result<()> {
    let signing_key_cert_der = BASE64
        .decode(bundle.signing_key_cert_der_base64.as_bytes())
        .context("failed to decode signing key certificate (base64 DER)")?;
    let issuer_cert_der = BASE64
        .decode(bundle.signing_key_cert_issuer_der_base64.as_bytes())
        .context("failed to decode signing key issuer certificate (base64 DER)")?;

    let signing_key_cert = X509::from_der(&signing_key_cert_der)
        .context("failed to parse signing key certificate DER")?;
    let issuer_cert =
        X509::from_der(&issuer_cert_der).context("failed to parse issuer certificate DER")?;

    // Ensure the signer cert is directly signed by the provided issuer cert.
    let issuer_public_key = issuer_cert
        .public_key()
        .context("failed to parse issuer certificate public key")?;
    let signer_signed_by_issuer = signing_key_cert
        .verify(&issuer_public_key)
        .context("failed to verify signing key certificate signature")?;
    if !signer_signed_by_issuer {
        return Err(anyhow!(
            "signing key certificate is not signed by the provided issuer certificate"
        ));
    }

    let client = Client::builder()
        .build()
        .context("failed to build HTTP client for certificate download")?;
    let roots_text = download_text(&client, roots_url)?;
    let intermediates_text = download_text(&client, intermediates_url)?;

    let root_certs = parse_pem_certificates(&roots_text)
        .with_context(|| format!("failed to parse root certificates from {roots_url}"))?;
    let intermediate_certs = parse_pem_certificates(&intermediates_text).with_context(|| {
        format!("failed to parse intermediate certificates from {intermediates_url}")
    })?;

    let mut trust_store_builder =
        X509StoreBuilder::new().context("failed to construct X509 trust store")?;
    for cert in root_certs {
        trust_store_builder
            .add_cert(cert)
            .context("failed to add root certificate to trust store")?;
    }
    let trust_store = trust_store_builder.build();

    let mut chain = Stack::new().context("failed to construct certificate chain stack")?;
    chain
        .push(issuer_cert)
        .context("failed to add issuer certificate to chain")?;
    for cert in intermediate_certs {
        chain
            .push(cert)
            .context("failed to add intermediate certificate to chain")?;
    }

    let mut verify_context =
        X509StoreContext::new().context("failed to construct X509 verify context")?;
    let verified = verify_context
        .init(&trust_store, &signing_key_cert, &chain, |context| {
            context.verify_cert()
        })
        .context("failed while verifying evidence certificate chain")?;
    if !verified {
        return Err(anyhow!(
            "evidence chain verification failed against Yubico CAs"
        ));
    }

    Ok(())
}

fn download_text(client: &Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to download {url}"))?
        .error_for_status()
        .with_context(|| format!("download returned error status for {url}"))?;

    response
        .text()
        .with_context(|| format!("failed to decode response body from {url}"))
}

fn parse_pem_certificates(input: &str) -> Result<Vec<X509>> {
    let mut certificates = Vec::new();
    for pem in extract_pem_blocks(input) {
        let cert = X509::from_pem(pem.as_bytes())
            .context("failed to parse certificate PEM block from downloaded data")?;
        certificates.push(cert);
    }

    if certificates.is_empty() {
        return Err(anyhow!("no PEM certificates found"));
    }

    Ok(certificates)
}

fn extract_pem_blocks(input: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut inside_block = false;

    for line in input.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            inside_block = true;
            current.clear();
        }

        if inside_block {
            current.push_str(line);
            current.push('\n');
        }

        if line.contains("-----END CERTIFICATE-----") && inside_block {
            blocks.push(current.clone());
            inside_block = false;
            current.clear();
        }
    }

    blocks
}

fn parse_slot(slot: &str) -> Result<u8, String> {
    let slot_value = match slot.to_ascii_lowercase().as_str() {
        "signature" => 0x9c,
        "authentication" => 0x9a,
        "key-management" | "key_management" | "keymanagement" => 0x9d,
        "card-authentication" | "card_authentication" | "cardauthentication" => 0x9e,
        other => {
            let slot_hex = other.strip_prefix("0x").unwrap_or(other);
            u8::from_str_radix(slot_hex, 16).map_err(|_| format!("unsupported slot '{slot}'"))?
        }
    };

    Ok(slot_value)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
