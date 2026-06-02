#[cfg(not(target_arch = "wasm32"))]
mod signer_adapter;

use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use anyhow::{anyhow, bail};
#[cfg(not(target_arch = "wasm32"))]
use chrono::{DateTime, Utc};
#[cfg(not(target_arch = "wasm32"))]
use integrity_signer::SignerType;
#[cfg(not(target_arch = "wasm32"))]
use serde_json::Value;
/// Re-export so callers (FFI, lineage-models, examples) don't depend on ssi
/// crate paths directly.
#[cfg(not(target_arch = "wasm32"))]
pub use ssi::claims::vc::v2::syntax::JsonCredential as Credential;
#[cfg(not(target_arch = "wasm32"))]
use ssi::{
    claims::{
        data_integrity::{AnySuite, CryptographicSuite, DataIntegrity, ProofOptions},
        vc::v2::syntax::JsonCredential,
        SignatureEnvironment, VerificationParameters,
    },
    dids::{AnyDidMethod, VerificationMethodDIDResolver},
    verification_methods::{AnyMethod, ProofPurpose},
};

#[cfg(not(target_arch = "wasm32"))]
use crate::signer_adapter::IntegritySigner;

/// A signed VC: a `JsonCredential` (W3C VC 2.0 syntax) bundled with one or
/// more Data-Integrity proofs from any supported cryptosuite.
#[cfg(not(target_arch = "wasm32"))]
pub type SignedVc = DataIntegrity<JsonCredential, AnySuite>;

/// Build an unsigned `JsonCredential` with the EQTY-flavored `@context`
/// bundle attached, ready to be passed to [`sign_vc`].
///
/// `@context` entries on the returned credential:
///   - `https://www.w3.org/ns/credentials/v2` — added by
///     `JsonCredential::default` (required by VC 2.0).
///   - `https://w3id.org/security/v2` — defines Data-Integrity proof
///     terms not covered by the v2 base context.
///   - `{"@vocab": "https://eqtylab.io/terms/"}` — an inline vocabulary
///     mapping for the EQTY-namespaced terms used by VComp evidence and
///     policy compliance VCs (`EqtyVComp*Evidence`, `report`,
///     `certificateChain`, `policy`, `statements`, …). Using `@vocab`
///     rather than a fetched/CID-pinned context document keeps the VC
///     self-describing: any term not already defined by the v2/security
///     contexts expands under this namespace, so no external schema is
///     required to canonicalize or verify.
///
/// `subject` must be a JSON object. Bare-identifier callers should wrap
/// as `serde_json::json!({"id": id})` before passing.
///
/// All evidence entries are deserialized into the default
/// `MaybeIdentifiedTypedObject` evidence type, which keeps `type` typed
/// and routes any extra keys (`report`, `certificateChain`, …) into
/// `extra_properties`.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_unsigned_with_eqty_contexts(
    id: &str,
    issuer_did: &str,
    subject: Value,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    evidence: Vec<Value>,
) -> Result<JsonCredential> {
    use iref::{IriRefBuf, UriBuf};
    use ssi::{
        claims::vc::syntax::{IdOr, MaybeIdentifiedTypedObject, NonEmptyObject, NonEmptyVec},
        json_ld::syntax::ContextEntry,
    };

    let subject_non_empty: NonEmptyObject = serde_json::from_value(subject)
        .map_err(|e| anyhow!("credential subject must be a non-empty JSON object: {e}"))?;

    let id_uri = UriBuf::new(id.as_bytes().to_vec())
        .map_err(|e| anyhow!("invalid credential id '{id}': {e:?}"))?;
    let issuer_uri = UriBuf::new(issuer_did.as_bytes().to_vec())
        .map_err(|e| anyhow!("invalid issuer DID '{issuer_did}': {e:?}"))?;

    let mut credential = JsonCredential::new(
        Some(id_uri),
        IdOr::Id(issuer_uri),
        NonEmptyVec::new(subject_non_empty),
    );

    if let Some(dt) = valid_from {
        credential.valid_from = Some(xsd_types::DateTimeStamp::from(dt).into());
    }
    if let Some(dt) = valid_until {
        credential.valid_until = Some(xsd_types::DateTimeStamp::from(dt).into());
    }

    // `https://w3id.org/security/v2` — Data-Integrity proof terms not
    // covered by the v2 base context.
    credential.context.insert(ContextEntry::IriRef(
        IriRefBuf::new("https://w3id.org/security/v2".to_string())
            .map_err(|e| anyhow!("invalid context IRI: {e:?}"))?,
    ));

    // EQTY-namespaced terms (`EqtyVComp*Evidence`, `report`,
    // `certificateChain`, `policy`, `statements`, …) are mapped with an
    // inline `@vocab` instead of a CID-pinned context document, so the VC
    // is self-describing and needs no external schema to canonicalize.
    // Terms already defined by the v2/security contexts keep their
    // mappings; anything else expands under this namespace.
    let eqty_vocab: ContextEntry = serde_json::from_value(serde_json::json!({
        "@vocab": "https://eqtylab.io/terms/"
    }))
    .map_err(|e| anyhow!("failed to build EQTY @vocab context entry: {e}"))?;
    credential.context.insert(eqty_vocab);

    credential.evidence = evidence
        .into_iter()
        .map(|v| {
            serde_json::from_value::<MaybeIdentifiedTypedObject>(v)
                .map_err(|e| anyhow!("invalid evidence entry: {e}"))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(credential)
}

/// Creates and signs a Verifiable Credential.
///
/// # Arguments
/// * `subject` - Credential subject. If it parses as a JSON object, used
///   directly; otherwise wrapped as `{"id": subject}`.
/// * `signer` - Signer for the credential. The issuer DID is derived from
///   `signer.get_did_doc().id`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn issue_vc(subject: &str, signer: SignerType) -> Result<SignedVc> {
    log::debug!("Issuing VC for '{subject}'");
    let adapter = IntegritySigner::new(signer);
    let unsigned = build_unsigned(subject, &adapter)?;
    log::trace!("Unsigned VC: {}", serde_json::to_string_pretty(&unsigned)?);
    sign(unsigned, adapter).await
}

/// Creates and signs a revocable Verifiable Credential.
///
/// Builds an unsigned VC, posts it to the vc-status-server at
/// `status_server_url` to allocate status-list slots, then signs the
/// returned VC (which now carries `credentialStatus` entries) and returns
/// it as a typed `SignedVc`.
///
/// The server's response shape (multi-entry `credentialStatus`) is now
/// natively supported by `JsonCredential` v2.
///
/// This is a thin wrapper over [`allocate_credential_status`] (the
/// allocate-and-augment step) followed by signing; callers holding a
/// pre-built unsigned credential should reach for that helper directly.
#[cfg(not(target_arch = "wasm32"))]
pub async fn issue_revocable_vc(
    subject: &str,
    signer: SignerType,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<SignedVc> {
    log::debug!("Issuing revocable VC for '{subject}' via {status_server_url}");

    let adapter = IntegritySigner::new(signer);
    let unsigned = build_unsigned(subject, &adapter)?;
    let allocated =
        allocate_credential_status(unsigned, status_server_url, status_server_jwt).await?;
    sign(allocated, adapter).await
}

/// Allocates credential-status slots for an already-built unsigned
/// `JsonCredential` against a vc-status-server, returning the augmented
/// unsigned credential.
///
/// This is the lower-level half of [`issue_revocable_vc`], exposed so
/// callers who assemble their own credential — e.g. via
/// [`build_unsigned_with_eqty_contexts`], or any other path that yields a
/// [`Credential`] — can opt into revocability without going through the
/// subject-string builder. It POSTs the serialized credential to
/// `{status_server_url}/credentials/status/allocate` with
/// `status_server_jwt` as a Bearer token; the server reserves a slot in
/// its revocation and suspension bitstrings and echoes the credential
/// back with the matching `credentialStatus` entries appended.
///
/// The returned credential is still **unsigned** — feed it straight into
/// [`sign_vc`] to obtain a [`SignedVc`]. The server's response shape
/// (multi-entry `credentialStatus`) is natively supported by
/// `JsonCredential` v2, so the augmented credential round-trips through
/// serde without manual JSON surgery.
///
/// # Errors
///
/// Returns an error if the credential can't be serialized, the HTTP
/// request fails, the server responds non-2xx (its response body is
/// surfaced verbatim), or the response body doesn't parse back as a
/// `JsonCredential`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn allocate_credential_status(
    unsigned: JsonCredential,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<JsonCredential> {
    let unsigned_json = serde_json::to_string(&unsigned)?;
    log::trace!("Unsigned VC sent to status server: {unsigned_json}");

    let url = format!(
        "{}/credentials/status/allocate",
        status_server_url.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(status_server_jwt)
        .header("Content-Type", "application/json")
        .body(unsigned_json)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;
    log::trace!("Status server response ({status}): {body}");

    if !status.is_success() {
        bail!("status server allocate failed ({status}): {body}");
    }

    serde_json::from_str(&body)
        .map_err(|e| anyhow!("failed to parse allocated VC as JsonCredential: {e}. Body: {body}"))
}

/// Signs an already-built unsigned `JsonCredential`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sign_vc(unsigned: JsonCredential, signer: SignerType) -> Result<SignedVc> {
    let adapter = IntegritySigner::new(signer);
    sign(unsigned, adapter).await
}

/// Verifies a signed VC's Data-Integrity proof.
///
/// **Cryptographic proof check only.** This function does not look at
/// the `credentialStatus` field, never fetches a status-list credential,
/// and never reads a revocation bit. To learn whether a credential has
/// been revoked or suspended, call [`check_credential_status`]
/// separately.
///
/// The split is deliberate. Proof verification here is offline (modulo
/// DID resolution, which for `did:key` is also offline) and
/// deterministic: it is purely a function of the input bytes plus the
/// bundled JSON-LD contexts. Status checking necessarily fetches
/// external bitstring lists over HTTP and so is treated as an opt-in
/// operation with different failure modes and security posture.
///
/// Returns a human-readable summary on success.
#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_vc(vc_json: &str) -> Result<String> {
    if is_legacy_vc(vc_json) {
        return verify_legacy_vc(vc_json).await;
    }

    let vc: SignedVc = serde_json::from_str(vc_json)?;
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let loader = integrity_jsonld::loader::loader(None)?;
    let params = VerificationParameters::from_resolver(resolver).with_json_ld_loader(loader);
    let outcome = vc
        .verify(params)
        .await
        .map_err(|e| anyhow!("verification error: {e}"))?;
    outcome.map_err(|e| anyhow!("invalid VC proof: {e:?}"))?;
    Ok("VC verification result: ok".to_string())
}

/// Outcome of a credential-status check.
///
/// Each field is `None` when the credential carries no `credentialStatus`
/// entry for that purpose, `Some(false)` when the status bit is clear, and
/// `Some(true)` when set. If a credential has multiple entries for the
/// same purpose (uncommon but spec-legal), their bits are OR'd — any one
/// set marks the credential as revoked/suspended.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialStatus {
    pub revoked: Option<bool>,
    pub suspended: Option<bool>,
}

/// Reads the bits referenced by the credential's `credentialStatus`
/// entries and reports whether revocation / suspension are set.
///
/// **Does not verify the input credential's own Data-Integrity proof.**
/// By design — proof verification belongs to [`verify_vc`]. Status truth
/// and signature truth are separate concerns; bundling them into one
/// call would couple two independent failure modes ("revoked" vs
/// "forged") and make the proof check implicit. Pair both functions
/// when you need both answers.
///
/// For each `credentialStatus` entry, fetches the referenced
/// `BitstringStatusListCredential`, **verifies that credential's own
/// Data-Integrity proof**, confirms it was signed by `status_list_signer`,
/// decodes the multibase/gzipped bitstring, and reads the bit at
/// `statusListIndex`. The two purposes (`"revocation"`, `"suspension"`)
/// are reported independently in the returned [`CredentialStatus`];
/// multiple entries for the same purpose are OR'd (any set ⇒ revoked).
///
/// # Required: `status_list_signer`
///
/// The DID expected to have signed every fetched status-list credential
/// — typically the issuer's DID, or the status server's DID if the
/// issuer delegates status-list signing. We refuse to read a status
/// from a list that is unsigned, signed by a DID other than
/// `status_list_signer`, or whose proof doesn't verify. Without this
/// pin, an attacker who can intercept the GET (DNS hijack, compromised
/// CDN, MITM on a non-TLS hop) could substitute their own valid
/// DID-signed bitstring and silently unflip the revocation bit. The
/// comparison is on the controller DID — everything before `#` in the
/// proof's `verificationMethod` IRI — so key rotation within the same
/// DID document is accepted; a different controller is not.
///
/// # No-status / legacy / unsupported cases
///
/// - No `credentialStatus` field, `null`, or empty array → both fields
///   `None`. (`status_list_signer` is ignored in this case.)
/// - Legacy (pre-ssi-0.16) VCs → both fields `None`: revocable VCs are
///   a post-VC-2.0 feature and legacy VCs by construction don't carry
///   `credentialStatus`.
/// - `"message"`-purpose entries are skipped (out of scope here).
#[cfg(not(target_arch = "wasm32"))]
pub async fn check_credential_status(
    vc_json: &str,
    status_list_signer: &str,
) -> Result<CredentialStatus> {
    check_credential_status_inner(vc_json, Some(status_list_signer), false).await
}

/// Which status bit a [`update_credential_status`] write targets.
///
/// A deliberate local mirror of the two *writable* purposes. We don't
/// re-export `ssi_status`'s `StatusPurpose` (which also carries a
/// `Message` variant that has no meaning for a revoke/suspend write), so
/// the crate's public surface stays free of `ssi` crate paths — matching
/// the policy behind the local [`CredentialStatus`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusPurpose {
    Revocation,
    Suspension,
}

#[cfg(not(target_arch = "wasm32"))]
impl StatusPurpose {
    /// The wire string the vc-status-server expects in `statusPurpose`,
    /// and the value `credentialStatus` entries are matched against.
    fn as_str(self) -> &'static str {
        match self {
            StatusPurpose::Revocation => "revocation",
            StatusPurpose::Suspension => "suspension",
        }
    }
}

/// Flips a credential's revocation or suspension bit on the
/// vc-status-server.
///
/// The write-side counterpart to [`check_credential_status`]: where that
/// function fetches a bitstring and reads a bit, this asks the server that
/// owns the bitstring to set or clear it. It POSTs to
/// `{status_server_url}/credentials/status` with `status_server_jwt` as a
/// Bearer token, identifying the credential by its top-level `id` and
/// forwarding the matching `credentialStatus` entry verbatim so the server
/// can cross-check it against the allocation it recorded at issuance.
///
/// `status = true` sets the bit (revoked / suspended); `status = false`
/// clears it. Returns the server-confirmed resulting bit (from the
/// `{"status": <bool>}` response) — which, for an idempotent no-op, equals
/// the value you passed.
///
/// # Revocation is one-way
///
/// The server refuses to clear a `revocation` bit once set (it answers
/// `409 revocation_irreversible`, surfaced here as an error). Suspension
/// is freely reversible — see [`suspend_vc`] / [`unsuspend_vc`]. This
/// asymmetry is why the purpose and `status` are explicit parameters
/// rather than the API implying a symmetry the server doesn't honor.
///
/// # Entry selection
///
/// The credential must carry exactly one `credentialStatus` entry whose
/// `statusPurpose` matches `purpose`. The whole entry object is forwarded
/// as-is (the server reads only `type`, `statusPurpose`, `statusListIndex`
/// and `statusListCredential` and ignores the rest, so the entry's `id`
/// rides along harmlessly). It is an error if the credential has no `id`,
/// no entry for the requested purpose, or more than one — a write can't
/// guess which allocation to flip. Legacy (pre-ssi-0.16) VCs never carry
/// `credentialStatus` and are rejected outright.
///
/// # Errors
///
/// Returns an error if `vc_json` isn't valid JSON, lacks a top-level
/// `id`, is a legacy VC, has zero or multiple matching entries, the HTTP
/// request fails, or the server responds non-2xx (its response body is
/// surfaced verbatim, including the `{"error","message"}` payload).
#[cfg(not(target_arch = "wasm32"))]
pub async fn update_credential_status(
    vc_json: &str,
    purpose: StatusPurpose,
    status: bool,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<bool> {
    if is_legacy_vc(vc_json) {
        bail!("legacy VCs do not carry credentialStatus; nothing to update");
    }

    let v: Value =
        serde_json::from_str(vc_json).map_err(|e| anyhow!("input is not valid JSON: {e}"))?;

    let credential_id = v
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("credential has no top-level `id`; cannot update status"))?;

    let purpose_str = purpose.as_str();
    let entries: Vec<&Value> = match v.get("credentialStatus") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => arr.iter().collect(),
        Some(single) => vec![single],
    };
    let mut matching = entries
        .into_iter()
        .filter(|e| e.get("statusPurpose").and_then(Value::as_str) == Some(purpose_str));
    let entry = matching.next().ok_or_else(|| {
        anyhow!("credential has no `{purpose_str}` credentialStatus entry to update")
    })?;
    if matching.next().is_some() {
        bail!(
            "credential has multiple `{purpose_str}` credentialStatus entries; \
             refusing to guess which to update"
        );
    }

    let body = serde_json::json!({
        "credentialId": credential_id,
        "credentialStatus": entry,
        "status": status,
    });

    let url = format!(
        "{}/credentials/status",
        status_server_url.trim_end_matches('/')
    );
    log::debug!(
        "Updating credential status for '{credential_id}' ({purpose_str}={status}) via {url}"
    );

    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(status_server_jwt)
        .json(&body)
        .send()
        .await?;

    let http_status = resp.status();
    let resp_body = resp.text().await?;
    log::trace!("Status server response ({http_status}): {resp_body}");

    if !http_status.is_success() {
        bail!("status server update failed ({http_status}): {resp_body}");
    }

    let parsed: Value = serde_json::from_str(&resp_body)
        .map_err(|e| anyhow!("failed to parse status update response: {e}. Body: {resp_body}"))?;
    parsed
        .get("status")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("status update response missing boolean `status`: {resp_body}"))
}

/// Revokes a credential — sets its `revocation` bit on the
/// vc-status-server. One-way: a revoked credential can't be un-revoked.
///
/// Convenience wrapper over [`update_credential_status`]. See it for
/// entry-selection rules and errors.
#[cfg(not(target_arch = "wasm32"))]
pub async fn revoke_vc(
    vc_json: &str,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<bool> {
    update_credential_status(
        vc_json,
        StatusPurpose::Revocation,
        true,
        status_server_url,
        status_server_jwt,
    )
    .await
}

/// Suspends a credential — sets its `suspension` bit on the
/// vc-status-server. Reversible via [`unsuspend_vc`].
///
/// Convenience wrapper over [`update_credential_status`]. See it for
/// entry-selection rules and errors.
#[cfg(not(target_arch = "wasm32"))]
pub async fn suspend_vc(
    vc_json: &str,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<bool> {
    update_credential_status(
        vc_json,
        StatusPurpose::Suspension,
        true,
        status_server_url,
        status_server_jwt,
    )
    .await
}

/// Un-suspends a credential — clears its `suspension` bit on the
/// vc-status-server.
///
/// Convenience wrapper over [`update_credential_status`]. See it for
/// entry-selection rules and errors.
#[cfg(not(target_arch = "wasm32"))]
pub async fn unsuspend_vc(
    vc_json: &str,
    status_server_url: &str,
    status_server_jwt: &str,
) -> Result<bool> {
    update_credential_status(
        vc_json,
        StatusPurpose::Suspension,
        false,
        status_server_url,
        status_server_jwt,
    )
    .await
}

/// Test-only entrypoint behind [`check_credential_status`].
///
/// - `status_list_signer = Some(did)` enforces the signer pin documented
///   on [`check_credential_status`].
/// - `status_list_signer = None` skips the pin entirely. **Never** pass
///   `None` outside tests: doing so accepts any valid DID-signed list,
///   defeating the security invariant the public entrypoint exists to
///   enforce.
/// - `allow_unsecured = true` accepts status-list credentials that
///   carry no proof at all (used so wiremock tests don't have to sign
///   their fixtures). Implies trusting the transport; do not set in
///   production.
#[cfg(not(target_arch = "wasm32"))]
async fn check_credential_status_inner(
    vc_json: &str,
    status_list_signer: Option<&str>,
    allow_unsecured: bool,
) -> Result<CredentialStatus> {
    use ssi::claims::data_integrity::{self, AnySuite, DataIntegrity};
    use ssi_status::{
        bitstring_status_list::{
            BitstringStatusListCredential, BitstringStatusListEntry, StatusPurpose as BsPurpose,
        },
        StatusMap,
    };

    if is_legacy_vc(vc_json) {
        return Ok(CredentialStatus {
            revoked: None,
            suspended: None,
        });
    }

    // Pull `credentialStatus` straight off the input JSON via serde. We
    // deliberately do NOT route this through `ssi_status::AnyEntrySet`,
    // because that path parses the whole credential as a
    // `BitstringStatusListEntrySetCredential` and re-runs Data-Integrity
    // proof verification on the input as a side effect — which would
    // silently couple this function to `verify_vc`'s job. Status
    // checking and proof verification are intentionally separate.
    let v: Value =
        serde_json::from_str(vc_json).map_err(|e| anyhow!("input is not valid JSON: {e}"))?;
    let entries: Vec<BitstringStatusListEntry> = match v.get("credentialStatus") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|e| serde_json::from_value(e.clone()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| anyhow!("malformed credentialStatus entry: {e}"))?,
        Some(single) => vec![serde_json::from_value(single.clone())
            .map_err(|e| anyhow!("malformed credentialStatus entry: {e}"))?],
    };
    if entries.is_empty() {
        return Ok(CredentialStatus {
            revoked: None,
            suspended: None,
        });
    }

    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let loader = integrity_jsonld::loader::loader(None)?;
    let verifier = VerificationParameters::from_resolver(resolver).with_json_ld_loader(loader);
    let http = reqwest::Client::new();

    let mut revoked: Option<bool> = None;
    let mut suspended: Option<bool> = None;

    for entry in &entries {
        let slot = match entry.status_purpose {
            BsPurpose::Revocation => &mut revoked,
            BsPurpose::Suspension => &mut suspended,
            BsPurpose::Message => continue,
        };

        let url = &entry.status_list_credential;
        let bytes = http
            .get(url.as_str())
            .send()
            .await
            .map_err(|e| anyhow!("failed to GET status list at {url}: {e}"))?
            .bytes()
            .await
            .map_err(|e| anyhow!("failed to read status list body from {url}: {e}"))?;

        let vc: DataIntegrity<BitstringStatusListCredential, AnySuite> =
            data_integrity::from_json_slice(&bytes)
                .map_err(|e| anyhow!("malformed status list at {url}: {e}"))?;

        if vc.proofs.is_empty() {
            if !allow_unsecured {
                bail!("status list at {url} is unsigned; refusing to trust it");
            }
        } else {
            // Cryptographic verification first ...
            vc.verify(&verifier)
                .await
                .map_err(|e| anyhow!("verification error for status list at {url}: {e}"))?
                .map_err(|e| anyhow!("invalid status list proof at {url}: {e:?}"))?;

            // ... then signer pinning: at least one proof must be from
            // the DID the caller approved. Compare on the controller
            // portion of the verificationMethod IRI (everything before
            // `#`) so key-id rotations within the same DID document
            // still pass.
            if let Some(expected) = status_list_signer {
                let signed_by_expected = vc.proofs.iter().any(|p| {
                    let vm = p.verification_method.id().as_str();
                    let controller = vm.split_once('#').map_or(vm, |(c, _)| c);
                    controller == expected
                });
                if !signed_by_expected {
                    let actual: Vec<&str> = vc
                        .proofs
                        .iter()
                        .map(|p| p.verification_method.id().as_str())
                        .collect();
                    bail!(
                        "status list at {url} not signed by expected DID `{expected}`; \
                         verificationMethod(s): {actual:?}"
                    );
                }
            }
        }

        let status_list = vc
            .claims
            .decode_status_list()
            .map_err(|e| anyhow!("failed to decode status list bitstring at {url}: {e}"))?;

        let bit = status_list
            .get_entry(entry)
            .map_err(|e| {
                anyhow!(
                    "invalid status size for entry at index {}: {e}",
                    entry.status_list_index
                )
            })?
            .ok_or_else(|| {
                anyhow!(
                    "status list index {} out of range for {url}",
                    entry.status_list_index
                )
            })?;

        let current = bit != 0;
        *slot = Some(slot.unwrap_or(false) || current);
    }

    Ok(CredentialStatus { revoked, suspended })
}

/// Detect a legacy VC: a JSON document whose top-level `@context` references
/// the W3C VC 2.0 base context AND whose top-level fields include
/// `issuanceDate` (a v1-only field that v2 doesn't define). Together these
/// uniquely identify pre-ssi-0.16 output from this repo, which used a
/// hybrid v1/v2 shape that ssi 0.16's strict JSON-LD pipeline can't
/// reproduce the canonical bytes for.
#[cfg(not(target_arch = "wasm32"))]
fn is_legacy_vc(vc_json: &str) -> bool {
    let v: Value = match serde_json::from_str(vc_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let has_issuance_date = v.get("issuanceDate").is_some();
    let v2_context = v
        .get("@context")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .any(|e| e.as_str() == Some("https://www.w3.org/ns/credentials/v2"))
        })
        .unwrap_or(false);
    has_issuance_date && v2_context
}

/// Verifies a legacy (pre-ssi-0.16) VC by dispatching to ssi 0.7, which is
/// kept around as an aliased `ssi-legacy` dep specifically for this case.
///
/// Uses a custom JSON-LD context loader (`LegacyV2Loader`) that overrides
/// `credentials/v2` with the ssi-contexts 0.1.5 content (the version ssi
/// 0.7 originally depended on) and delegates everything else to the
/// standard ssi-json-ld static loader. 0.1.5's `credentials/v2` includes a
/// top-level `@vocab: "https://www.w3.org/ns/credentials/issuer-dependent#"`
/// fallback that ssi-contexts 0.1.10 dropped — that fallback is what made
/// `issuanceDate` and undefined evidence types expand to fallback IRIs
/// (instead of erroring) during the original signing canonicalization.
/// Cargo unifies ssi-contexts to 0.1.10 in our build because ssi 0.16's
/// chain requires `>=0.1.10`, so we can't pin downward — but we CAN feed
/// 0.1.5's content directly to the loader for the legacy path only.
#[cfg(not(target_arch = "wasm32"))]
async fn verify_legacy_vc(vc_json: &str) -> Result<String> {
    use did_method_key_legacy::DIDKey;
    use ssi_legacy::vc::Credential;

    let vc = Credential::from_json_unsigned(vc_json)
        .map_err(|e| anyhow!("failed to parse legacy VC: {e}"))?;

    let mut loader = ssi_legacy::jsonld::ContextLoader::empty()
        .with_context_map_from(legacy_context_overrides())
        .map_err(|e| anyhow!("failed to build legacy context loader: {e}"))?;
    let result = vc.verify(None, &DIDKey, &mut loader).await;
    log::debug!(
        "legacy verify errors={:?} warnings={:?} checks={:?}",
        result.errors,
        result.warnings,
        result.checks
    );
    if !result.errors.is_empty() {
        bail!("legacy VC verification failed: {:?}", result.errors);
    }
    Ok("VC verification result: ok (legacy path)".to_string())
}

/// Bundled W3C contexts at the ssi-contexts 0.1.5 revision — the version
/// shipped with ssi 0.7 originally. We override the same URLs the static
/// loader would resolve so that legacy verification sees the older context
/// shape (notably `credentials/v2` with its `@vocab` fallback that lets
/// custom evidence terms expand to predictable `issuer-dependent#` IRIs).
#[cfg(not(target_arch = "wasm32"))]
fn legacy_context_overrides() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        "https://www.w3.org/ns/credentials/v2".to_string(),
        include_str!("legacy_contexts/credentials-v2.jsonld").to_string(),
    );
    map.insert(
        "https://w3id.org/security/v2".to_string(),
        include_str!("legacy_contexts/security-v2.jsonld").to_string(),
    );
    map.insert(
        "https://w3id.org/security/v1".to_string(),
        include_str!("legacy_contexts/security-v1.jsonld").to_string(),
    );
    map
}

#[cfg(not(target_arch = "wasm32"))]
fn build_unsigned(subject: &str, adapter: &IntegritySigner) -> Result<JsonCredential> {
    use iref::UriBuf;
    use ssi::claims::vc::syntax::{IdOr, NonEmptyVec};

    // Subject can be either a JSON object or an opaque string (DID, URN, ...)
    // — match the polymorphism of the old API.
    let subject_value: serde_json::Map<String, Value> =
        if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(subject) {
            obj
        } else {
            let mut m = serde_json::Map::new();
            m.insert("id".to_string(), Value::String(subject.to_string()));
            m
        };
    let subject_json_syntax: json_syntax::Object = serde_json::from_value(Value::Object(
        subject_value,
    ))
    .map(|v: json_syntax::Value| match v {
        json_syntax::Value::Object(o) => o,
        _ => unreachable!("we just serialized from a Value::Object"),
    })?;
    let subject_non_empty = ssi::claims::vc::syntax::NonEmptyObject::try_from(subject_json_syntax)
        .map_err(|_| anyhow!("credential subject must be a non-empty object"))?;

    let id = UriBuf::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()).into_bytes())
        .map_err(|e| anyhow!("failed to construct urn:uuid id: {e:?}"))?;

    let issuer = IdOr::Id(adapter.issuer_uri()?);

    // Backdate by 1 hour so VCs are valid immediately even across systems
    // with slight clock drift — same heuristic as the old code at
    // integrity-vc/src/lib.rs:113.
    let valid_from: DateTime<Utc> = Utc::now() - chrono::Duration::hours(1);
    let valid_from_xsd = xsd_types::DateTimeStamp::from(valid_from);

    let mut credential = JsonCredential::new(Some(id), issuer, NonEmptyVec::new(subject_non_empty));
    credential.valid_from = Some(valid_from_xsd.into());

    // The v1-era proof suites (Ed25519Signature2018, EcdsaSecp256r1Signature2019,
    // EcdsaSecp256k1Signature2019) define their proof terms in
    // `https://w3id.org/security/v2` — without it, JSON-LD expansion of the
    // proof's `@type` fails. Adding the context here keeps both the v2 credential
    // body and the v1-era proof spec-coherent.
    credential
        .context
        .insert(ssi::json_ld::syntax::ContextEntry::IriRef(
            iref::IriRefBuf::new("https://w3id.org/security/v2".to_string())
                .map_err(|e| anyhow!("invalid security/v2 IRI: {e:?}"))?,
        ));

    Ok(credential)
}

#[cfg(not(target_arch = "wasm32"))]
async fn sign(unsigned: JsonCredential, adapter: IntegritySigner) -> Result<SignedVc> {
    log::debug!("Signing VC");
    let suite = adapter.suite()?;
    let vm_iri = adapter.verification_method_iri()?;
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());

    // Match the same backdate-by-1-hour the credential uses for valid_from.
    let created: DateTime<Utc> = Utc::now() - chrono::Duration::hours(1);
    let created_xsd = xsd_types::DateTimeStamp::from(created);

    let proof_options = ProofOptions::new(
        created_xsd.into(),
        ssi::verification_methods::ReferenceOrOwned::Reference(vm_iri),
        ProofPurpose::Assertion,
        Default::default(),
    );

    let environment = SignatureEnvironment {
        json_ld_loader: integrity_jsonld::loader::loader(None)?,
        eip712_loader: (),
    };

    suite
        .sign_with(
            environment,
            unsigned,
            &resolver,
            &adapter,
            proof_options,
            Default::default(),
        )
        .await
        .map_err(|e| anyhow!("signature failed: {e}"))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use integrity_signer::{Ed25519Signer, SignerType};

    use super::*;

    #[tokio::test]
    async fn test_issue_vc_with_simple_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya";
        let signed = issue_vc(subject, signer_type).await.unwrap();

        assert!(
            !signed.proofs.is_empty(),
            "SignedVc should carry at least one proof"
        );

        let vc_json = serde_json::to_string(&signed).unwrap();
        assert!(vc_json.contains(subject), "Should reference subject");
    }

    #[tokio::test]
    async fn test_issue_vc_with_did_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP";
        let signed = issue_vc(subject, signer_type).await.unwrap();
        assert!(!signed.proofs.is_empty());

        let vc_json = serde_json::to_string(&signed).unwrap();
        assert!(
            vc_json.contains(subject),
            "Credential should contain the subject DID"
        );
    }

    #[tokio::test]
    async fn test_issue_and_verify_vc() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya";
        let signed = issue_vc(subject, signer_type).await.unwrap();

        let vc_json = serde_json::to_string(&signed).unwrap();
        let result = verify_vc(&vc_json).await;
        assert!(
            result.is_ok(),
            "Credential verification should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_issue_vc_with_json_subject() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);

        let subject = r#"{"id": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya", "name": "Test Subject"}"#;
        let signed = issue_vc(subject, signer_type).await.unwrap();
        assert!(!signed.proofs.is_empty());

        let vc_json = serde_json::to_string(&signed).unwrap();
        assert!(vc_json.contains("Test Subject"));
    }

    #[tokio::test]
    async fn test_issue_revocable_vc() {
        use wiremock::{
            matchers::{header, method, path},
            Mock, MockServer, Request, Respond, ResponseTemplate,
        };

        struct AllocateResponder;
        impl Respond for AllocateResponder {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let mut vc: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                vc["credentialStatus"] = serde_json::json!([
                    {
                        "id": "https://status.example/status-lists/abc#42",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "revocation",
                        "statusListIndex": "42",
                        "statusListCredential": "https://status.example/status-lists/abc"
                    },
                    {
                        "id": "https://status.example/status-lists/abc#43",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "suspension",
                        "statusListIndex": "43",
                        "statusListCredential": "https://status.example/status-lists/abc"
                    }
                ]);
                ResponseTemplate::new(200).set_body_json(vc)
            }
        }

        let _ = env_logger::builder().is_test(true).try_init();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/credentials/status/allocate"))
            .and(header("Authorization", "Bearer test-jwt"))
            .respond_with(AllocateResponder)
            .mount(&server)
            .await;

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);
        let signed = issue_revocable_vc(
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            signer_type,
            &server.uri(),
            "test-jwt",
        )
        .await
        .unwrap();

        assert!(!signed.proofs.is_empty(), "SignedVc should have a proof");

        // Multi-status is now native — typed access, no JSON munging.
        let statuses = &signed.claims.credential_status;
        assert_eq!(
            statuses.len(),
            2,
            "Both revocation and suspension entries preserved"
        );
    }

    #[tokio::test]
    async fn test_issue_revocable_vc_propagates_server_error() {
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let _ = env_logger::builder().is_test(true).try_init();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/credentials/status/allocate"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string(r#"{"error":"forbidden","message":"sub mismatch"}"#),
            )
            .mount(&server)
            .await;

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);
        let err = issue_revocable_vc(
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            signer_type,
            &server.uri(),
            "test-jwt",
        )
        .await
        .unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("403"), "error should mention status: {msg}");
        assert!(
            msg.contains("sub mismatch"),
            "error should include body: {msg}"
        );
    }

    #[tokio::test]
    async fn test_allocate_credential_status_appends_entries() {
        use wiremock::{
            matchers::{header, method, path},
            Mock, MockServer, Request, Respond, ResponseTemplate,
        };

        struct AllocateResponder;
        impl Respond for AllocateResponder {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let mut vc: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                vc["credentialStatus"] = serde_json::json!([
                    {
                        "id": "https://status.example/status-lists/abc#42",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "revocation",
                        "statusListIndex": "42",
                        "statusListCredential": "https://status.example/status-lists/abc"
                    },
                    {
                        "id": "https://status.example/status-lists/abc#43",
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "suspension",
                        "statusListIndex": "43",
                        "statusListCredential": "https://status.example/status-lists/abc"
                    }
                ]);
                ResponseTemplate::new(200).set_body_json(vc)
            }
        }

        let _ = env_logger::builder().is_test(true).try_init();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/credentials/status/allocate"))
            .and(header("Authorization", "Bearer test-jwt"))
            .respond_with(AllocateResponder)
            .mount(&server)
            .await;

        let signer = Ed25519Signer::create().unwrap();
        let issuer_did = signer.did_doc.id.clone();

        // The motivating caller: a hand-assembled unsigned credential that
        // never touched `issue_revocable_vc`'s subject-string path.
        let unsigned = build_unsigned_with_eqty_contexts(
            "urn:uuid:11111111-1111-1111-1111-111111111111",
            &issuer_did,
            serde_json::json!({ "id": "did:example:holder" }),
            None,
            None,
            vec![],
        )
        .unwrap();

        let allocated = allocate_credential_status(unsigned, &server.uri(), "test-jwt")
            .await
            .unwrap();
        assert_eq!(
            allocated.credential_status.len(),
            2,
            "helper returns the augmented credential with both entries"
        );

        // And the augmented credential still signs through the existing path.
        let signed = sign_vc(allocated, SignerType::ED25519(signer))
            .await
            .unwrap();
        assert!(!signed.proofs.is_empty(), "SignedVc should have a proof");
    }

    #[tokio::test]
    async fn test_update_credential_status_revoke() {
        use wiremock::{
            matchers::{body_partial_json, header, method, path},
            Mock, ResponseTemplate,
        };

        // Standard topology: a revocable VC whose `credentialStatus` points
        // at `{server}/status-lists/{purpose}`, revocation index 42.
        let (server, vc_json) = setup_revocable_vc_against_mock(None).await;
        let vc_id = serde_json::from_str::<serde_json::Value>(&vc_json).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        Mock::given(method("POST"))
            .and(path("/credentials/status"))
            .and(header("Authorization", "Bearer test-jwt"))
            .and(body_partial_json(serde_json::json!({
                "credentialId": vc_id,
                "credentialStatus": {
                    "type": "BitstringStatusListEntry",
                    "statusPurpose": "revocation",
                    "statusListIndex": "42",
                    "statusListCredential": format!("{}/status-lists/revocation", server.uri()),
                },
                "status": true
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": true })),
            )
            .mount(&server)
            .await;

        let revoked = revoke_vc(&vc_json, &server.uri(), "test-jwt")
            .await
            .unwrap();
        assert!(revoked, "server-confirmed bit should be true");
    }

    #[tokio::test]
    async fn test_update_credential_status_propagates_server_error() {
        use wiremock::{
            matchers::{method, path},
            Mock, ResponseTemplate,
        };

        let (server, vc_json) = setup_revocable_vc_against_mock(None).await;
        Mock::given(method("POST"))
            .and(path("/credentials/status"))
            .respond_with(ResponseTemplate::new(409).set_body_string(
                r#"{"error":"revocation_irreversible","message":"revocation status cannot be cleared once set"}"#,
            ))
            .mount(&server)
            .await;

        let err = update_credential_status(
            &vc_json,
            StatusPurpose::Revocation,
            false,
            &server.uri(),
            "test-jwt",
        )
        .await
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("409"), "error should mention status: {msg}");
        assert!(
            msg.contains("revocation_irreversible"),
            "error should include body: {msg}"
        );
    }

    #[tokio::test]
    async fn test_update_credential_status_no_matching_entry() {
        let _ = env_logger::builder().is_test(true).try_init();

        // A plain (non-revocable) VC carries no `credentialStatus`.
        let signer = Ed25519Signer::create().unwrap();
        let signed = issue_vc(
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            SignerType::ED25519(signer),
        )
        .await
        .unwrap();
        let vc_json = serde_json::to_string(&signed).unwrap();

        // URL is never contacted — the error happens before any HTTP.
        let err = revoke_vc(&vc_json, "http://127.0.0.1:1", "test-jwt")
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("no `revocation` credentialStatus entry"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_suspend_vc() {
        use wiremock::{
            matchers::{body_partial_json, method, path},
            Mock, ResponseTemplate,
        };

        let (server, vc_json) = setup_revocable_vc_against_mock(None).await;
        Mock::given(method("POST"))
            .and(path("/credentials/status"))
            .and(body_partial_json(serde_json::json!({
                "credentialStatus": {
                    "statusPurpose": "suspension",
                    "statusListIndex": "43",
                    "statusListCredential": format!("{}/status-lists/suspension", server.uri()),
                },
                "status": true
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": true })),
            )
            .mount(&server)
            .await;

        let suspended = suspend_vc(&vc_json, &server.uri(), "test-jwt")
            .await
            .unwrap();
        assert!(suspended, "server-confirmed suspension bit should be true");
    }

    #[tokio::test]
    async fn test_unsuspend_vc() {
        use wiremock::{
            matchers::{body_partial_json, method, path},
            Mock, ResponseTemplate,
        };

        let (server, vc_json) = setup_revocable_vc_against_mock(None).await;
        Mock::given(method("POST"))
            .and(path("/credentials/status"))
            .and(body_partial_json(serde_json::json!({
                "credentialStatus": { "statusPurpose": "suspension", "statusListIndex": "43" },
                "status": false
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": false })),
            )
            .mount(&server)
            .await;

        let suspended = unsuspend_vc(&vc_json, &server.uri(), "test-jwt")
            .await
            .unwrap();
        assert!(
            !suspended,
            "server-confirmed suspension bit should be false"
        );
    }

    /// Captured from running `test_issue_and_verify_vc` on commit 82f0f2e
    /// (last pre-ssi-0.16 commit). The OLD code's verify_vc successfully
    /// verified this exact JSON. If our `ssi-legacy` aliased dep behaves
    /// the same as the OLD code's ssi 0.7 dep, this should also verify.
    #[tokio::test]
    async fn test_verify_captured_old_vc() {
        let _ = env_logger::builder().is_test(true).try_init();

        let captured = r#"{"@context":["https://www.w3.org/ns/credentials/v2","https://w3id.org/security/v2"],"id":"urn:uuid:cf35933b-b49d-4b18-82ee-0e594912ec87","type":["VerifiableCredential"],"credentialSubject":{"id":"urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya"},"issuer":"did:key:z6Mkt1QV8soXyenn4uUYtrMzFDnWWq8e8Mu71t2KmBsWi2mv","issuanceDate":"2026-05-14T13:43:44Z","proof":{"type":"Ed25519Signature2018","proofPurpose":"assertionMethod","verificationMethod":"did:key:z6Mkt1QV8soXyenn4uUYtrMzFDnWWq8e8Mu71t2KmBsWi2mv#z6Mkt1QV8soXyenn4uUYtrMzFDnWWq8e8Mu71t2KmBsWi2mv","created":"2026-05-14T13:43:44Z","jws":"eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..P1CYP_-UNuPSyJUfE3EfLnHDZxHE1rZt961j1UQ6wx0f4ftTs3cUNmQ6pINp6VECGscjWnmvYtt4r2jt1-0YDg"},"validFrom":"2026-05-14T13:43:44Z"}"#;

        assert!(is_legacy_vc(captured), "should detect as legacy");
        let result = verify_vc(captured).await;
        assert!(
            result.is_ok(),
            "captured OLD-issued VC should verify via legacy path: {:?}",
            result.err()
        );
    }

    /// User-supplied legacy fixture with a custom `evidence` type. The
    /// `EqtyVCompCustomV1Evidence` term and `customType`/`report` properties
    /// aren't defined in any context the VC explicitly references — they
    /// rely on ssi-contexts 0.1.5's `@vocab` fallback in `credentials/v2`
    /// (`https://www.w3.org/ns/credentials/issuer-dependent#`) to expand
    /// to predictable IRIs during canonicalization. The legacy verifier
    /// feeds the 0.1.5 `credentials/v2` content to its loader directly via
    /// [`legacy_context_overrides`], so the canonical bytes match what the
    /// original signer hashed.
    #[tokio::test]
    async fn test_verify_legacy_vc() {
        let _ = env_logger::builder().is_test(true).try_init();

        let legacy_vc = r#"{
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/security/v2"
          ],
          "id": "urn:uuid:9c759cce-6433-4679-a293-9f77158a831a",
          "type": ["VerifiableCredential"],
          "credentialSubject": {
            "id": "urn:cid:bagb6qaq6edsd23d466wxytmkkdjqjfagkccwhtgetbfrkyqql3xdmgepe5s5k"
          },
          "issuer": "did:key:zDnaexxwdJ1key82YfVudPYvDqcKMhvcyYdTV7WDhATqbVtVc",
          "issuanceDate": "2026-04-30T15:51:28Z",
          "proof": {
            "type": "EcdsaSecp256r1Signature2019",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:key:zDnaexxwdJ1key82YfVudPYvDqcKMhvcyYdTV7WDhATqbVtVc#zDnaexxwdJ1key82YfVudPYvDqcKMhvcyYdTV7WDhATqbVtVc",
            "created": "2026-04-30T15:51:28Z",
            "jws": "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..fv7jObmZYGuX6tScXOmP-umY15zn4-9zjCpLnfVP4AAln00_p7t0j1CQYrQKMcPRD2e6Z0aS6WDRDnAg9790rg"
          },
          "evidence": {
            "type": ["EqtyVCompCustomV1Evidence"],
            "value": {
              "customType": "eqty-vcomp-amd-sev-v1",
              "report": "urn:cid:bafkr4iaosvuo7es74abc4wmwmwyui6xtbmgzxhway26y262a54kjhnzaze"
            }
          },
          "validFrom": "2026-04-30T15:51:28Z"
        }"#;

        let result = verify_vc(legacy_vc).await;
        assert!(
            result.is_ok(),
            "legacy VC verification should succeed: {:?}",
            result.err()
        );
    }

    /// User-supplied VC carrying a custom JSON-LD context
    /// (`https://eqtylab.io/contexts/vcomp/v1`) and custom evidence terms
    /// (`EqtyVCompNvidiaCcV0Evidence`, `report`, `certificateChain`) that are
    /// only defined in that context. We sign with a fresh signer — rewriting
    /// `issuer` to match (the original fixture's DID is unowned) — and
    /// otherwise leave the VC as supplied. Expected to fail today because
    /// ssi 0.16's static context loader can't resolve the custom URL, so
    /// JSON-LD expansion of the evidence terms fails during canonicalization.
    #[tokio::test]
    async fn test_verify_vc_with_custom_context() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);
        let issuer_did = signer_type.get_did_doc().id;

        let mut unsigned_value: Value = serde_json::from_str(
            r#"{
              "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/v2",
                "urn:cid:bafkr4ic7ydwk3rtoltyzx4zn3vvu3r7hpzxtmbzmnksotx7k5nbnwclf6m"
              ],
              "type": ["VerifiableCredential"],
              "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
              "issuer": "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
              "validFrom": "2024-03-26T12:34:56Z",
              "credentialSubject": {
                "id": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya"
              },
              "evidence": [
                {
                  "type": ["EqtyVCompNvidiaCcV0Evidence"],
                  "report": "the report",
                  "certificateChain": "certificate chain"
                }
              ]
            }"#,
        )
        .unwrap();
        unsigned_value["issuer"] = Value::String(issuer_did);

        let unsigned: JsonCredential = serde_json::from_value(unsigned_value).unwrap();
        let signed = sign_vc(unsigned, signer_type).await.unwrap();

        let vc_json = serde_json::to_string(&signed).unwrap();
        let result = verify_vc(&vc_json).await;
        assert!(
            result.is_ok(),
            "VC verification should succeed: {:?}",
            result.err()
        );
    }

    /// Backward-compat guard: VCs issued *before* the switch to an inline
    /// `@vocab` carry the IG-common context as a `urn:cid:` link — exactly
    /// what `build_unsigned_with_eqty_contexts` used to attach. The JSON-LD
    /// loader still ships that context document, so `verify_vc` must keep
    /// verifying such credentials. Build one the old way (CID context plus
    /// EQTY subject terms `policy`/`statements`), sign, and verify.
    #[tokio::test]
    async fn test_verify_vc_with_ig_common_cid_context() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signer_type = SignerType::ED25519(signer);
        let issuer_did = signer_type.get_did_doc().id;

        let cid_context = integrity_jsonld::ig_common_context_link();
        let mut unsigned_value: Value = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/v2",
                cid_context.clone(),
            ],
            "type": ["VerifiableCredential"],
            "id": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "issuer": "placeholder",
            "validFrom": "2024-03-26T12:34:56Z",
            "credentialSubject": {
                "id": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
                "policy": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
                "statements": ["urn:cid:bagb6qaq6ebv5rcenbhret6apdolkskuht43bdyke4d2lzkldnvqqnizbpsjvu"],
            },
        });
        unsigned_value["issuer"] = Value::String(issuer_did);

        let unsigned: JsonCredential = serde_json::from_value(unsigned_value).unwrap();
        let signed = sign_vc(unsigned, signer_type).await.unwrap();
        let vc_json = serde_json::to_string(&signed).unwrap();

        // Precondition: the VC really carries the urn:cid: context, not @vocab.
        assert!(
            vc_json.contains(&cid_context),
            "test VC must carry the IG-common urn:cid: context: {vc_json}"
        );

        verify_vc(&vc_json)
            .await
            .expect("VC carrying the IG-common urn:cid: context must still verify");
    }

    /// Second user-supplied legacy fixture: Ed25519-signed, no evidence,
    /// minimal v2-with-issuanceDate shape. Confirms the legacy path also
    /// handles the simpler proof-suite-without-evidence variant.
    #[tokio::test]
    async fn test_verify_legacy_vc_ed25519_no_evidence() {
        let _ = env_logger::builder().is_test(true).try_init();

        let legacy_vc = r#"{
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/security/v2"
          ],
          "id": "urn:uuid:a77f4f8f-0ab1-4611-bd51-6090ebdefc8d",
          "type": ["VerifiableCredential"],
          "credentialSubject": {
            "id": "urn:cid:bagb6qaq6edqk2q2vksxblheqmhcfp6lfmwk5f6qqy7fkuzykaebfzyccfmsh4"
          },
          "issuer": "did:key:z6MkmwihXQDhgNbWpwpWZ5NHygqC9PtHjVW62MM8ZJSggRD4",
          "issuanceDate": "2025-05-22T16:25:37Z",
          "proof": {
            "type": "Ed25519Signature2018",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:key:z6MkmwihXQDhgNbWpwpWZ5NHygqC9PtHjVW62MM8ZJSggRD4#z6MkmwihXQDhgNbWpwpWZ5NHygqC9PtHjVW62MM8ZJSggRD4",
            "created": "2025-05-22T16:25:37Z",
            "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..gHHpLIaNbMKQFHoyaOQEGu_HLgLwnwgBNSc6yRaWjoOBLGBj7x_FrX7nTBaiWcl_tcd9D-ir8QtFUh8n29WLAw"
          },
          "validFrom": "2025-05-22T16:25:37Z"
        }"#;

        let result = verify_vc(legacy_vc).await;
        assert!(
            result.is_ok(),
            "legacy VC verification should succeed: {:?}",
            result.err()
        );
    }

    /// Exercise `build_unsigned_with_eqty_contexts` end-to-end: build a
    /// VComp-shaped VC (subject + custom EQTY evidence terms), sign it
    /// with a fresh Ed25519 key, and verify. Verification going green
    /// proves the EQTY context bundle covers everything in the signed
    /// payload — i.e. the helper attaches the right contexts so callers
    /// don't have to.
    #[tokio::test]
    async fn test_build_unsigned_with_eqty_contexts_vcomp_shape() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let issuer_did = signer.did_doc.id.clone();
        let signer_type = SignerType::ED25519(signer);

        let unsigned = build_unsigned_with_eqty_contexts(
            "urn:uuid:11111111-1111-1111-1111-111111111111",
            &issuer_did,
            serde_json::json!({ "id": "urn:cid:subject" }),
            Some(
                chrono::DateTime::parse_from_rfc3339("2024-03-26T12:34:56Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            None,
            vec![serde_json::json!({
                "type": ["EqtyVCompNvidiaCcV0Evidence"],
                "report": "the report",
                "certificateChain": "certificate chain",
            })],
        )
        .expect("helper must build vcomp-shaped credential");

        // Sanity-check the typed builder produced the fields we asked for
        // before going to the signer (which would fail-loud if anything's
        // off anyway).
        assert_eq!(
            unsigned.id.as_ref().map(|u| u.as_str()),
            Some("urn:uuid:11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(unsigned.evidence.len(), 1);

        // EQTY terms are carried by an inline `@vocab`, not a urn:cid:
        // context document.
        let ctx = serde_json::to_value(&unsigned.context).unwrap();
        assert_eq!(
            ctx,
            serde_json::json!([
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/v2",
                { "@vocab": "https://eqtylab.io/terms/" }
            ]),
            "EQTY context must be an inline @vocab with no urn:cid: entry"
        );

        let signed = sign_vc(unsigned, signer_type).await.unwrap();
        let signed_json = serde_json::to_string(&signed).unwrap();
        verify_vc(&signed_json)
            .await
            .expect("vcomp-shape VC must verify with attached contexts");
    }

    /// Mirror the policy-compliance shape: subject is a struct-derived
    /// JSON object with EQTY-namespaced keys (`policy`, `statements`),
    /// `valid_until` set instead of `valid_from`, no evidence. Sign and
    /// verify to prove the same context bundle covers this shape too.
    #[tokio::test]
    async fn test_build_unsigned_with_eqty_contexts_compliance_shape() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let issuer_did = signer.did_doc.id.clone();
        let signer_type = SignerType::ED25519(signer);

        let subject = serde_json::json!({
            "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "policy": "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
            "statements": ["urn:cid:bagb6qaq6ebv5rcenbhret6apdolkskuht43bdyke4d2lzkldnvqqnizbpsjvu"],
        });

        let unsigned = build_unsigned_with_eqty_contexts(
            "urn:uuid:22222222-2222-2222-2222-222222222222",
            &issuer_did,
            subject,
            None,
            Some(
                chrono::DateTime::parse_from_rfc3339("2030-07-04T23:59:59Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            vec![],
        )
        .expect("helper must build compliance-shaped credential");

        assert!(unsigned.valid_from.is_none());
        assert!(unsigned.valid_until.is_some());
        assert!(unsigned.evidence.is_empty());

        let signed = sign_vc(unsigned, signer_type).await.unwrap();
        let signed_json = serde_json::to_string(&signed).unwrap();
        verify_vc(&signed_json)
            .await
            .expect("compliance-shape VC must verify with attached contexts");
    }

    /// A non-object subject (here a JSON string) is a programmer error;
    /// the helper should surface that as a clear error rather than panic
    /// or silently corrupt the credential.
    #[test]
    fn test_build_unsigned_with_eqty_contexts_rejects_non_object_subject() {
        let result = build_unsigned_with_eqty_contexts(
            "urn:uuid:33333333-3333-3333-3333-333333333333",
            "did:key:z6MkmwihXQDhgNbWpwpWZ5NHygqC9PtHjVW62MM8ZJSggRD4",
            serde_json::Value::String("urn:cid:not-an-object".to_string()),
            None,
            None,
            vec![],
        );
        assert!(
            result.is_err(),
            "non-object subject must be rejected, got: {result:?}"
        );
    }

    /// A VC with no `credentialStatus` field — the plain `issue_vc` path —
    /// reports no statement about either purpose. The signer pin is
    /// irrelevant here because no list is ever fetched; we pass a
    /// placeholder DID to satisfy the required parameter.
    #[tokio::test]
    async fn test_check_credential_status_no_status_list() {
        let _ = env_logger::builder().is_test(true).try_init();

        let signer = Ed25519Signer::create().unwrap();
        let signed = issue_vc(
            "urn:cid:bafkr4ibthuzk3zug7ghmx63yjqaiu6rx4hhfdv3453j5bodskgw57bx2ya",
            SignerType::ED25519(signer),
        )
        .await
        .unwrap();
        let vc_json = serde_json::to_string(&signed).unwrap();

        let status = check_credential_status(&vc_json, "did:key:irrelevant-no-fetch-occurs")
            .await
            .unwrap();
        assert_eq!(
            status,
            CredentialStatus {
                revoked: None,
                suspended: None
            }
        );
    }

    /// End-to-end: issue a revocable VC against a mocked status server,
    /// serve unsigned all-zero status lists, and verify both bits read as
    /// clear. Goes through the test-only inner helper so the in-test
    /// status lists don't need a Data-Integrity proof or signer pin.
    #[tokio::test]
    async fn test_check_credential_status_clear_bits() {
        let status = run_revocable_status_check(None).await.unwrap();
        assert_eq!(
            status,
            CredentialStatus {
                revoked: Some(false),
                suspended: Some(false)
            }
        );
    }

    /// Same setup as the clear-bits test, but with the revocation list's
    /// bit at the credential's `statusListIndex` flipped to 1.
    #[tokio::test]
    async fn test_check_credential_status_revoked() {
        let status = run_revocable_status_check(Some(StatusBitToSet::Revocation))
            .await
            .unwrap();
        assert_eq!(
            status,
            CredentialStatus {
                revoked: Some(true),
                suspended: Some(false)
            }
        );
    }

    /// And the symmetric case for suspension.
    #[tokio::test]
    async fn test_check_credential_status_suspended() {
        let status = run_revocable_status_check(Some(StatusBitToSet::Suspension))
            .await
            .unwrap();
        assert_eq!(
            status,
            CredentialStatus {
                revoked: Some(false),
                suspended: Some(true)
            }
        );
    }

    /// The public entrypoint must REJECT a status list with no proof —
    /// otherwise an attacker who can intercept the GET could serve a
    /// fresh, unsigned bitstring with the revocation bit cleared. Drive
    /// the same wiremock topology, then call the public function (which
    /// requires `allow_unsecured = false`) and expect an error.
    #[tokio::test]
    async fn test_check_credential_status_rejects_unsigned_status_list() {
        let err = run_revocable_status_check_public(None, "did:key:irrelevant-will-fail-first")
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unsigned"),
            "error should explain the rejection: {msg}"
        );
    }

    #[derive(Clone, Copy)]
    enum StatusBitToSet {
        Revocation,
        Suspension,
    }

    /// Drives the revocable-status flow against the test-only inner
    /// helper (no signer pin, accepts unsigned lists).
    async fn run_revocable_status_check(set: Option<StatusBitToSet>) -> Result<CredentialStatus> {
        let (_server, vc_json) = setup_revocable_vc_against_mock(set).await;
        check_credential_status_inner(&vc_json, None, true).await
    }

    /// Same setup, but call the PUBLIC entrypoint — i.e. the one that
    /// requires a signed status list and a pinned signer. Used to assert
    /// rejection of unsigned lists.
    async fn run_revocable_status_check_public(
        set: Option<StatusBitToSet>,
        signer_did: &str,
    ) -> Result<CredentialStatus> {
        let (_server, vc_json) = setup_revocable_vc_against_mock(set).await;
        check_credential_status(&vc_json, signer_did).await
    }

    /// Stands up the wiremock topology used by every status-check test:
    /// (1) mock POST /credentials/status/allocate → returns the VC with
    /// `credentialStatus` pointing back at the mock for two lists; (2)
    /// mock GET /status-lists/{revocation,suspension} → returns unsigned
    /// `BitstringStatusListCredential` JSON whose encoded list is either
    /// all zeros or has the entry's bit set. Returns the running server
    /// (kept alive by the caller's binding) and the serialized signed VC.
    async fn setup_revocable_vc_against_mock(
        set: Option<StatusBitToSet>,
    ) -> (wiremock::MockServer, String) {
        use ssi_status::bitstring_status_list::{SizedBitString, StatusSize};
        use wiremock::{
            matchers::{header, method, path},
            Mock, MockServer, Request, Respond, ResponseTemplate,
        };

        const REVOCATION_INDEX: usize = 42;
        const SUSPENSION_INDEX: usize = 43;

        struct AllocateResponder {
            server_uri: String,
        }
        impl Respond for AllocateResponder {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let mut vc: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                vc["credentialStatus"] = serde_json::json!([
                    {
                        "id": format!("{}/status-lists/revocation#{REVOCATION_INDEX}", self.server_uri),
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "revocation",
                        "statusListIndex": REVOCATION_INDEX.to_string(),
                        "statusListCredential": format!("{}/status-lists/revocation", self.server_uri),
                    },
                    {
                        "id": format!("{}/status-lists/suspension#{SUSPENSION_INDEX}", self.server_uri),
                        "type": "BitstringStatusListEntry",
                        "statusPurpose": "suspension",
                        "statusListIndex": SUSPENSION_INDEX.to_string(),
                        "statusListCredential": format!("{}/status-lists/suspension", self.server_uri),
                    }
                ]);
                ResponseTemplate::new(200).set_body_json(vc)
            }
        }

        fn status_list_body(server_uri: &str, purpose: &str, set_index: Option<usize>) -> String {
            let status_size = StatusSize::try_from(1u8).unwrap();
            let mut bs = SizedBitString::new_zeroed(status_size, 16_384);
            if let Some(i) = set_index {
                bs.set(i, 1).unwrap();
            }
            let encoded = bs.encode();
            serde_json::json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": format!("{server_uri}/status-lists/{purpose}"),
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "credentialSubject": {
                    "type": "BitstringStatusList",
                    "statusPurpose": purpose,
                    "encodedList": encoded,
                }
            })
            .to_string()
        }

        let _ = env_logger::builder().is_test(true).try_init();
        let server = MockServer::start().await;
        let server_uri = server.uri();

        Mock::given(method("POST"))
            .and(path("/credentials/status/allocate"))
            .and(header("Authorization", "Bearer test-jwt"))
            .respond_with(AllocateResponder {
                server_uri: server_uri.clone(),
            })
            .mount(&server)
            .await;

        let revocation_set =
            matches!(set, Some(StatusBitToSet::Revocation)).then_some(REVOCATION_INDEX);
        let suspension_set =
            matches!(set, Some(StatusBitToSet::Suspension)).then_some(SUSPENSION_INDEX);

        Mock::given(method("GET"))
            .and(path("/status-lists/revocation"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                status_list_body(&server_uri, "revocation", revocation_set),
                "application/vc+ld+json",
            ))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/status-lists/suspension"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                status_list_body(&server_uri, "suspension", suspension_set),
                "application/vc+ld+json",
            ))
            .mount(&server)
            .await;

        let signer = Ed25519Signer::create().unwrap();
        let signed = issue_revocable_vc(
            "did:key:z6Mkw2PvzC9DHXiYQHMDRwyxCCV9n4EDc6vqqp1uyi9nrwsP",
            SignerType::ED25519(signer),
            &server_uri,
            "test-jwt",
        )
        .await
        .unwrap();
        let vc_json = serde_json::to_string(&signed).unwrap();
        (server, vc_json)
    }
}
