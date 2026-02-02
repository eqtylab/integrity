use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::{
    common::{
        deserialize_option_u8_arr_from_hex, serialize_option_u8_arr_as_hex, UrnCidWithSha256,
    },
    compute_cid, format_timestamp, get_jsonld_filename, StatementTrait,
};
use crate::json_ld::ig_common_context_link;

/// Type identifier for AMD SEV verified computing statements
pub const VCOMP_TYPE_VALUE: &str = "EqtyVCompAmdSevV1";

/// DID registration with AMD SEV (Secure Encrypted Virtualization) attestation
///
/// This statement type registers a DID with proof of execution in an
/// AMD SEV-protected virtual machine environment.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompAmdSevV1 {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// The DID being registered
    pub did: String,
    /// Verified computing attestation data
    pub vcomp: DidStatementEqtyVCompAmdSevV1VComp,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

/// AMD SEV verified computing attestation data
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompAmdSevV1VComp {
    /// Verified computing type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// Optional measurement hash from AMD SEV attestation
    #[serde(
        serialize_with = "serialize_option_u8_arr_as_hex",
        deserialize_with = "deserialize_option_u8_arr_from_hex"
    )]
    pub measurement: Option<[u8; 32]>,
    /// Information about the measured components
    pub measurement_info: DidStatementEqtyVCompAmdSevV1VCompMeasurementInfo,
}

/// Details about the components measured in AMD SEV attestation
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompAmdSevV1VCompMeasurementInfo {
    /// AMD SEV mode (e.g., "SEV", "SEV-ES", "SEV-SNP")
    sev_mode: String,
    /// Number of CPU cores allocated
    num_cpu_cores: u32,
    /// CPU type identifier
    cpu_type: String,
    /// OVMF (UEFI firmware) with hash
    ovmf: UrnCidWithSha256,
    /// Linux kernel with hash
    kernel: UrnCidWithSha256,
    /// Initial RAM disk with hash
    initrd: UrnCidWithSha256,
    /// Kernel command-line arguments with hash
    append: UrnCidWithSha256,
}

impl StatementTrait for DidStatementEqtyVCompAmdSevV1 {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        vec![
            self.vcomp.measurement_info.ovmf.cid.clone(),
            self.vcomp.measurement_info.kernel.cid.clone(),
            self.vcomp.measurement_info.initrd.cid.clone(),
            self.vcomp.measurement_info.append.cid.clone(),
        ]
    }
}

impl DidStatementEqtyVCompAmdSevV1 {
    /// Creates a new DidStatement_EqtyVCompAmdSevV1 object.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        did: String,
        measurement: Option<[u8; 32]>,
        sev_mode: String,
        num_cpu_cores: u32,
        cpu_type: String,
        ovmf: UrnCidWithSha256,
        kernel: UrnCidWithSha256,
        initrd: UrnCidWithSha256,
        append: UrnCidWithSha256,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let vcomp = DidStatementEqtyVCompAmdSevV1VComp {
            type_: VCOMP_TYPE_VALUE.to_owned(),
            measurement,
            measurement_info: DidStatementEqtyVCompAmdSevV1VCompMeasurementInfo {
                sev_mode,
                num_cpu_cores,
                cpu_type,
                ovmf,
                kernel,
                initrd,
                append,
            },
        };

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_: "DidRegistration".to_owned(),
            did,
            vcomp,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}
