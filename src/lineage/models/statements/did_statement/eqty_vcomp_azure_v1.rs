use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::{
    common::{
        deserialize_option_u8_vec_from_hex, serialize_option_u8_vec_as_hex, UrnCidWithSha256,
        UrnCidWithSha384,
    },
    compute_cid, format_timestamp, get_jsonld_filename, StatementTrait,
};
use crate::{cid::prepend_urn_cid, json_ld::ig_common_context_link};

/// Type identifier for Azure verified computing statements
pub const VCOMP_TYPE_VALUE: &str = "EqtyVCompAzureV1";

/// DID registration with Azure Confidential Computing attestation
///
/// This statement type registers a DID with proof of execution in an
/// Azure confidential computing environment.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompAzureV1 {
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
    pub vcomp: DidStatementEqtyVCompAzureV1VComp,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
    pub timestamp: String,
}

/// Azure confidential computing attestation data
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompAzureV1VComp {
    /// Verified computing type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// Optional measurement values from TPM or firmware
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<DidStatementEqtyVCompAzureV1VCompMeasurement>,
    /// Optional information about measured components
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_info: Option<DidStatementEqtyVCompAzureV1VCompMeasurementInfo>,
}

/// Measurement values from Azure attestation
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompAzureV1VCompMeasurement {
    /// Optional TPM PCR11 value
    #[serde(
        serialize_with = "serialize_option_u8_vec_as_hex",
        deserialize_with = "deserialize_option_u8_vec_from_hex"
    )]
    pub pcr11: Option<Vec<u8>>,
    /// Optional firmware measurement
    #[serde(
        serialize_with = "serialize_option_u8_vec_as_hex",
        deserialize_with = "deserialize_option_u8_vec_from_hex"
    )]
    pub firmware: Option<Vec<u8>>,
}

/// Details about components measured in Azure attestation
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompAzureV1VCompMeasurementInfo {
    /// Optional Unified Kernel Image CID
    uki: Option<String>,
    /// Optional kernel with hash
    kernel: Option<UrnCidWithSha384>,
    /// Optional initial RAM disk with hash
    initrd: Option<UrnCidWithSha384>,
    /// Optional kernel command-line arguments with hash
    append: Option<UrnCidWithSha384>,
    /// Optional root filesystem with hash
    rootfs: Option<UrnCidWithSha256>,
}

impl StatementTrait for DidStatementEqtyVCompAzureV1 {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        let mut cids = Vec::new();

        if let Some(measurement_info) = &self.vcomp.measurement_info {
            if let Some(uki) = &measurement_info.uki {
                cids.push(uki.clone());
            }
            if let Some(kernel) = &measurement_info.kernel {
                cids.push(kernel.cid.clone());
            }
            if let Some(initrd) = &measurement_info.initrd {
                cids.push(initrd.cid.clone());
            }
            if let Some(append) = &measurement_info.append {
                cids.push(append.cid.clone());
            }
            if let Some(rootfs) = &measurement_info.rootfs {
                cids.push(rootfs.cid.clone());
            }
        }

        cids
    }
}

impl DidStatementEqtyVCompAzureV1 {
    /// Creates a new DidStatementEqtyVCompAzureV1 object.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        did: String,
        pcr11: Option<Vec<u8>>,
        firmware: Option<Vec<u8>>,
        uki: Option<String>,
        kernel: Option<UrnCidWithSha384>,
        initrd: Option<UrnCidWithSha384>,
        append: Option<UrnCidWithSha384>,
        rootfs: Option<UrnCidWithSha256>,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let uki = match uki {
            Some(uki) => Some(prepend_urn_cid(&uki)?),
            None => None,
        };

        let vcomp = DidStatementEqtyVCompAzureV1VComp {
            type_: VCOMP_TYPE_VALUE.to_owned(),
            measurement: match (pcr11, firmware) {
                (None, None) => None,
                (pcr11, firmware) => {
                    Some(DidStatementEqtyVCompAzureV1VCompMeasurement { pcr11, firmware })
                }
            },
            measurement_info: match (uki, kernel, initrd, append, rootfs) {
                (None, None, None, None, None) => None,
                (uki, kernel, initrd, append, rootfs) => {
                    Some(DidStatementEqtyVCompAzureV1VCompMeasurementInfo {
                        uki,
                        kernel,
                        initrd,
                        append,
                        rootfs,
                    })
                }
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
