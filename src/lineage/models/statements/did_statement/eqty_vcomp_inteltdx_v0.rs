use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::super::{
    common::{
        deserialize_vec_u8_arr_48_from_hex, serialize_vec_u8_arr_48_as_hex, UrnCidWithSha384,
    },
    compute_cid, format_timestamp, get_jsonld_filename, StatementTrait,
};
use crate::json_ld::ig_common_context_link;

pub const VCOMP_TYPE_VALUE: &str = "EqtyVCompIntelTdxV0";

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompIntelTdxV0 {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    pub did: String,
    pub vcomp: DidStatementEqtyVCompIntelTdxV0VComp,
    pub registered_by: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompIntelTdxV0VComp {
    #[serde(rename = "@type")]
    pub type_: String,
    #[serde(
        serialize_with = "serialize_vec_u8_arr_48_as_hex",
        deserialize_with = "deserialize_vec_u8_arr_48_from_hex"
    )]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub measurement: Vec<[u8; 48]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_info: Option<DidStatementEqtyVCompIntelTdxV0VCompMeasurementInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DidStatementEqtyVCompIntelTdxV0VCompMeasurementInfo {
    ovmf: Option<UrnCidWithSha384>,
    kernel: Option<UrnCidWithSha384>,
    initrd: Option<UrnCidWithSha384>,
    append: Option<UrnCidWithSha384>,
}

impl StatementTrait for DidStatementEqtyVCompIntelTdxV0 {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        let mut cids = Vec::new();

        if let Some(measurement_info) = &self.vcomp.measurement_info {
            if let Some(ovmf) = &measurement_info.ovmf {
                cids.push(ovmf.cid.clone());
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
        }

        cids
    }
}

impl DidStatementEqtyVCompIntelTdxV0 {
    /// Creates a new DidStatement_EqtyVCompIntelTdxV0 object.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        did: String,
        measurements: Vec<[u8; 48]>,
        ovmf: Option<UrnCidWithSha384>,
        kernel: Option<UrnCidWithSha384>,
        initrd: Option<UrnCidWithSha384>,
        append: Option<UrnCidWithSha384>,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let vcomp = DidStatementEqtyVCompIntelTdxV0VComp {
            type_: VCOMP_TYPE_VALUE.to_owned(),
            measurement: measurements,
            measurement_info: match (ovmf, kernel, initrd, append) {
                (None, None, None, None) => None,
                (ovmf, kernel, initrd, append) => {
                    Some(DidStatementEqtyVCompIntelTdxV0VCompMeasurementInfo {
                        ovmf,
                        kernel,
                        initrd,
                        append,
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
