//! DID (Decentralized Identifier) statement types
//!
//! This module contains statement types for registering DIDs with various
//! verified computing (vcomp) attestations.

/// DID statement with AMD SEV verified computing attestation
pub mod eqty_vcomp_amdsev_v1;
/// DID statement with Azure verified computing attestation
pub mod eqty_vcomp_azure_v1;
/// DID statement with custom verified computing attestation
pub mod eqty_vcomp_custom_v1;
/// DID statement with Docker container verified computing attestation
pub mod eqty_vcomp_docker_v1;
/// DID statement with Intel TDX verified computing attestation
pub mod eqty_vcomp_inteltdx_v0;
/// Regular DID statement without attestation
pub mod regular;

pub use eqty_vcomp_amdsev_v1::DidStatementEqtyVCompAmdSevV1;
pub use eqty_vcomp_azure_v1::DidStatementEqtyVCompAzureV1;
pub use eqty_vcomp_custom_v1::DidStatementEqtyVCompCustomV1;
pub use eqty_vcomp_docker_v1::DidStatementEqtyVCompDockerV1;
pub use eqty_vcomp_inteltdx_v0::DidStatementEqtyVCompIntelTdxV0;
pub use regular::DidStatementRegular;

use super::StatementTrait;

/// Enum representing different types of DID registration statements
///
/// Each variant corresponds to a specific attestation format for verified
/// computing environments or a regular DID registration.
#[derive(Debug, Clone, utoipa::ToSchema, serde::Serialize, PartialEq)]
#[serde(untagged)]
pub enum DidStatement {
    /// DID with AMD SEV verified computing attestation
    AmdSevV1(DidStatementEqtyVCompAmdSevV1),
    /// DID with Docker container verified computing attestation
    DockerV1(DidStatementEqtyVCompDockerV1),
    /// DID with custom verified computing attestation
    CustomV1(DidStatementEqtyVCompCustomV1),
    /// DID with Intel TDX verified computing attestation
    IntelTdxV0(DidStatementEqtyVCompIntelTdxV0),
    /// DID with Azure verified computing attestation
    AzureV1(DidStatementEqtyVCompAzureV1),
    /// Regular DID registration without attestation
    Regular(DidStatementRegular),
}

impl DidStatement {
    /// Returns the DID of the entity that registered this statement
    pub fn get_registered_by(&self) -> &str {
        match self {
            DidStatement::AmdSevV1(s) => &s.registered_by,
            DidStatement::DockerV1(s) => &s.registered_by,
            DidStatement::CustomV1(s) => &s.registered_by,
            DidStatement::IntelTdxV0(s) => &s.registered_by,
            DidStatement::AzureV1(s) => &s.registered_by,
            DidStatement::Regular(s) => &s.registered_by,
        }
    }

    /// Returns the verified computing type or statement type
    pub fn get_type(&self) -> &str {
        match self {
            DidStatement::AmdSevV1(s) => &s.vcomp.type_,
            DidStatement::DockerV1(s) => &s.vcomp.type_,
            DidStatement::CustomV1(s) => &s.vcomp.type_,
            DidStatement::IntelTdxV0(s) => &s.vcomp.type_,
            DidStatement::AzureV1(s) => &s.vcomp.type_,
            DidStatement::Regular(s) => &s.type_,
        }
    }

    /// Returns the DID being registered
    pub fn get_did(&self) -> &str {
        match self {
            DidStatement::AmdSevV1(s) => &s.did,
            DidStatement::DockerV1(s) => &s.did,
            DidStatement::CustomV1(s) => &s.did,
            DidStatement::IntelTdxV0(s) => &s.did,
            DidStatement::AzureV1(s) => &s.did,
            DidStatement::Regular(s) => &s.did,
        }
    }
}

impl StatementTrait for DidStatement {
    fn get_id(&self) -> String {
        match self {
            DidStatement::AmdSevV1(s) => s.get_id(),
            DidStatement::DockerV1(s) => s.get_id(),
            DidStatement::CustomV1(s) => s.get_id(),
            DidStatement::IntelTdxV0(s) => s.get_id(),
            DidStatement::AzureV1(s) => s.get_id(),
            DidStatement::Regular(s) => s.get_id(),
        }
    }

    fn jsonld_filename(&self) -> String {
        match self {
            DidStatement::AmdSevV1(s) => s.jsonld_filename(),
            DidStatement::DockerV1(s) => s.jsonld_filename(),
            DidStatement::CustomV1(s) => s.jsonld_filename(),
            DidStatement::IntelTdxV0(s) => s.jsonld_filename(),
            DidStatement::AzureV1(s) => s.jsonld_filename(),
            DidStatement::Regular(s) => s.jsonld_filename(),
        }
    }

    fn referenced_cids(&self) -> Vec<String> {
        match self {
            DidStatement::AmdSevV1(s) => s.referenced_cids(),
            DidStatement::DockerV1(s) => s.referenced_cids(),
            DidStatement::CustomV1(s) => s.referenced_cids(),
            DidStatement::IntelTdxV0(s) => s.referenced_cids(),
            DidStatement::AzureV1(s) => s.referenced_cids(),
            DidStatement::Regular(s) => s.referenced_cids(),
        }
    }
}

impl<'de> serde::Deserialize<'de> for DidStatement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = serde_json::Value::deserialize(deserializer)?;

        let vcomp = raw.get("vcomp");

        let err_msg_type;

        let did_statement = if let Some(vcomp) = vcomp {
            let type_ = vcomp
                .get("@type")
                .ok_or_else(|| serde::de::Error::missing_field("@type in vcomp"))?
                .as_str()
                .ok_or_else(|| serde::de::Error::custom("@type in vcomp is not a string"))?
                .to_owned();
            err_msg_type = type_.clone();

            match type_.as_str() {
                eqty_vcomp_amdsev_v1::VCOMP_TYPE_VALUE => {
                    serde_json::from_value(raw).map(DidStatement::AmdSevV1)
                }
                eqty_vcomp_docker_v1::VCOMP_TYPE_VALUE => {
                    serde_json::from_value(raw).map(DidStatement::DockerV1)
                }
                eqty_vcomp_inteltdx_v0::VCOMP_TYPE_VALUE => {
                    serde_json::from_value(raw).map(DidStatement::IntelTdxV0)
                }
                eqty_vcomp_azure_v1::VCOMP_TYPE_VALUE => {
                    serde_json::from_value(raw).map(DidStatement::AzureV1)
                }
                eqty_vcomp_custom_v1::VCOMP_TYPE_VALUE => {
                    serde_json::from_value(raw).map(DidStatement::CustomV1)
                }
                _ => Err(serde::de::Error::custom(format!(
                    "Unknown vcomp type: {type_}"
                ))),
            }
        } else {
            err_msg_type = "Regular".to_owned();

            serde_json::from_value(raw).map(DidStatement::Regular)
        }
        .map_err(|e| {
            serde::de::Error::custom(format!(
                "Failed to deserialize `{err_msg_type}` DidRegistration: {e}",
            ))
        })?;

        Ok(did_statement)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::common::{UrnCidWithSha256, UrnCidWithSha384},
        *,
    };

    #[tokio::test]
    async fn serde_roundtrip_eqty_vcomp_amdsev_v1() {
        let did_statement = DidStatement::AmdSevV1(
            DidStatementEqtyVCompAmdSevV1::create(
                "did:example:123".to_owned(),
                Some([0; 32]),
                "SEV MODE Auto".to_owned(),
                1,
                "AMD EPYC".to_owned(),
                UrnCidWithSha256 {
                    cid: "urn:cid:OVMF".to_owned(),
                    sha256: [0; 32],
                },
                UrnCidWithSha256 {
                    cid: "urn:cid:kernel".to_owned(),
                    sha256: [0; 32],
                },
                UrnCidWithSha256 {
                    cid: "urn:cid:initrd".to_owned(),
                    sha256: [0; 32],
                },
                UrnCidWithSha256 {
                    cid: "urn:cid:append".to_owned(),
                    sha256: [0; 32],
                },
                "did:example:456".to_owned(),
                None,
            )
            .await
            .unwrap(),
        );

        let reimported_statement =
            serde_json::from_str(serde_json::to_string(&did_statement).unwrap().as_str()).unwrap();

        assert_eq!(did_statement, reimported_statement);
    }

    #[tokio::test]
    async fn serde_roundtrip_eqty_vcomp_azure_v1() {
        let did_statement = DidStatement::AzureV1(
            DidStatementEqtyVCompAzureV1::create(
                "did:example:123".to_owned(),
                Some(vec![0; 32]),
                Some(vec![0; 32]),
                Some("urn:cid:uki".to_owned()),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:kernel".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:initrd".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:append".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha256 {
                    cid: "urn:cid:rootfs".to_owned(),
                    sha256: [0; 32],
                }),
                "did:example:456".to_owned(),
                None,
            )
            .await
            .unwrap(),
        );

        let reimported_statement =
            serde_json::from_str(serde_json::to_string(&did_statement).unwrap().as_str()).unwrap();

        assert_eq!(did_statement, reimported_statement);
    }

    #[tokio::test]
    async fn serde_roundtrip_eqty_vcomp_docker_v1() {
        let did_statement = DidStatement::DockerV1(
            DidStatementEqtyVCompDockerV1::create(
                "did:example:123".to_owned(),
                vec![],
                "urn:cid:compose".to_owned(),
                "did:example:456".to_owned(),
                "did:example:789".to_owned(),
                "did:example:012".to_owned(),
                None,
            )
            .await
            .unwrap(),
        );

        let reimported_statement =
            serde_json::from_str(serde_json::to_string(&did_statement).unwrap().as_str()).unwrap();

        assert_eq!(did_statement, reimported_statement);
    }

    #[tokio::test]
    async fn serde_roundtrip_eqty_vcomp_inteltdx_v0() {
        let did_statement = DidStatement::IntelTdxV0(
            DidStatementEqtyVCompIntelTdxV0::create(
                "did:example:123".to_owned(),
                vec![[0; 48]; 2],
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:ovmf".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:kernel".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:initrd".to_owned(),
                    sha384: [0; 48],
                }),
                Some(UrnCidWithSha384 {
                    cid: "urn:cid:append".to_owned(),
                    sha384: [0; 48],
                }),
                "did:example:456".to_owned(),
                None,
            )
            .await
            .unwrap(),
        );

        let reimported_statement =
            serde_json::from_str(serde_json::to_string(&did_statement).unwrap().as_str()).unwrap();

        assert_eq!(did_statement, reimported_statement);
    }

    #[tokio::test]
    async fn serde_roundtrip_regular() {
        let did_statement = DidStatement::Regular(
            DidStatementRegular::create(
                "did:example:123".to_owned(),
                "did:example:456".to_owned(),
                None,
            )
            .await
            .unwrap(),
        );

        let reimported_statement =
            serde_json::from_str(serde_json::to_string(&did_statement).unwrap().as_str()).unwrap();

        assert_eq!(did_statement, reimported_statement);
    }
}
