//! DID (Decentralized Identifier) statement types
//!
//! This module contains statement types for registering DIDs.

/// Regular DID statement without attestation
pub mod regular;

pub use regular::DidStatementRegular;

use super::StatementTrait;

/// Enum representing different types of DID registration statements
#[derive(Debug, Clone, utoipa::ToSchema, serde::Serialize, PartialEq)]
#[serde(untagged)]
pub enum DidStatement {
    /// Regular DID registration without attestation
    Regular(DidStatementRegular),
}

impl DidStatement {
    /// Returns the DID of the entity that registered this statement
    pub fn get_registered_by(&self) -> &str {
        match self {
            DidStatement::Regular(s) => &s.registered_by,
        }
    }

    /// Returns the statement type
    pub fn get_type(&self) -> &str {
        match self {
            DidStatement::Regular(s) => &s.type_,
        }
    }

    /// Returns the DID being registered
    pub fn get_did(&self) -> &str {
        match self {
            DidStatement::Regular(s) => &s.did,
        }
    }
}

impl StatementTrait for DidStatement {
    fn get_id(&self) -> String {
        match self {
            DidStatement::Regular(s) => s.get_id(),
        }
    }

    fn jsonld_filename(&self) -> String {
        match self {
            DidStatement::Regular(s) => s.jsonld_filename(),
        }
    }

    fn referenced_cids(&self) -> Vec<String> {
        match self {
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

        // VComp DID registrations are no longer supported; fail loudly rather
        // than silently downgrading a VComp payload to a Regular registration.
        if raw.get("vcomp").is_some() {
            return Err(serde::de::Error::custom(
                "vcomp DID registrations are no longer supported",
            ));
        }

        serde_json::from_value(raw)
            .map(DidStatement::Regular)
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "Failed to deserialize Regular DidRegistration: {e}"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn deserialize_rejects_vcomp_payload() {
        let did_statement = DidStatement::Regular(
            DidStatementRegular::create(
                "did:example:123".to_owned(),
                "did:example:456".to_owned(),
                None,
            )
            .await
            .unwrap(),
        );

        // Take a valid Regular payload and graft a `vcomp` object onto it.
        let mut value = serde_json::to_value(&did_statement).unwrap();
        value.as_object_mut().unwrap().insert(
            "vcomp".to_owned(),
            serde_json::json!({ "@type": "EqtyVCompAmdSevV1" }),
        );

        let result: Result<DidStatement, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }
}
