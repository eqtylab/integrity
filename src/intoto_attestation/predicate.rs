use std::{convert::TryFrom, fmt, str::FromStr};

use anyhow::Result;
use serde_json::Value;

use super::models;

const SPDX_PREDICATE_URI: &str = "https://spdx.dev/Document";
const MODEL_SIGNING_SIGNATURE_PREDICATE_URI: &str = "https://model_signing/signature/v1.0";

/// A predicate (claim) containing type information and data.
///
/// Predicates describe what happened to subjects in a supply chain event,
/// with strongly-typed predicate types and flexible JSON data.
#[derive(Debug, Clone)]
pub struct Predicate {
    /// The type of predicate being made
    pub predicate_type: PredicateType,
    /// The predicate data as arbitrary JSON
    pub predicate: Value,
}

/// Supported predicate types for in-toto attestations.
///
/// Defines the schema and interpretation of predicate data,
/// with built-in support for SPDX and extensibility for custom types.
#[derive(Debug, Clone)]
pub enum PredicateType {
    /// SPDX document predicate
    Spdx,
    /// Model signing signature predicate
    ModelSigningSignature,
    /// Any other custom predicate type
    Other(String),
}

impl fmt::Display for PredicateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PredicateType::Spdx => write!(f, "{}", SPDX_PREDICATE_URI),
            PredicateType::ModelSigningSignature => {
                write!(f, "{}", MODEL_SIGNING_SIGNATURE_PREDICATE_URI)
            }
            PredicateType::Other(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for PredicateType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            SPDX_PREDICATE_URI => Ok(PredicateType::Spdx),
            _ => Ok(PredicateType::Other(s.to_owned())),
        }
    }
}

impl TryFrom<models::Predicate> for Predicate {
    type Error = anyhow::Error;

    fn try_from(p: models::Predicate) -> Result<Self> {
        let models::Predicate {
            predicate_type,
            predicate,
        } = p;

        let predicate_type = PredicateType::from_str(&predicate_type)?;

        Ok(Self {
            predicate_type,
            predicate,
        })
    }
}

impl From<Predicate> for models::Predicate {
    fn from(p: Predicate) -> Self {
        let Predicate {
            predicate_type,
            predicate,
        } = p;

        let predicate_type = predicate_type.to_string();

        Self {
            predicate_type,
            predicate,
        }
    }
}
