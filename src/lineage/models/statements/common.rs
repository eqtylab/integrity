//! Common types and utilities for statement serialization

use std::fmt;

use serde::{
    de::{Error, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A CID reference with its SHA-256 hash for verification
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UrnCidWithSha256 {
    /// Content identifier in URN format
    #[serde(rename = "@id")]
    pub cid: String,
    /// SHA-256 hash of the content
    #[serde(
        serialize_with = "serialize_u8_arr_as_hex",
        deserialize_with = "deserialize_u8_arr_32_from_hex"
    )]
    pub sha256: [u8; 32],
}

/// A CID reference with its SHA-384 hash for verification
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UrnCidWithSha384 {
    /// Content identifier in URN format
    #[serde(rename = "@id")]
    pub cid: String,
    /// SHA-384 hash of the content
    #[serde(
        serialize_with = "serialize_u8_arr_as_hex",
        deserialize_with = "deserialize_u8_arr_48_from_hex"
    )]
    pub sha384: [u8; 48],
}

/// Serializes a byte array as a hex string
pub fn serialize_u8_arr_as_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

/// Serializes an optional byte vector as a hex string
pub fn serialize_option_u8_vec_as_hex<S>(
    bytes: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(vec) => serializer.serialize_some(&hex::encode(vec)),
        None => serializer.serialize_none(),
    }
}

/// Serializes an optional 32-byte array as a hex string
pub fn serialize_option_u8_arr_as_hex<S>(
    bytes: &Option<[u8; 32]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(array) => serializer.serialize_some(&hex::encode(array)),
        None => serializer.serialize_none(),
    }
}

/// Serializes a vector of 48-byte arrays as a list of hex strings
pub fn serialize_vec_u8_arr_48_as_hex<S>(vec: &[[u8; 48]], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_strings: Vec<String> = vec.iter().map(hex::encode).collect();
    serializer.serialize_some(&hex_strings)
}

/// Deserializes a hex string into an optional byte vector
pub fn deserialize_option_u8_vec_from_hex<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(s).map_err(D::Error::custom)?;

    Ok(Some(bytes))
}

/// Deserializes a hex string into a 32-byte array
pub fn deserialize_u8_arr_32_from_hex<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(s).map_err(D::Error::custom)?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| D::Error::custom("Expected 32 bytes"))?;
    Ok(array)
}

/// Deserializes a hex string into a 48-byte array
pub fn deserialize_u8_arr_48_from_hex<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(s).map_err(D::Error::custom)?;
    let array: [u8; 48] = bytes
        .try_into()
        .map_err(|_| D::Error::custom("Expected 48 bytes"))?;
    Ok(array)
}

/// Deserializes a hex string into an optional 32-byte array
pub fn deserialize_option_u8_arr_from_hex<'de, D>(
    deserializer: D,
) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str).map_err(D::Error::custom)?;
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| D::Error::custom("Expected 32 bytes"))?;
            Ok(Some(array))
        }
        None => Ok(None),
    }
}

/// Deserializes a list of hex strings into a vector of 48-byte arrays
pub fn deserialize_vec_u8_arr_48_from_hex<'de, D>(
    deserializer: D,
) -> Result<Vec<[u8; 48]>, D::Error>
where
    D: Deserializer<'de>,
{
    struct HexStringVecVisitor;

    impl<'de> Visitor<'de> for HexStringVecVisitor {
        type Value = Vec<[u8; 48]>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a list of 48-byte hex strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(hex_str) = seq.next_element::<String>()? {
                let bytes = hex::decode(&hex_str).map_err(A::Error::custom)?;
                let array = bytes
                    .try_into()
                    .map_err(|_| A::Error::custom("Expected 48 bytes"))?;
                vec.push(array);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_seq(HexStringVecVisitor)
}
