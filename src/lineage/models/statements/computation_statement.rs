use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{
    compute_cid, format_cids, format_timestamp, get_jsonld_filename, StatementTrait, ValueOrArray,
};
use crate::{cid::prepend_urn_cid, json_ld::ig_common_context_link};

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComputationStatement {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computation: Option<String>,
    #[schema(value_type = String)]
    pub input: ValueOrArray<String>,
    #[schema(value_type = String)]
    pub output: ValueOrArray<String>,
    pub operated_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_on: Option<String>,
    pub registered_by: String,
    pub timestamp: String,
}

impl StatementTrait for ComputationStatement {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn jsonld_filename(&self) -> String {
        get_jsonld_filename(self)
    }

    fn referenced_cids(&self) -> Vec<String> {
        let mut refs = Vec::new();
        match &self.input {
            ValueOrArray::Value(v) => refs.push(v.clone()),
            ValueOrArray::Array(a) => refs.extend(a.clone()),
        };

        match &self.output {
            ValueOrArray::Value(v) => refs.push(v.clone()),
            ValueOrArray::Array(a) => refs.extend(a.clone()),
        };

        if let Some(computation) = &self.computation {
            refs.push(computation.clone())
        }

        if let Some(executed_on) = &self.executed_on {
            refs.push(executed_on.clone())
        }

        refs
    }
}

impl ComputationStatement {
    /// Creates a new ComputationRegistrationStatement object.
    /// `input` and `output` cids will be prepended with `urn:cid:` if not already formatted with the prefix
    pub async fn create(
        computation: Option<String>,
        input: Vec<String>,
        output: Vec<String>,
        operated_by: String,
        executed_on: Option<String>,
        registered_by: String,
        timestamp: Option<String>,
    ) -> Result<Self> {
        let computation = computation
            .map(|s| prepend_urn_cid(s.as_str()))
            .transpose()?;
        let input = format_cids(input)?;
        let output = format_cids(output)?;

        let statement = Self {
            context: ig_common_context_link(),
            id: String::from("in-progress"),
            type_: "ComputationRegistration".to_owned(),
            computation,
            input,
            output,
            operated_by,
            executed_on,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;

    #[tokio::test]
    async fn generate_computation_statement() {
        let expected_context = ig_common_context_link();
        let expected_id = "urn:cid:bagb6qaq6ebhv3dwuqzdfds7gvltntmovpf7ing7b3npjpll7xjge7c6bddl5m";
        let expected_type = "ComputationRegistration";
        let expected_computation =
            "urn:cid:bafkr4ifoun4lisqjjft75svkzewgwybr65arm5lc72hpzlgenqkfrcfanm";
        let expected_input = "urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi";
        let expected_output = "urn:cid:bafkr4ifqnz4knhvvgorsjl6hwhtmzfkfurebfslr3mwe2bqygcgu4bq3wi";
        let expected_operated_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
        let expected_registered_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
        let expected_timestamp = "2024-06-27T14:36:35Z";

        let generated_statement = ComputationStatement::create(
            Some(expected_computation.to_owned()),
            vec![expected_input.to_owned()],
            vec![expected_output.to_owned()],
            expected_operated_by.to_owned(),
            Some(expected_operated_by.to_owned()),
            expected_operated_by.to_owned(),
            Some(expected_timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            generated_statement.context, expected_context,
            "Context match failed"
        );
        assert_eq!(generated_statement.id, expected_id, "ID match failed");
        assert_eq!(
            generated_statement.type_, expected_type,
            "Type match failed"
        );
        assert_eq!(
            generated_statement.input,
            ValueOrArray::Value(expected_input.to_owned())
        );
        assert_eq!(
            generated_statement.output,
            ValueOrArray::Value(expected_output.to_owned())
        );
        assert_eq!(
            generated_statement.operated_by, expected_operated_by,
            "OperatedBy match failed"
        );
        assert_eq!(
            generated_statement.registered_by, expected_registered_by,
            "RegisteredBy match failed"
        );
        assert_eq!(
            generated_statement.timestamp, expected_timestamp,
            "Timestamp match failed"
        );
        assert_eq!(
            generated_statement.computation.unwrap(),
            expected_computation,
            "Computation match failed"
        );
    }

    #[tokio::test]
    async fn generate_computation_statement_no_prefix() {
        let expected_context = ig_common_context_link();
        let expected_id = "urn:cid:bagb6qaq6ebhv3dwuqzdfds7gvltntmovpf7ing7b3npjpll7xjge7c6bddl5m";
        let expected_type = "ComputationRegistration";
        let expected_computation =
            "urn:cid:bafkr4ifoun4lisqjjft75svkzewgwybr65arm5lc72hpzlgenqkfrcfanm";
        let expected_input = "urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi";
        let expected_output = "urn:cid:bafkr4ifqnz4knhvvgorsjl6hwhtmzfkfurebfslr3mwe2bqygcgu4bq3wi";
        let expected_operated_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
        let expected_registered_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
        let expected_timestamp = "2024-06-27T14:36:35Z";

        let generated_statement = ComputationStatement::create(
            Some("bafkr4ifoun4lisqjjft75svkzewgwybr65arm5lc72hpzlgenqkfrcfanm".to_owned()),
            vec!["bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi".to_owned()],
            vec!["bafkr4ifqnz4knhvvgorsjl6hwhtmzfkfurebfslr3mwe2bqygcgu4bq3wi".to_owned()],
            expected_operated_by.to_owned(),
            Some(expected_operated_by.to_owned()),
            expected_operated_by.to_owned(),
            Some(expected_timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            generated_statement.input,
            ValueOrArray::Value(expected_input.to_owned())
        );
        assert_eq!(
            generated_statement.output,
            ValueOrArray::Value(expected_output.to_owned())
        );
        assert_eq!(
            generated_statement.operated_by, expected_operated_by,
            "OperatedBy match failed"
        );
        assert_eq!(
            generated_statement.registered_by, expected_registered_by,
            "RegisteredBy match failed"
        );
        assert_eq!(
            generated_statement.timestamp, expected_timestamp,
            "Timestamp match failed"
        );
        assert_eq!(
            generated_statement.computation.unwrap(),
            expected_computation,
            "Computation match failed"
        );
        assert_eq!(generated_statement.id, expected_id, "ID match failed");
        assert_eq!(
            generated_statement.context, expected_context,
            "Context match failed"
        );
        assert_eq!(
            generated_statement.type_, expected_type,
            "Type match failed"
        );
    }

    #[tokio::test]
    async fn generate_computation_statement_no_timestamp() {
        let min_timestamp: DateTime<Utc> = "2024-06-27T14:00:00Z".parse().unwrap();

        let expected_context = ig_common_context_link();
        let expected_type = "ComputationRegistration";
        let expected_computation =
            "urn:cid:bafkr4ifoun4lisqjjft75svkzewgwybr65arm5lc72hpzlgenqkfrcfanm";
        let expected_input = "urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi";
        let expected_output = "urn:cid:bafkr4ifqnz4knhvvgorsjl6hwhtmzfkfurebfslr3mwe2bqygcgu4bq3wi";
        let expected_operated_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
        let expected_registered_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";

        let generated_statement = ComputationStatement::create(
            Some("bafkr4ifoun4lisqjjft75svkzewgwybr65arm5lc72hpzlgenqkfrcfanm".to_owned()),
            vec!["bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi".to_owned()],
            vec!["bafkr4ifqnz4knhvvgorsjl6hwhtmzfkfurebfslr3mwe2bqygcgu4bq3wi".to_owned()],
            expected_operated_by.to_owned(),
            Some(expected_operated_by.to_owned()),
            expected_operated_by.to_owned(),
            None,
        )
        .await
        .unwrap();

        let generated_timestamp: DateTime<Utc> = generated_statement.timestamp.parse().unwrap();

        assert!(generated_timestamp > min_timestamp);

        assert_eq!(
            generated_statement.input,
            ValueOrArray::Value(expected_input.to_owned())
        );
        assert_eq!(
            generated_statement.output,
            ValueOrArray::Value(expected_output.to_owned())
        );
        assert_eq!(
            generated_statement.operated_by, expected_operated_by,
            "OperatedBy match failed"
        );
        assert_eq!(
            generated_statement.registered_by, expected_registered_by,
            "RegisteredBy match failed"
        );
        assert_eq!(
            generated_statement.computation.unwrap(),
            expected_computation,
            "Computation match failed"
        );
        assert_eq!(
            generated_statement.context, expected_context,
            "Context match failed"
        );
        assert_eq!(
            generated_statement.type_, expected_type,
            "Type match failed"
        );
    }

    #[tokio::test]
    async fn generate_computation_statement_empty_cids() {
        let expected_context = ig_common_context_link();
        let expected_id = "urn:cid:bagb6qaq6ea2yaowqq2ckitmg6mcgfzosxczzb6xqhl66qiowf37n2g6my3w2u";
        let expected_type = "ComputationRegistration";
        let expected_computation =
            "urn:cid:bafkr4ifoun4lisqjjft75svkzewgwybr65arm5lc72hpzlgenqkfrcfanm";
        let expected_input = vec![
            "urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi".to_owned(),
            "urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsowlx".to_owned(),
        ];
        let expected_output = vec!["urn:cid:output1".to_owned(), "urn:cid:output2".to_owned()];
        let expected_operated_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
        let expected_registered_by = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
        let expected_timestamp = "2024-06-27T14:36:35Z";

        let generated_statement = ComputationStatement::create(
            Some(expected_computation.to_owned()),
            vec![
                "urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi".to_owned(),
                "".to_owned(),
                "bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsowlx".to_owned(),
            ]
            .clone(),
            vec![
                "".to_owned(),
                "output1".to_owned(),
                "output2".to_owned(),
                "".to_owned(),
            ],
            expected_operated_by.to_owned(),
            Some(expected_operated_by.to_owned()),
            expected_operated_by.to_owned(),
            Some(expected_timestamp.to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(
            generated_statement.input,
            ValueOrArray::Array(expected_input),
            "Input match failed"
        );
        assert_eq!(
            generated_statement.output,
            ValueOrArray::Array(expected_output),
            "Output match failed"
        );
        assert_eq!(
            generated_statement.operated_by, expected_operated_by,
            "OperatedBy match failed"
        );
        assert_eq!(
            generated_statement.registered_by, expected_registered_by,
            "RegisteredBy match failed"
        );
        assert_eq!(
            generated_statement.timestamp, expected_timestamp,
            "Timestamp match failed"
        );
        assert_eq!(
            generated_statement.computation.unwrap(),
            expected_computation,
            "Computation match failed"
        );
        assert_eq!(generated_statement.id, expected_id, "ID match failed");
        assert_eq!(
            generated_statement.context, expected_context,
            "Context match failed"
        );
        assert_eq!(
            generated_statement.type_, expected_type,
            "Type match failed"
        );
    }
}
