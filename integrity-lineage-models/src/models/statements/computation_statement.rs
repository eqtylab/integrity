use anyhow::{anyhow, bail, Result};
use chrono::DateTime;
use integrity_jsonld::{ig_common_context_link, ig_computation_context_link};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    compute_cid, format_cids, format_timestamp, get_jsonld_filename, StatementTrait, ValueOrArray,
};
use crate::cid::prepend_urn_cid;

/// Namespace of the name-based UUIDs that identify OpenTelemetry spans (see [`otel_span_urn`]).
pub const OTEL_SPAN_NAMESPACE: Uuid = Uuid::from_u128(0x3eeccd21_6917_4419_a92d_893e3fd3a821);

/// The `urn:uuid` that identifies an OpenTelemetry span: a version 5 (name-based)
/// UUID in [`OTEL_SPAN_NAMESPACE`] of `"{trace_id}/{span_id}"`.
///
/// The same trace and span always give the same URN, so a child can name its
/// parent from the `traceparent` it is called with, before the parent has ended.
/// IDs are the W3C trace-context hex forms (32 and 16 digits, not all zero) and
/// are read case-insensitively.
pub fn otel_span_urn(trace_id: &str, span_id: &str) -> Result<String> {
    let trace_id = otel_hex_id(trace_id, 32, "trace")?;
    let span_id = otel_hex_id(span_id, 16, "span")?;
    let uuid = Uuid::new_v5(
        &OTEL_SPAN_NAMESPACE,
        format!("{trace_id}/{span_id}").as_bytes(),
    );
    Ok(format!("urn:uuid:{uuid}"))
}

fn otel_hex_id(id: &str, digits: usize, kind: &str) -> Result<String> {
    let id = id.to_ascii_lowercase();
    if id.len() != digits || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("OpenTelemetry {kind} ID '{id}' is not {digits} hex digits.");
    }
    if id.bytes().all(|b| b == b'0') {
        bail!("OpenTelemetry {kind} ID '{id}' is all zeros, which is invalid.");
    }
    Ok(id)
}

/// When a computation ran and which span it was, as an OpenTelemetry span records.
///
/// `start_time` and `end_time` are when the work itself began and ended, which is
/// different from the statement's `timestamp` (when it was registered). `span` and
/// `parent_span` are `urn:uuid` identifiers of the computation's own span and of the
/// span it ran inside (see [`otel_span_urn`]). A computation names its parent, not
/// its children, so every statement can be registered as soon as its own span ends;
/// the nesting is read back by matching each `parentSpan` to a `span`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ComputationSpan {
    /// RFC 3339 time at which the computation started
    pub start_time: Option<String>,
    /// RFC 3339 time at which the computation ended
    pub end_time: Option<String>,
    /// `urn:uuid` of this computation's span
    pub span: Option<String>,
    /// `urn:uuid` of the span this computation ran inside
    pub parent_span: Option<String>,
}

impl ComputationSpan {
    /// The span of an OpenTelemetry span: its times and its, and its parent's, `urn:uuid`.
    pub fn from_otel(
        trace_id: &str,
        span_id: &str,
        parent_span_id: Option<&str>,
        start_time: Option<String>,
        end_time: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            start_time,
            end_time,
            span: Some(otel_span_urn(trace_id, span_id)?),
            parent_span: parent_span_id
                .map(|parent| otel_span_urn(trace_id, parent))
                .transpose()?,
        })
    }

    fn is_empty(&self) -> bool {
        self.start_time.is_none()
            && self.end_time.is_none()
            && self.span.is_none()
            && self.parent_span.is_none()
    }
}

/// A span identifier in its canonical form, `urn:uuid:` and a lowercase hyphenated UUID.
fn canonical_span_urn(urn: &str, term: &str) -> Result<String> {
    let uuid = urn
        .strip_prefix("urn:uuid:")
        .ok_or_else(|| anyhow!("Computation {term} '{urn}' is not a urn:uuid."))
        .and_then(|uuid| {
            Uuid::parse_str(uuid).map_err(|e| anyhow!("Computation {term} '{urn}': {e}"))
        })?;
    Ok(format!("urn:uuid:{}", uuid.hyphenated()))
}

/// Records a computational process with its inputs and outputs
///
/// This statement type captures the lineage of data transformations,
/// including the computation performed, input data, output data,
/// and the entity that executed the computation.
///
/// A computation may also record when it ran and which span it was, and the span
/// it ran inside (see [`ComputationSpan`]). Statements that do so use the
/// computation context, which extends the common context with those terms.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComputationStatement {
    /// JSON-LD context URL
    #[serde(rename = "@context")]
    pub context: String,
    /// Unique identifier for this statement
    #[serde(rename = "@id")]
    id: String,
    /// Statement type identifier
    #[serde(rename = "@type")]
    pub type_: String,
    /// Optional CID of the computation definition or code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computation: Option<String>,
    /// Input data CIDs (single value or array)
    #[schema(value_type = String)]
    pub input: ValueOrArray<String>,
    /// Output data CIDs (single value or array)
    #[schema(value_type = String)]
    pub output: ValueOrArray<String>,
    /// DID of the entity that operated the computation
    pub operated_by: String,
    /// Optional identifier of the system where computation was executed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_on: Option<String>,
    /// Optional RFC 3339 time at which the computation started
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Optional RFC 3339 time at which the computation ended
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Optional `urn:uuid` of this computation's span
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
    /// Optional `urn:uuid` of the span this computation ran inside
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span: Option<String>,
    /// DID of the entity that registered this statement
    pub registered_by: String,
    /// ISO 8601 timestamp of when the statement was created
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
        Self::create_with_span(
            computation,
            input,
            output,
            operated_by,
            executed_on,
            registered_by,
            timestamp,
            ComputationSpan::default(),
        )
        .await
    }

    /// Creates a new ComputationRegistrationStatement object that records when it
    /// ran, which span it was, and the span it ran inside.
    ///
    /// An empty `span` produces the same statement, and the same CID, as [`Self::create`].
    /// A parent span needs the computation's own span, and the two must differ.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_span(
        computation: Option<String>,
        input: Vec<String>,
        output: Vec<String>,
        operated_by: String,
        executed_on: Option<String>,
        registered_by: String,
        timestamp: Option<String>,
        span: ComputationSpan,
    ) -> Result<Self> {
        let computation = computation
            .map(|s| prepend_urn_cid(s.as_str()))
            .transpose()?;
        let input = format_cids(input)?;
        let output = format_cids(output)?;

        let start = span.start_time.as_deref().map(parse_time).transpose()?;
        let end = span.end_time.as_deref().map(parse_time).transpose()?;
        if let (Some(start), Some(end)) = (start, end) {
            if end < start {
                bail!("Computation endTime must not be before its startTime.");
            }
        }

        let context = if span.is_empty() {
            ig_common_context_link()
        } else {
            ig_computation_context_link()
        };
        let own_span = span
            .span
            .as_deref()
            .map(|urn| canonical_span_urn(urn, "span"))
            .transpose()?;
        let parent_span = span
            .parent_span
            .as_deref()
            .map(|urn| canonical_span_urn(urn, "parentSpan"))
            .transpose()?;
        match (&own_span, &parent_span) {
            (None, Some(_)) => bail!("Computation parentSpan needs the computation's own span."),
            (Some(own), Some(parent)) if own == parent => {
                bail!("Computation span and parentSpan must differ.")
            }
            _ => {}
        }

        let statement = Self {
            context,
            id: String::from("in-progress"),
            type_: "ComputationRegistration".to_owned(),
            computation,
            input,
            output,
            operated_by,
            executed_on,
            start_time: span.start_time,
            end_time: span.end_time,
            span: own_span,
            parent_span,
            registered_by,
            timestamp: format_timestamp(timestamp),
        };

        // compute real CID and set
        let id = compute_cid(&statement).await?;
        let statement = Self { id, ..statement };

        Ok(statement)
    }
}

fn parse_time(time: &str) -> Result<DateTime<chrono::FixedOffset>> {
    DateTime::parse_from_rfc3339(time)
        .map_err(|e| anyhow::anyhow!("Computation time '{time}' is not RFC 3339: {e}"))
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

    const DID: &str = "did:key:z6Mkvt1grez4Avdvhqc196hTs6Lxb4qmu1NUdGk2An7QKqnT";
    const INPUT: &str = "urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi";
    const OUTPUT: &str = "urn:cid:bafkr4ifqnz4knhvvgorsjl6hwhtmzfkfurebfslr3mwe2bqygcgu4bq3wi";
    const TRACE: &str = "01a1401d684b7f40a85aba2fa15ba51d";
    const ROOT: &str = "a85aba2fa15ba51d";
    const CHILD: &str = "93460e50e31602c0";

    async fn with_span(span: ComputationSpan) -> Result<ComputationStatement> {
        ComputationStatement::create_with_span(
            None,
            vec![INPUT.to_owned()],
            vec![OUTPUT.to_owned()],
            DID.to_owned(),
            None,
            DID.to_owned(),
            Some("2024-06-27T14:36:35Z".to_owned()),
            span,
        )
        .await
    }

    fn full_span() -> ComputationSpan {
        ComputationSpan::from_otel(
            TRACE,
            CHILD,
            Some(ROOT),
            Some("2024-06-27T14:36:20.404544Z".to_owned()),
            Some("2024-06-27T14:36:34.768539Z".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn otel_span_urn_is_a_v5_uuid_of_trace_and_span() {
        let urn = otel_span_urn(TRACE, CHILD).unwrap();
        let uuid = Uuid::parse_str(urn.strip_prefix("urn:uuid:").unwrap()).unwrap();
        assert_eq!(uuid.get_version_num(), 5);
        assert_eq!(
            uuid,
            Uuid::new_v5(&OTEL_SPAN_NAMESPACE, format!("{TRACE}/{CHILD}").as_bytes())
        );
        // Stable across releases: other implementations derive the same value
        assert_eq!(urn, "urn:uuid:44f895c1-bcfc-5980-ac00-84ace1063312");
        // Hex case does not matter; another span or trace gives another URN
        assert_eq!(
            otel_span_urn(&TRACE.to_uppercase(), &CHILD.to_uppercase()).unwrap(),
            urn
        );
        assert_ne!(otel_span_urn(TRACE, ROOT).unwrap(), urn);
    }

    #[test]
    fn otel_span_urn_rejects_invalid_ids() {
        assert!(otel_span_urn("01a1401d", CHILD).is_err());
        assert!(otel_span_urn(TRACE, "93460e50e31602cz").is_err());
        assert!(otel_span_urn(&"0".repeat(32), CHILD).is_err());
        assert!(otel_span_urn(TRACE, &"0".repeat(16)).is_err());
    }

    #[tokio::test]
    async fn empty_span_keeps_common_context_and_cid() {
        let plain = with_span(ComputationSpan::default()).await.unwrap();
        let created = ComputationStatement::create(
            None,
            vec![INPUT.to_owned()],
            vec![OUTPUT.to_owned()],
            DID.to_owned(),
            None,
            DID.to_owned(),
            Some("2024-06-27T14:36:35Z".to_owned()),
        )
        .await
        .unwrap();

        assert_eq!(plain, created);
        assert_eq!(plain.context, ig_common_context_link());
        let json = serde_json::to_value(&plain).unwrap();
        for key in ["startTime", "endTime", "span", "parentSpan"] {
            assert!(
                json.get(key).is_none(),
                "{key} serialized on a plain statement"
            );
        }
    }

    #[tokio::test]
    async fn span_uses_computation_context() {
        let statement = with_span(full_span()).await.unwrap();

        assert_eq!(statement.context, ig_computation_context_link());
        let json = serde_json::to_value(&statement).unwrap();
        assert_eq!(json["startTime"], "2024-06-27T14:36:20.404544Z");
        assert_eq!(json["endTime"], "2024-06-27T14:36:34.768539Z");
        assert_eq!(json["span"], otel_span_urn(TRACE, CHILD).unwrap());
        assert_eq!(json["parentSpan"], otel_span_urn(TRACE, ROOT).unwrap());
        assert!(json.get("subcomputations").is_none());

        let parsed: ComputationStatement = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, statement);
    }

    #[tokio::test]
    async fn span_terms_are_covered_by_the_cid() {
        let base = with_span(full_span()).await.unwrap();

        let mut later_start = full_span();
        later_start.start_time = Some("2024-06-27T14:36:21Z".to_owned());
        let mut later_end = full_span();
        later_end.end_time = Some("2024-06-27T14:36:35Z".to_owned());
        let mut other_span = full_span();
        other_span.span = Some(otel_span_urn(TRACE, "b0ce072c04d26a6c").unwrap());
        let mut root = full_span();
        root.parent_span = None;

        for span in [later_start, later_end, other_span, root] {
            let changed = with_span(span).await.unwrap();
            assert_ne!(changed.get_id(), base.get_id(), "span term not in the CID");
        }
    }

    #[tokio::test]
    async fn span_urns_are_canonical() {
        let mut span = full_span();
        span.span = span
            .span
            .map(|urn| urn.to_uppercase().replace("URN:UUID:", "urn:uuid:"));

        let statement = with_span(span).await.unwrap();
        assert_eq!(statement.span, Some(otel_span_urn(TRACE, CHILD).unwrap()));
    }

    #[tokio::test]
    async fn span_rejects_bad_times_and_spans() {
        let mut reversed = full_span();
        reversed.end_time = Some("2024-06-27T14:36:00Z".to_owned());
        assert!(with_span(reversed).await.is_err());

        let mut unparsable = full_span();
        unparsable.start_time = Some("yesterday".to_owned());
        assert!(with_span(unparsable).await.is_err());

        let mut orphan_parent = full_span();
        orphan_parent.span = None;
        assert!(with_span(orphan_parent).await.is_err());

        let mut own_parent = full_span();
        own_parent.parent_span = own_parent.span.clone();
        assert!(with_span(own_parent).await.is_err());

        let mut not_a_uuid = full_span();
        not_a_uuid.span =
            Some("urn:cid:bafkr4ia3wmrvedxwkjm6jfmtqy2bdcpi47hv5bni7twshohepck3gsgodi".to_owned());
        assert!(with_span(not_a_uuid).await.is_err());
    }
}
