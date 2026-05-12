use std::collections::HashMap;

use anyhow::Result;
use json_ld::{JsonLdProcessor, RemoteDocument};
use json_syntax::Parse;
use rdf_types::generator;

/// Trait for types that can be converted to JSON-LD input strings.
///
/// Enables flexible input types for JSON-LD processing, supporting both
/// string and JSON value representations.
pub trait Input {
    /// Converts the input type to a JSON-LD string representation.
    fn convert_input(self) -> Result<String>;
}

impl Input for String {
    fn convert_input(self) -> Result<String> {
        Ok(self)
    }
}

impl Input for serde_json::Value {
    fn convert_input(self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }
}

/// Convert JSON-LD to N-Quads (non-canonical).
///
/// Optionally provide additional runtime contexts that take precedence over static contexts.
pub async fn jsonld_to_nquads<I>(
    input: I,
    additional_contexts: Option<HashMap<String, String>>,
) -> Result<String>
where
    I: Input,
{
    let input = input.convert_input()?;
    let loader = crate::loader::loader(additional_contexts)?;

    let (json, _) = json_syntax::Value::parse_str(&input)
        .map_err(|e| anyhow::anyhow!("failed to parse input JSON-LD: {e}"))?;
    let doc = RemoteDocument::new(None, None, json);

    let mut generator = generator::Blank::new();
    let mut rdf = doc
        .to_rdf(&mut generator, &loader)
        .await
        .map_err(|e| anyhow::anyhow!("failed to convert JSON-LD to RDF: {e}"))?;

    let nquads = rdf
        .cloned_quads()
        .map(|q| format!("{q} ."))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(nquads)
}

#[cfg(test)]
#[cfg(feature = "tokio-tests")]
mod tests {
    use nquads_syntax::parsing::Parse;

    use super::*;

    macro_rules! tests {
        ($($name:ident: $fixture:literal),* $(,)?) => {
            $(
                #[tokio::test]
                async fn $name() {
                    let json_ld = serde_json::from_str::<serde_json::Value>(
                        include_str!(concat!("../../fixtures/", $fixture, ".jsonld"))
                    ).unwrap();

                    let expected = nquads_syntax::Document::parse_str(
                        include_str!(concat!("../../fixtures/", $fixture, ".nquads")),
                    ).unwrap();
                    let expected = expected
                        .0
                        .into_iter()
                        .map(|q| q.strip_all_but_predicate())
                        .collect::<Vec<_>>();

                    let computed = jsonld_to_nquads(json_ld, None).await.unwrap();
                    let computed = nquads_syntax::Document::parse_str(&computed).unwrap();
                    let computed = computed
                        .0
                        .into_iter()
                        .map(|q| q.strip_all_but_predicate())
                        .collect::<Vec<_>>();

                    assert_eq!(computed, expected);
                }
            )*
        };
    }

    tests! {
        blank_nodes: "blank-nodes",
        foobar: "foobar",
        simple_compute: "simple-compute",
        simple_registration: "simple-registration",
    }

    #[tokio::test]
    async fn with_additional_context() {
        let json_ld = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../fixtures/additional-context.jsonld"
        ))
        .unwrap();

        let context = include_str!("../../fixtures/additional-context.context.json");

        let mut additional_contexts = HashMap::new();
        additional_contexts.insert(
            "https://example.com/custom-context".to_string(),
            context.to_string(),
        );

        let expected = nquads_syntax::Document::parse_str(include_str!(
            "../../fixtures/additional-context.nquads"
        ))
        .unwrap();
        let expected = expected
            .0
            .into_iter()
            .map(|q| q.strip_all_but_predicate())
            .collect::<Vec<_>>();

        let computed = jsonld_to_nquads(json_ld, Some(additional_contexts))
            .await
            .unwrap();
        let computed = nquads_syntax::Document::parse_str(&computed).unwrap();
        let computed = computed
            .0
            .into_iter()
            .map(|q| q.strip_all_but_predicate())
            .collect::<Vec<_>>();

        assert_eq!(computed, expected);
    }
}
