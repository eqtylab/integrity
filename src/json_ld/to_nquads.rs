use std::collections::HashMap;

use anyhow::Result;
use json_ld::syntax::Parse;
use ssi_json_ld::rdf::IntoNQuads;

pub trait Input {
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

/// Convert JSON-LD to N-Quads.
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

    let mut loader = crate::json_ld::loader::loader(additional_contexts)?;

    let dataset = ssi_json_ld::json_to_dataset(
        json_ld::syntax::Value::parse_str(&input, |span| span)?,
        &mut loader,
        None,
    )
    .await?;

    let nquads = dataset.into_nquads();

    Ok(nquads)
}

#[cfg(test)]
#[cfg(feature = "tokio-tests")]
mod tests {
    use locspan::Meta;
    use nquads_syntax::parsing::Parse;
    use rdf_types::Quad;

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
                        |span| span,
                    ).unwrap();
                    let expected = expected
                        .into_value()
                        .into_iter()
                        .map(Meta::into_value)
                        .map(Quad::strip_all_but_predicate)
                        .collect::<Vec<_>>();

                    let computed = jsonld_to_nquads(json_ld, None).await.unwrap();
                    let computed = nquads_syntax::Document::parse_str(&computed, |span| span).unwrap();
                    let computed = computed
                        .into_value()
                        .into_iter()
                        .map(Meta::into_value)
                        .map(Quad::strip_all_but_predicate)
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

        let expected = nquads_syntax::Document::parse_str(
            include_str!("../../fixtures/additional-context.nquads"),
            |span| span,
        )
        .unwrap();
        let expected = expected
            .into_value()
            .into_iter()
            .map(Meta::into_value)
            .map(Quad::strip_all_but_predicate)
            .collect::<Vec<_>>();

        let computed = jsonld_to_nquads(json_ld, Some(additional_contexts))
            .await
            .unwrap();
        let computed = nquads_syntax::Document::parse_str(&computed, |span| span).unwrap();
        let computed = computed
            .into_value()
            .into_iter()
            .map(Meta::into_value)
            .map(Quad::strip_all_but_predicate)
            .collect::<Vec<_>>();

        assert_eq!(computed, expected);
    }
}
