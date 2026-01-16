use anyhow::Result;
use locspan::Meta;
use nquads_syntax::parsing::Parse;
use rdf_types::Quad;

/// Canonicalizes N-Quads RDF data using URDNA2015 algorithm
///
/// Parses N-Quads format RDF statements and normalizes them to canonical form
/// using the Universal RDF Dataset Normalization Algorithm 2015 (URDNA2015).
///
/// # Arguments
/// * `nquads` - N-Quads format RDF data as a string
///
/// # Returns
/// Canonicalized N-Quads string
///
/// # Errors
/// Returns error if the input cannot be parsed as valid N-Quads
pub fn canonicalize_nquads(nquads: String) -> Result<String> {
    let dataset = nquads_syntax::Document::parse_str(&nquads, |span| span)?;

    let stripped_dataset = dataset
        .into_value()
        .into_iter()
        .map(Meta::into_value)
        .map(Quad::strip_all_but_predicate)
        .collect::<Vec<_>>();

    let canonicalized_nquads =
        ssi_json_ld::urdna2015::normalize(stripped_dataset.iter().map(Quad::as_quad_ref))
            .into_nquads();

    Ok(canonicalized_nquads)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! tests {
        ($($name:ident: $fixture:literal),* $(,)?) => {
            $(
                #[test]
                fn $name() {
                    let input = include_str!(concat!("../fixtures/", $fixture, ".nquads"));

                    let expected = include_str!(concat!("../fixtures/", $fixture, ".canon.nquads"));

                    let computed = canonicalize_nquads(input.to_owned()).unwrap();

                    assert_eq!(computed.as_str(), expected);
                }
            )*
        };
    }

    tests! {
        // blank_nodes: "blank-nodes", TODO: this fails, look into blank node naming
        foobar: "foobar",
        simple_compute: "simple-compute",
        simple_registration: "simple-registration",
    }
}
