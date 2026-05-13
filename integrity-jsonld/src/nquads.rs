use anyhow::Result;
use nquads_syntax::Parse;

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
    let parsed = nquads_syntax::Document::parse_str(&nquads)
        .map_err(|e| anyhow::anyhow!("failed to parse n-quads: {e}"))?;

    let stripped: Vec<rdf_types::LexicalQuad> = parsed
        .into_value()
        .into_iter()
        .map(|meta_quad| {
            let quad = meta_quad.into_value();
            quad.map_all(
                |s| s.into_value(),
                |p| p.into_value(),
                |o| o.into_value(),
                |g| g.map(|m| m.into_value()),
            )
        })
        .collect();

    let canonicalized =
        ssi_rdf::urdna2015::normalize(stripped.iter().map(|q| q.as_lexical_quad_ref()))
            .into_nquads();

    Ok(canonicalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! tests {
        ($($name:ident: $fixture:literal),* $(,)?) => {
            $(
                #[test]
                fn $name() {
                    let input = include_str!(concat!("../../fixtures/", $fixture, ".nquads"));

                    let expected = include_str!(concat!("../../fixtures/", $fixture, ".canon.nquads"));

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
