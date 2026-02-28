use anyhow::Result;
use locspan::Meta;
use nquads_syntax::parsing::Parse;
use rdf_types::Quad;

/// Canonicalizes N-Quads RDF data using URDNA2015 algorithm.
///
/// Parses N-Quads format RDF statements and normalizes them to canonical form.
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
