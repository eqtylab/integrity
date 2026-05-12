use anyhow::Result;
use nquads_syntax::Parse;

/// Canonicalizes N-Quads RDF data using URDNA2015 algorithm.
///
/// Parses N-Quads format RDF statements and normalizes them to canonical form.
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
        ssi::rdf::urdna2015::normalize(stripped.iter().map(|q| q.as_lexical_quad_ref()))
            .into_nquads();

    Ok(canonicalized)
}
