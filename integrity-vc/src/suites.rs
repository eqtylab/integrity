//! Data Integrity suites that sign like ssi's but canonicalize through
//! `integrity-jsonld`.
//!
//! These match ssi's `Ed25519Signature2018`, `EcdsaSecp256r1Signature2019` and
//! `EcdsaSecp256k1Signature2019` in everything but the transformation step,
//! which expands the claims and the proof configuration with
//! [`integrity_jsonld::to_nquads::expand_jsonld`]. That reuses processed
//! top-level contexts across calls; ssi processes them again for every
//! expansion. Converting to RDF and canonicalizing is left to ssi, so the
//! canonical forms, and so the proofs, are the same.

use integrity_jsonld::{loader::IntegrityLoader, to_nquads::expand_jsonld};
use serde::Serialize;
use sha2::Sha256;
use ssi::{
    claims::data_integrity::{
        canonicalization::{CanonicalClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
        signing::DetachedJwsSigning,
        suite::{
            standard::{
                TransformationAlgorithm, TransformationError, TypedTransformationAlgorithm,
            },
            NoConfiguration, TransformationOptions,
        },
        CryptographicSuite, ProofConfigurationRef, SerializeCryptographicSuite,
        StandardCryptographicSuite, TypeRef,
    },
    crypto::algorithm::{EdDSA, ES256, ES256K},
    json_ld::{
        expansion::{Action, Policy},
        JsonLdLoaderProvider, JsonLdNodeObject,
    },
    rdf::{urdna2015, AnyLdEnvironment, LdEnvironment, LexicalQuad},
    verification_methods::{
        EcdsaSecp256k1VerificationKey2019, EcdsaSecp256r1VerificationKey2019,
        Ed25519VerificationKey2018,
    },
};

macro_rules! suite {
    ($name:ident, $type_name:literal, $method:ty, $algorithm:ty) => {
        #[doc = concat!("`", $type_name, "`, canonicalized through `integrity-jsonld`.")]
        #[derive(Debug, Default, Clone, Copy)]
        pub struct $name;

        impl StandardCryptographicSuite for $name {
            type Configuration = NoConfiguration;
            type Transformation = Canonicalize;
            type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;
            type VerificationMethod = $method;
            type SignatureAlgorithm = DetachedJwsSigning<$algorithm>;
            type ProofOptions = ();

            fn type_(&self) -> TypeRef<'_> {
                TypeRef::Other($type_name)
            }
        }
    };
}

suite!(
    Ed25519Signature2018,
    "Ed25519Signature2018",
    Ed25519VerificationKey2018,
    EdDSA
);
suite!(
    EcdsaSecp256r1Signature2019,
    "EcdsaSecp256r1Signature2019",
    EcdsaSecp256r1VerificationKey2019,
    ES256
);
suite!(
    EcdsaSecp256k1Signature2019,
    "EcdsaSecp256k1Signature2019",
    EcdsaSecp256k1VerificationKey2019,
    ES256K
);

/// ssi's `CanonicalizeClaimsAndConfiguration`, through `integrity-jsonld`.
pub struct Canonicalize;

impl<S: CryptographicSuite> TransformationAlgorithm<S> for Canonicalize {
    type Output = CanonicalClaimsAndConfiguration;
}

impl<S, T, C> TypedTransformationAlgorithm<S, T, C> for Canonicalize
where
    S: SerializeCryptographicSuite,
    T: Serialize + JsonLdNodeObject,
    C: JsonLdLoaderProvider<Loader = IntegrityLoader>,
{
    async fn transform(
        context: &C,
        data: &T,
        proof_configuration: ProofConfigurationRef<'_, S>,
        _verification_method: &S::VerificationMethod,
        _transformation_options: TransformationOptions<S>,
    ) -> Result<Self::Output, TransformationError> {
        let loader = context.loader();

        let claims = quads(data, loader).await?;

        // Like ssi, expand the proof configuration with the document's
        // `@context` and `type`, then keep the triples of the proof's graph.
        let embedded = quads(&proof_configuration.embed(data), loader).await?;
        let configuration = proof_graph(embedded)?;

        Ok(CanonicalClaimsAndConfiguration {
            claims: canonical_lines(&claims),
            configuration: canonical_lines(&configuration),
        })
    }
}

/// Expansion policy ssi's `CompactJsonLd` uses: invalid values and undefined
/// terms are errors.
fn strict_policy() -> Policy {
    Policy {
        invalid: Action::Reject,
        allow_undefined: false,
        ..Default::default()
    }
}

async fn quads(
    document: &impl Serialize,
    loader: &IntegrityLoader,
) -> Result<Vec<LexicalQuad>, TransformationError> {
    let expansion_error = |e: anyhow::Error| TransformationError::JsonLdExpansion(e.to_string());

    let json = serde_json::to_value(document).map_err(|e| expansion_error(e.into()))?;
    let expanded = expand_jsonld(json, loader, strict_policy())
        .await
        .map_err(expansion_error)?;

    LdEnvironment::default()
        .quads_of(&expanded)
        .map_err(TransformationError::JsonLdDeserialization)
}

/// The triples in the graph named by the default graph's `sec:proof` object.
fn proof_graph(quads: Vec<LexicalQuad>) -> Result<Vec<LexicalQuad>, TransformationError> {
    let missing = || TransformationError::JsonLdExpansion("missing proof configuration".into());

    let graph = quads
        .iter()
        .find(|q| q.3.is_none() && q.1.as_str() == ssi::security::PROOF.as_str())
        .and_then(|q| q.2.as_id())
        .cloned()
        .ok_or_else(missing)?;

    Ok(quads
        .into_iter()
        .filter(|q| q.3.as_ref() == Some(&graph))
        .map(|mut q| {
            q.3 = None;
            q
        })
        .collect())
}

fn canonical_lines(quads: &[LexicalQuad]) -> Vec<String> {
    urdna2015::normalize(quads.iter().map(|q| q.as_lexical_quad_ref())).into_nquads_lines()
}
