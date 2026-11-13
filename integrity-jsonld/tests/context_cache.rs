//! Checks that reusing processed contexts never changes results.
//!
//! Two caches are involved: `integrity-jsonld`'s cache of processed top-level
//! contexts, and the memoization in the vendored `json-ld-context-processing`
//! (see `vendor/README.md`). The reference here expands with the `&mut ()`
//! vocabulary, which behaves like `()` but is cached by neither.

use std::collections::HashMap;

use futures::executor::block_on;
use integrity_jsonld::{ig_common_context_link, loader::loader, to_nquads::jsonld_to_nquads};
use json_ld::{
    context_processing::Warning, syntax::TryFromJson, Context, JsonLdProcessor, Process,
};
use json_syntax::Parse;
use serde_json::{json, Value};

type Contexts = Option<HashMap<String, String>>;

const LEGACY_VC: &str = include_str!("../../fixtures/legacy-vc/ed25519.json");

fn reference(document: &Value, contexts: Contexts) -> String {
    let loader = loader(contexts).unwrap();
    let (json, _) = json_syntax::Value::parse_str(&document.to_string()).unwrap();
    let document = json_ld::RemoteDocument::new(None, None, json);

    let mut vocabulary = ();
    let mut generator = rdf_types::generator::Blank::new();
    let mut rdf = block_on(document.to_rdf_with_using(
        &mut vocabulary,
        &mut generator,
        &loader,
        json_ld::Options::default(),
    ))
    .unwrap();

    rdf.cloned_quads()
        .map(|q| format!("{q} ."))
        .collect::<Vec<_>>()
        .join("\n")
}

fn computed(document: &Value, contexts: Contexts) -> String {
    block_on(jsonld_to_nquads(document.clone(), contexts)).unwrap()
}

/// Converts `document` repeatedly, so later calls hit both caches.
fn assert_matches_reference(document: &Value, contexts: Contexts) -> String {
    let expected = reference(document, contexts.clone());
    assert!(!expected.is_empty(), "{document} has no quads");
    for _ in 0..3 {
        assert_eq!(computed(document, contexts.clone()), expected, "{document}");
    }
    expected
}

fn fixture(name: &str) -> Value {
    let path = format!("{}/../fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A `CredentialRegistration` embedding a credential: the credential's
/// contexts are processed on top of the large common context.
fn credential_registration() -> Value {
    json!({
        "@context": ig_common_context_link(),
        "@type": "CredentialRegistration",
        "credential": serde_json::from_str::<Value>(LEGACY_VC).unwrap(),
        "registeredBy": "did:key:z6MknaHxxxqhq3imRYTHxZuqp1mNnSrtoo5XZoPzscsoC9iX",
        "timestamp": "2026-11-05T00:00:00Z",
    })
}

#[test]
fn matches_uncached_expansion() {
    let mut credential: Value = serde_json::from_str(LEGACY_VC).unwrap();
    credential.as_object_mut().unwrap().remove("proof");

    for document in [
        fixture("foobar.jsonld"),
        fixture("simple-compute.jsonld"),
        fixture("simple-registration.jsonld"),
        fixture("blank-nodes.jsonld"),
        serde_json::from_str(LEGACY_VC).unwrap(),
        credential,
        credential_registration(),
    ] {
        assert_matches_reference(&document, None);
    }
}

#[test]
fn caller_context_overriding_a_static_context() {
    let document = credential_registration();
    let bundled = assert_matches_reference(&document, None);

    let overridden = Some(HashMap::from([(
        ig_common_context_link(),
        json!({"@context": {"registeredBy": "https://example.com/registeredBy"}}).to_string(),
    )]));
    let replaced = assert_matches_reference(&document, overridden);
    assert_ne!(replaced, bundled);

    assert_eq!(computed(&document, None), bundled);
}

#[test]
fn caller_context_changing_between_calls() {
    let url = "https://example.com/changing-context";
    let document = json!({"@context": url, "@id": "urn:test:subject", "name": "Test"});

    let mut seen = Vec::new();
    for iri in [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/a",
    ] {
        let contexts = Some(HashMap::from([(
            url.to_string(),
            json!({"@context": {"name": iri}}).to_string(),
        )]));
        seen.push(assert_matches_reference(&document, contexts));
    }

    assert_ne!(seen[0], seen[1]);
    assert_eq!(seen[0], seen[2]);
}

#[test]
fn top_level_context_that_does_not_propagate() {
    // `@propagate` only applies to a context that is a single object.
    let document = json!({
        "@context": {"@propagate": false, "nickname": "https://example.com/nickname"},
        "@id": "urn:test:parent",
        "nickname": "parent",
        "https://example.com/child": {"@id": "urn:test:child", "nickname": "child"},
    });

    let nquads = assert_matches_reference(&document, None);
    assert!(nquads.contains(r#"<urn:test:parent> <https://example.com/nickname> "parent""#));
    assert!(!nquads.contains(r#""child""#));
}

#[test]
fn same_context_against_different_active_contexts() {
    let url = "https://example.com/shared-context";
    let contexts = Some(HashMap::from([(
        url.to_string(),
        json!({"@context": {"name": "https://example.com/name"}}).to_string(),
    )]));

    let top_level = json!({"@context": url, "@id": "urn:test:a", "name": "a"});
    // Here `url` is processed on top of an active context that also defines
    // `nickname`, which must stay defined inside `inner`.
    let nested = json!({
        "@context": {
            "nickname": "https://example.com/nickname",
            "inner": "https://example.com/inner",
        },
        "@id": "urn:test:b",
        "inner": {"@context": url, "@id": "urn:test:c", "name": "c", "nickname": "c"},
    });

    assert_matches_reference(&top_level, contexts.clone());
    let nquads = assert_matches_reference(&nested, contexts);
    assert!(nquads.contains(r#"<urn:test:c> <https://example.com/nickname> "c""#));
}

#[test]
fn invalid_contexts_fail_like_uncached_expansion() {
    let documents = [
        json!({"@context": "https://example.com/unknown", "@id": "urn:test:subject"}),
        json!({"@context": 5, "@id": "urn:test:subject"}),
    ];
    for document in documents {
        let loader = loader(None).unwrap();
        let (json, _) = json_syntax::Value::parse_str(&document.to_string()).unwrap();
        let expected = block_on(
            json_ld::RemoteDocument::new(None, None, json).to_rdf_with_using(
                &mut (),
                &mut rdf_types::generator::Blank::new(),
                &loader,
                json_ld::Options::default(),
            ),
        )
        .err()
        .unwrap();

        for _ in 0..2 {
            let error = block_on(jsonld_to_nquads(document.clone(), None)).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("failed to convert JSON-LD to RDF: {expected}"),
                "{document}"
            );
        }
    }
}

#[derive(Default)]
struct Collect(Vec<String>);

impl json_ld::warning::Handler<(), Warning> for Collect {
    fn handle(&mut self, _vocabulary: &(), warning: Warning) {
        self.0.push(warning.to_string())
    }
}

#[test]
fn warnings_are_replayed() {
    let url = "https://example.com/keyword-like-context";
    let loader = loader(Some(HashMap::from([(
        url.to_string(),
        json!({"@context": {"term": {"@id": "@keywordLike"}}}).to_string(),
    )])))
    .unwrap();
    let (local, _) = json_syntax::Value::parse_str(&json!([url]).to_string()).unwrap();
    let local = json_ld::syntax::context::Context::try_from_json(local).unwrap();

    let mut runs = Vec::new();
    for _ in 0..2 {
        let mut warnings = Collect::default();
        block_on(local.process_full(
            &mut (),
            &Context::new(None),
            &loader,
            None,
            Default::default(),
            &mut warnings,
        ))
        .unwrap();
        runs.push(warnings.0);
    }

    assert!(!runs[0].is_empty());
    assert_eq!(runs[0], runs[1]);
}

#[test]
fn caches_keep_working_once_full() {
    let url = "https://example.com/shared-context";
    let contexts = Some(HashMap::from([(
        url.to_string(),
        json!({"@context": {"name": "https://example.com/name"}}).to_string(),
    )]));

    // Each document's top-level context is distinct and loads `url`, so it is
    // stored by both caches. 300 is more than either holds.
    for i in 0..300 {
        let term = format!("term{i}");
        let document = json!({
            "@context": [url, {&term: format!("https://example.com/{term}")}],
            "@id": "urn:test:subject",
            "name": "a",
            &term: "b",
        });
        assert_matches_reference(&document, contexts.clone());
    }
}
