//! Expansion that reuses the processed top-level `@context` across calls.
//!
//! Processing a document's `@context` costs far more than expanding the rest
//! of a typical statement or credential, and most documents share one of a few
//! top-level contexts. A processed context is reused only when every context
//! document it loaded is frozen: one of ssi's built-in W3C contexts, or one of
//! our static contexts that the caller's loader does not override.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use iref::{Iri, IriBuf};
use json_ld::{
    expansion, syntax::TryFromJson, Context, Expand, ExpandedDocument, JsonLdProcessor, Loader,
    Process, RemoteDocument, ToRdfError,
};
use json_syntax::object::{Entry, Object};
use once_cell::sync::Lazy;

use crate::loader::IntegrityLoader;

/// Upper bound on the number of contexts kept. Storing a context when it is
/// reached clears the cache first.
const MAX_ENTRIES: usize = 64;

struct CachedContext {
    context: Context,
    /// The static contexts processing loaded. Each must still resolve to our
    /// static document for the entry to be reused.
    bundled: Vec<IriBuf>,
}

static ENTRIES: Lazy<Mutex<HashMap<json_syntax::Value, Arc<CachedContext>>>> =
    Lazy::new(Default::default);

/// Expands `document` the way [`JsonLdProcessor::to_rdf`] does: default
/// options, unordered, and no base URL.
pub(crate) async fn expand(
    mut document: json_syntax::Value,
    loader: &IntegrityLoader,
) -> Result<ExpandedDocument, ToRdfError> {
    let options = json_ld::Options::<IriBuf>::default().unordered();

    match SplitDocument::new(document) {
        Ok(split) => {
            // Errors here are the ones expansion reports for the top-level
            // `@context`.
            let processed = processed_context(&split.context.value, loader, &options)
                .await
                .map_err(expansion_error)?;
            if let Some(active) = processed {
                return split
                    .body
                    .expand_full(
                        &mut (),
                        active,
                        None,
                        loader,
                        options.expansion_options(),
                        (),
                    )
                    .await
                    .map_err(expansion_error);
            }
            document = split.into_document();
        }
        Err(unsplit) => document = unsplit,
    }

    JsonLdProcessor::expand_full(
        &RemoteDocument::new(None, None, document),
        &mut (),
        loader,
        options,
        (),
    )
    .await
    .map_err(ToRdfError::Expand)
}

fn expansion_error(e: expansion::Error) -> ToRdfError {
    ToRdfError::Expand(json_ld::ExpandError::Expansion(e))
}

/// A JSON object with its single top-level `@context` entry taken out.
struct SplitDocument {
    context: Entry,
    /// Position of `context` among the object's entries.
    index: usize,
    body: json_syntax::Value,
}

impl SplitDocument {
    /// Splits `document`, or returns it unchanged when it is not an object
    /// with exactly one `@context` entry.
    fn new(document: json_syntax::Value) -> Result<Self, json_syntax::Value> {
        let json_syntax::Value::Object(object) = document else {
            return Err(document);
        };
        if !matches!(object.get_unique("@context"), Ok(Some(_))) {
            return Err(json_syntax::Value::Object(object));
        }

        let mut entries: Vec<Entry> = object.into_iter().collect();
        let index = entries
            .iter()
            .position(|entry| entry.key == "@context")
            .expect("checked above");
        let context = entries.remove(index);

        Ok(Self {
            context,
            index,
            body: json_syntax::Value::Object(Object::from_vec(entries)),
        })
    }

    /// The original document, with entries in their original order.
    fn into_document(self) -> json_syntax::Value {
        let json_syntax::Value::Object(body) = self.body else {
            unreachable!("body is always an object");
        };
        let mut entries: Vec<Entry> = body.into_iter().collect();
        entries.insert(self.index, self.context);
        json_syntax::Value::Object(Object::from_vec(entries))
    }
}

/// The result of processing `context` against the initial active context,
/// as expansion does for a top-level `@context`. `Ok(None)` when expansion
/// must process the context itself.
async fn processed_context(
    context: &json_syntax::Value,
    loader: &IntegrityLoader,
    options: &json_ld::Options<IriBuf>,
) -> Result<Option<Context>, expansion::Error> {
    let cached = ENTRIES.lock().unwrap().get(context).cloned();
    if let Some(entry) = cached {
        if entry.bundled.iter().all(|iri| loader.is_bundled(iri)) {
            return Ok(Some(entry.context.clone()));
        }
    }

    let syntax = json_ld::syntax::context::Context::try_from_json(context.clone())?;
    let recording = RecordingLoader {
        inner: loader,
        loaded: Mutex::default(),
    };
    let active = syntax
        .process_with(
            &mut (),
            &Context::new(None),
            &recording,
            None,
            options.context_processing_options(),
        )
        .await?
        .into_processed();

    // A context with `@propagate: false` makes expansion revert to the
    // previous context below the top-level object, which it only does when
    // it processed that context itself.
    if active.previous_context().is_some() {
        return Ok(None);
    }

    let mut bundled = Vec::new();
    for iri in recording.loaded.into_inner().unwrap() {
        if IntegrityLoader::is_builtin(&iri).await {
            continue;
        }
        if !loader.is_bundled(&iri) {
            // Correct for this loader, but not frozen.
            return Ok(Some(active));
        }
        bundled.push(iri);
    }

    let mut entries = ENTRIES.lock().unwrap();
    if entries.len() >= MAX_ENTRIES {
        entries.clear();
    }
    entries.insert(
        context.clone(),
        Arc::new(CachedContext {
            context: active.clone(),
            bundled,
        }),
    );

    Ok(Some(active))
}

/// Records every URL loaded through it.
struct RecordingLoader<'a> {
    inner: &'a IntegrityLoader,
    loaded: Mutex<Vec<IriBuf>>,
}

impl Loader for RecordingLoader<'_> {
    async fn load(&self, url: &Iri) -> json_ld::LoadingResult {
        self.loaded.lock().unwrap().push(url.to_owned());
        self.inner.load(url).await
    }
}
