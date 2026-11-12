//! Process-wide memoization of context processing.
//!
//! Not part of the upstream crate; see `vendor/README.md`.
//!
//! Processing a local context that references remote contexts is expensive
//! (the W3C credentials context alone takes a few hundred microseconds), and
//! the same local contexts are processed against the same active contexts
//! over and over: every expansion of every credential starts by processing
//! `["https://www.w3.org/ns/credentials/v2", ...]` against the empty context.
//!
//! An entry is reused only when every input that processing depends on is
//! equal:
//!
//! - the options, base URL and local context;
//! - the active context, compared structurally including its term
//!   definitions;
//! - every document processing loaded: the remote contexts the local context
//!   names, the contexts those name, `@import`s, and the remote contexts of
//!   scoped contexts (processed for validation). On a hit each is loaded again
//!   through the caller's loader and must be identical to the document the
//!   entry was computed from, so loaders that resolve the same IRI to
//!   different documents never see each other's results.
//!
//! The warnings a computation emits are stored with its result and replayed
//! to the caller's handler on a hit.
//!
//! Only the unit vocabulary `()` is cached. Other vocabularies may intern IRIs
//! into per-vocabulary indices that would be meaningless to another caller.

use std::{
	hash::Hash,
	mem::{size_of, ManuallyDrop},
	sync::{Arc, Mutex},
};

use iref::{Iri, IriBuf};
use json_ld_core::{context::BindingRef, Context, Loader, LoadingResult};
use json_ld_syntax::{
	self as syntax,
	context::{ContextEntry, TermDefinition},
	Nullable,
};
use rdf_types::{vocabulary::IriVocabularyMut, BlankIdBuf};

use crate::{Error, Options, ProcessingStack, Warning};

type UnitContext = Context<IriBuf, BlankIdBuf>;

// The casts below rely on the unit vocabulary using these IRI and blank node
// types; this fails to compile otherwise.
const _: fn(
	Context<
		<() as rdf_types::vocabulary::IriVocabulary>::Iri,
		<() as rdf_types::vocabulary::BlankIdVocabulary>::BlankId,
	>,
) -> UnitContext = |c| c;

/// Upper bound on the number of entries kept. Storing a result when it is
/// reached clears the cache first.
const MAX_ENTRIES: usize = 256;

struct Entry {
	options: Options,
	base_url: Option<IriBuf>,
	local: syntax::context::Context,
	active: UnitContext,
	documents: Vec<(IriBuf, json_syntax::Value)>,
	result: UnitContext,
	warnings: Vec<Warning>,
}

impl Entry {
	fn matches(
		&self,
		options: Options,
		base_url: Option<&IriBuf>,
		local: &syntax::context::Context,
		active: &UnitContext,
	) -> bool {
		self.options == options
			&& self.base_url.as_ref() == base_url
			&& self.local == *local
			&& same_context(&self.active, active)
	}
}

static ENTRIES: Mutex<Vec<Arc<Entry>>> = Mutex::new(Vec::new());

/// Whether the cache can be used for vocabulary type `N`.
pub(crate) fn applies<N: ?Sized>() -> bool {
	typeid::of::<N>() == typeid::of::<()>()
}

/// Reinterprets a value of type `T` as type `U`.
///
/// # Safety
///
/// `T` and `U` must be the same type. This exists to move values between a
/// generic signature and the concrete unit-vocabulary types once
/// [`applies`] has established that they are the same.
pub(crate) unsafe fn same_type<T, U>(value: T) -> U {
	assert_eq!(size_of::<T>(), size_of::<U>());
	let value = ManuallyDrop::new(value);
	std::ptr::read(&*value as *const T as *const U)
}

/// Processes `local` against `active`, reusing an earlier result when every
/// input is unchanged. Returns the processed context and the warnings
/// processing emitted, for the caller to pass on to its handler.
pub(crate) async fn process<L: Loader>(
	vocabulary: &mut (),
	active: &UnitContext,
	local: &syntax::context::Context,
	loader: &L,
	base_url: Option<IriBuf>,
	options: Options,
) -> Result<(UnitContext, Vec<Warning>), Error> {
	if !references_remote(local) {
		// Inline-only contexts are cheap to process, and cheaper than
		// comparing a large active context to find an entry.
		return compute(vocabulary, active, local, loader, base_url, options).await;
	}

	let candidate = ENTRIES
		.lock()
		.unwrap()
		.iter()
		.find(|e| e.matches(options, base_url.as_ref(), local, active))
		.cloned();

	if let Some(entry) = candidate {
		if documents_unchanged(&entry.documents, loader).await {
			return Ok((entry.result.clone(), entry.warnings.clone()));
		}
	}

	let recording = RecordingLoader {
		inner: loader,
		loaded: Mutex::default(),
	};
	let (result, warnings) = compute(
		vocabulary,
		active,
		local,
		&recording,
		base_url.clone(),
		options,
	)
	.await?;

	if let Some(documents) = recording.into_documents() {
		let entry = Arc::new(Entry {
			options,
			base_url,
			local: local.clone(),
			active: active.clone(),
			documents,
			result: result.clone(),
			warnings: warnings.clone(),
		});

		let mut entries = ENTRIES.lock().unwrap();
		entries.retain(|e| {
			!e.matches(
				entry.options,
				entry.base_url.as_ref(),
				&entry.local,
				&entry.active,
			)
		});
		if entries.len() >= MAX_ENTRIES {
			entries.clear();
		}
		entries.push(entry);
	}

	Ok((result, warnings))
}

/// Collects warnings so they can be stored with a result.
struct Collect(Vec<Warning>);

impl json_ld_core::warning::Handler<(), Warning> for Collect {
	fn handle(&mut self, _vocabulary: &(), warning: Warning) {
		self.0.push(warning)
	}
}

async fn compute<L: Loader>(
	vocabulary: &mut (),
	active: &UnitContext,
	local: &syntax::context::Context,
	loader: &L,
	base_url: Option<IriBuf>,
	options: Options,
) -> Result<(UnitContext, Vec<Warning>), Error> {
	let mut warnings = Collect(Vec::new());
	let processed = crate::algorithm::process_context(
		json_ld_core::Environment {
			vocabulary,
			loader,
			warnings: &mut warnings,
		},
		active,
		local,
		ProcessingStack::default(),
		base_url,
		options,
	)
	.await?;

	Ok((processed.into_processed(), warnings.0))
}

/// Whether `context` refers to a remote context, including through
/// `@import` and scoped contexts.
fn references_remote(context: &syntax::context::Context) -> bool {
	context.iter().any(|entry| match entry {
		ContextEntry::Null => false,
		ContextEntry::IriRef(_) => true,
		ContextEntry::Definition(definition) => {
			definition.import.is_some()
				|| definition.bindings.iter().any(|(_, binding)| {
					matches!(
						binding,
						Nullable::Some(TermDefinition::Expanded(expanded))
							if expanded.context.as_deref().is_some_and(references_remote)
					)
				})
		}
	})
}

/// Passes loads on to `inner` and records each document it returns, so an
/// entry stores exactly the documents its result was computed from.
struct RecordingLoader<'a, L> {
	inner: &'a L,
	loaded: Mutex<Vec<(IriBuf, json_syntax::Value)>>,
}

impl<L> RecordingLoader<'_, L> {
	fn record(&self, iri: IriBuf, document: &json_syntax::Value) {
		let mut loaded = self.loaded.lock().unwrap();
		if !loaded.iter().any(|(i, d)| *i == iri && d == document) {
			loaded.push((iri, document.clone()));
		}
	}

	/// The documents loaded, or `None` if one IRI loaded to different
	/// documents, which no later load could match.
	fn into_documents(self) -> Option<Vec<(IriBuf, json_syntax::Value)>> {
		let loaded = self.loaded.into_inner().unwrap();
		for (index, (iri, _)) in loaded.iter().enumerate() {
			if loaded[..index].iter().any(|(earlier, _)| earlier == iri) {
				return None;
			}
		}
		Some(loaded)
	}
}

impl<L: Loader> Loader for RecordingLoader<'_, L> {
	async fn load_with<V>(&self, vocabulary: &mut V, url: V::Iri) -> LoadingResult<V::Iri>
	where
		V: IriVocabularyMut,
		V::Iri: Clone + Eq + Hash,
	{
		let iri = vocabulary.iri(&url).map(|iri| iri.to_owned());
		let document = self.inner.load_with(vocabulary, url).await?;
		if let Some(iri) = iri {
			self.record(iri, document.document());
		}
		Ok(document)
	}

	async fn load(&self, url: &Iri) -> LoadingResult {
		let document = self.inner.load(url).await?;
		self.record(url.to_owned(), document.document());
		Ok(document)
	}
}

async fn documents_unchanged<L: Loader>(
	documents: &[(IriBuf, json_syntax::Value)],
	loader: &L,
) -> bool {
	for (iri, expected) in documents {
		match loader.load_with(&mut (), iri.clone()).await {
			Ok(document) if document.document() == expected => (),
			_ => return false,
		}
	}

	true
}

/// Structural equality of processed contexts.
///
/// `Context`'s own `PartialEq` does not compare term definitions.
fn same_context(a: &UnitContext, b: &UnitContext) -> bool {
	a == b
		&& same_definitions(a, b)
		&& match (a.previous_context(), b.previous_context()) {
			(Some(a), Some(b)) => same_context(a, b),
			(None, None) => true,
			_ => false,
		}
}

fn same_definitions(a: &UnitContext, b: &UnitContext) -> bool {
	let (a, b) = (a.definitions(), b.definitions());

	a.len() == b.len()
		&& a.get_type() == b.get_type()
		&& a.iter().all(|binding| match binding {
			BindingRef::Normal(key, definition) => b.get_normal(key) == Some(definition),
			BindingRef::Type(_) => true,
		})
}
