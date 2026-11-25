//! A member's Bluesky preferences, kept in their pod (stage 3, C).
//!
//! The reference PDS keeps `app.bsky.actor.getPreferences`'s answer in
//! private actor storage. Here it is member data with a profile's reach: one
//! RDF document in the member's storage, `/~/settings/atproto-preferences.ttl`,
//! which their Solid apps can find through the private type index and read
//! as Turtle, and which leaves with their export.
//!
//! * **Faithful, not mapped.** The body goes through the same lossless
//!   JSON ⇄ RDF encoding every ATProto record takes (D7), so a preference
//!   type this build has never heard of round-trips exactly. The term space
//!   is `app.bsky.actor.getPreferences` — the output lexicon — because
//!   `app.bsky.actor.defs#preferences` carries a fragment, and a fragment in
//!   a term space would put a second `#` in every predicate.
//! * **Replaced whole.** `putPreferences` means "here is the full set", so a
//!   write is an LDP `put` of the document, not a patch.
//! * **The member's to break.** It sits inside `/~/`, so the member or one of
//!   their apps can delete or rewrite it. A missing or undecodable document
//!   reads as no preferences; it is never a server fault.
//! * **Not provisioned.** Nothing exists until the first write creates it and
//!   registers it, as any Solid app would register a document it keeps.

use brolly_domain::{faithful, vocab};
use brolly_store::StoreError;
use brolly_store::resources::{Content, PodRead, PodWrite};
use oxigraph::model::{GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use serde_json::{Value, json};

/// The term space the document's predicates live in.
pub const LEXICON: &str = "app.bsky.actor.getPreferences";

/// The class the type index registers the document under: the lexicon's own
/// `preferences` definition, named in the faithful layer's IRI form.
pub const CLASS: &str = "at://app.bsky.actor.defs#preferences";

/// The serialized cap, the repo's own per-record one: a runaway client cannot
/// turn its settings into a storage problem.
pub const MAX_BYTES: usize = crate::repo::MAX_RECORD_BYTES;

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// The document's IRI under a storage root (`https://alice.{base}/~/`).
pub fn document(root: &str) -> String {
    format!("{root}settings/atproto-preferences.ttl")
}

/// The node the preferences hang off, inside the document.
fn subject(root: &str) -> NamedNode {
    iri(&format!("{}#preferences", document(root)))
}

/// Why a `putPreferences` body is not preferences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// No `preferences` array.
    NotAnArray,
    /// An item that is not an object with a string `$type`.
    Untyped,
    /// Over [`MAX_BYTES`] serialized.
    TooLarge,
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Invalid::NotAnArray => write!(f, "preferences must be an array"),
            Invalid::Untyped => write!(f, "every preference must be an object with a $type"),
            Invalid::TooLarge => write!(f, "preferences are capped at {MAX_BYTES} bytes"),
        }
    }
}

/// Validate a `putPreferences` body structurally: the lexicon's
/// `#preferences` is an array of `$type`d objects, and that is all this
/// checks — unknown `$type`s are a client newer than the server, not an error.
pub fn validate(body: &Value) -> Result<&[Value], Invalid> {
    let items = body
        .get("preferences")
        .and_then(Value::as_array)
        .ok_or(Invalid::NotAnArray)?;
    let typed = |item: &Value| item.get("$type").is_some_and(Value::is_string);
    if !items.iter().all(|item| item.is_object() && typed(item)) {
        return Err(Invalid::Untyped);
    }
    if serde_json::to_vec(items).map_or(usize::MAX, |b| b.len()) > MAX_BYTES {
        return Err(Invalid::TooLarge);
    }
    Ok(items)
}

/// The member's preferences, as `getPreferences` answers them. A document
/// that is missing, or that does not decode faithfully, is no preferences.
pub fn read(store: &impl PodRead, root: &str) -> Vec<Value> {
    let doc = iri(&document(root));
    let quads: Vec<Quad> = store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(doc.as_ref())),
        )
        .filter_map(Result::ok)
        .collect();
    if quads.is_empty() {
        return Vec::new();
    }
    match faithful::decode(&quads, &subject(root)) {
        Ok(Value::Object(mut body)) => match body.remove("preferences") {
            Some(Value::Array(items)) => items,
            _ => Vec::new(),
        },
        Ok(_) => Vec::new(),
        Err(e) => {
            tracing::warn!(error = %e, document = %doc, "preferences do not decode; reading none");
            Vec::new()
        }
    }
}

/// Replace the member's preferences, and register the document in their
/// private type index if nothing registers the class yet. Returns how many
/// quads the document holds.
pub fn write(w: &mut PodWrite<'_>, root: &str, items: &[Value]) -> Result<usize, StoreError> {
    let doc = iri(&document(root));
    let body = json!({ "preferences": items });
    let quads = faithful::encode(&body, &subject(root), &doc, LEXICON)
        .map_err(|e| StoreError::Invalid(e.to_string()))?;
    w.put(doc.as_str(), Content::Rdf(&quads))?;
    register(w, root, doc.as_str())?;
    Ok(quads.len())
}

/// Announce the document in the private type index — the way a Solid app
/// announces a document it keeps — once.
///
/// An index the member has deleted is left deleted: recreating it here would
/// seat an index without its classes, which is worse than none. And an
/// existing registration for the class, whoever wrote it, is left alone.
fn register(w: &mut PodWrite<'_>, root: &str, doc: &str) -> Result<(), StoreError> {
    let (_, _, private) = brolly_store::resources::resource_iris(root);
    if w.meta(&private)?.is_none() {
        return Ok(());
    }
    let index = iri(&private);
    let class = iri(CLASS);
    let registered = w
        .quads_for_pattern(
            None,
            Some(iri(vocab::SOLID_FOR_CLASS).as_ref()),
            Some(Term::NamedNode(class.clone()).as_ref()),
            Some(GraphNameRef::NamedNode(index.as_ref())),
        )
        .next()
        .is_some();
    if registered {
        return Ok(());
    }
    let registration = NamedOrBlankNode::NamedNode(iri(&format!("{private}#atproto-preferences")));
    let graph = oxigraph::model::GraphName::NamedNode(index);
    let quad = |predicate: &str, object: Term| {
        Quad::new(registration.clone(), iri(predicate), object, graph.clone())
    };
    w.append(
        &private,
        &[
            quad(
                vocab::RDF_TYPE,
                Term::NamedNode(iri(vocab::SOLID_TYPE_REGISTRATION)),
            ),
            quad(vocab::SOLID_FOR_CLASS, Term::NamedNode(class)),
            quad(vocab::SOLID_INSTANCE, Term::NamedNode(iri(doc))),
        ],
    )?;
    Ok(())
}
