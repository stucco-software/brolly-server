//! The WebID profile document.
//!
//! Every protocol asserts its profile triples onto **this** node (D8): the
//! Solid profile writer, the ActivityPub actor builder and the ATProtocol
//! profile adapter all name `…/profile#me`, so there is nothing to join and no
//! `owl:sameAs` to chase.
//!
//! Which is why writing is a replace of the specific predicates rather than an
//! insert. Two `foaf:name` triples is not "a name that was edited"; it is a
//! profile with two names, and every reader downstream has to pick one.

use brolly_domain::vocab;
use brolly_store::Store;
use brolly_store::write::{WriteError, insert_quads};
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// What the dashboard's profile form edits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub display_name: String,
    pub bio: String,
}

/// Read the profile triples for `webid` out of `document`.
pub fn read(store: &Store, webid: &str, document: &str) -> Profile {
    Profile {
        display_name: literal(store, webid, document, vocab::FOAF_NAME),
        bio: literal(store, webid, document, vocab::VCARD_NOTE),
    }
}

fn literal(store: &Store, webid: &str, document: &str, predicate: &str) -> String {
    let graph = iri(document);
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(iri(webid))).into()),
            Some(iri(predicate).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(graph.as_ref())),
        )
        .filter_map(Result::ok)
        .find_map(|q| match q.object {
            Term::Literal(l) => Some(l.value().to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Write the profile, replacing the predicates it owns.
///
/// Only `foaf:name` and `vcard:note` are touched: the profile document also
/// holds `space:storage`, keys and type triples that this form knows nothing
/// about, so clearing the graph would delete them.
pub fn write(
    store: &Store,
    webid: &str,
    document: &str,
    profile: &Profile,
) -> Result<(), WriteError> {
    let graph = iri(document);
    let subject = NamedOrBlankNode::NamedNode(iri(webid));

    for predicate in [vocab::FOAF_NAME, vocab::VCARD_NOTE] {
        let existing: Vec<Quad> = store
            .quads_for_pattern(
                Some((&subject).into()),
                Some(iri(predicate).as_ref()),
                None,
                Some(GraphNameRef::NamedNode(graph.as_ref())),
            )
            .filter_map(Result::ok)
            .collect();
        for quad in existing {
            store
                .remove(&quad)
                .map_err(brolly_store::StoreError::from)?;
        }
    }

    // An empty field means "no value", not an empty string: a blank
    // `foaf:name` reads as a person literally named "".
    let mut quads = Vec::new();
    for (predicate, value) in [
        (vocab::FOAF_NAME, &profile.display_name),
        (vocab::VCARD_NOTE, &profile.bio),
    ] {
        if value.trim().is_empty() {
            continue;
        }
        quads.push(Quad::new(
            subject.clone(),
            iri(predicate),
            Term::Literal(Literal::new_simple_literal(value.trim())),
            GraphName::NamedNode(graph.clone()),
        ));
    }
    if !quads.is_empty() {
        insert_quads(store, &quads)?;
    }
    Ok(())
}
