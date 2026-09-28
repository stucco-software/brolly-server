//! The storage description (Solid Protocol §4.1).
//!
//! **Generated, never stored.** It holds nothing a member could edit, and
//! storing it would put a resource *inside* the storage that describes the
//! storage, which `ldp:contains` would then list.
//!
//! **World-readable, and no ACL governs it.** It describes the storage, not
//! its contents, and a client has to be able to read it *before* it has a
//! credential — that is how it discovers where to authenticate. There is no
//! WAC exemption to write, because there is no stored resource here for an ACL
//! to be about: everything below is derived from the routing table.

use brolly_domain::vocab;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};

/// Where it is served, on every pod subdomain.
///
/// The protocol mandates the `Link` relation, not a path. This is the path CSS
/// uses for the same document, so a client that has seen one server recognises
/// ours, and our own well-known space stays clear: `openid-configuration` is
/// apex-only, `webfinger` and `nodeinfo` are apex paths, and ATProto's
/// `oauth-authorization-server` and `atproto-did` are different names.
pub const PATH: &str = "/.well-known/solid";

/// The description's own IRI on `base` (`https://alice.brolly.id`).
///
/// The one place this string is built. `pod::links` advertises it and
/// `pod::storage_description` serves it; if they ever disagree, the link goes
/// to a 404 and discovery stops there.
pub fn iri(base: &str) -> String {
    format!("{base}{PATH}")
}

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// This storage, and whose it is.
///
/// Two triples, both about the description's own IRI, in its own graph — the
/// shape `brolly_solid::profile` uses, so a serializer that keeps graphs
/// (TriG, N-Quads) names the document rather than the default graph.
pub fn document(base: &str, owner: &str) -> Vec<Quad> {
    let subject = n(&iri(base));
    let graph = GraphName::NamedNode(subject.clone());
    [
        (vocab::RDF_TYPE, vocab::PIM_STORAGE),
        (vocab::SOLID_OWNER, owner),
    ]
    .into_iter()
    .map(|(predicate, object)| {
        Quad::new(
            NamedOrBlankNode::NamedNode(subject.clone()),
            n(predicate),
            Term::NamedNode(n(object)),
            graph.clone(),
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brolly_domain::vocab;

    const BASE: &str = "https://alice.brolly.test";
    const OWNER: &str = "https://alice.brolly.test/profile#me";

    /// A client reads `pim:Storage` here to confirm what it found. Solid
    /// Protocol §4.1 makes the link mandatory; a document at the end of it
    /// that types nothing answers no question.
    #[test]
    fn the_description_types_itself_as_a_storage() {
        let quads = document(BASE, OWNER);
        assert!(
            quads.iter().any(|q| {
                q.predicate.as_str() == vocab::RDF_TYPE
                    && q.object.to_string() == format!("<{}>", vocab::PIM_STORAGE)
            }),
            "{quads:?}"
        );
    }

    /// Without this a client that has the storage still has to fetch the root
    /// and read *its* header to learn whose it is.
    #[test]
    fn the_description_names_its_owner() {
        let quads = document(BASE, OWNER);
        assert!(
            quads.iter().any(|q| {
                q.predicate.as_str() == vocab::SOLID_OWNER
                    && q.object.to_string() == format!("<{OWNER}>")
            }),
            "{quads:?}"
        );
    }

    /// Everything is said about the IRI the document is served from. A
    /// description whose subject is some other IRI is a document about
    /// something else, and a client following `rel="storageDescription"` has
    /// no way to notice.
    #[test]
    fn the_description_describes_the_iri_it_is_served_from() {
        assert_eq!(iri(BASE), format!("{BASE}/.well-known/solid"));
        let subject = format!("<{}>", iri(BASE));
        for quad in document(BASE, OWNER) {
            assert_eq!(quad.subject.to_string(), subject, "{quad}");
            assert_eq!(quad.graph_name.to_string(), subject, "{quad}");
        }
    }
}
