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
    /// Follows need approval. The predecessor accepted this and ignored it, so
    /// locking an account did nothing at all.
    pub locked: bool,
    pub bot: bool,
    pub discoverable: bool,
}

impl Profile {
    /// A profile with no triples yet.
    ///
    /// `discoverable` defaults **true** and `locked` defaults **false**,
    /// matching Mastodon — but note these are opposite defaults, and both are
    /// the permissive one. That is deliberate: it is what a member who has
    /// never opened the settings page expects, and every other reading would
    /// surprise somebody. Anyone who wants otherwise sets it explicitly.
    pub fn blank() -> Self {
        Self {
            discoverable: true,
            ..Default::default()
        }
    }
}

/// Read the profile triples for `webid` out of `document`.
pub fn read(store: &Store, webid: &str, document: &str) -> Profile {
    Profile {
        display_name: literal(store, webid, document, vocab::FOAF_NAME),
        bio: literal(store, webid, document, vocab::VCARD_NOTE),
        locked: flag(store, webid, document, vocab::AS2_MANUALLY_APPROVES).unwrap_or(false),
        bot: flag(store, webid, document, vocab::MASTODON_BOT).unwrap_or(false),
        // Absent means discoverable, matching Mastodon's default.
        discoverable: flag(store, webid, document, vocab::MASTODON_DISCOVERABLE).unwrap_or(true),
    }
}

/// Read a boolean flag, distinguishing "absent" from "false".
///
/// The distinction matters: `discoverable` defaults true when absent, so
/// collapsing absent into false would quietly de-list every member who has
/// never touched their settings.
fn flag(store: &Store, webid: &str, document: &str, predicate: &str) -> Option<bool> {
    let raw = literal(store, webid, document, predicate);
    match raw.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
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

    for predicate in [
        vocab::FOAF_NAME,
        vocab::VCARD_NOTE,
        vocab::AS2_MANUALLY_APPROVES,
        vocab::MASTODON_BOT,
        vocab::MASTODON_DISCOVERABLE,
    ] {
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
    // Flags are written always, including when false. Unlike a name, absence
    // is meaningful here — `discoverable` absent means *true* — so omitting a
    // false value would read back as the opposite of what was set.
    for (predicate, value) in [
        (vocab::AS2_MANUALLY_APPROVES, profile.locked),
        (vocab::MASTODON_BOT, profile.bot),
        (vocab::MASTODON_DISCOVERABLE, profile.discoverable),
    ] {
        quads.push(Quad::new(
            subject.clone(),
            iri(predicate),
            Term::Literal(Literal::new_typed_literal(
                if value { "true" } else { "false" },
                iri(vocab::XSD_BOOLEAN),
            )),
            GraphName::NamedNode(graph.clone()),
        ));
    }

    if !quads.is_empty() {
        insert_quads(store, &quads)?;
    }
    Ok(())
}

/// The WebID profile document, as a client dereferencing the WebID sees it.
///
/// A **projection**, not a second copy: the member's own triples come out of
/// the pod exactly as they were written, and the server adds the handful that
/// make the document usable.
///
/// Those additions are generated per request rather than persisted at
/// provisioning, and that is the load-bearing decision here. `oidcIssuer` and
/// `space:storage` are both derived from the base domain, so writing them into
/// the pod would freeze one deployment's hostname into every member's data —
/// change `BROLLY_BASE_DOMAIN` and every profile would still name the old
/// issuer, which is precisely the failure that makes one image unable to serve
/// many deployments.
///
/// `solid:oidcIssuer` is the reason this endpoint has to exist at all. An app
/// handed a WebID dereferences it and reads that triple to learn where to send
/// the member to authenticate; without it there is no way in, however well the
/// OIDC endpoints themselves work.
pub fn document(
    store: &Store,
    webid: &str,
    document: &str,
    storage_root: &str,
    issuer: &str,
) -> Vec<Quad> {
    let graph = iri(document);
    let subject = NamedOrBlankNode::NamedNode(iri(webid));

    // Whatever the member has written, verbatim.
    let mut quads: Vec<Quad> = store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(graph.as_ref())),
        )
        .filter_map(Result::ok)
        .collect();

    let derived = [
        // The document describes the person; it is not the person. That
        // distinction is what the `#me` fragment exists for.
        (
            NamedOrBlankNode::NamedNode(graph.clone()),
            vocab::RDF_TYPE,
            vocab::FOAF_PERSONAL_PROFILE_DOCUMENT,
        ),
        (
            NamedOrBlankNode::NamedNode(graph.clone()),
            vocab::FOAF_PRIMARY_TOPIC,
            webid,
        ),
        (subject.clone(), vocab::RDF_TYPE, vocab::FOAF_PERSON),
        (subject.clone(), vocab::SOLID_OIDC_ISSUER, issuer),
        (subject.clone(), vocab::SPACE_STORAGE, storage_root),
    ];

    for (s, p, o) in derived {
        let quad = Quad::new(
            s,
            iri(p),
            Term::NamedNode(iri(o)),
            GraphName::NamedNode(graph.clone()),
        );
        // A member could have written one of these themselves. Theirs stands;
        // duplicating it would put two values on a predicate whose readers
        // expect one.
        if !quads.contains(&quad) {
            quads.push(quad);
        }
    }
    quads
}
