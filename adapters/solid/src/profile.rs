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

use brolly_domain::syntax;
use brolly_domain::vocab;
use brolly_store::StoreError;
use brolly_store::resources::{Pod, PodRead, PodWrite};
use oxigraph::model::{GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, Quad, Term};

use crate::ldp::{self, LdpError, PatchBody};
use crate::patch::{self, PatchError};

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
pub fn read(store: &impl PodRead, webid: &str, document: &str) -> Profile {
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
fn flag(store: &impl PodRead, webid: &str, document: &str, predicate: &str) -> Option<bool> {
    let raw = literal(store, webid, document, predicate);
    match raw.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn literal(store: &impl PodRead, webid: &str, document: &str, predicate: &str) -> String {
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
///
/// The profile document is protocol state outside the storage root, so it is
/// written with `PodWrite`'s outside-root methods.
pub fn write(
    w: &mut PodWrite<'_>,
    webid: &str,
    document: &str,
    profile: &Profile,
) -> Result<(), StoreError> {
    let graph = iri(document);
    let subject = NamedOrBlankNode::NamedNode(iri(webid));

    let mut existing: Vec<Quad> = Vec::new();
    for predicate in [
        vocab::FOAF_NAME,
        vocab::VCARD_NOTE,
        vocab::AS2_MANUALLY_APPROVES,
        vocab::MASTODON_BOT,
        vocab::MASTODON_DISCOVERABLE,
    ] {
        existing.extend(
            w.quads_for_pattern(
                Some((&subject).into()),
                Some(iri(predicate).as_ref()),
                None,
                Some(GraphNameRef::NamedNode(graph.as_ref())),
            )
            .filter_map(Result::ok),
        );
    }
    w.remove_quads(&existing)?;

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
        w.insert(&quads)?;
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
///
/// Since spec 6 (H1) the derived five are **unconditional**: whatever the
/// member stored at those positions, the served value is the deployment's —
/// their copy is not served beside it, and a self-asserted storage root or
/// issuer is not served at all.
///
/// Since H2, three more join them: the links to the settings resources
/// (`solid:publicTypeIndex`, `solid:privateTypeIndex`,
/// `space:preferencesFile`), derived from the storage root the same way, so
/// the per-request derivation stays load-bearing — one image, many
/// deployments, and a moved base domain moves the links with it. SolidOS
/// reads these off every profile it is handed, so a profile without them is a
/// pod it can log into and do nothing with.
pub fn document(
    store: &impl PodRead,
    webid: &str,
    document: &str,
    storage_root: &str,
    issuer: &str,
) -> Vec<Quad> {
    let graph = iri(document);

    // Whatever the member has written, verbatim — except at the eight reserved
    // positions, which the projection derives below. Their stored copy is not
    // served beside the derived one: two values on a predicate whose readers
    // expect one.
    let mut quads: Vec<Quad> = store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(graph.as_ref())),
        )
        .filter_map(Result::ok)
        .filter(|q| !at_reserved_position(q, webid, document))
        .collect();

    quads.extend(reserved(webid, document, storage_root, issuer));
    quads
}

// --- writing over Solid (spec 6, H1) -----------------------------------------

/// The eight positions the projection derives (spec 6, H1 and H2), as quads
/// in the document's graph with the deployment's values.
/// [`at_reserved_position`] decides what a write may not seat there.
fn reserved(webid: &str, document: &str, storage_root: &str, issuer: &str) -> Vec<Quad> {
    let graph = iri(document);
    let doc = NamedOrBlankNode::NamedNode(graph.clone());
    let me = NamedOrBlankNode::NamedNode(iri(webid));
    let object = |value: &str| Term::NamedNode(iri(value));
    // The settings links (H2), derived from the storage root: the same
    // reasoning as `space:storage` — deployment facts pointing at
    // deployment-provisioned resources, so they move with the base domain.
    let (preferences, public, private) = brolly_store::resources::resource_iris(storage_root);
    vec![
        // The document describes the person; it is not the person. That
        // distinction is what the `#me` fragment exists for.
        Quad::new(
            doc.clone(),
            iri(vocab::RDF_TYPE),
            object(vocab::FOAF_PERSONAL_PROFILE_DOCUMENT),
            GraphName::NamedNode(graph.clone()),
        ),
        Quad::new(
            doc,
            iri(vocab::FOAF_PRIMARY_TOPIC),
            object(webid),
            GraphName::NamedNode(graph.clone()),
        ),
        Quad::new(
            me.clone(),
            iri(vocab::RDF_TYPE),
            object(vocab::FOAF_PERSON),
            GraphName::NamedNode(graph.clone()),
        ),
        Quad::new(
            me.clone(),
            iri(vocab::SOLID_OIDC_ISSUER),
            object(issuer),
            GraphName::NamedNode(graph.clone()),
        ),
        Quad::new(
            me.clone(),
            iri(vocab::SPACE_STORAGE),
            object(storage_root),
            GraphName::NamedNode(graph.clone()),
        ),
        Quad::new(
            me.clone(),
            iri(vocab::SOLID_PUBLIC_TYPE_INDEX),
            object(&public),
            GraphName::NamedNode(graph.clone()),
        ),
        Quad::new(
            me.clone(),
            iri(vocab::SOLID_PRIVATE_TYPE_INDEX),
            object(&private),
            GraphName::NamedNode(graph.clone()),
        ),
        Quad::new(
            me,
            iri(vocab::SPACE_PREFERENCES_FILE),
            object(&preferences),
            GraphName::NamedNode(graph),
        ),
    ]
}

/// Does this quad sit at one of the eight reserved positions (spec 6, H1 and
/// H2)?
///
/// Three are reserved as exact (subject, predicate, object) triples: the two
/// `rdf:type` positions and `foaf:primaryTopic`. Never by predicate alone —
/// `rdf:type` is at once a reserved position and the commonest predicate in a
/// hand-written profile, so filtering on the predicate would drop
/// `<#me> a schema:Person` and every other type a member asserts about
/// themselves. The exact object is what leaves those their own.
///
/// The other five are the deployment facts — `solid:oidcIssuer` and
/// `space:storage` on `#me` from H1, and the three settings links from H2 —
/// and they are reserved as whole (subject, predicate) slots: whatever object
/// a member writes there is a self-assertion of a deployment fact, and the
/// projection serves the deployment's value, so theirs is dropped whatever it
/// says. A member writing `space:storage <https://elsewhere/>` must not be
/// able to point every client that trusts the profile at storage we do not
/// serve; a member writing `solid:publicTypeIndex <https://elsewhere/>` must
/// not be able to point SolidOS at an index we do not host — the same
/// precedent, carried forward.
fn at_reserved_position(quad: &Quad, webid: &str, document: &str) -> bool {
    let doc = NamedOrBlankNode::NamedNode(iri(document));
    let me = NamedOrBlankNode::NamedNode(iri(webid));
    let exact = |subject: &NamedOrBlankNode, predicate: &str, object: &str| {
        quad.subject == *subject
            && quad.predicate == iri(predicate)
            && quad.object == Term::NamedNode(iri(object))
    };
    // The two type positions and the primary topic: exact triples, so a
    // member's own types survive beside them.
    if exact(&doc, vocab::RDF_TYPE, vocab::FOAF_PERSONAL_PROFILE_DOCUMENT)
        || exact(&doc, vocab::FOAF_PRIMARY_TOPIC, webid)
        || exact(&me, vocab::RDF_TYPE, vocab::FOAF_PERSON)
    {
        return true;
    }
    // The five deployment facts: whole slots, whatever the object.
    let slot = |subject: &NamedOrBlankNode, predicate: &str| {
        quad.subject == *subject && quad.predicate == iri(predicate)
    };
    slot(&me, vocab::SOLID_OIDC_ISSUER)
        || slot(&me, vocab::SPACE_STORAGE)
        || slot(&me, vocab::SOLID_PUBLIC_TYPE_INDEX)
        || slot(&me, vocab::SOLID_PRIVATE_TYPE_INDEX)
        || slot(&me, vocab::SPACE_PREFERENCES_FILE)
}

/// Drop the reserved positions from a graph bound for the pod (spec 6, H1):
/// what a `PUT` stores and what a `PATCH` writes back hold the member's own
/// triples and nothing the projection derives.
fn unreserved(quads: Vec<Quad>, webid: &str, document: &str) -> Vec<Quad> {
    quads
        .into_iter()
        .filter(|q| !at_reserved_position(q, webid, document))
        .collect()
}

/// `PUT` the profile document's graph (spec 6, H1) — LDP `PUT` semantics over
/// the projection's backing graph, delegated to the LDP write path's body
/// handling: RDF only, parsed into the document's own named graph exactly as a
/// `PUT` under `/~/` is.
///
/// The body replaces the graph wholesale, so one that omits the dashboard's
/// predicates clears them — `as:manuallyApprovesFollowers` absent reads as
/// *false*, so a locked account comes back unlocked. That is LDP `PUT`
/// semantics, the same here as for any resource, and H1 owns it: reserving the
/// five instead would make the `PUT` silently drop triples it accepted, which
/// is a lie about what was stored.
///
/// The reserved positions — H1's five and H2's three settings links — are
/// dropped on the way in; the graph holds the member's triples and nothing the
/// projection derives.
pub fn put(
    pod: &Pod,
    webid: &str,
    document: &str,
    body: &[u8],
    content_type: &str,
) -> Result<(), LdpError> {
    // The same refusals a pod `PUT` makes before it takes the lock, in the
    // same order (`Target::prepare`): RDF/XML is served and never parsed
    // (ADR 0007), and this resource takes RDF only.
    ldp::refuse_rdf_xml(content_type)?;
    if !syntax::is_parseable_rdf(content_type) {
        return Err(LdpError::NotRdf);
    }
    let format = syntax::read_format(content_type)?;
    let quads = ldp::parse_into_graph(body, format, document)?;
    let kept = unreserved(quads, webid, document);
    // The profile graph is outside the storage root, so it stores as a bare
    // graph — the same family `write` above uses — rather than as a recorded
    // resource with metadata and containment.
    ldp::in_write(pod, move |w| {
        w.replace_graph(document, &kept)?;
        Ok(())
    })
}

/// `PATCH` the profile document's graph (spec 6, H1): the same solver every
/// other patch takes (`patch::Prepared::solve`), scoped to the profile graph,
/// with 5c's parse and classification of the body and the reserved positions
/// filtered from the result.
///
/// The classification — inserts only are Append, any delete is Write — gates
/// nothing here, because the owner check that authorized this call already
/// authorized Write; it is part of the same path, and the parse that produces
/// it is what refuses a malformed patch or a SPARQL Update in a form a `PATCH`
/// may not take, exactly as on the pod surface.
pub fn patch(
    pod: &Pod,
    webid: &str,
    document: &str,
    body: PatchBody<'_>,
) -> Result<(), PatchError> {
    ldp::in_write(pod, |w| {
        let prepared = patch::prepare(body, document)?;
        let patched = prepared.solve(w, document)?;
        let kept = unreserved(patched, webid, document);
        w.replace_graph(document, &kept)?;
        Ok(())
    })
}
