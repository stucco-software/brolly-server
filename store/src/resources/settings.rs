//! The settings resources every member's pod carries (spec 6, H2).
//!
//! A preferences file and the two type indexes, provisioned with the storage
//! root rather than left to members, because SolidOS — the client most members
//! arrive with — cannot boot without them: it dereferences the profile, reads
//! the three links, and fails to discover anything else if they point at
//! nothing. The public index is the one resource whose ACL grants the world
//! (`acl:agentClass foaf:Agent`), a deliberate exception to "WAC grants nothing
//! by default": a *public* type index exists to be read by other people's apps,
//! and provisioning it owner-only would make the name a lie.
//!
//! Both halves of that ACL are load-bearing. The closest ACL governs to the
//! exclusion of every ancestor's, so an ACL holding only the world grant would
//! lock the owner out of their own index with no `Control` to fix it with. The
//! owner's grant therefore comes too — the root grant's shape, minus
//! `acl:default`, which an index does not need because nothing inherits from a
//! document. The world's authorization carries no `acl:default` either:
//! nothing is meant to inherit *it*.
//!
//! No registrations are written. Apps register their own
//! `solid:TypeRegistration` instances; the server seeds the containers empty.
//! Inventing registrations nobody asked for is the predecessor's habit, not
//! ours.
//!
//! One code path serves two callers: provisioning at registration, and the
//! upgrade on open for pods provisioned before this existed. Same content,
//! same path — the upgrade is idempotent by construction, creating each
//! resource only when it is absent and touching nothing that exists.

use brolly_domain::vocab;
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};

use super::{Content, PodRead, PodWrite};
use crate::manager::StoreError;

/// `acl:` as a namespace, for the grant's predicates and modes.
const ACL: &str = "http://www.w3.org/ns/auth/acl#";

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn quad(graph: &str, subject: &str, predicate: &str, object: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(iri(subject)),
        iri(predicate),
        Term::NamedNode(iri(object)),
        GraphName::NamedNode(iri(graph)),
    )
}

/// The three settings resources under `root`, with the types they carry in
/// their own graphs — stored content, not projection (spec 6, H2).
fn resources(root: &str) -> Vec<(String, Vec<Quad>)> {
    let (preferences, public, private) = resource_iris(root);
    let preferences_quads = vec![quad(
        &preferences,
        &preferences,
        vocab::RDF_TYPE,
        vocab::SPACE_CONFIGURATION_FILE,
    )];
    let public_quads = vec![
        quad(&public, &public, vocab::RDF_TYPE, vocab::SOLID_TYPE_INDEX),
        quad(
            &public,
            &public,
            vocab::RDF_TYPE,
            vocab::SOLID_LISTED_DOCUMENT,
        ),
    ];
    let private_quads = vec![
        quad(&private, &private, vocab::RDF_TYPE, vocab::SOLID_TYPE_INDEX),
        quad(
            &private,
            &private,
            vocab::RDF_TYPE,
            vocab::SOLID_UNLISTED_DOCUMENT,
        ),
    ];
    vec![
        (preferences, preferences_quads),
        (public, public_quads),
        (private, private_quads),
    ]
}

/// The public index's ACL: the owner's grant plus the world's one Read (spec
/// 6, H2), as quads in the ACL's graph.
///
/// The owner's grant is the root grant's shape minus `acl:default` — the root
/// governs a container and everything inside it, while this governs one
/// document. The world's grant carries no `acl:default`: nothing inherits it.
fn public_index_acl(public: &str, owner: &str) -> Vec<Quad> {
    let acl = format!("{public}.acl");
    let own = format!("{acl}#owner");
    let world = format!("{acl}#public");
    vec![
        quad(&acl, &own, &format!("{ACL}accessTo"), public),
        quad(&acl, &own, &format!("{ACL}mode"), &format!("{ACL}Read")),
        quad(&acl, &own, &format!("{ACL}mode"), &format!("{ACL}Write")),
        quad(&acl, &own, &format!("{ACL}mode"), &format!("{ACL}Control")),
        quad(&acl, &own, &format!("{ACL}agent"), owner),
        quad(&acl, &world, &format!("{ACL}accessTo"), public),
        quad(&acl, &world, &format!("{ACL}mode"), &format!("{ACL}Read")),
        quad(&acl, &world, &format!("{ACL}agentClass"), vocab::FOAF_AGENT),
    ]
}

/// Create the settings resources under `root` that don't exist yet, and the
/// public index's ACL, returning how many resources were created (spec 6, H2).
///
/// Existing resources are left alone: a member who wrote their own preferences
/// file keeps it, content and version both — the upgrade's contract is
/// "created if absent, nothing existing touched", and this is the same path
/// registration takes, so a fresh pod and an upgraded one end up identical.
///
/// `owner` is the member's WebID, the one the public index's owner grant
/// names. It is never `None` here: the caller knows the owner at registration,
/// and the upgrade skips provisioning entirely when it cannot find one, rather
/// than seat a public index whose ACL holds only the world grant — which would
/// lock the owner out of it (see the module docs).
pub fn provision_settings(
    w: &mut PodWrite<'_>,
    root: &str,
    owner: &str,
) -> Result<usize, StoreError> {
    let mut created = 0;
    for (resource, types) in resources(root) {
        if w.meta(&resource)?.is_some() {
            continue;
        }
        w.put(&resource, Content::Rdf(&types))?;
        created += 1;
    }
    let (_, public, _) = resource_iris(root);
    let acl = format!("{public}.acl");
    if w.meta(&acl)?.is_none() {
        let grant = public_index_acl(&public, owner);
        w.put(&acl, Content::Auxiliary(&grant))?;
        created += 1;
    }
    Ok(created)
}

/// The three settings IRIs: the preferences file, the public index, the
/// private index. Shared with the profile projection, which derives its three
/// link triples from the storage root the same way.
pub fn resource_iris(root: &str) -> (String, String, String) {
    let settings = format!("{root}settings/");
    (
        format!("{settings}preferences.ttl"),
        format!("{settings}publicTypeIndex.ttl"),
        format!("{settings}privateTypeIndex.ttl"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "https://alice.brolly.test/~/";
    const OWNER: &str = "https://alice.brolly.test/profile#me";

    /// A fresh pod, provisioned the way `Pod::write` hands one over.
    fn pod() -> (tempfile::TempDir, super::super::Pod) {
        let dir = tempfile::tempdir().unwrap();
        let pod = super::super::Pod::open(dir.path()).unwrap();
        pod.write(|w| w.create_root(ROOT)).unwrap();
        (dir, pod)
    }

    fn holds(pod: &super::super::Pod, quad: &Quad) -> bool {
        pod.read_store()
            .quads_for_pattern(
                Some(quad.subject.as_ref()),
                Some(quad.predicate.as_ref()),
                Some(quad.object.as_ref()),
                Some(quad.graph_name.as_ref()),
            )
            .next()
            .is_some()
    }

    #[test]
    fn the_public_index_acl_carries_both_grants_and_no_default() {
        let public = format!("{ROOT}publicTypeIndex.ttl");
        let acl = format!("{public}.acl");
        let own = format!("{acl}#owner");
        let world = format!("{acl}#public");
        let grant = public_index_acl(&public, OWNER);

        // Grant by grant (spec 6, H2). The owner's half: the root grant's
        // shape minus `acl:default` — accessTo the index, Read, Write,
        // Control, and the owner.
        for expected in [
            quad(&acl, &own, &format!("{ACL}accessTo"), &public),
            quad(&acl, &own, &format!("{ACL}mode"), &format!("{ACL}Read")),
            quad(&acl, &own, &format!("{ACL}mode"), &format!("{ACL}Write")),
            quad(&acl, &own, &format!("{ACL}mode"), &format!("{ACL}Control")),
            quad(&acl, &own, &format!("{ACL}agent"), OWNER),
        ] {
            assert!(grant.contains(&expected), "missing {expected:?}");
        }
        // The world's half: one Read, via foaf:Agent, accessTo the index.
        for expected in [
            quad(&acl, &world, &format!("{ACL}accessTo"), &public),
            quad(&acl, &world, &format!("{ACL}mode"), &format!("{ACL}Read")),
            quad(&acl, &world, &format!("{ACL}agentClass"), vocab::FOAF_AGENT),
        ] {
            assert!(grant.contains(&expected), "missing {expected:?}");
        }
        // Nothing else, and no `acl:default` on either grant: neither is
        // meant to be inherited.
        assert_eq!(grant.len(), 8, "more than the two grants: {grant:?}");
        assert!(
            !grant
                .iter()
                .any(|q| q.predicate.as_str() == format!("{ACL}default")),
            "an authorization carries acl:default: {grant:?}"
        );
    }

    #[test]
    fn provisioning_creates_the_three_resources_and_the_worlds_acl() {
        let (_dir, pod) = pod();
        let created = pod.write(|w| provision_settings(w, ROOT, OWNER)).unwrap();
        assert_eq!(created, 4, "three resources and the public index's ACL");

        for (resource, kind) in [
            (format!("{ROOT}settings/preferences.ttl"), "preferences"),
            (format!("{ROOT}settings/publicTypeIndex.ttl"), "public"),
            (format!("{ROOT}settings/privateTypeIndex.ttl"), "private"),
        ] {
            let meta = pod.read(|r| r.meta(&resource)).unwrap().expect(kind);
            assert_eq!(meta.kind, super::super::Kind::RdfSource, "{kind}");
        }
        assert!(holds(
            &pod,
            &quad(
                &format!("{ROOT}settings/preferences.ttl"),
                &format!("{ROOT}settings/preferences.ttl"),
                vocab::RDF_TYPE,
                vocab::SPACE_CONFIGURATION_FILE
            )
        ));
        assert!(holds(
            &pod,
            &quad(
                &format!("{ROOT}settings/publicTypeIndex.ttl"),
                &format!("{ROOT}settings/publicTypeIndex.ttl"),
                vocab::RDF_TYPE,
                vocab::SOLID_TYPE_INDEX
            )
        ));
        assert!(holds(
            &pod,
            &quad(
                &format!("{ROOT}settings/privateTypeIndex.ttl"),
                &format!("{ROOT}settings/privateTypeIndex.ttl"),
                vocab::RDF_TYPE,
                vocab::SOLID_UNLISTED_DOCUMENT
            )
        ));

        // The world's one grant is on the public index and nowhere else.
        let acl = format!("{ROOT}settings/publicTypeIndex.ttl.acl");
        let world: Vec<Quad> = pod
            .read_store()
            .quads_for_pattern(
                None,
                Some(iri(&format!("{ACL}agentClass")).as_ref()),
                Some(iri(vocab::FOAF_AGENT).as_ref().into()),
                None,
            )
            .map(Result::unwrap)
            .collect();
        assert_eq!(world.len(), 1, "more than one world grant: {world:?}");
        assert_eq!(world[0].graph_name, GraphName::NamedNode(iri(&acl)));
    }

    #[test]
    fn provisioning_creates_nothing_that_already_exists() {
        let (_dir, pod) = pod();
        pod.write(|w| provision_settings(w, ROOT, OWNER)).unwrap();

        // A member's own content on the preferences file, and a member-written
        // ACL on the public index — written through `put`, the one way a
        // member's write reaches either.
        let preferences = format!("{ROOT}settings/preferences.ttl");
        let mine = quad(
            &preferences,
            &preferences,
            "https://example.org/kept",
            "mine",
        );
        let public_acl = format!("{ROOT}settings/publicTypeIndex.ttl.acl");
        let theirs = quad(&public_acl, &public_acl, "https://example.org/acl", "mine");
        pod.write(|w| {
            w.put(&preferences, Content::Rdf(std::slice::from_ref(&mine)))?;
            w.put(
                &public_acl,
                Content::Auxiliary(std::slice::from_ref(&theirs)),
            )
        })
        .unwrap();
        let version = pod.read(|r| r.meta(&preferences)).unwrap().unwrap().version;

        let created = pod.write(|w| provision_settings(w, ROOT, OWNER)).unwrap();
        assert_eq!(created, 0, "everything existed");

        assert!(holds(&pod, &mine), "the member's triple was replaced");
        assert_eq!(
            pod.read(|r| r.meta(&preferences)).unwrap().unwrap().version,
            version,
            "the member's version moved"
        );
        assert!(holds(&pod, &theirs), "the member-written ACL was replaced");
    }
}
