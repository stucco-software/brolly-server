//! The storage root and container bookkeeping.

use brolly_domain::vocab;
use brolly_store::write::{WriteError, insert_quads};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use oxigraph::store::Store;

pub const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
pub const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
pub const LDP_NON_RDF_SOURCE: &str = "http://www.w3.org/ns/ldp#NonRDFSource";
pub const PIM_STORAGE: &str = "http://www.w3.org/ns/pim/space#Storage";

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// Create the user's storage root: an `ldp:BasicContainer` that is also a
/// `pim:Storage`, which is what makes it discoverable as *the* pod root rather
/// than just another container.
pub fn init_storage_root(store: &Store, root: &str) -> Result<(), WriteError> {
    let node = iri(root);
    let quads = vec![
        Quad::new(
            NamedOrBlankNode::NamedNode(node.clone()),
            iri(vocab::RDF_TYPE),
            Term::NamedNode(iri(LDP_BASIC_CONTAINER)),
            GraphName::NamedNode(node.clone()),
        ),
        Quad::new(
            NamedOrBlankNode::NamedNode(node.clone()),
            iri(vocab::RDF_TYPE),
            Term::NamedNode(iri(LDP_RESOURCE)),
            GraphName::NamedNode(node.clone()),
        ),
        Quad::new(
            NamedOrBlankNode::NamedNode(node.clone()),
            iri(vocab::RDF_TYPE),
            Term::NamedNode(iri(PIM_STORAGE)),
            GraphName::NamedNode(node),
        ),
    ];
    insert_quads(store, &quads)?;
    Ok(())
}

/// The container that directly holds `resource`.
///
/// `/~/a/b/c` → `/~/a/b/`, `/~/a/` → `/~/`. Returns `None` at the storage root,
/// which has no parent inside the pod.
pub fn parent_container(resource: &str, root: &str) -> Option<String> {
    if resource == root || !resource.starts_with(root) {
        return None;
    }
    let trimmed = resource.trim_end_matches('/');
    let cut = trimmed.rfind('/')?;
    let parent = &trimmed[..cut + 1];
    (parent.len() >= root.len()).then(|| parent.to_string())
}

/// Record `resource` as contained by its parent, all the way up.
///
/// Containment is maintained on write rather than derived on read, because an
/// LDP `GET` on a container must list its members and walking the whole pod to
/// find them would be the outbox-walking mistake in another costume.
pub fn add_containment(store: &Store, resource: &str, root: &str) -> Result<(), WriteError> {
    let mut child = resource.to_string();
    while let Some(parent) = parent_container(&child, root) {
        let parent_node = iri(&parent);
        insert_quads(
            store,
            &[
                Quad::new(
                    NamedOrBlankNode::NamedNode(parent_node.clone()),
                    iri(LDP_CONTAINS),
                    Term::NamedNode(iri(&child)),
                    GraphName::NamedNode(parent_node.clone()),
                ),
                Quad::new(
                    NamedOrBlankNode::NamedNode(parent_node.clone()),
                    iri(vocab::RDF_TYPE),
                    Term::NamedNode(iri(LDP_BASIC_CONTAINER)),
                    GraphName::NamedNode(parent_node),
                ),
            ],
        )?;
        child = parent;
    }
    Ok(())
}

/// Remove a containment triple when a resource is deleted.
pub fn remove_containment(
    store: &Store,
    resource: &str,
    root: &str,
) -> Result<(), oxigraph::store::StorageError> {
    let Some(parent) = parent_container(resource, root) else {
        return Ok(());
    };
    let parent_node = iri(&parent);
    let quad = Quad::new(
        NamedOrBlankNode::NamedNode(parent_node.clone()),
        iri(LDP_CONTAINS),
        Term::NamedNode(iri(resource)),
        GraphName::NamedNode(parent_node),
    );
    store.remove(&quad)?;
    Ok(())
}

/// Members of a container.
pub fn members(store: &Store, container: &str) -> Vec<String> {
    let node = iri(container);
    store
        .quads_for_pattern(
            Some((&NamedOrBlankNode::NamedNode(node.clone())).into()),
            Some(iri(LDP_CONTAINS).as_ref()),
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .filter_map(Result::ok)
        .filter_map(|q| match q.object {
            Term::NamedNode(n) => Some(n.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// Remove every `ldp:contains` triple that names an ACL resource.
///
/// ACL resources are auxiliary and aren't members of their container (Solid
/// Protocol §4.3), but `ldp::put` recorded them as members until stage 0. This
/// is the repair `brolly-admin acl-uncontain` runs on each pod. It returns how
/// many triples it removed, so a second run reports zero.
pub fn uncontain_acls(store: &Store) -> Result<usize, oxigraph::store::StorageError> {
    let stale = store
        .quads_for_pattern(None, Some(iri(LDP_CONTAINS).as_ref()), None, None)
        .filter_map(|quad| match quad {
            Ok(quad) => is_acl_containment(&quad).then_some(Ok(quad)),
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<Quad>, _>>()?;
    for quad in &stale {
        store.remove(quad)?;
    }
    Ok(stale.len())
}

/// The shape [`add_containment`] writes, naming an ACL: a container's own
/// graph saying it contains an `.acl` resource.
///
/// Matching the graph as well as the predicate leaves a member's own documents
/// alone, even if they happen to use `ldp:contains`.
fn is_acl_containment(quad: &Quad) -> bool {
    let (
        NamedOrBlankNode::NamedNode(container),
        Term::NamedNode(member),
        GraphName::NamedNode(graph),
    ) = (&quad.subject, &quad.object, &quad.graph_name)
    else {
        return false;
    };
    container == graph
        && is_container(container.as_str())
        && crate::ldp::governed(member.as_str()).is_some()
}

/// Does a resource exist, as a graph with any triples?
pub fn exists(store: &Store, resource: &str) -> bool {
    let node = iri(resource);
    store
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(node.as_ref())),
        )
        .next()
        .is_some()
}

/// True when the IRI names a container by LDP convention.
pub fn is_container(resource: &str) -> bool {
    resource.ends_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "https://alice.brolly.id/~/";

    #[test]
    fn parents_walk_up_to_the_storage_root() {
        assert_eq!(
            parent_container("https://alice.brolly.id/~/a/b/c", ROOT).as_deref(),
            Some("https://alice.brolly.id/~/a/b/")
        );
        assert_eq!(
            parent_container("https://alice.brolly.id/~/a/", ROOT).as_deref(),
            Some(ROOT)
        );
    }

    #[test]
    fn the_storage_root_has_no_parent() {
        assert_eq!(parent_container(ROOT, ROOT), None);
    }

    #[test]
    fn containment_never_escapes_the_pod() {
        // A path outside the root must not produce a parent, or containment
        // triples would be written onto protocol resources.
        assert_eq!(
            parent_container("https://alice.brolly.id/profile", ROOT),
            None
        );
        assert_eq!(
            parent_container("https://alice.brolly.id/oauth/token", ROOT),
            None
        );
    }

    #[test]
    fn containers_are_recognised_by_trailing_slash() {
        assert!(is_container("https://alice.brolly.id/~/notes/"));
        assert!(!is_container("https://alice.brolly.id/~/notes/first"));
    }
}
