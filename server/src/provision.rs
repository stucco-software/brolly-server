//! Giving a new member a pod they can actually use.
//!
//! A storage root with no ACL is a pod its owner cannot write to. WAC grants
//! nothing by default — deliberately, since a missing ACL meaning "allow" is
//! how authorization bugs become data leaks — so the grant has to be created,
//! and the only moment that is certainly right is account creation.
//!
//! This was missing: registration created a user row and nothing else, so the
//! first write any member attempted was refused. It surfaced as a `403` from
//! the Mastodon composer with a pod that looked fine from the outside.

use brolly_identity::{routing, webid};
use brolly_solid::storage;
use brolly_store::write::{WriteError, insert_quads};
use oxigraph_model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};

const ACL: &str = "http://www.w3.org/ns/auth/acl#";

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn triple(graph: &str, subject: &str, predicate: &str, object: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(iri(subject)),
        iri(predicate),
        Term::NamedNode(iri(object)),
        GraphName::NamedNode(iri(graph)),
    )
}

/// Create a member's storage root and the ACL that makes it theirs.
///
/// The grant carries **both** `acl:accessTo` and `acl:default`: the first
/// governs the container itself, the second governs everything inside it. They
/// are distinct scopes, and conflating them is how an ACL silently grants more
/// or less than intended.
pub fn pod(
    store: &brolly_store::Store,
    username: &str,
    base_domain: &str,
) -> Result<(), WriteError> {
    let root = routing::storage_root(username, base_domain);
    storage::init_storage_root(store, &root)?;

    let acl = format!("{root}.acl");
    let owner = format!("{acl}#owner");
    let member = webid::webid(username, base_domain);

    insert_quads(
        store,
        &[
            triple(&acl, &owner, &format!("{ACL}accessTo"), &root),
            triple(&acl, &owner, &format!("{ACL}default"), &root),
            triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            triple(
                &acl,
                &owner,
                &format!("{ACL}mode"),
                &format!("{ACL}Control"),
            ),
            triple(&acl, &owner, &format!("{ACL}agent"), &member),
        ],
    )?;
    Ok(())
}
