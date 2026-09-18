//! Stage 0, A2: an ACL resource is guarded by Control on the resource it
//! governs, never by the modes that resource hands out.
//!
//! `bob` holds Read and Write on everything under `/~/shared/` through
//! `acl:default`, and no Control. Before this fix that was enough to read the
//! container's ACL (learning who else has access), rewrite it (granting himself
//! Control), or delete it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_authz::AccessMode;
use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp::{self, LdpError};
use brolly_solid::storage;
use brolly_store::{StoreManager, insert_quads};
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.id";
const ROOT: &str = "https://alice.brolly.id/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const ALICE: &str = "https://alice.brolly.id/profile#me";
const BOB: &str = "https://bob.brolly.id/profile#me";
const CAROL: &str = "https://carol.brolly.id/profile#me";

const NOTE: &[u8] = br#"<> <https://example.org/title> "A note" ."#;

const ALL: [AccessMode; 4] = [
    AccessMode::Read,
    AccessMode::Write,
    AccessMode::Append,
    AccessMode::Control,
];

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn t(graph: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(n(s)),
        n(p),
        Term::NamedNode(n(o)),
        GraphName::NamedNode(n(graph)),
    )
}

fn member(name: &str, webid: &str) -> Subject {
    Subject::local(
        Uuid::new_v4(),
        format!("did:plc:{name}"),
        webid.into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    )
}

fn alice() -> Subject {
    member("alice", ALICE)
}

fn bob() -> Subject {
    member("bob", BOB)
}

fn carol() -> Subject {
    member("carol", CAROL)
}

/// A pod whose root ACL gives Alice Read, Write and Control over everything.
fn pod() -> (
    StoreManager,
    tempfile::TempDir,
    std::sync::Arc<oxigraph::store::Store>,
) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();
    storage::init_storage_root(&store, ROOT).unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    insert_quads(
        &store,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &a, &format!("{ACL}agent"), ALICE),
        ],
    )
    .unwrap();
    (mgr, dir, store)
}

/// `pod()`, plus `/~/shared/.acl`: Alice controls the container, Bob may read
/// and write inside it through `acl:default`, and holds no Control.
///
/// Written straight into the store so the setup doesn't depend on the code
/// under test.
fn shared_pod() -> (
    StoreManager,
    tempfile::TempDir,
    std::sync::Arc<oxigraph::store::Store>,
) {
    let (mgr, dir, store) = pod();
    let shared = format!("{ROOT}shared/");
    let g = format!("{shared}.acl");
    let owner = format!("{g}#owner");
    let bob = format!("{g}#bob");
    insert_quads(
        &store,
        &[
            t(&g, &owner, &format!("{ACL}accessTo"), &shared),
            t(&g, &owner, &format!("{ACL}default"), &shared),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &owner, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &owner, &format!("{ACL}agent"), ALICE),
            t(&g, &bob, &format!("{ACL}default"), &shared),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &bob, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &bob, &format!("{ACL}agent"), BOB),
        ],
    )
    .unwrap();
    (mgr, dir, store)
}

/// An ACL document giving `agent` Read, Write and Control over `resource` and
/// everything under it.
fn acl_granting(agent: &str, resource: &str) -> String {
    format!(
        "@prefix acl: <{ACL}> .\n\
         <#grant> a acl:Authorization ;\n\
           acl:agent <{agent}> ;\n\
           acl:accessTo <{resource}> ;\n\
           acl:default <{resource}> ;\n\
           acl:mode acl:Read, acl:Write, acl:Control .\n"
    )
}

#[test]
fn bob_cannot_read_rewrite_or_delete_the_containers_acl() {
    let (_m, _d, store) = shared_pod();
    let takeover = acl_granting(BOB, &format!("{ROOT}shared/"));

    assert!(
        matches!(
            ldp::read(&store, None, BASE, "/~/shared/.acl", &bob(), None),
            Err(LdpError::NotFound)
        ),
        "inherited Read must not reveal who else has access"
    );
    assert!(matches!(
        ldp::put(
            &store,
            None,
            BASE,
            "/~/shared/.acl",
            &bob(),
            takeover.as_bytes(),
            "text/turtle",
            ROOT
        ),
        Err(LdpError::Forbidden)
    ));
    assert!(matches!(
        ldp::append(
            &store,
            None,
            BASE,
            "/~/shared/.acl",
            &bob(),
            takeover.as_bytes(),
            "text/turtle",
            ROOT
        ),
        Err(LdpError::Forbidden)
    ));
    assert!(
        !ldp::may_write(&store, BASE, "/~/shared/.acl", &bob()).unwrap(),
        "PATCH goes through may_write"
    );
    assert!(matches!(
        ldp::delete(&store, None, BASE, "/~/shared/.acl", &bob(), ROOT),
        Err(LdpError::Forbidden)
    ));

    // Nothing above landed: Bob still holds exactly what he was given.
    assert_eq!(
        ldp::granted_modes(&store, BASE, "/~/shared/doc", &bob()),
        vec![AccessMode::Read, AccessMode::Write, AccessMode::Append]
    );
}

/// No `doc.acl.acl` exists in this test, on purpose. If one did, it would be
/// the first ACL candidate for `doc.acl` under the old rule and would refuse
/// Bob by itself (it grants nothing), so the assertion would pass without the
/// fix.
#[test]
fn bob_cannot_create_the_acl_of_a_document_he_can_write() {
    let (_m, _d, store) = shared_pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let takeover = acl_granting(BOB, &format!("{ROOT}shared/doc"));
    assert!(
        matches!(
            ldp::put(
                &store,
                None,
                BASE,
                "/~/shared/doc.acl",
                &bob(),
                takeover.as_bytes(),
                "text/turtle",
                ROOT
            ),
            Err(LdpError::Forbidden)
        ),
        "Write on a document must not let Bob create its ACL"
    );
    assert!(!storage::exists(&store, &format!("{ROOT}shared/doc.acl")));
}

#[test]
fn bob_cannot_read_an_acl_of_an_acl() {
    let (_m, _d, store) = shared_pod();
    // Alice creates it, so the refusal below means "refused", not "absent".
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl.acl",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(matches!(
        ldp::read(&store, None, BASE, "/~/shared/doc.acl.acl", &bob(), None),
        Err(LdpError::NotFound)
    ));
}

#[test]
fn bob_keeps_his_access_to_ordinary_resources() {
    let (_m, _d, store) = shared_pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc",
        &bob(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    let out = ldp::read(&store, None, BASE, "/~/shared/doc", &bob(), None).unwrap();
    assert!(String::from_utf8(out.body).unwrap().contains("A note"));
    assert_eq!(
        out.granted,
        vec![AccessMode::Read, AccessMode::Write, AccessMode::Append]
    );
}

/// The regression guard: this passes before the fix and must still pass after.
/// Alice holds Control on `/~/shared/` (and so, by default, on everything in
/// it), so tightening ACL access must not lock her out of any of it.
#[test]
fn the_owner_can_do_all_of_it() {
    let (_m, _d, store) = shared_pod();
    let doc = format!("{ROOT}shared/doc");

    assert!(ldp::read(&store, None, BASE, "/~/shared/.acl", &alice(), None).is_ok());
    assert!(ldp::may_write(&store, BASE, "/~/shared/.acl", &alice()).unwrap());

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        acl_granting(ALICE, &doc).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert!(ldp::read(&store, None, BASE, "/~/shared/doc.acl", &alice(), None).is_ok());
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl.acl",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert!(ldp::read(&store, None, BASE, "/~/shared/doc.acl.acl", &alice(), None).is_ok());

    // `doc.acl.acl` goes before `doc.acl`. It holds a note, not grants, and
    // while it exists the old rule takes it as `doc.acl`'s own ACL, which would
    // refuse the delete for a reason that has nothing to do with this fix.
    ldp::delete(&store, None, BASE, "/~/shared/doc.acl.acl", &alice(), ROOT).unwrap();
    ldp::delete(&store, None, BASE, "/~/shared/doc.acl", &alice(), ROOT).unwrap();
    assert!(!storage::exists(&store, &format!("{doc}.acl")));

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/.acl",
        &alice(),
        acl_granting(ALICE, &format!("{ROOT}shared/")).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::delete(&store, None, BASE, "/~/shared/.acl", &alice(), ROOT).unwrap();
}

/// `WAC-Allow` on an ACL is all or nothing: Control on the governed resource
/// means every mode, and anything short of it means none.
#[test]
fn wac_allow_on_an_acl_is_all_or_nothing() {
    let (_m, _d, store) = shared_pod();

    // Carol holds Control on /~/shared/ and nothing else, which is still
    // enough to manage its ACL.
    let g = format!("{ROOT}shared/.acl");
    let c = format!("{g}#carol");
    insert_quads(
        &store,
        &[
            t(&g, &c, &format!("{ACL}accessTo"), &format!("{ROOT}shared/")),
            t(&g, &c, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &c, &format!("{ACL}agent"), CAROL),
        ],
    )
    .unwrap();

    let owner = ldp::read(&store, None, BASE, "/~/shared/.acl", &alice(), None).unwrap();
    assert_eq!(owner.granted, ALL.to_vec());

    let carol = ldp::read(&store, None, BASE, "/~/shared/.acl", &carol(), None).unwrap();
    assert_eq!(carol.granted, ALL.to_vec());

    assert!(ldp::granted_modes(&store, BASE, "/~/shared/.acl", &bob()).is_empty());
}

/// ACLs are auxiliary resources, not members of their container
/// (Solid Protocol §4.3).
#[test]
fn an_acl_is_not_a_member_of_its_container() {
    let (_m, _d, store) = shared_pod();
    let doc = format!("{ROOT}shared/doc");

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        acl_granting(ALICE, &doc).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    let appended = ldp::append(
        &store,
        None,
        BASE,
        "/~/shared/.acl",
        &alice(),
        acl_granting(CAROL, &format!("{ROOT}shared/")).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert_eq!(appended, format!("{ROOT}shared/.acl"));

    let members = storage::members(&store, &format!("{ROOT}shared/"));
    assert!(
        members.contains(&doc),
        "an ordinary resource is still contained"
    );
    assert!(
        !members.contains(&format!("{ROOT}shared/doc.acl")),
        "got {members:?}"
    );
    assert!(
        !members.contains(&format!("{ROOT}shared/.acl")),
        "got {members:?}"
    );
}

/// An ACL may exist before the resource it governs. Writing one must not
/// create that resource as a side effect.
#[test]
fn an_acl_does_not_create_the_container_it_governs() {
    let (_m, _d, store) = pod();
    let newdir = format!("{ROOT}newdir/");

    ldp::put(
        &store,
        None,
        BASE,
        "/~/newdir/.acl",
        &alice(),
        acl_granting(ALICE, &newdir).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(storage::exists(&store, &format!("{newdir}.acl")));
    assert!(!storage::exists(&store, &newdir), "/~/newdir/ was created");
    assert!(!storage::members(&store, ROOT).contains(&newdir));
}

/// Solid Protocol §5.4: deleting a resource deletes its auxiliary resources.
#[test]
fn deleting_a_resource_deletes_its_acl() {
    let (_m, _d, store) = shared_pod();
    let doc = format!("{ROOT}shared/doc");

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        acl_granting(ALICE, &doc).as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();

    ldp::delete(&store, None, BASE, "/~/shared/doc", &alice(), ROOT).unwrap();

    assert!(!storage::exists(&store, &doc));
    assert!(!storage::exists(&store, &format!("{doc}.acl")));
}

/// A container with an ACL can now be deleted, because the ACL isn't a
/// member. Recreating it must not silently restore the grants.
#[test]
fn a_recreated_container_does_not_get_its_old_grants_back() {
    let (_m, _d, store) = pod();
    let shared = format!("{ROOT}shared/");
    let grants = format!(
        "@prefix acl: <{ACL}> .\n\
         <#owner> acl:agent <{ALICE}> ; acl:accessTo <{shared}> ; acl:default <{shared}> ;\n\
           acl:mode acl:Read, acl:Write, acl:Control .\n\
         <#bob> acl:agent <{BOB}> ; acl:default <{shared}> ;\n\
           acl:mode acl:Read, acl:Write .\n"
    );

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/.acl",
        &alice(),
        grants.as_bytes(),
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert!(
        ldp::granted_modes(&store, BASE, "/~/shared/doc", &bob()).contains(&AccessMode::Write),
        "precondition: Bob was granted Write"
    );

    ldp::delete(&store, None, BASE, "/~/shared/", &alice(), ROOT).unwrap();
    assert!(!storage::exists(&store, &format!("{shared}.acl")));

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    assert!(
        ldp::granted_modes(&store, BASE, "/~/shared/doc", &bob()).is_empty(),
        "the old grants came back with the container"
    );
}

/// What `put` wrote before this fix, and the sweep that removes it.
#[test]
fn stale_acl_containment_is_swept_and_a_rerun_removes_nothing() {
    let (_m, _d, store) = shared_pod();
    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    // The triples an old `put` of each ACL would have left behind.
    storage::add_containment(&store, &format!("{ROOT}.acl"), ROOT).unwrap();
    storage::add_containment(&store, &format!("{ROOT}shared/.acl"), ROOT).unwrap();

    assert_eq!(storage::uncontain_acls(&store).unwrap(), 2);
    assert_eq!(
        storage::members(&store, &format!("{ROOT}shared/")),
        vec![format!("{ROOT}shared/doc")]
    );
    let root = storage::members(&store, ROOT);
    assert!(!root.contains(&format!("{ROOT}.acl")), "got {root:?}");
    assert!(root.contains(&format!("{ROOT}shared/")), "got {root:?}");

    // The ACLs themselves are untouched; only their membership goes.
    assert!(storage::exists(&store, &format!("{ROOT}.acl")));
    assert!(storage::exists(&store, &format!("{ROOT}shared/.acl")));

    assert_eq!(storage::uncontain_acls(&store).unwrap(), 0, "idempotent");
}
