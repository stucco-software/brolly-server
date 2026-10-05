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
use brolly_store::StoreManager;
use brolly_store::resources::{Content, Kind, Pod, PodRead, ResourceMeta};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
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

/// Add `quads` to the ACL at `acl`, recording it as an auxiliary resource if
/// it's new. Metadata is what makes an ACL exist, so a raw seed isn't enough.
/// Goes through the pod, not through `ldp`, so the setup doesn't depend on the
/// code under test.
fn grant(pod: &Pod, acl: &str, quads: &[Quad]) {
    pod.write(|w| {
        let mut all = w
            .quads_for_pattern(
                None,
                None,
                None,
                Some(GraphNameRef::NamedNode(n(acl).as_ref())),
            )
            .collect::<Result<Vec<_>, _>>()?;
        all.extend_from_slice(quads);
        w.put(acl, Content::Auxiliary(&all))?;
        Ok(())
    })
    .unwrap();
}

/// What the metadata records about `resource`: `Some` is existence.
fn meta(pod: &Pod, resource: &str) -> Option<ResourceMeta> {
    pod.read(|r| r.meta(resource)).unwrap()
}

/// A container's members, sorted, from metadata.
fn members(pod: &Pod, container: &str) -> Vec<String> {
    let mut members = pod.write(|w| w.members(container)).unwrap();
    members.sort();
    members
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
fn pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().unwrap();
    let mgr = StoreManager::open(dir.path(), 4, 60).unwrap();
    let store = mgr.pod(Uuid::new_v4()).unwrap();
    store.write(|w| w.create_root(ROOT)).unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    grant(
        &store,
        &g,
        &[
            t(&g, &a, &format!("{ACL}default"), ROOT),
            t(&g, &a, &format!("{ACL}accessTo"), ROOT),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
            t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &a, &format!("{ACL}agent"), ALICE),
        ],
    );
    (mgr, dir, store)
}

/// `pod()`, plus `/~/shared/.acl`: Alice controls the container, Bob may read
/// and write inside it through `acl:default`, and holds no Control.
///
/// Written straight into the store so the setup doesn't depend on the code
/// under test.
fn shared_pod() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let (mgr, dir, store) = pod();
    let shared = format!("{ROOT}shared/");
    let g = format!("{shared}.acl");
    let owner = format!("{g}#owner");
    let bob = format!("{g}#bob");
    grant(
        &store,
        &g,
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
    );
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
            Err(LdpError::Denied)
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
        Err(LdpError::Denied)
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
            ROOT,
            None,
            ldp::RequestedKind::Auto,
        ),
        Err(LdpError::Denied)
    ));
    assert!(
        !ldp::may_write(&store.read_store(), BASE, "/~/shared/.acl", &bob()).unwrap(),
        "PATCH goes through may_write"
    );
    assert!(matches!(
        ldp::delete(&store, BASE, "/~/shared/.acl", &bob(), ROOT),
        Err(LdpError::Denied)
    ));

    // Nothing above landed: Bob still holds exactly what he was given.
    assert_eq!(
        ldp::granted_modes(&store.read_store(), BASE, "/~/shared/doc", &bob()),
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
            Err(LdpError::Denied)
        ),
        "Write on a document must not let Bob create its ACL"
    );
    assert!(meta(&store, &format!("{ROOT}shared/doc.acl")).is_none());
}

/// H1 (spec 5d, the change of heart): `doc.acl.acl` is a fiction now, not a
/// reachable resource stage 0 guarded — the store refuses to record an
/// auxiliary of an auxiliary whoever asks, and the 404 that answers the shape
/// on the wire is `pod.rs`'s gate, later. Under the gate the shape is still
/// guarded by Control on the thing at the bottom, so Bob's Write on the
/// container does not read what the path governs.
#[test]
fn bob_cannot_read_an_acl_of_an_acl() {
    let (_m, _d, store) = shared_pod();
    // Not even the owner can bring the fiction into existence.
    assert!(matches!(
        ldp::put(
            &store,
            None,
            BASE,
            "/~/shared/doc.acl.acl",
            &alice(),
            NOTE,
            "text/turtle",
            ROOT
        ),
        Err(LdpError::Store(_))
    ));

    assert!(matches!(
        ldp::read(&store, None, BASE, "/~/shared/doc.acl.acl", &bob(), None),
        Err(LdpError::Denied)
    ));
    assert!(meta(&store, &format!("{ROOT}shared/doc.acl.acl")).is_none());
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
        out.description.granted,
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
    assert!(ldp::may_write(&store.read_store(), BASE, "/~/shared/.acl", &alice()).unwrap());

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
    // `doc.acl.acl` is a fiction (spec 5d, H1): there is no ACL-of-an-ACL to
    // clear out of the way before the delete below, because nobody can create
    // one — the store's refusal is the floor under the 404 gate.
    assert!(matches!(
        ldp::put(
            &store,
            None,
            BASE,
            "/~/shared/doc.acl.acl",
            &alice(),
            NOTE,
            "text/turtle",
            ROOT
        ),
        Err(LdpError::Store(_))
    ));

    ldp::delete(&store, BASE, "/~/shared/doc.acl", &alice(), ROOT).unwrap();
    assert!(meta(&store, &format!("{doc}.acl")).is_none());

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
    ldp::delete(&store, BASE, "/~/shared/.acl", &alice(), ROOT).unwrap();
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
    grant(
        &store,
        &g,
        &[
            t(&g, &c, &format!("{ACL}accessTo"), &format!("{ROOT}shared/")),
            t(&g, &c, &format!("{ACL}mode"), &format!("{ACL}Control")),
            t(&g, &c, &format!("{ACL}agent"), CAROL),
        ],
    );

    let owner = ldp::read(&store, None, BASE, "/~/shared/.acl", &alice(), None).unwrap();
    assert_eq!(owner.description.granted, ALL.to_vec());

    let carol = ldp::read(&store, None, BASE, "/~/shared/.acl", &carol(), None).unwrap();
    assert_eq!(carol.description.granted, ALL.to_vec());

    assert!(ldp::granted_modes(&store.read_store(), BASE, "/~/shared/.acl", &bob()).is_empty());
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
    // 5c H3: POST is a container method; the ACL is written by `PUT`, and a
    // member minted by POST into the container is contained — the contrast
    // the test exists to draw.
    let minted = ldp::append(
        &store,
        None,
        BASE,
        "/~/shared/",
        &alice(),
        NOTE,
        "text/turtle",
        ROOT,
        Some("member"),
        ldp::RequestedKind::Auto,
    )
    .unwrap();
    assert_eq!(minted.member, format!("{ROOT}shared/member"));

    let members = members(&store, &format!("{ROOT}shared/"));
    assert!(
        members.contains(&doc),
        "an ordinary resource is still contained"
    );
    assert!(
        members.contains(&minted.member),
        "a POST-minted member is contained: {members:?}"
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

    assert!(matches!(
        meta(&store, &format!("{newdir}.acl")).unwrap().kind,
        Kind::Auxiliary
    ));
    assert!(meta(&store, &newdir).is_none(), "/~/newdir/ was created");
    assert!(!members(&store, ROOT).contains(&newdir));
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

    ldp::delete(&store, BASE, "/~/shared/doc", &alice(), ROOT).unwrap();

    assert!(meta(&store, &doc).is_none());
    assert!(meta(&store, &format!("{doc}.acl")).is_none());
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
        ldp::granted_modes(&store.read_store(), BASE, "/~/shared/doc", &bob())
            .contains(&AccessMode::Write),
        "precondition: Bob was granted Write"
    );

    ldp::delete(&store, BASE, "/~/shared/", &alice(), ROOT).unwrap();
    assert!(meta(&store, &format!("{shared}.acl")).is_none());

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
        ldp::granted_modes(&store.read_store(), BASE, "/~/shared/doc", &bob()).is_empty(),
        "the old grants came back with the container"
    );
}

/// An ACL is a resource: it exists, has a version, and goes with what it
/// governs.
#[test]
fn an_acl_exists_has_a_version_and_goes_with_its_resource() {
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

    let acl = meta(&store, &format!("{doc}.acl")).expect("the ACL exists");
    assert!(matches!(acl.kind, Kind::Auxiliary));
    assert!(!acl.version.is_empty());

    ldp::delete(&store, BASE, "/~/shared/doc", &alice(), ROOT).unwrap();
    assert!(meta(&store, &format!("{doc}.acl")).is_none());
}

#[test]
fn an_acl_takes_an_rdf_body_only() {
    let (_m, _d, store) = shared_pod();
    let err = ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/.acl",
        &alice(),
        b"\x89PNG",
        "image/png",
        ROOT,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::NotRdf), "got {err:?}");
}

/// Solid's rule: an existing ACL governs, and an empty one grants nothing. It
/// must not fall through to the container's broader `acl:default`.
#[test]
fn an_empty_acl_governs_and_grants_nothing() {
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
    assert!(
        ldp::granted_modes(&store.read_store(), BASE, "/~/shared/doc", &bob())
            .contains(&AccessMode::Write),
        "precondition: the container's default reaches Bob"
    );

    ldp::put(
        &store,
        None,
        BASE,
        "/~/shared/doc.acl",
        &alice(),
        b"",
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(meta(&store, &format!("{ROOT}shared/doc.acl")).is_some());
    assert!(
        ldp::granted_modes(&store.read_store(), BASE, "/~/shared/doc", &bob()).is_empty(),
        "an empty ACL fell through to the container's default"
    );
    assert!(matches!(
        ldp::read(&store, None, BASE, "/~/shared/doc", &bob(), None),
        Err(LdpError::Denied)
    ));
}

// --- read access follows the publication (spec 4, H5, ADR 0017) -----------------

/// The composer's ACL shape, exactly as `outbox::write_acl` writes it: the
/// author (Read, Write, Control) plus one audience grant. Written here in the
/// test rather than published through the composer, which lives a crate over
/// in the server — what this file pins is the WAC-level behaviour the shape
/// depends on.
fn composer_acl(resource: &str, author: &str, audience: &[Quad]) -> Vec<Quad> {
    let acl = format!("{resource}.acl");
    let owner = format!("{acl}#owner");
    let mut quads = vec![
        t(&acl, &owner, &format!("{ACL}accessTo"), resource),
        t(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(
            &acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ),
        t(&acl, &owner, &format!("{ACL}agent"), author),
    ];
    quads.extend_from_slice(audience);
    quads
}

/// The audience grant of a public post: `foaf:Agent`, Read.
fn public_audience(resource: &str) -> Vec<Quad> {
    let acl = format!("{resource}.acl");
    let auth = format!("{acl}#read-0");
    vec![
        t(&acl, &auth, &format!("{ACL}accessTo"), resource),
        t(&acl, &auth, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(
            &acl,
            &auth,
            &format!("{ACL}agentClass"),
            "http://xmlns.com/foaf/0.1/Agent",
        ),
    ]
}

#[test]
fn a_composer_shaped_acl_governs_the_resource_alone() {
    // The exclusion fact the author grant rides on: once the resource has its
    // own ACL, it alone decides, and the ancestor's broader default does not
    // reach through. Bob holds Read and Write on everything under /~/shared/
    // by `acl:default`; the medium inside with its own ACL grants him nothing,
    // and his write on it is denied.
    let (_m, _d, store) = shared_pod();
    let medium = format!("{ROOT}shared/medium");
    store
        .write(|w| {
            w.put(&medium, Content::Rdf(&[]))?;
            let acl = composer_acl(&medium, ALICE, &[]);
            w.put(&format!("{medium}.acl"), Content::Auxiliary(&acl))
        })
        .unwrap();

    assert!(
        !ldp::granted_modes(&store.read_store(), BASE, "/~/shared/medium", &bob())
            .contains(&AccessMode::Write),
        "the container's default reached through the medium's own ACL"
    );
    assert!(matches!(
        ldp::put(
            &store,
            None,
            BASE,
            "/~/shared/medium",
            &bob(),
            NOTE,
            "text/turtle",
            ROOT,
        ),
        Err(LdpError::Denied)
    ));
    // The author, meanwhile, holds everything the ACL names — Read, Write,
    // and Control, which is the mode the member fixes access with.
    let granted = ldp::granted_modes(&store.read_store(), BASE, "/~/shared/medium", &alice());
    for mode in [AccessMode::Read, AccessMode::Write, AccessMode::Control] {
        assert!(granted.contains(&mode), "the author lacks {mode:?}");
    }
}

#[test]
fn an_audience_only_acl_locks_the_author_out() {
    // The hole the author grant closes: an ACL with the audience's grant and
    // no author grant leaves the author — who holds Read, Write and Control
    // on the whole pod through the root's `acl:default` — with nothing on
    // their own resource. The audience reads; the author cannot even fix the
    // ACL, because Control went with the exclusion.
    let (_m, _d, store) = pod();
    let medium = format!("{ROOT}medium");
    store
        .write(|w| {
            w.put(&medium, Content::Rdf(&[]))?;
            let acl = public_audience(&medium);
            w.put(&format!("{medium}.acl"), Content::Auxiliary(&acl))
        })
        .unwrap();

    // The audience reads, anonymously even.
    assert!(
        ldp::granted_modes(
            &store.read_store(),
            BASE,
            "/~/medium",
            &Subject::anonymous()
        )
        .contains(&AccessMode::Read),
        "the public audience does not read"
    );
    // The author: Read as one foaf:Agent among many, and nothing else — not
    // Write, not Control.
    let granted = ldp::granted_modes(&store.read_store(), BASE, "/~/medium", &alice());
    assert_eq!(
        granted,
        vec![AccessMode::Read],
        "the author kept more than Read"
    );
    assert!(matches!(
        ldp::put(
            &store,
            None,
            BASE,
            "/~/medium",
            &alice(),
            NOTE,
            "text/turtle",
            ROOT,
        ),
        Err(LdpError::Denied)
    ));
    assert!(matches!(
        ldp::put(
            &store,
            None,
            BASE,
            "/~/medium.acl",
            &alice(),
            b"",
            "text/turtle",
            ROOT,
        ),
        Err(LdpError::Denied)
    ));
}
