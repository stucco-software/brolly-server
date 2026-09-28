//! LDP-NR: binary resources.
//!
//! A pod holds images and PDFs as well as triples. The bytes live in the blob
//! store; the graph holds a digest, a media type and a size, so WAC, containment
//! and deletion all work on a binary exactly as they do on an RDF source —
//! there is no second authorization path for media.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp::{self, LdpError, PatchBody};
use brolly_solid::patch::PatchError;
use brolly_store::BlobStore;
use brolly_store::resources::{Content, Kind, Pod, PodRead, ResourceMeta};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.test";
const ROOT: &str = "https://alice.brolly.test/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const WEBID: &str = "https://alice.brolly.test/profile#me";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR pretend this is an image";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn t(g: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(n(s)),
        n(p),
        Term::NamedNode(n(o)),
        GraphName::NamedNode(n(g)),
    )
}

/// Add `quads` to the ACL at `acl`, recording it as an auxiliary resource if
/// it's new. Metadata is what makes an ACL exist, so a raw seed isn't enough.
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

struct Fixture {
    store: std::sync::Arc<Pod>,
    blobs: BlobStore,
    _stores: brolly_store::StoreManager,
    _dir: tempfile::TempDir,
}

/// A pod whose root ACL grants Alice read and write.
fn pod() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let stores = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
    let user = Uuid::new_v4();
    let store = stores.pod(user).unwrap();
    let blobs = stores.blobs(user).unwrap();

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
            t(&g, &a, &format!("{ACL}agent"), WEBID),
        ],
    );

    Fixture {
        store,
        blobs,
        _stores: stores,
        _dir: dir,
    }
}

fn alice() -> Subject {
    Subject::local(
        Uuid::new_v4(),
        String::new(),
        WEBID.into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    )
}

fn a_stranger() -> Subject {
    Subject {
        user_id: None,
        did: None,
        webid: Some("https://mallory.example/profile#me".into()),
        scope: Scope::default(),
        via: Via::SolidDpop,
    }
}

#[test]
fn a_binary_round_trips_with_its_media_type() {
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/avatar.png",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();

    let outcome = ldp::read(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/avatar.png",
        &alice(),
        // A binary ignores Accept: there is nothing to negotiate, and
        // serializing it as Turtle would hand back the metadata instead of the
        // file the client asked for.
        Some("text/turtle"),
    )
    .unwrap();

    assert_eq!(outcome.body, PNG);
    assert_eq!(outcome.media_type, "image/png");
}

#[test]
fn a_binary_is_typed_as_a_non_rdf_source() {
    // How a generic Solid client knows not to parse it.
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/avatar.png",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();

    let resource = format!("{BASE}/~/avatar.png");
    let recorded = meta(&pod.store, &resource).expect("the binary exists");
    assert!(matches!(recorded.kind, Kind::NonRdfSource));
    let own: Vec<Quad> = pod
        .store
        .read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(n(&resource).as_ref())),
        )
        .map(Result::unwrap)
        .collect();
    assert!(
        own.is_empty(),
        "the blob pointer is the server's, not in the graph: {own:?}"
    );
}

#[test]
fn a_binary_is_listed_by_its_container() {
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/media/avatar.png",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();

    let members = members(&pod.store, &format!("{BASE}/~/media/"));
    assert!(
        members.contains(&format!("{BASE}/~/media/avatar.png")),
        "a binary must appear in its container like any other resource: {members:?}"
    );
}

#[test]
fn wac_governs_a_binary_exactly_as_it_governs_a_graph() {
    // The failure this guards against is a media path that reads bytes off disk
    // without consulting the ACL — private images served to anyone with the URL.
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/private.png",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();

    let refused = ldp::read(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/private.png",
        &a_stranger(),
        None,
    );
    assert!(
        matches!(refused, Err(LdpError::Denied)),
        "an unauthorized reader must not get the bytes"
    );

    let write = ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/private.png",
        &a_stranger(),
        b"replaced",
        "image/png",
        ROOT,
    );
    // The pre-lock check for a non-RDF body. If this stayed `Forbidden`, the
    // status would depend on the `Content-Type`.
    assert!(matches!(write, Err(LdpError::Denied)));
}

#[test]
fn replacing_a_binary_replaces_the_bytes() {
    let pod = pod();
    let put = |bytes: &[u8]| {
        ldp::put(
            &pod.store,
            Some(&pod.blobs),
            BASE,
            "/~/avatar.png",
            &alice(),
            bytes,
            "image/png",
            ROOT,
        )
        .unwrap()
    };
    put(PNG);
    let old = ldp::blob_digest(&pod.store, &format!("{BASE}/~/avatar.png")).unwrap();
    put(b"a completely different image");

    let outcome = ldp::read(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/avatar.png",
        &alice(),
        None,
    )
    .unwrap();
    assert_eq!(outcome.body, b"a completely different image");
    assert!(
        !pod.blobs.contains(&old),
        "the replaced bytes are released once nothing names them"
    );
}

#[test]
fn deleting_a_binary_removes_its_bytes() {
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/avatar.png",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();
    let digest = brolly_solid::ldp::blob_digest(&pod.store, &format!("{BASE}/~/avatar.png"))
        .expect("a digest was recorded");

    ldp::delete(&pod.store, BASE, "/~/avatar.png", &alice(), ROOT).unwrap();

    assert!(
        !pod.blobs.contains(&digest),
        "an orphaned blob is a member's deleted photo still on disk"
    );
}

#[test]
fn deleting_one_of_two_resources_sharing_bytes_keeps_the_other_readable() {
    // Content addressing means two resources can name one blob. Deleting either
    // must not blank the other — this is the bug that content addressing invites
    // and refcount-free deletion causes.
    let pod = pod();
    for path in ["/~/one.png", "/~/two.png"] {
        ldp::put(
            &pod.store,
            Some(&pod.blobs),
            BASE,
            path,
            &alice(),
            PNG,
            "image/png",
            ROOT,
        )
        .unwrap();
    }

    ldp::delete(&pod.store, BASE, "/~/one.png", &alice(), ROOT).unwrap();

    let survivor = ldp::read(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/two.png",
        &alice(),
        None,
    )
    .unwrap();
    assert_eq!(survivor.body, PNG, "the surviving resource lost its bytes");
}

#[test]
fn rdf_xml_is_still_refused_rather_than_stored_as_a_blob() {
    // ADR 0007. Falling through to blob storage would be the silent acceptance
    // the ADR exists to prevent — two live quick-xml advisories are reachable
    // from parsed RDF/XML, and storing it opaquely just defers the parse.
    let pod = pod();
    let result = ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/doc.rdf",
        &alice(),
        b"<rdf:RDF/>",
        "application/rdf+xml",
        ROOT,
    );

    assert!(
        matches!(result, Err(LdpError::Syntax(_))),
        "RDF/XML must 415, not become an opaque blob: {result:?}"
    );
}

#[test]
fn turtle_still_goes_to_the_graph_and_not_the_blob_store() {
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/note",
        &alice(),
        b"<#it> <https://example.org/p> <https://example.org/o> .",
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(
        ldp::blob_digest(&pod.store, &format!("{BASE}/~/note")).is_none(),
        "an RDF source must not acquire a blob"
    );
    let outcome = ldp::read(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/note",
        &alice(),
        None,
    )
    .unwrap();
    assert_eq!(outcome.media_type, "text/turtle");
}

#[test]
fn posting_a_binary_to_a_container_mints_a_member() {
    let pod = pod();
    let created = ldp::append(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/media/",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();

    assert!(created.starts_with(&format!("{BASE}/~/media/")));
    let members = members(&pod.store, &format!("{BASE}/~/media/"));
    assert!(members.contains(&created));
}

#[test]
fn a_binary_cannot_be_patched() {
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/avatar.png",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap();
    let err = ldp::patch(
        &pod.store,
        BASE,
        "/~/avatar.png",
        &alice(),
        PatchBody::SparqlUpdate("INSERT DATA { <a:b> <a:c> <a:d> }"),
        ROOT,
    )
    .unwrap_err();
    assert!(
        matches!(err, PatchError::Ldp(LdpError::NotRdf)),
        "got {err:?}"
    );
}

#[test]
fn a_non_rdf_post_to_a_document_is_not_rdf() {
    let pod = pod();
    ldp::put(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/note",
        &alice(),
        b"<#it> <https://example.org/p> <https://example.org/o> .",
        "text/turtle",
        ROOT,
    )
    .unwrap();
    let err = ldp::append(
        &pod.store,
        Some(&pod.blobs),
        BASE,
        "/~/note",
        &alice(),
        PNG,
        "image/png",
        ROOT,
    )
    .unwrap_err();
    assert!(matches!(err, LdpError::NotRdf), "got {err:?}");
}
