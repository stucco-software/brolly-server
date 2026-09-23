//! Phase 4 exit criterion: a write to a non-publication container provably
//! emits no activity and no repo commit (D9, ADR 0012).
//!
//! Publication is not a property checked on LDP writes — it is a path that does
//! not exist inside `/~/`. These assert the observable consequence: nothing a
//! user stores in their pod produces a pointer in the server-agent index, which
//! is where published things appear (ADR 0005 R1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::{Scope, Subject, Via};
use brolly_solid::ldp;
use brolly_store::resources::{Content, Pod, PodRead};
use brolly_store::{StoreManager, index};
use oxigraph::model::{GraphName, GraphNameRef, NamedNode, NamedOrBlankNode, Quad, Term};
use std::sync::Arc;
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.id";
const ROOT: &str = "https://alice.brolly.id/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";

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

fn alice() -> Subject {
    Subject::local(
        Uuid::new_v4(),
        "did:plc:alice".into(),
        "https://alice.brolly.id/profile#me".into(),
        Scope::parse("webid"),
        Via::SolidDpop,
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    manager: StoreManager,
    pod: Arc<Pod>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let manager = StoreManager::open(dir.path(), 4, 60).unwrap();
    let pod = manager.pod(Uuid::new_v4()).unwrap();

    let g = format!("{ROOT}.acl");
    let a = format!("{g}#owner");
    let grants = [
        t(&g, &a, &format!("{ACL}default"), ROOT),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")),
        t(
            &g,
            &a,
            &format!("{ACL}agent"),
            "https://alice.brolly.id/profile#me",
        ),
    ];
    pod.write(|w| {
        w.create_root(ROOT)?;
        w.put(&g, Content::Auxiliary(&grants))?;
        Ok(())
    })
    .unwrap();

    Fixture {
        _dir: dir,
        manager,
        pod,
    }
}

fn index_is_empty(manager: &StoreManager) -> bool {
    manager
        .instance()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(n(index::PUBLIC_TIMELINE).as_ref())),
        )
        .next()
        .is_none()
}

/// A body that is unmistakably an ActivityStreams Note.
const A_REAL_POST: &[u8] = br#"
<> a <https://www.w3.org/ns/activitystreams#Note> ;
   <https://www.w3.org/ns/activitystreams#content> "This looks exactly like a post." .
"#;

#[test]
fn storing_a_note_anywhere_in_the_pod_publishes_nothing() {
    let f = fixture();
    assert!(index_is_empty(&f.manager));

    // Including paths chosen to look as much like a publication surface as
    // possible. Shape is not enough, and neither is naming (ADR 0012).
    for path in [
        "/~/note",
        "/~/outbox/first",
        "/~/public/announcement",
        "/~/activitystreams/note",
    ] {
        ldp::put(
            &f.pod,
            None,
            BASE,
            path,
            &alice(),
            A_REAL_POST,
            "text/turtle",
            ROOT,
        )
        .unwrap();
    }

    assert!(
        index_is_empty(&f.manager),
        "an LDP write must not produce a timeline pointer"
    );
}

#[test]
fn a_container_named_outbox_inside_the_pod_is_just_a_container() {
    let f = fixture();
    let created = ldp::append(
        &f.pod,
        None,
        BASE,
        "/~/outbox/",
        &alice(),
        A_REAL_POST,
        "text/turtle",
        ROOT,
    )
    .unwrap();

    assert!(created.starts_with(ROOT), "it is ordinary pod storage");
    assert!(
        index_is_empty(&f.manager),
        "naming a pod container 'outbox' must not make it a publication surface"
    );
}

#[test]
fn the_real_outbox_is_outside_the_pod_and_unreachable_from_ldp() {
    // ADR 0012: the publication surface is the AS2 outbox at the subdomain
    // root, which ADR 0010 keeps outside the storage root entirely. An LDP
    // write cannot address it, so publication cannot happen by accident.
    let f = fixture();
    let err = ldp::put(
        &f.pod,
        None,
        BASE,
        "/outbox",
        &alice(),
        A_REAL_POST,
        "text/turtle",
        ROOT,
    )
    .unwrap_err();

    assert!(
        matches!(err, ldp::LdpError::OutsideStorage),
        "the outbox is a protocol resource, not pod storage; got {err:?}"
    );
}

#[test]
fn deleting_pod_content_also_publishes_nothing() {
    let f = fixture();
    ldp::put(
        &f.pod,
        None,
        BASE,
        "/~/note",
        &alice(),
        A_REAL_POST,
        "text/turtle",
        ROOT,
    )
    .unwrap();
    ldp::delete(&f.pod, BASE, "/~/note", &alice(), ROOT).unwrap();

    assert!(
        index_is_empty(&f.manager),
        "a delete inside the pod is not a Delete activity"
    );
}
