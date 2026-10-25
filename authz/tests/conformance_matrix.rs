//! Phase 2 exit criterion: **one** authorization matrix, run identically
//! through a stub of each of the four surfaces.
//!
//! This is the test the predecessor could not have written. Its WAC was
//! reachable only from `solid/ldp.rs`; ActivityPub, Mastodon, and XRPC reads
//! bypassed authorization entirely and reimplemented visibility in their own
//! idioms. The same triple was reachable through four doors and one checked the
//! lock.
//!
//! Here every surface funnels through `effective_acl` + `authorize`, so the
//! matrix must produce identical answers regardless of which door was used. A
//! surface that grows its own logic makes this test fail.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_authz::{AccessMode, Agent, AuthzError, EffectiveAcl, authorize, effective_acl};
use brolly_store::StoreManager;
use brolly_store::resources::{Content, Pod, PodRead};
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.id";
const ROOT: &str = "https://alice.brolly.id/~/";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const FOAF: &str = "http://xmlns.com/foaf/0.1/";
const VCARD: &str = "http://www.w3.org/2006/vcard/ns#";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn t(graph: &str, subject: &str, predicate: &str, object: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(n(subject)),
        n(predicate),
        Term::NamedNode(n(object)),
        GraphName::NamedNode(n(graph)),
    )
}

/// The four protocol surfaces. Each is a stub standing in for the adapter that
/// will exist in Phases 4–7; the whole point is that none of them may resolve
/// authorization differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Solid,
    ActivityPub,
    Mastodon,
    Xrpc,
}

const SURFACES: [Surface; 4] = [
    Surface::Solid,
    Surface::ActivityPub,
    Surface::Mastodon,
    Surface::Xrpc,
];

/// How a surface answers "may this agent do this?".
///
/// Every arm is deliberately identical. If a future adapter needs a different
/// answer, that difference belongs in an *additional* filter layered on top —
/// never in a replacement for this call.
fn surface_allows(
    _surface: Surface,
    store: &impl PodRead,
    path: &str,
    agent: &Agent,
    mode: AccessMode,
) -> bool {
    let Some(acl) = effective_acl(store, BASE, path).expect("effective acl") else {
        return false; // no ACL anywhere means no grant
    };
    authorize(store, &acl, agent, mode).expect("authorize")
}

fn fixture() -> (StoreManager, tempfile::TempDir, std::sync::Arc<Pod>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mgr = StoreManager::open(dir.path(), 4, 60).expect("manager");
    let store = mgr.pod(Uuid::new_v4()).expect("pod");

    let authorization = |g: &str, fragment: &str, pairs: &[(&str, String)]| -> Vec<Quad> {
        let a = format!("{g}#{fragment}");
        pairs
            .iter()
            .map(|(p, o)| t(g, &a, &format!("{ACL}{p}"), o))
            .collect()
    };
    let mut acls: Vec<(String, Vec<Quad>)> = Vec::new();

    // /~/public.acl — public read.
    let g = format!("{ROOT}public.acl");
    let quads = authorization(
        &g,
        "public",
        &[
            ("accessTo", format!("{ROOT}public")),
            ("mode", format!("{ACL}Read")),
            ("agentClass", format!("{FOAF}Agent")),
        ],
    );
    acls.push((g, quads));

    // /~/members.acl — any authenticated agent may read.
    let g = format!("{ROOT}members.acl");
    let quads = authorization(
        &g,
        "members",
        &[
            ("accessTo", format!("{ROOT}members")),
            ("mode", format!("{ACL}Read")),
            ("agentClass", format!("{ACL}AuthenticatedAgent")),
        ],
    );
    acls.push((g, quads));

    // /~/bob-only.acl — one specific WebID, read + write.
    let g = format!("{ROOT}bob-only.acl");
    let quads = authorization(
        &g,
        "bob",
        &[
            ("accessTo", format!("{ROOT}bob-only")),
            ("mode", format!("{ACL}Read")),
            ("mode", format!("{ACL}Write")),
            ("agent", "https://bob.example/profile#me".to_string()),
        ],
    );
    acls.push((g, quads));

    // /~/friends.acl — group access. The group is `groups/inner#g`, so its
    // document — the graph a server dereferences the group IRI to — is
    // `groups/inner`. Membership is read from there and nowhere else: a
    // `vcard:hasMember` triple for the same group IRI written into some other
    // graph is not membership, or else Append on any resource in the pod
    // would be enough to join every group its ACLs name.
    let g = format!("{ROOT}friends.acl");
    let quads = authorization(
        &g,
        "friends",
        &[
            ("accessTo", format!("{ROOT}friends")),
            ("mode", format!("{ACL}Read")),
            ("agentGroup", format!("{ROOT}groups/inner#g")),
        ],
    );
    acls.push((g, quads));

    let group_doc = format!("{ROOT}groups/inner");
    let group = [t(
        &group_doc,
        &format!("{ROOT}groups/inner#g"),
        &format!("{VCARD}hasMember"),
        "https://carol.example/profile#me",
    )];
    // The planted claim: dave, naming himself a member of the same group, in
    // a graph the group IRI does not name.
    let planted_doc = format!("{ROOT}groups/somewhere-else");
    let planted = [t(
        &planted_doc,
        &format!("{ROOT}groups/inner#g"),
        &format!("{VCARD}hasMember"),
        "https://dave.example/profile#me",
    )];

    // /~/notes/.acl — inherited default: authenticated append on the container.
    let g = format!("{ROOT}notes/.acl");
    let quads = authorization(
        &g,
        "inherit",
        &[
            ("default", format!("{ROOT}notes/")),
            ("mode", format!("{ACL}Write")),
            ("agentClass", format!("{ACL}AuthenticatedAgent")),
        ],
    );
    acls.push((g, quads));

    store
        .write(|w| {
            w.create_root(ROOT)?;
            for (acl, quads) in &acls {
                w.put(acl, Content::Auxiliary(quads))?;
            }
            w.put(&group_doc, Content::Rdf(&group))?;
            w.put(&planted_doc, Content::Rdf(&planted))?;
            Ok(())
        })
        .expect("seed acls");
    (mgr, dir, store)
}

struct Case {
    path: &'static str,
    agent: Agent,
    mode: AccessMode,
    expect: bool,
    why: &'static str,
}

fn matrix() -> Vec<Case> {
    let bob = || Agent::Authenticated("https://bob.example/profile#me".to_string());
    let carol = || Agent::Authenticated("https://carol.example/profile#me".to_string());
    let dave = || Agent::Authenticated("https://dave.example/profile#me".to_string());

    vec![
        Case {
            path: "/~/public",
            agent: Agent::Anonymous,
            mode: AccessMode::Read,
            expect: true,
            why: "foaf:Agent grants anonymous read",
        },
        Case {
            path: "/~/public",
            agent: Agent::Anonymous,
            mode: AccessMode::Write,
            expect: false,
            why: "public read does not imply write",
        },
        Case {
            path: "/~/members",
            agent: Agent::Anonymous,
            mode: AccessMode::Read,
            expect: false,
            why: "AuthenticatedAgent must not match anonymous",
        },
        Case {
            path: "/~/members",
            agent: dave(),
            mode: AccessMode::Read,
            expect: true,
            why: "any authenticated agent matches AuthenticatedAgent",
        },
        Case {
            path: "/~/bob-only",
            agent: bob(),
            mode: AccessMode::Read,
            expect: true,
            why: "acl:agent names bob",
        },
        Case {
            path: "/~/bob-only",
            agent: dave(),
            mode: AccessMode::Read,
            expect: false,
            why: "a different WebID must not match",
        },
        Case {
            path: "/~/bob-only",
            agent: bob(),
            mode: AccessMode::Append,
            expect: true,
            why: "acl:Write implies acl:Append",
        },
        Case {
            path: "/~/friends",
            agent: carol(),
            mode: AccessMode::Read,
            expect: true,
            why: "vcard:hasMember in the group's own document is membership",
        },
        Case {
            path: "/~/friends",
            agent: dave(),
            mode: AccessMode::Read,
            expect: false,
            why: "a hasMember triple planted in some other graph is not membership",
        },
        Case {
            path: "/~/notes/first",
            agent: dave(),
            mode: AccessMode::Append,
            expect: true,
            why: "acl:default on the container is inherited, and Write implies Append",
        },
        Case {
            path: "/~/notes/first",
            agent: Agent::Anonymous,
            mode: AccessMode::Append,
            expect: false,
            why: "inherited authenticated grant must not reach anonymous",
        },
        Case {
            path: "/~/nothing-here",
            agent: dave(),
            mode: AccessMode::Read,
            expect: false,
            why: "no ACL anywhere in the hierarchy means no grant",
        },
    ]
}

#[test]
fn every_surface_reaches_the_same_verdict() {
    let (_mgr, _dir, store) = fixture();

    for case in matrix() {
        let verdicts: Vec<(Surface, bool)> = SURFACES
            .iter()
            .map(|s| {
                (
                    *s,
                    surface_allows(*s, &store.read_store(), case.path, &case.agent, case.mode),
                )
            })
            .collect();

        for (surface, got) in &verdicts {
            assert_eq!(
                *got, case.expect,
                "{surface:?} on {} as {:?} for {:?}: expected {} — {}",
                case.path, case.agent, case.mode, case.expect, case.why
            );
        }

        let first = verdicts[0].1;
        assert!(
            verdicts.iter().all(|(_, v)| *v == first),
            "surfaces disagreed on {} — authorization must not depend on the door: {verdicts:?}",
            case.path
        );
    }
}

#[test]
fn direct_acl_wins_over_inherited() {
    let (_mgr, _dir, store) = fixture();

    // /notes/first has no ACL of its own, so it inherits /notes/.acl.
    let acl = effective_acl(&store.read_store(), BASE, "/~/notes/first")
        .unwrap()
        .unwrap();
    assert_eq!(acl.graph.as_str(), format!("{ROOT}notes/.acl"));
    assert!(!acl.direct, "an inherited ACL matches acl:default");
    assert_eq!(
        acl.scope.as_str(),
        format!("{ROOT}notes/"),
        "an inherited ACL scopes to the container, not the requested resource"
    );

    // /public has its own.
    let acl = effective_acl(&store.read_store(), BASE, "/~/public")
        .unwrap()
        .unwrap();
    assert_eq!(acl.graph.as_str(), format!("{ROOT}public.acl"));
    assert!(acl.direct, "a resource's own ACL matches acl:accessTo");
}

#[test]
fn an_accessto_grant_does_not_leak_through_inheritance() {
    let (_mgr, _dir, store) = fixture();

    // /public.acl grants via acl:accessTo. Treat it as if it had been found by
    // inheritance and the grant must not apply — accessTo and default are
    // distinct scopes, and conflating them is how ACLs silently over-grant.
    let as_inherited = EffectiveAcl {
        graph: n(&format!("{ROOT}public.acl")),
        direct: false,
        scope: n(&format!("{ROOT}public")),
    };
    let allowed = authorize(
        &store.read_store(),
        &as_inherited,
        &Agent::Anonymous,
        AccessMode::Read,
    )
    .unwrap();
    assert!(
        !allowed,
        "acl:accessTo must not satisfy an acl:default lookup"
    );
}

/// A reader inside a write sees that write's own changes. Commit 2 checks WAC
/// inside the transaction a PUT is about to change, so this is what it relies
/// on. The ACL goes in as a resource, not raw quads, so the test holds once
/// ACLs exist by metadata too.
#[test]
fn an_acl_written_earlier_in_the_same_write_governs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mgr = StoreManager::open(dir.path(), 4, 60).expect("manager");
    let pod = mgr.pod(Uuid::new_v4()).expect("pod");

    let g = format!("{ROOT}draft.acl");
    let a = format!("{g}#public");
    let acl = [
        t(&g, &a, &format!("{ACL}accessTo"), &format!("{ROOT}draft")),
        t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")),
        t(&g, &a, &format!("{ACL}agentClass"), &format!("{FOAF}Agent")),
    ];

    let (found, allowed) = pod
        .write(|w| {
            w.create_root(ROOT)?;
            w.put(&g, Content::Auxiliary(&acl))?;
            let governing = effective_acl(&*w, BASE, "/~/draft")
                .expect("effective acl")
                .expect("an ACL governs /~/draft");
            let allowed =
                authorize(&*w, &governing, &Agent::Anonymous, AccessMode::Read).expect("authorize");
            Ok((governing.graph.as_str().to_string(), allowed))
        })
        .expect("write");

    assert_eq!(found, g, "the reader missed the write's own ACL");
    assert!(allowed, "the ACL written in this write didn't grant");
}

#[test]
fn an_empty_recorded_acl_governs_and_grants_nothing() {
    let (_mgr, _dir, store) = fixture();
    let locked = format!("{ROOT}notes/locked.acl");
    store
        .write(|w| w.put(&locked, Content::Auxiliary(&[])).map(|_| ()))
        .expect("record an empty ACL");

    let reader = store.read_store();
    let acl = effective_acl(&reader, BASE, "/~/notes/locked")
        .unwrap()
        .expect("the empty ACL governs");
    assert_eq!(acl.graph.as_str(), locked);
    assert!(acl.direct);
    let dave = Agent::Authenticated("https://dave.example/profile#me".to_string());
    assert!(
        !authorize(&reader, &acl, &dave, AccessMode::Append).unwrap(),
        "an empty ACL grants nothing, whatever the container's default says"
    );
    // Its sibling still inherits the container's.
    assert!(surface_allows(
        Surface::Solid,
        &reader,
        "/~/notes/first",
        &dave,
        AccessMode::Append
    ));
}

/// The candidate list is spliced into the query as IRI terms, so each
/// candidate must *be* an IRI — checked here, in the crate that builds the
/// query, not promised by whoever called it. A path that cannot be an IRI is
/// its own error, raised before any query is built: not a parse failure from
/// the engine with the caller's text inside it.
#[test]
fn a_path_that_is_not_an_iri_is_refused_before_the_query() {
    let (_mgr, _dir, store) = fixture();

    let result = effective_acl(&store.read_store(), BASE, "/~/a> } }");

    assert!(
        matches!(result, Err(AuthzError::NotAnIri(_))),
        "expected NotAnIri, got {result:?}"
    );
}
