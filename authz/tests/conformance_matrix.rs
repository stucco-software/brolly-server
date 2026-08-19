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

use brolly_authz::{AccessMode, Agent, EffectiveAcl, authorize, effective_acl};
use brolly_store::{StoreManager, insert_quads};
use oxigraph::model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use uuid::Uuid;

const BASE: &str = "https://alice.brolly.id";
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
    store: &oxigraph::store::Store,
    path: &str,
    agent: &Agent,
    mode: AccessMode,
) -> bool {
    let Some(acl) = effective_acl(store, BASE, path).expect("effective acl") else {
        return false; // no ACL anywhere means no grant
    };
    authorize(store, &acl, agent, mode).expect("authorize")
}

fn fixture() -> (
    StoreManager,
    tempfile::TempDir,
    std::sync::Arc<oxigraph::store::Store>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mgr = StoreManager::open(dir.path(), 4, 60).expect("manager");
    let store = mgr.pod(Uuid::new_v4()).expect("pod");

    let mut quads = Vec::new();

    // /public.acl — public read.
    let g = format!("{BASE}/public.acl");
    let a = format!("{g}#public");
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}accessTo"),
        &format!("{BASE}/public"),
    ));
    quads.push(t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")));
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}agentClass"),
        &format!("{FOAF}Agent"),
    ));

    // /members.acl — any authenticated agent may read.
    let g = format!("{BASE}/members.acl");
    let a = format!("{g}#members");
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}accessTo"),
        &format!("{BASE}/members"),
    ));
    quads.push(t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")));
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}agentClass"),
        &format!("{ACL}AuthenticatedAgent"),
    ));

    // /bob-only.acl — one specific WebID, read + write.
    let g = format!("{BASE}/bob-only.acl");
    let a = format!("{g}#bob");
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}accessTo"),
        &format!("{BASE}/bob-only"),
    ));
    quads.push(t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")));
    quads.push(t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")));
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}agent"),
        "https://bob.example/profile#me",
    ));

    // /friends.acl — group access. The group document lives at a graph the ACL
    // does not name, which is what the predecessor's fragment-stripping assumed.
    let g = format!("{BASE}/friends.acl");
    let a = format!("{g}#friends");
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}accessTo"),
        &format!("{BASE}/friends"),
    ));
    quads.push(t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Read")));
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}agentGroup"),
        &format!("{BASE}/groups/inner#g"),
    ));

    let g = format!("{BASE}/groups/somewhere-else");
    quads.push(t(
        &g,
        &format!("{BASE}/groups/inner#g"),
        &format!("{VCARD}hasMember"),
        "https://carol.example/profile#me",
    ));

    // /notes/.acl — inherited default: authenticated append on the container.
    let g = format!("{BASE}/notes/.acl");
    let a = format!("{g}#inherit");
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}default"),
        &format!("{BASE}/notes/"),
    ));
    quads.push(t(&g, &a, &format!("{ACL}mode"), &format!("{ACL}Write")));
    quads.push(t(
        &g,
        &a,
        &format!("{ACL}agentClass"),
        &format!("{ACL}AuthenticatedAgent"),
    ));

    insert_quads(&store, &quads).expect("seed acls");
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
            path: "/public",
            agent: Agent::Anonymous,
            mode: AccessMode::Read,
            expect: true,
            why: "foaf:Agent grants anonymous read",
        },
        Case {
            path: "/public",
            agent: Agent::Anonymous,
            mode: AccessMode::Write,
            expect: false,
            why: "public read does not imply write",
        },
        Case {
            path: "/members",
            agent: Agent::Anonymous,
            mode: AccessMode::Read,
            expect: false,
            why: "AuthenticatedAgent must not match anonymous",
        },
        Case {
            path: "/members",
            agent: dave(),
            mode: AccessMode::Read,
            expect: true,
            why: "any authenticated agent matches AuthenticatedAgent",
        },
        Case {
            path: "/bob-only",
            agent: bob(),
            mode: AccessMode::Read,
            expect: true,
            why: "acl:agent names bob",
        },
        Case {
            path: "/bob-only",
            agent: dave(),
            mode: AccessMode::Read,
            expect: false,
            why: "a different WebID must not match",
        },
        Case {
            path: "/bob-only",
            agent: bob(),
            mode: AccessMode::Append,
            expect: true,
            why: "acl:Write implies acl:Append",
        },
        Case {
            path: "/friends",
            agent: carol(),
            mode: AccessMode::Read,
            expect: true,
            why: "vcard:hasMember in another graph still joins",
        },
        Case {
            path: "/friends",
            agent: dave(),
            mode: AccessMode::Read,
            expect: false,
            why: "non-members must not match the group",
        },
        Case {
            path: "/notes/first",
            agent: dave(),
            mode: AccessMode::Append,
            expect: true,
            why: "acl:default on the container is inherited, and Write implies Append",
        },
        Case {
            path: "/notes/first",
            agent: Agent::Anonymous,
            mode: AccessMode::Append,
            expect: false,
            why: "inherited authenticated grant must not reach anonymous",
        },
        Case {
            path: "/nothing-here",
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
                    surface_allows(*s, &store, case.path, &case.agent, case.mode),
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
    let acl = effective_acl(&store, BASE, "/notes/first")
        .unwrap()
        .unwrap();
    assert_eq!(acl.graph.as_str(), format!("{BASE}/notes/.acl"));
    assert!(!acl.direct, "an inherited ACL matches acl:default");
    assert_eq!(
        acl.scope.as_str(),
        format!("{BASE}/notes/"),
        "an inherited ACL scopes to the container, not the requested resource"
    );

    // /public has its own.
    let acl = effective_acl(&store, BASE, "/public").unwrap().unwrap();
    assert_eq!(acl.graph.as_str(), format!("{BASE}/public.acl"));
    assert!(acl.direct, "a resource's own ACL matches acl:accessTo");
}

#[test]
fn an_accessto_grant_does_not_leak_through_inheritance() {
    let (_mgr, _dir, store) = fixture();

    // /public.acl grants via acl:accessTo. Treat it as if it had been found by
    // inheritance and the grant must not apply — accessTo and default are
    // distinct scopes, and conflating them is how ACLs silently over-grant.
    let as_inherited = EffectiveAcl {
        graph: n(&format!("{BASE}/public.acl")),
        direct: false,
        scope: n(&format!("{BASE}/public")),
    };
    let allowed = authorize(&store, &as_inherited, &Agent::Anonymous, AccessMode::Read).unwrap();
    assert!(
        !allowed,
        "acl:accessTo must not satisfy an acl:default lookup"
    );
}
