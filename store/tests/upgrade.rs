//! Old-layout pods upgrade themselves on first open (spec 5a, *Upgrading
//! existing pods*).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use brolly_domain::vocab;
use brolly_store::resources::{
    self, Kind, METADATA_GRAPH, Pod, PodRead, ResourceMeta, UpgradeOutcome,
};
use brolly_store::{Store, StoreManager};
use oxigraph::model::{
    GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode,
    NamedOrBlankNodeRef, Quad, Term, TermRef,
};
use uuid::Uuid;

const ROOT: &str = "https://alice.brolly.test/~/";
const MALLORY_ROOT: &str = "https://mallory.brolly.test/~/";
const PROFILE: &str = "https://alice.brolly.test/profile";
const TITLE: &str = "https://example.org/title";
const ALT: &str = "https://www.w3.org/ns/activitystreams#name";
const ACL_MODE: &str = "http://www.w3.org/ns/auth/acl#mode";
const ACL_READ: &str = "http://www.w3.org/ns/auth/acl#Read";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n pretend this is an image";

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// `<s> <p> <o>` in graph `g`.
fn iri(g: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(n(s), n(p), n(o), GraphName::NamedNode(n(g)))
}

/// `<s> <p> "o"` in graph `g`.
fn lit(g: &str, s: &str, p: &str, o: &str) -> Quad {
    Quad::new(
        n(s),
        n(p),
        Literal::new_simple_literal(o),
        GraphName::NamedNode(n(g)),
    )
}

/// The root as the old layout wrote it, before layout 2.
fn old_root(root: &str) -> Vec<Quad> {
    vec![
        iri(root, root, vocab::RDF_TYPE, vocab::LDP_BASIC_CONTAINER),
        iri(root, root, vocab::RDF_TYPE, vocab::LDP_RESOURCE),
        iri(root, root, vocab::RDF_TYPE, vocab::PIM_STORAGE),
    ]
}

/// A data directory holding one member's pod, written in the old layout
/// before any `StoreManager` opens it.
struct OldPod {
    dir: tempfile::TempDir,
    user: Uuid,
}

impl OldPod {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            user: Uuid::new_v4(),
        }
    }

    /// Where `StoreManager` keeps this member's graph (`users/<id>/rdf`). If
    /// that moved, these pods would open empty and every test here fails.
    fn rdf_dir(&self) -> PathBuf {
        self.dir
            .path()
            .join("users")
            .join(self.user.to_string())
            .join("rdf")
    }

    /// Write quads straight into the store, the way the old code left them.
    /// The raw store is dropped at the end, releasing RocksDB's lock.
    fn seed(&self, quads: &[Quad]) {
        std::fs::create_dir_all(self.rdf_dir()).unwrap();
        Store::open(self.rdf_dir())
            .unwrap()
            .extend(quads.iter().cloned())
            .unwrap();
    }

    /// Put bytes in this member's blob store, returning their digest.
    fn blob(&self, bytes: &[u8]) -> String {
        let stores = StoreManager::open(self.dir.path(), 4, 60).unwrap();
        stores.blobs(self.user).unwrap().put(bytes).unwrap()
    }

    /// Open the pod through a fresh manager, which upgrades it.
    fn open(&self) -> (StoreManager, Arc<Pod>) {
        let stores = StoreManager::open(self.dir.path(), 4, 60).unwrap();
        let pod = stores.pod(self.user).unwrap();
        (stores, pod)
    }
}

fn meta(pod: &Pod, resource: &str) -> Option<ResourceMeta> {
    pod.read(|r| r.meta(resource)).unwrap()
}

fn members(pod: &Pod, container: &str) -> Vec<String> {
    let mut members = pod.write(|w| w.members(container)).unwrap();
    members.sort();
    members
}

/// One graph's quads, through the public read path.
fn content(pod: &Pod, graph: &str) -> Vec<Quad> {
    pod.read_store()
        .quads_for_pattern(
            None,
            None,
            None,
            Some(GraphNameRef::NamedNode(n(graph).as_ref())),
        )
        .map(Result::unwrap)
        .collect()
}

/// Every quad in the pod, as sorted text, so "unchanged" compares content.
fn dump(pod: &Pod) -> Vec<String> {
    let mut all: Vec<String> = pod
        .read_store()
        .quads_for_pattern(None, None, None, None)
        .map(|q| q.unwrap().to_string())
        .collect();
    all.sort();
    all
}

fn is_marked(pod: &Pod) -> bool {
    let graph = NamedNodeRef::new_unchecked(METADATA_GRAPH);
    pod.read_store()
        .quads_for_pattern(
            Some(NamedOrBlankNodeRef::NamedNode(graph)),
            Some(NamedNodeRef::new_unchecked(vocab::BROLLY_LAYOUT)),
            None,
            Some(GraphNameRef::NamedNode(graph)),
        )
        .next()
        .is_some()
}

fn about(quad: &Quad, subject: &str) -> bool {
    matches!(&quad.subject, NamedOrBlankNode::NamedNode(s) if s.as_str() == subject)
}

fn names(quad: &Quad, object: &str) -> bool {
    matches!(&quad.object, Term::NamedNode(o) if o.as_str() == object)
}

// --- which pods it touches ------------------------------------------------

#[test]
fn an_empty_store_is_marked_at_once() {
    let old = OldPod::new();
    let (_stores, pod) = old.open();

    assert!(is_marked(&pod), "a new pod is layout 2 before provisioning");
    assert_eq!(resources::upgrade(&pod).unwrap(), UpgradeOutcome::Current);
    assert!(
        meta(&pod, ROOT).is_none(),
        "provisioning records the root, not the upgrade"
    );
}

#[test]
fn a_layout_2_pod_is_not_rescanned() {
    let old = OldPod::new();
    {
        let (_stores, pod) = old.open();
        pod.write(|w| w.create_root(ROOT)).unwrap();
    }
    // What an upgrade would record if it ran: a graph under the root that
    // nothing wrote through `put`.
    let stray = format!("{ROOT}stray");
    old.seed(&[lit(&stray, &stray, TITLE, "stray")]);

    let (_stores, pod) = old.open();
    assert_eq!(resources::upgrade(&pod).unwrap(), UpgradeOutcome::Current);
    assert!(meta(&pod, &stray).is_none(), "a layout 2 pod was rescanned");
    assert!(!members(&pod, ROOT).contains(&stray));
}

// --- a whole old-layout pod ---------------------------------------------------

/// Every shape the upgrade has to handle, in one pod. Returns the pod and the
/// digest of its one real blob.
fn old_layout_pod() -> (OldPod, String) {
    let old = OldPod::new();
    let digest = old.blob(PNG);
    let root_acl = format!("{ROOT}.acl");
    let notes = format!("{ROOT}notes/");
    let first = format!("{notes}first");
    let empty = format!("{notes}empty");
    let deep = format!("{ROOT}unlisted/deep/doc");
    let pic = format!("{ROOT}media/pic.png");

    let mut quads = old_root(ROOT);
    quads.extend([
        // The root lists a container and, from before stage 0, its own ACL.
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &notes),
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &root_acl),
        // A member's own triple about something else, in the root's graph.
        iri(
            ROOT,
            "https://example.org/a",
            vocab::LDP_CONTAINS,
            "https://example.org/b",
        ),
        iri(&root_acl, &format!("{root_acl}#owner"), ACL_MODE, ACL_READ),
        // A container with a title, listing a document and one whose graph is
        // empty (today's empty resources).
        iri(&notes, &notes, vocab::RDF_TYPE, vocab::LDP_BASIC_CONTAINER),
        iri(&notes, &notes, vocab::LDP_CONTAINS, &first),
        iri(&notes, &notes, vocab::LDP_CONTAINS, &empty),
        lit(&notes, &notes, TITLE, "Notes"),
        lit(&first, &first, TITLE, "First"),
        // Nobody lists this one, nor its two containers.
        lit(&deep, &deep, TITLE, "Deep"),
        // A binary as `ldp::put` wrote it, with alt text. Not listed either.
        iri(&pic, &pic, vocab::RDF_TYPE, vocab::LDP_NON_RDF_SOURCE),
        iri(&pic, &pic, vocab::RDF_TYPE, vocab::LDP_RESOURCE),
        lit(&pic, &pic, vocab::BROLLY_BLOB_DIGEST, &digest),
        lit(&pic, &pic, vocab::BROLLY_MEDIA_TYPE, "image/png"),
        Quad::new(
            n(&pic),
            n(vocab::BROLLY_BYTE_SIZE),
            Literal::new_typed_literal(PNG.len().to_string(), n(vocab::XSD_INTEGER)),
            GraphName::NamedNode(n(&pic)),
        ),
        lit(&pic, &pic, ALT, "a cat"),
        // Protocol state outside the root.
        lit(PROFILE, &format!("{PROFILE}#me"), TITLE, "Alice"),
    ]);
    old.seed(&quads);
    (old, digest)
}

#[test]
fn every_step_runs_on_an_old_layout_pod() {
    let (old, digest) = old_layout_pod();
    let (_stores, pod) = old.open();
    let root_acl = format!("{ROOT}.acl");
    let notes = format!("{ROOT}notes/");
    let pic = format!("{ROOT}media/pic.png");

    // The root, and what it contains: never its ACL.
    assert!(matches!(meta(&pod, ROOT).unwrap().kind, Kind::Container));
    assert_eq!(
        members(&pod, ROOT),
        vec![
            format!("{ROOT}media/"),
            notes.clone(),
            format!("{ROOT}unlisted/")
        ]
    );
    assert!(matches!(
        meta(&pod, &root_acl).unwrap().kind,
        Kind::Auxiliary
    ));

    // Listed members, including one rescued from an empty graph.
    assert_eq!(
        members(&pod, &notes),
        vec![format!("{notes}empty"), format!("{notes}first")]
    );
    let empty = meta(&pod, &format!("{notes}empty")).expect("the empty document exists");
    assert!(matches!(empty.kind, Kind::RdfSource));
    assert!(content(&pod, &format!("{notes}empty")).is_empty());

    // Unlisted resources, with their missing containers created.
    assert_eq!(
        members(&pod, &format!("{ROOT}unlisted/deep/")),
        vec![format!("{ROOT}unlisted/deep/doc")]
    );
    assert_eq!(
        members(&pod, &format!("{ROOT}unlisted/")),
        vec![format!("{ROOT}unlisted/deep/")]
    );

    // The binary: metadata, containment, and a graph holding only its alt text
    // (and the old type triples, which aren't blob triples).
    let pic_meta = meta(&pod, &pic).unwrap();
    assert!(matches!(pic_meta.kind, Kind::NonRdfSource));
    let blob = pic_meta.blob.expect("blob metadata");
    assert_eq!(blob.digest, digest);
    assert_eq!(blob.media_type, "image/png");
    assert_eq!(blob.byte_size, PNG.len() as u64);
    assert_eq!(members(&pod, &format!("{ROOT}media/")), vec![pic.clone()]);
    let pic_graph = content(&pod, &pic);
    assert!(
        pic_graph.iter().any(|q| q.predicate.as_str() == ALT),
        "alt text lost"
    );
    for blob_term in [
        vocab::BROLLY_BLOB_DIGEST,
        vocab::BROLLY_MEDIA_TYPE,
        vocab::BROLLY_BYTE_SIZE,
    ] {
        assert!(
            !pic_graph.iter().any(|q| q.predicate.as_str() == blob_term),
            "{blob_term} left in the binary's graph"
        );
    }

    // Stripping is subject-scoped: the server's triples about the container go,
    // a member's triple about something else stays.
    let root_graph = content(&pod, ROOT);
    assert!(!root_graph.iter().any(|q| about(q, ROOT)
        && (q.predicate.as_str() == vocab::LDP_CONTAINS
            || names(q, vocab::LDP_BASIC_CONTAINER)
            || names(q, vocab::PIM_STORAGE))));
    assert!(root_graph.iter().any(|q| about(q, "https://example.org/a")));
    let notes_graph = content(&pod, &notes);
    assert_eq!(
        notes_graph.len(),
        1,
        "only the title stays: {notes_graph:?}"
    );

    // Everything recorded has a version and a modified time.
    for resource in [
        ROOT.to_string(),
        root_acl,
        notes.clone(),
        format!("{notes}first"),
        format!("{ROOT}unlisted/"),
        format!("{ROOT}unlisted/deep/"),
        format!("{ROOT}unlisted/deep/doc"),
        pic,
    ] {
        let m = meta(&pod, &resource).unwrap_or_else(|| panic!("{resource} not recorded"));
        assert!(!m.version.is_empty(), "{resource} has no version");
        assert!(!m.modified.is_empty(), "{resource} has no modified time");
    }

    // Outside the root: skipped, and untouched.
    assert!(meta(&pod, PROFILE).is_none());
    assert_eq!(content(&pod, PROFILE).len(), 1);
    assert!(is_marked(&pod));
}

#[test]
fn after_the_upgrade_no_container_graph_holds_ldp_contains() {
    let (old, _) = old_layout_pod();
    let (_stores, pod) = old.open();
    let leftovers: Vec<Quad> = pod
        .read_store()
        .quads_for_pattern(None, Some(n(vocab::LDP_CONTAINS).as_ref()), None, None)
        .map(Result::unwrap)
        .filter(|q| {
            matches!((&q.subject, &q.graph_name),
                (NamedOrBlankNode::NamedNode(s), GraphName::NamedNode(g)) if s == g)
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "containment left in content: {leftovers:?}"
    );
}

#[test]
fn a_second_run_changes_nothing() {
    let (old, _) = old_layout_pod();
    let before = {
        let (_stores, pod) = old.open();
        let before = dump(&pod);
        assert_eq!(resources::upgrade(&pod).unwrap(), UpgradeOutcome::Current);
        assert_eq!(dump(&pod), before, "a second run in the same process");
        before
    };
    let (_stores, pod) = old.open();
    assert_eq!(dump(&pod), before, "a reopen upgraded again");
}

// --- forgeries ------------------------------------------------------------------

#[test]
fn forged_containment_is_dropped() {
    let old = OldPod::new();
    let a = format!("{ROOT}a/");
    let mut quads = old_root(ROOT);
    quads.extend([
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, "https://mallory.example/x"), // foreign
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &format!("{ROOT}a/b")),       // a grandchild
        iri(ROOT, ROOT, vocab::LDP_CONTAINS, &a),                          // fine
        iri(&a, &a, vocab::LDP_CONTAINS, &format!("{ROOT}sibling")),       // not a's child
        iri(&a, &a, vocab::LDP_CONTAINS, &format!("{ROOT}a/.acl")),        // an ACL
    ]);
    old.seed(&quads);

    let (_stores, pod) = old.open();
    assert_eq!(members(&pod, ROOT), vec![a.clone()]);
    assert!(members(&pod, &a).is_empty());
    for forged in [
        "https://mallory.example/x".to_string(),
        format!("{ROOT}a/b"),
        format!("{ROOT}sibling"),
        format!("{ROOT}a/.acl"),
    ] {
        assert!(meta(&pod, &forged).is_none(), "{forged} was recorded");
    }
}

#[test]
fn forged_blob_digests_are_not_binaries() {
    let old = OldPod::new();
    let real = old.blob(PNG);
    let elsewhere = format!("{ROOT}elsewhere");
    let not_a_digest = format!("{ROOT}not-a-digest");
    let no_file = format!("{ROOT}no-file");
    let mut quads = old_root(ROOT);
    quads.extend([
        // A real digest, but about another subject than the graph.
        lit(
            &elsewhere,
            "https://example.org/x",
            vocab::BROLLY_BLOB_DIGEST,
            &real,
        ),
        lit(
            &not_a_digest,
            &not_a_digest,
            vocab::BROLLY_BLOB_DIGEST,
            "../../../etc/passwd",
        ),
        lit(
            &no_file,
            &no_file,
            vocab::BROLLY_BLOB_DIGEST,
            &"ab".repeat(32),
        ),
    ]);
    old.seed(&quads);

    let (_stores, pod) = old.open();
    for doc in [&elsewhere, &not_a_digest, &no_file] {
        let m = meta(&pod, doc).unwrap_or_else(|| panic!("{doc} not recorded"));
        assert!(matches!(m.kind, Kind::RdfSource), "{doc} became a binary");
        assert!(m.blob.is_none());
        assert!(
            content(&pod, doc)
                .iter()
                .any(|q| q.predicate.as_str() == vocab::BROLLY_BLOB_DIGEST),
            "{doc}'s digest triple should stay, as data"
        );
    }
}

#[test]
fn a_planted_storage_type_is_not_a_second_root() {
    let old = OldPod::new();
    let doc = format!("{ROOT}app/doc");
    let mut quads = old_root(ROOT);
    quads.push(iri(&doc, &doc, vocab::RDF_TYPE, vocab::PIM_STORAGE));
    old.seed(&quads);

    let (_stores, pod) = old.open();
    assert!(matches!(meta(&pod, &doc).unwrap().kind, Kind::RdfSource));
    let roots: Vec<String> = pod
        .read_store()
        .quads_for_pattern(
            None,
            Some(n(vocab::RDF_TYPE).as_ref()),
            Some(TermRef::NamedNode(n(vocab::PIM_STORAGE).as_ref())),
            Some(GraphNameRef::NamedNode(NamedNodeRef::new_unchecked(
                METADATA_GRAPH,
            ))),
        )
        .map(|q| q.unwrap().subject.to_string())
        .collect();
    assert_eq!(roots, vec![format!("<{ROOT}>")]);
    assert_eq!(
        content(&pod, &doc).len(),
        1,
        "the member's triple stays as data"
    );
}

#[test]
fn a_pod_with_no_root_is_left_unmarked() {
    let old = OldPod::new();
    let doc = format!("{ROOT}orphan");
    old.seed(&[lit(&doc, &doc, TITLE, "orphan")]);
    let (_stores, pod) = old.open();
    assert!(!is_marked(&pod));
    assert!(meta(&pod, &doc).is_none());
    assert_eq!(
        resources::upgrade(&pod).unwrap(),
        UpgradeOutcome::NoRoot {
            candidates: Vec::new()
        }
    );

    // Two candidates, on different hosts: no root either.
    let old = OldPod::new();
    old.seed(&[old_root(ROOT), old_root(MALLORY_ROOT)].concat());
    let (_stores, pod) = old.open();
    assert!(!is_marked(&pod));
    assert_eq!(
        resources::upgrade(&pod).unwrap(),
        UpgradeOutcome::NoRoot {
            candidates: vec![ROOT.to_string(), MALLORY_ROOT.to_string()]
        }
    );
}

/// A pod that got a graph before it was provisioned opens unmarked (no root
/// anywhere yet). Provisioning then records the root in metadata only, so the
/// next open finds a layout 2 root and marks the pod, rather than looking for
/// an old-layout root that was never written and logging it missing.
#[test]
fn an_unmarked_pod_with_a_recorded_root_is_marked() {
    let old = OldPod::new();
    old.seed(&[lit(PROFILE, PROFILE, TITLE, "written before provisioning")]);
    {
        let (_stores, pod) = old.open();
        assert!(!is_marked(&pod), "setup: no root yet, so unmarked");
        pod.write(|w| w.create_root(ROOT)).unwrap();
    }

    let (_stores, pod) = old.open();
    assert!(
        is_marked(&pod),
        "a pod with a recorded root stayed unmarked"
    );
    assert_eq!(resources::upgrade(&pod).unwrap(), UpgradeOutcome::Current);
    assert_eq!(meta(&pod, ROOT).map(|m| m.kind), Some(Kind::Container));
    assert_eq!(
        content(&pod, PROFILE).len(),
        1,
        "marking changes nothing else"
    );
}
