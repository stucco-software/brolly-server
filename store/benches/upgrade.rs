//! How long the layout-2 upgrade holds a pod's first open (spec 5a, *Cost*).
//!
//! `cargo bench -p brolly-store --bench upgrade`. Builds old-layout pods of
//! growing size, then times the first `StoreManager::pod`, which upgrades, and
//! a reopen, which only reads the layout mark. A report, not a gate: nothing
//! here fails on a number.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::time::{Duration, Instant};

use brolly_domain::vocab;
use brolly_store::{Store, StoreManager};
use oxigraph::model::{GraphName, Literal, NamedNode, Quad};
use uuid::Uuid;

const ROOT: &str = "https://alice.brolly.test/~/";
const CONTAINERS: usize = 10;
const TRIPLES_PER_DOCUMENT: usize = 5;

fn n(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

/// An old-layout pod: the root, `CONTAINERS` listed containers, and
/// `documents` listed documents spread across them.
fn old_pod(documents: usize) -> Vec<Quad> {
    let g = |iri: &str| GraphName::NamedNode(n(iri));
    let mut quads = vec![
        Quad::new(
            n(ROOT),
            n(vocab::RDF_TYPE),
            n(vocab::LDP_BASIC_CONTAINER),
            g(ROOT),
        ),
        Quad::new(n(ROOT), n(vocab::RDF_TYPE), n(vocab::PIM_STORAGE), g(ROOT)),
    ];
    for c in 0..CONTAINERS {
        let container = format!("{ROOT}c{c}/");
        quads.push(Quad::new(
            n(ROOT),
            n(vocab::LDP_CONTAINS),
            n(&container),
            g(ROOT),
        ));
        quads.push(Quad::new(
            n(&container),
            n(vocab::RDF_TYPE),
            n(vocab::LDP_BASIC_CONTAINER),
            g(&container),
        ));
    }
    for d in 0..documents {
        let container = format!("{ROOT}c{}/", d % CONTAINERS);
        let doc = format!("{container}d{d}");
        quads.push(Quad::new(
            n(&container),
            n(vocab::LDP_CONTAINS),
            n(&doc),
            g(&container),
        ));
        for t in 0..TRIPLES_PER_DOCUMENT {
            quads.push(Quad::new(
                n(&doc),
                n(&format!("https://example.org/p{t}")),
                Literal::new_simple_literal(format!("value {t}")),
                g(&doc),
            ));
        }
    }
    quads
}

/// Open the pod through a fresh manager and time it.
fn timed_open(dir: &std::path::Path, user: Uuid) -> Duration {
    let stores = StoreManager::open(dir, 4, 60).unwrap();
    let started = Instant::now();
    stores.pod(user).unwrap();
    started.elapsed()
}

fn main() {
    println!("{:>10} {:>14} {:>14}", "documents", "first open", "reopen");
    for documents in [100, 1_000, 10_000] {
        let dir = tempfile::tempdir().unwrap();
        let user = Uuid::new_v4();
        let rdf = dir.path().join("users").join(user.to_string()).join("rdf");
        std::fs::create_dir_all(&rdf).unwrap();
        Store::open(&rdf)
            .unwrap()
            .extend(old_pod(documents))
            .unwrap();

        let first = timed_open(dir.path(), user);
        let reopen = timed_open(dir.path(), user);
        println!("{documents:>10} {first:>14.2?} {reopen:>14.2?}");
    }
}
