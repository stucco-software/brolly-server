//! Open decision O5 — what does one pod actually cost?
//!
//! The predecessor shipped an LRU of 500 open stores with a 1h idle timeout and
//! never validated either number. At thousands of users that ceiling is a real
//! budget line: every resident pod carries its own memtables and file handles.
//!
//! Run: `cargo run -p brolly-store --example store_budget --release`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::time::Instant;

use brolly_store::StoreManager;
use oxigraph::model::NamedNode;
use serde_json::json;
use uuid::Uuid;

const PODS: usize = 200;
const RECORDS_PER_POD: usize = 20;

fn main() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Ceiling above PODS so nothing is evicted mid-measurement.
    let mgr = StoreManager::open(dir.path(), 10_000, 3600).expect("manager");

    let users: Vec<Uuid> = (0..PODS).map(|_| Uuid::new_v4()).collect();

    let start = Instant::now();
    for user in &users {
        let pod = mgr.pod(*user).expect("open pod");
        for i in 0..RECORDS_PER_POD {
            let subject = NamedNode::new_unchecked(format!("https://u.brolly.id/notes/{i}"));
            let quads = brolly_domain::faithful::encode(
                &json!({"$type": "app.bsky.feed.post", "text": "benchmark record", "i": i}),
                &subject,
                &subject,
                "app.bsky.feed.post",
            )
            .expect("encode");
            pod.write(|w| w.insert(&quads)).expect("write");
        }
    }
    let create = start.elapsed();

    // RocksDB takes an exclusive per-directory process lock, so the first
    // manager must be dropped before a second can open the same tree. That is
    // also why one process owns the data directory (D1: single image, no
    // sidecar sharing files, no horizontal scale-out).
    drop(mgr);

    // Cold open: a fresh manager over the same directory, so nothing is cached.
    let cold = StoreManager::open(dir.path(), 10_000, 3600).expect("manager");
    let start = Instant::now();
    for user in &users {
        cold.pod(*user).expect("open pod");
    }
    let cold_open = start.elapsed();

    let start = Instant::now();
    for user in &users {
        cold.pod(*user).expect("cached pod");
    }
    let warm_open = start.elapsed();

    let bytes: u64 = users.iter().map(|u| cold.pod_bytes(*u).unwrap_or(0)).sum();

    println!("\nstore budget — {PODS} pods x {RECORDS_PER_POD} records\n");
    println!(
        "  create + write   {:>9.1?}  ({:>7.2?} per pod)",
        create,
        create / PODS as u32
    );
    println!(
        "  cold open        {:>9.1?}  ({:>7.2?} per pod)",
        cold_open,
        cold_open / PODS as u32
    );
    println!(
        "  warm (cached)    {:>9.1?}  ({:>7.2?} per pod)",
        warm_open,
        warm_open / PODS as u32
    );
    println!(
        "  disk             {:>9.1} MB ({:>7.1} KB per pod)",
        bytes as f64 / 1_048_576.0,
        bytes as f64 / PODS as f64 / 1024.0
    );
    println!("  resident pods    {}", cold.open_pods());
    println!();
    println!("  Read the cold-open number as the cost of an LRU miss, and the");
    println!("  per-pod disk number as the floor for capacity planning at the");
    println!("  thousands-of-users target (D16).\n");
}
