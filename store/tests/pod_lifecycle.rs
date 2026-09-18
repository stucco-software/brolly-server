//! A pod is one RocksDB database, and RocksDB lets one process open a
//! directory once. The cache must never ask for a second open while the first
//! handle is alive.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use brolly_store::StoreManager;
use uuid::Uuid;

/// Let every cached pod go idle and be evicted. Idle expiry, not capacity:
/// moka's admission policy may refuse a newcomer rather than evict, so a full
/// cache doesn't reliably push anything out.
fn idle_out(stores: &StoreManager) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(stores.open_pods(), 0, "setup: the cache still holds a pod");
}

#[test]
fn a_pod_evicted_while_in_use_is_handed_back_rather_than_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let stores = StoreManager::open(dir.path(), 8, 1).unwrap();
    let alice = Uuid::new_v4();

    // A request is still holding alice's pod when the cache lets it go.
    let held = stores.pod(alice).unwrap();
    idle_out(&stores);

    // The next request for alice must get the live handle, not a second open
    // that RocksDB refuses because the first still holds the lock.
    let again = stores
        .pod(alice)
        .expect("a live pod was reopened and the lock refused it");
    assert!(Arc::ptr_eq(&held, &again), "two handles on one database");
}

#[test]
fn concurrent_first_opens_of_one_pod_share_a_handle() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Arc::new(StoreManager::open(dir.path(), 8, 60).unwrap());
    let alice = Uuid::new_v4();

    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let stores = Arc::clone(&stores);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                stores.pod(alice)
            })
        })
        .collect();

    let pods: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().expect("a concurrent open was refused"))
        .collect();
    assert!(
        pods.windows(2).all(|w| Arc::ptr_eq(&w[0], &w[1])),
        "concurrent requests opened the database more than once"
    );
}

#[test]
fn a_pod_nobody_holds_can_be_evicted_and_reopened() {
    // Nobody holds it, so it may have been closed. Either way a later request
    // has to get it back.
    let dir = tempfile::tempdir().unwrap();
    let stores = StoreManager::open(dir.path(), 8, 1).unwrap();
    let alice = Uuid::new_v4();

    drop(stores.pod(alice).unwrap());
    idle_out(&stores);

    stores.pod(alice).expect("reopening an evicted pod");
}
