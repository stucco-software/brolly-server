//! Content-addressed blob storage, per pod.
//!
//! Bytes live beside the pod rather than inside the graph (plan §2.2): an
//! Oxigraph store is a triple store, and putting a 4 MB image in it as a
//! base64 literal is how the predecessor's pods became unqueryable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_store::StoreManager;
use uuid::Uuid;

fn manager() -> (tempfile::TempDir, StoreManager) {
    let dir = tempfile::tempdir().unwrap();
    let manager = StoreManager::open(dir.path(), 4, 60).unwrap();
    (dir, manager)
}

#[test]
fn a_blob_round_trips() {
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    let blobs = manager.blobs(user).unwrap();

    let digest = blobs.put(b"\x89PNG\r\n\x1a\n not really a png").unwrap();
    assert_eq!(
        blobs.get(&digest).unwrap().as_deref(),
        Some(&b"\x89PNG\r\n\x1a\n not really a png"[..])
    );
}

#[test]
fn identical_bytes_are_stored_once() {
    // Content addressing is the point: an avatar re-uploaded unchanged, or the
    // same file saved to two paths, costs one copy.
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    let blobs = manager.blobs(user).unwrap();

    let first = blobs.put(b"the same bytes").unwrap();
    let second = blobs.put(b"the same bytes").unwrap();
    assert_eq!(first, second);

    let different = blobs.put(b"other bytes").unwrap();
    assert_ne!(first, different);
}

#[test]
fn a_missing_blob_is_absent_rather_than_an_error() {
    let (_dir, manager) = manager();
    let blobs = manager.blobs(Uuid::new_v4()).unwrap();
    let absent = "0".repeat(64);
    assert!(blobs.get(&absent).unwrap().is_none());
}

#[test]
fn a_digest_that_is_not_a_digest_cannot_escape_the_blob_directory() {
    // The digest reaches this from a stored triple, and a pod's triples are
    // writable by any app the member has authorised. It is untrusted input.
    let (_dir, manager) = manager();
    let blobs = manager.blobs(Uuid::new_v4()).unwrap();

    for hostile in [
        "../../../../etc/passwd",
        "..",
        "/etc/passwd",
        "abc/../../secret",
        "",
        // Right length, wrong alphabet.
        &"z".repeat(64),
    ] {
        assert!(
            blobs.get(hostile).unwrap().is_none(),
            "{hostile} must not resolve to a file"
        );
        assert!(blobs.remove(hostile).is_err(), "{hostile} must not delete");
    }
}

#[test]
fn removing_a_blob_removes_the_bytes() {
    let (_dir, manager) = manager();
    let blobs = manager.blobs(Uuid::new_v4()).unwrap();

    let digest = blobs.put(b"transient").unwrap();
    blobs.remove(&digest).unwrap();
    assert!(blobs.get(&digest).unwrap().is_none());
}

#[test]
fn removing_a_blob_that_is_already_gone_is_not_an_error() {
    // Delete is idempotent because a resource and its bytes are removed in two
    // steps, and a retry after a crash between them must converge.
    let (_dir, manager) = manager();
    let blobs = manager.blobs(Uuid::new_v4()).unwrap();
    let digest = blobs.put(b"transient").unwrap();

    blobs.remove(&digest).unwrap();
    blobs.remove(&digest).unwrap();
}

#[test]
fn one_users_blobs_are_invisible_to_another() {
    // D2's physical isolation has to hold for bytes too, not just triples.
    let (_dir, manager) = manager();
    let alice = manager.blobs(Uuid::new_v4()).unwrap();
    let bob = manager.blobs(Uuid::new_v4()).unwrap();

    let digest = alice.put(b"alice's private image").unwrap();
    assert!(
        bob.get(&digest).unwrap().is_none(),
        "a digest is guessable from the content; it must not be a capability across pods"
    );
}

#[test]
fn blob_bytes_count_towards_the_pod_quota() {
    // `pod_bytes` sizes the quota. If it only measured triples, a member could
    // store unlimited media under a quota that never moved.
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    manager.pod(user).unwrap();
    let before = manager.pod_bytes(user).unwrap();

    manager
        .blobs(user)
        .unwrap()
        .put(&vec![0u8; 64 * 1024])
        .unwrap();

    let after = manager.pod_bytes(user).unwrap();
    assert!(
        after >= before + 64 * 1024,
        "expected the blob to be counted: {before} -> {after}"
    );
}

#[test]
fn deleting_a_pod_takes_its_blobs() {
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    manager.pod(user).unwrap();
    let digest = manager.blobs(user).unwrap().put(b"bytes").unwrap();

    manager.delete_pod(user).unwrap();

    assert!(
        manager.blobs(user).unwrap().get(&digest).unwrap().is_none(),
        "`rm -rf` on the pod directory is the whole delete story (D2)"
    );
}
