//! Content-addressed blob storage, per pod.
//!
//! Bytes live beside the pod rather than inside the graph (plan §2.2): an
//! Oxigraph store is a triple store, and putting a 4 MB image in it as a
//! base64 literal is how the predecessor's pods became unqueryable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

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

// --- atomic writes and temps (spec 4, H1 and H7) ---------------------------------

/// The blob fanout under a pod directory, and every file in it.
fn fanout_files(base: &Path, user: Uuid) -> Vec<(PathBuf, String)> {
    let blobs = base.join("users").join(user.to_string()).join("blobs");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&blobs).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() {
            continue;
        }
        for file in std::fs::read_dir(entry.path()).unwrap() {
            let file = file.unwrap();
            files.push((file.path(), file.file_name().to_str().unwrap().to_owned()));
        }
    }
    files
}

#[test]
fn a_put_leaves_no_temp_files_behind() {
    // H1's invariant from the outside: after a `put`, the fanout holds only
    // digest paths — the rename moved the temp onto the digest, so nothing
    // half-named survives a successful upload.
    let (dir, manager) = manager();
    let user = Uuid::new_v4();
    let blobs = manager.blobs(user).unwrap();

    blobs.put(b"first").unwrap();
    blobs.put(b"second").unwrap();

    let files = fanout_files(dir.path(), user);
    assert_eq!(files.len(), 2, "one file per put");
    for (_, name) in &files {
        assert_eq!(
            name.len(),
            62,
            "the file name is the digest minus its fanout: {name}"
        );
        assert!(name.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

#[test]
fn the_same_bytes_put_concurrently_converge_on_complete_bytes() {
    // Two writers of one content are the rename race (spec 4, H1): both miss
    // the dedup short-circuit, both rename their own temp onto the digest
    // path, and whichever lands last wins atomically — same bytes, so the
    // file is the complete content either way, and no temp survives.
    let (dir, manager) = manager();
    let user = Uuid::new_v4();
    let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();

    let blobs = std::sync::Arc::new(manager.blobs(user).unwrap());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let digests: Vec<_> = (0..8)
        .map(|_| {
            let blobs = std::sync::Arc::clone(&blobs);
            let barrier = std::sync::Arc::clone(&barrier);
            let bytes = bytes.clone();
            std::thread::spawn(move || {
                barrier.wait();
                blobs.put(&bytes)
            })
        })
        .collect();
    let digests: Vec<_> = digests
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    assert!(
        digests.windows(2).all(|w| w[0] == w[1]),
        "one content, one digest"
    );

    let blobs = manager.blobs(user).unwrap();
    assert_eq!(blobs.get(&digests[0]).unwrap().as_deref(), Some(&bytes[..]));
    assert!(
        fanout_files(dir.path(), user)
            .iter()
            .all(|(_, name)| !name.contains(".tmp-")),
        "no temp survived the race"
    );
}

#[test]
fn a_temp_from_a_crashed_put_is_not_a_blob() {
    // The temp never occupies the digest path (spec 4, H1): a crash between
    // temp-write and rename leaves the content absent, not half-there, so
    // `get` answers None and the dedup short-circuit stays honest.
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    manager.pod(user).unwrap();
    let blobs = manager.blobs(user).unwrap();

    let digest = "ab".to_string() + &"c".repeat(62);
    let temp = _dir
        .path()
        .join("users")
        .join(user.to_string())
        .join("blobs")
        .join(&digest[..2])
        .join(format!("{}.tmp-CRASHED", &digest[2..]));
    std::fs::create_dir_all(temp.parent().unwrap()).unwrap();
    std::fs::write(&temp, b"half of the bytes").unwrap();

    assert!(blobs.get(&digest).unwrap().is_none());
    assert!(!blobs.contains(&digest));
}

/// Plant a `.tmp-*` file in `user`'s blob fanout, as a crashed `put` leaves
/// one (spec 4, H1), with its mtime set `age` ago.
fn plant_temp(base: &Path, user: Uuid, digest: &str, age: Duration) {
    let temp = base
        .join("users")
        .join(user.to_string())
        .join("blobs")
        .join(&digest[..2])
        .join(format!("{}.tmp-CRASHED", &digest[2..]));
    std::fs::create_dir_all(temp.parent().unwrap()).unwrap();
    std::fs::write(&temp, b"half of the bytes").unwrap();
    let file = std::fs::File::options().write(true).open(&temp).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now() - age))
        .unwrap();
}

#[test]
fn the_temp_sweep_removes_stale_temps_and_keeps_fresh_ones_and_blobs() {
    // The bound is the safety story (spec 4, H7): a fresh temp is an in-flight
    // write from this process or a crashed one waiting for the next open, and
    // a stale temp is disk waste — the hour between them is what a second
    // process sharing the pod directory can never cross. Digest paths never
    // match, so stored bytes are never the sweep's to take.
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    manager.pod(user).unwrap();
    let blobs = manager.blobs(user).unwrap();

    let digest = blobs.put(b"real bytes").unwrap();
    let crashed = "cd".to_string() + &"e".repeat(62);
    plant_temp(
        _dir.path(),
        user,
        &crashed,
        Duration::from_secs(2 * 60 * 60),
    );
    let fresh = "12".to_string() + &"3".repeat(62);
    plant_temp(_dir.path(), user, &fresh, Duration::ZERO);

    let swept = blobs.sweep_temp(brolly_store::blobs::TEMP_MAX_AGE).unwrap();
    assert_eq!(swept, 1, "only the stale temp");
    assert!(
        blobs.get(&digest).unwrap().is_some(),
        "a digest path is never swept"
    );
    assert!(
        _dir.path()
            .join("users")
            .join(user.to_string())
            .join("blobs")
            .join(&fresh[..2])
            .join(format!("{}.tmp-CRASHED", &fresh[2..]))
            .exists(),
        "a fresh temp is an in-flight write, not litter"
    );
}

#[test]
fn the_temp_sweep_takes_everything_at_zero_age() {
    // The degenerate bound is what makes the sweep testable without waiting:
    // every `.tmp-*` file is at least zero old, so `ZERO` is "all of them",
    // still never a digest path.
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    manager.pod(user).unwrap();
    let blobs = manager.blobs(user).unwrap();

    let digest = blobs.put(b"real bytes").unwrap();
    let crashed = "cd".to_string() + &"e".repeat(62);
    plant_temp(_dir.path(), user, &crashed, Duration::ZERO);

    assert_eq!(blobs.sweep_temp(Duration::ZERO).unwrap(), 1);
    assert!(blobs.get(&digest).unwrap().is_some());
}

#[test]
fn opening_a_pod_sweeps_stale_temps_and_leaves_fresh_ones() {
    // `Pod::open` runs the sweep on the real bound (spec 4, H7). Planted as a
    // crashed previous process would leave them, before this process ever
    // opens the pod: a stale temp — a write nobody came back for — goes at
    // the next open, while a fresh one survives, which is what keeps an
    // in-flight upload from a second process safe from this one's sweep.
    let dir = tempfile::tempdir().unwrap();
    let manager = StoreManager::open(dir.path(), 4, 60).unwrap();
    let user = Uuid::new_v4();

    let stale = "ab".to_string() + &"c".repeat(62);
    let fresh = "12".to_string() + &"3".repeat(62);
    plant_temp(
        dir.path(),
        user,
        &stale,
        2 * brolly_store::blobs::TEMP_MAX_AGE,
    );
    plant_temp(dir.path(), user, &fresh, Duration::ZERO);

    manager.pod(user).unwrap();

    let temp = |digest: &str| {
        dir.path()
            .join("users")
            .join(user.to_string())
            .join("blobs")
            .join(&digest[..2])
            .join(format!("{}.tmp-CRASHED", &digest[2..]))
    };
    assert!(!temp(&stale).exists(), "the stale temp was swept at open");
    assert!(temp(&fresh).exists(), "the fresh temp survived the open");
}

#[test]
fn orphans_are_the_blobs_no_record_names() {
    // The disk side of ADR 0013's diff (spec 4, H7): whatever is on disk and
    // not in the referenced set is an orphan, reported with its bytes. Temps
    // are not blobs and never make the list — they are the temp sweep's, not
    // the orphan sweep's.
    let (_dir, manager) = manager();
    let user = Uuid::new_v4();
    let blobs = manager.blobs(user).unwrap();

    let kept = blobs.put(b"referenced").unwrap();
    let loose = blobs.put(b"orphaned").unwrap();
    plant_temp(
        _dir.path(),
        user,
        &("ab".to_string() + &"c".repeat(62)),
        Duration::ZERO,
    );

    let orphans = blobs.orphans(std::slice::from_ref(&kept)).unwrap();
    assert_eq!(
        orphans
            .iter()
            .map(|o| (o.digest.as_str(), o.bytes))
            .collect::<Vec<_>>(),
        vec![(loose.as_str(), b"orphaned".len() as u64)],
        "the unreferenced blob, and nothing else"
    );

    // An empty referenced set orphans every blob on disk — and the temp still
    // is not one. After the removal, only the kept blob remains to find.
    assert_eq!(
        blobs.orphans(&[]).unwrap().len(),
        2,
        "both blobs, and the temp is not a blob"
    );
    blobs.remove(&loose).unwrap();
    assert_eq!(blobs.orphans(&[]).unwrap().len(), 1);
    assert!(blobs.orphans(&[kept]).unwrap().is_empty());
}
