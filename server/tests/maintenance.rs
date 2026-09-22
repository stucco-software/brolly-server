//! The sweeps behind `brolly-admin`, called as a library.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use brolly_identity::{db, routing};
use brolly_solid::storage;
use brolly_store::StoreManager;

const BASE_DOMAIN: &str = "brolly.test";

/// Every member's pod is swept, disabled members included (they can be
/// re-enabled, and their pod is unchanged meanwhile). A member whose pod was
/// never opened doesn't get one created.
#[tokio::test]
async fn acl_uncontain_sweeps_every_pod_and_a_rerun_is_a_no_op() {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let stores = StoreManager::open(dir.path(), 4, 60).unwrap();

    let mut seeded = Vec::new();
    for username in ["alice", "carol"] {
        let user = db::create_user(&db.pool, username, None, "correct-horse-battery", "member")
            .await
            .unwrap();
        let pod = stores.pod(user.id).unwrap();
        brolly_server::provision::pod(&pod, username, BASE_DOMAIN).unwrap();
        // What an old `put` of the root ACL left behind.
        let root = routing::storage_root(username, BASE_DOMAIN);
        pod.write(|w| storage::add_containment(w, &format!("{root}.acl"), &root))
            .unwrap();
        seeded.push((user.id, root));
    }
    sqlx::query("UPDATE users SET status = 'disabled' WHERE username = 'carol'")
        .execute(&db.pool)
        .await
        .unwrap();
    let bob = db::create_user(&db.pool, "bob", None, "correct-horse-battery", "member")
        .await
        .unwrap();

    let first = brolly_server::maintenance::acl_uncontain(&db.pool, &stores)
        .await
        .unwrap();
    assert_eq!(first.accounts, 3, "bob is counted even without a pod");
    let mut removed: Vec<(String, usize)> = first
        .pods
        .iter()
        .map(|sweep| (sweep.username.clone(), *sweep.outcome.as_ref().unwrap()))
        .collect();
    removed.sort();
    assert_eq!(
        removed,
        vec![("alice".to_string(), 1), ("carol".to_string(), 1)]
    );
    assert!(!stores.pod_exists(bob.id), "the sweep created a pod");

    for (user, root) in &seeded {
        let pod = stores.pod(*user).unwrap();
        assert!(!storage::members(&pod.read_store(), root).contains(&format!("{root}.acl")));
        assert!(
            storage::exists(&pod.read_store(), &format!("{root}.acl")),
            "the ACL stays"
        );
    }

    let second = brolly_server::maintenance::acl_uncontain(&db.pool, &stores)
        .await
        .unwrap();
    assert_eq!(second.pods.len(), 2);
    assert!(
        second
            .pods
            .iter()
            .all(|sweep| matches!(sweep.outcome, Ok(0))),
        "a rerun removed something: {second:?}"
    );
}
