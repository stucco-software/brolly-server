//! `brolly-admin`, spawned as a real binary.
//!
//! `CARGO_BIN_EXE_brolly-admin` is set by Cargo for integration tests in the
//! package that declares the binary, which `server` does.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output};

use brolly_identity::{db, routing};
use brolly_solid::storage;
use brolly_store::StoreManager;

/// `brolly-admin acl-uncontain`, against this database and data directory.
fn acl_uncontain(database_url: &str, data_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_brolly-admin"))
        .arg("acl-uncontain")
        .env("DATABASE_URL", database_url)
        .env("BROLLY_DATA_DIR", data_dir)
        .output()
        .expect("spawn brolly-admin")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[tokio::test]
async fn acl_uncontain_sweeps_the_configured_data_dir_and_is_safe_to_rerun() {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();
    let alice = db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let root = routing::storage_root("alice", "brolly.test");
    let acl = format!("{root}.acl");

    // Seeded in a scope of its own. Oxigraph opens a store exclusively, so the
    // test must let go of it before the binary can open it. That's also why
    // operators stop the server first.
    {
        let stores = StoreManager::open(dir.path(), 4, 60).unwrap();
        let pod = stores.pod(alice.id).unwrap();
        brolly_server::provision::pod(&pod, "alice", "brolly.test").unwrap();
        pod.write(|w| storage::add_containment(w, &acl, &root))
            .unwrap();
    }

    let first = acl_uncontain(&db.url, dir.path());
    assert!(first.status.success(), "stderr: {}", stderr(&first));
    assert_eq!(String::from_utf8_lossy(&first.stdout), "alice\t1\n");

    let second = acl_uncontain(&db.url, dir.path());
    assert!(second.status.success(), "stderr: {}", stderr(&second));
    assert_eq!(String::from_utf8_lossy(&second.stdout), "alice\t0\n");

    let stores = StoreManager::open(dir.path(), 4, 60).unwrap();
    let pod = stores.pod(alice.id).unwrap();
    assert!(!storage::members(&pod.read_store(), &root).contains(&acl));
    assert!(
        storage::exists(&pod.read_store(), &acl),
        "the ACL itself stays"
    );
}

/// An unset or mistyped `BROLLY_DATA_DIR` must not "succeed". `StoreManager::open`
/// would create an empty data directory there, find no pods, and exit 0.
#[tokio::test]
async fn acl_uncontain_refuses_a_data_dir_without_a_users_directory() {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    let dir = tempfile::tempdir().unwrap();

    let out = acl_uncontain(&db.url, dir.path());
    let err = stderr(&out);
    assert!(
        err.contains("no pod directory at") && err.contains("BROLLY_DATA_DIR"),
        "stderr: {err}"
    );
    assert!(!out.status.success());
    assert!(
        !dir.path().join("users").exists(),
        "the refusal created users/"
    );
    assert!(
        !dir.path().join("instance").exists(),
        "the refusal created instance/"
    );
}

/// Members in the database and none of their pods on disk means the command is
/// looking in the wrong place, not that there is nothing to do.
#[tokio::test]
async fn acl_uncontain_fails_when_the_database_has_members_but_no_pods_are_found() {
    let db = brolly_test_support::postgres().await;
    db::MIGRATOR.run(&db.pool).await.expect("migrations");
    db::create_user(&db.pool, "alice", None, "correct-horse-battery", "member")
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    // A data directory in the right shape with nobody's pod in it.
    std::fs::create_dir(dir.path().join("users")).unwrap();

    let out = acl_uncontain(&db.url, dir.path());
    let err = stderr(&out);
    assert!(
        err.contains("1 account(s) in the database but no pods under"),
        "stderr: {err}"
    );
    assert!(!out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}
