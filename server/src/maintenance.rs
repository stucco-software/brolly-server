//! One-off repairs an operator runs through `brolly-admin`.
//!
//! The loops live here, not in the binary, so tests can call them without
//! spawning a process, and the binary is left with arguments and printing.

use brolly_identity::db::{self, DbError};
use brolly_store::StoreManager;
use sqlx::PgPool;

/// What [`acl_uncontain`] found and did.
#[derive(Debug)]
pub struct AclUncontain {
    /// Every row in `users`, whatever its status. Compared with `pods.len()`,
    /// this is how `brolly-admin` notices it was pointed at the wrong data
    /// directory: members in the database, none of their pods on disk.
    pub accounts: usize,
    /// One entry per account whose pod exists on disk.
    pub pods: Vec<PodSweep>,
}

/// What a sweep did to one member's pod.
#[derive(Debug)]
pub struct PodSweep {
    pub username: String,
    /// How many triples were removed, or why this pod couldn't be swept. One
    /// pod failing doesn't stop the rest, and a rerun picks it up.
    pub outcome: Result<usize, String>,
}

/// Stop listing `.acl` resources as members of their containers, in every pod.
///
/// Stage 0 (A2) made ACL resources auxiliary, and `ldp::put` no longer records
/// them as members. This removes the triples it recorded before that. It's
/// idempotent. Every account is visited whatever its status. An account whose
/// pod has never been opened is skipped rather than having one created.
///
/// This is a command, not a startup task, because it opens every pod. At
/// startup that would slow boot and churn the store cache on a large instance.
pub async fn acl_uncontain(pool: &PgPool, stores: &StoreManager) -> Result<AclUncontain, DbError> {
    let users = db::list_users(pool).await?;
    let accounts = users.len();
    let pods = users
        .into_iter()
        .filter(|user| stores.pod_exists(user.id))
        .map(|user| {
            let outcome = stores
                .pod(user.id)
                .map_err(|e| e.to_string())
                .and_then(|pod| {
                    brolly_solid::storage::uncontain_acls(&pod).map_err(|e| e.to_string())
                });
            PodSweep {
                username: user.username,
                outcome,
            }
        })
        .collect();
    Ok(AclUncontain { accounts, pods })
}
