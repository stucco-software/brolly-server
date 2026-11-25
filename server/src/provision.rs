//! Giving a new member a pod they can actually use.
//!
//! A storage root with no ACL is a pod its owner cannot write to. WAC grants
//! nothing by default — deliberately, since a missing ACL meaning "allow" is
//! how authorization bugs become data leaks — so the grant has to be created,
//! and the only moment that is certainly right is account creation.
//!
//! This was missing: registration created a user row and nothing else, so the
//! first write any member attempted was refused. It surfaced as a `403` from
//! the Mastodon composer with a pod that looked fine from the outside.

use brolly_identity::db::{self, DbError};
use brolly_identity::{routing, webid};
use brolly_store::StoreError;
use brolly_store::resources::{Content, Pod, provision_settings};
use oxigraph_model::{GraphName, NamedNode, NamedOrBlankNode, Quad, Term};
use sqlx::PgPool;
use uuid::Uuid;

const ACL: &str = "http://www.w3.org/ns/auth/acl#";

fn iri(s: &str) -> NamedNode {
    NamedNode::new_unchecked(s)
}

fn triple(graph: &str, subject: &str, predicate: &str, object: &str) -> Quad {
    Quad::new(
        NamedOrBlankNode::NamedNode(iri(subject)),
        iri(predicate),
        Term::NamedNode(iri(object)),
        GraphName::NamedNode(iri(graph)),
    )
}

/// Create a member's storage root, the ACL that makes it theirs, and the
/// settings resources that make it usable (spec 6, H2).
///
/// One write. `create_root` records the root in the pod's metadata, and only
/// provisioning calls it. The ACL is stored as an auxiliary resource, so it
/// exists and has a version but is never a member of the root. A root without
/// its ACL is a pod its owner can't write to, so the two commit together or
/// not at all — and since spec 6, so do the three settings resources and the
/// public index's ACL, for the same reason: SolidOS can't boot without them,
/// so a member whose pod has a root but no settings has an account that works
/// in theory and in no client.
///
/// The root grant carries **both** `acl:accessTo` and `acl:default`: the first
/// governs the container itself, the second governs everything inside it. They
/// are distinct scopes, and conflating them is how an ACL silently grants more
/// or less than intended.
pub fn pod(pod: &Pod, username: &str, base_domain: &str) -> Result<(), StoreError> {
    let root = routing::storage_root(username, base_domain);
    let acl = format!("{root}.acl");
    let owner = format!("{acl}#owner");
    let member = webid::webid(username, base_domain);
    let grant = [
        triple(&acl, &owner, &format!("{ACL}accessTo"), &root),
        triple(&acl, &owner, &format!("{ACL}default"), &root),
        triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Read")),
        triple(&acl, &owner, &format!("{ACL}mode"), &format!("{ACL}Write")),
        triple(
            &acl,
            &owner,
            &format!("{ACL}mode"),
            &format!("{ACL}Control"),
        ),
        triple(&acl, &owner, &format!("{ACL}agent"), &member),
    ];

    pod.write(|w| {
        w.create_root(&root)?;
        w.put(&acl, Content::Auxiliary(&grant))?;
        provision_settings(w, &root, &member)?;
        Ok(())
    })
}

// --- accounts ---------------------------------------------------------------

/// Why creating an account's substance failed. The web signup path maps
/// these onto its own error (the member sees one answer); the operator CLI
/// reports them directly, because the operator can act on the difference.
#[derive(Debug)]
pub enum AccountError {
    /// The handle or the email is already somebody's.
    UsernameTaken,
    EmailTaken,
    /// The database refused or failed. When this lands after the row did,
    /// the account is half-built — a member with no pod or no ATProtocol
    /// identity — and `whoami` shows which; the operator finishes by hand or
    /// deletes the row and starts over.
    Db(DbError),
    /// The pod's storage root or ACL could not be written. The row is in;
    /// the account cannot write to its pod until an operator intervenes.
    Pod(StoreError),
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountError::UsernameTaken => f.write_str("that handle is already a member's"),
            AccountError::EmailTaken => f.write_str("that email is already a member's"),
            AccountError::Db(e) => write!(f, "the database refused the account: {e}"),
            AccountError::Pod(e) => write!(f, "the pod could not be provisioned: {e}"),
        }
    }
}

impl std::error::Error for AccountError {}

/// Create the account — the row, the pod with its storage root and ACL, the
/// ATProtocol identity — which is to say: everything every signup gets,
/// after whatever door the caller came through. Shared by the web signup
/// path, the service API, and the operator CLI (`brolly-admin
/// agent-account`), so "what an account is" has one definition.
///
/// The firehose event rides the return rather than a broadcast: the shared
/// listener (1, G) delivers it to any attached consumer from the log, and a
/// caller holding a channel — the signup path — sends it as the fast path. A
/// caller without one, like the CLI, just returns it to nobody.
pub async fn account(
    pool: &PgPool,
    stores: &brolly_store::StoreManager,
    username: &str,
    email: Option<&str>,
    password: &str,
    role: &str,
    base_domain: &str,
    plc_client: Option<&reqwest::Client>,
) -> Result<(db::User, Option<brolly_atproto::firehose::IdentityEvent>), AccountError> {
    let user = db::create_user(pool, username, email, password, role)
        .await
        .map_err(|e| match e {
            DbError::UsernameTaken => AccountError::UsernameTaken,
            DbError::EmailTaken => AccountError::EmailTaken,
            e => AccountError::Db(e),
        })?;

    // Give them a pod they can write to. WAC grants nothing by default, so
    // without this the first write any new member attempts is refused — and
    // the pod looks fine from the outside.
    let opened = stores.pod(user.id).map_err(|e| {
        tracing::error!(error = %e, user = %user.id, "pod unavailable at provisioning");
        AccountError::Pod(e)
    })?;
    if let Err(e) = pod(&opened, username, base_domain) {
        tracing::error!(error = %e, user = %user.id, "pod provisioning failed");
        return Err(AccountError::Pod(e));
    }

    // An ATProtocol identity, in the same breath — the same reasoning as the
    // signup path: an account that works in three protocols and not the
    // fourth reads as a bug in the fourth.
    let identity =
        match atproto_identity(pool, stores, user.id, username, base_domain, plc_client).await {
            Ok(identity) => identity,
            Err(e) => {
                tracing::error!(error = %e, user = %user.id, "atproto provisioning failed");
                return Err(AccountError::Db(e));
            }
        };
    tracing::info!(
        user = %user.id,
        did = %identity.did,
        plc_registered = identity.plc_registered,
        "account provisioned"
    );
    Ok((user, identity.identity_event))
}

// --- ATProtocol identity ---------------------------------------------------

/// What provisioning produced, so a caller can log or return it.
#[derive(Debug, Clone)]
pub struct AtprotoIdentity {
    pub did: String,
    /// The genesis operation's CID, for the PLC chain.
    pub operation_cid: String,
    /// The repo's first root.
    pub root_cid: String,
    /// Whether the PLC directory has accepted the genesis operation.
    ///
    /// False is a normal outcome locally and on first boot behind a firewall.
    /// It is recorded rather than retried inline so the member exists either
    /// way and `identity::unsubmitted` can pick it up later.
    pub plc_registered: bool,
    /// The `#identity` event the genesis logged, for the live channel (1, E).
    ///
    /// `None` when the operation was already recorded — a re-run announces
    /// nothing twice. Durable consumers read the event from the log either
    /// way; this exists so the caller can hand it to consumers already
    /// attached.
    pub identity_event: Option<brolly_atproto::firehose::IdentityEvent>,
}

/// Give a member an ATProtocol identity: keys, a DID, and a repository.
///
/// All three or none. A member with a key and no repo, or a DID and no key,
/// has an account that looks provisioned and cannot participate — and the
/// failure surfaces much later, as an XRPC write that cannot find something.
///
/// **The local half is synchronous and must succeed. The network half must
/// not block it.** Submitting the genesis operation to the PLC directory is a
/// call to a third party; making registration depend on it would mean an
/// outage somewhere else stops people signing up here. The DID is derived
/// locally and deterministically (ADR 0015's reasoning applies — it commits to
/// the keys, nobody assigns it), so it is correct whether or not the directory
/// has heard of it yet.
pub async fn atproto_identity(
    pool: &PgPool,
    stores: &brolly_store::StoreManager,
    user_id: Uuid,
    username: &str,
    base_domain: &str,
    plc_client: Option<&reqwest::Client>,
) -> Result<AtprotoIdentity, DbError> {
    use brolly_atproto::{blocks::PodBlocks, identity, keys, plc, repo, state};

    // Two keys, two purposes, and they must differ — see `keys::ATPROTO_ROTATION`.
    let (signing_bytes, signing_public) = keys::generate_pair()?;
    let (rotation_bytes, rotation_public) = keys::generate_pair()?;

    db::store_key(
        pool,
        user_id,
        keys::ATPROTO_SIGNING,
        &signing_bytes,
        &signing_public,
    )
    .await?;
    db::store_key(
        pool,
        user_id,
        keys::ATPROTO_ROTATION,
        &rotation_bytes,
        &rotation_public,
    )
    .await?;

    let signing = keys::SigningKey::from_bytes(&signing_bytes)?;
    let rotation = keys::SigningKey::from_bytes(&rotation_bytes)?;

    let handle = format!("{username}.{base_domain}");
    let pds = format!("https://{base_domain}");
    let (operation, did) = plc::create(&signing, &rotation, &handle, &pds)
        .map_err(|e| DbError::Hash(format!("building the genesis operation: {e}")))?;

    let (operation_cid, identity_event) =
        identity::record_operation(pool, Some(user_id), &did, &operation).await?;

    // The DID goes on the member now, not after submission. It is derived from
    // the operation rather than assigned by the directory, so it is already
    // theirs — and every AT-URI minted from here on names it (D11), which is
    // the whole point of having it before anything else happens.
    sqlx::query("UPDATE users SET did_plc = $1 WHERE id = $2")
        .bind(&did)
        .bind(user_id)
        .execute(pool)
        .await?;

    // The repository, with a genesis commit signed by the key just stored.
    // The genesis commit's own rev is persisted with the root, so the stored
    // rev is the commit's from the first row (1, A).
    let blocks = PodBlocks::new(
        stores
            .repo_blocks(user_id)
            .map_err(|e| DbError::Hash(format!("opening repo blocks: {e}")))?,
    );
    let (root, genesis_rev) = repo::create(blocks, &did, &signing)
        .await
        .map_err(|e| DbError::Hash(format!("genesis commit: {e}")))?;
    state::create(pool, user_id, &root.to_string(), &genesis_rev).await?;

    // Best effort, and explicitly so.
    let plc_registered = match plc_client {
        Some(client) => match plc::submit(client, &did, &operation).await {
            Ok(()) => {
                identity::mark_submitted(pool, &operation_cid).await?;
                true
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    retryable = e.is_retryable(),
                    %did,
                    "PLC registration deferred; the member exists and is unresolvable until it succeeds"
                );
                false
            }
        },
        None => {
            tracing::info!(%did, "no PLC client configured; registration deferred");
            false
        }
    };

    Ok(AtprotoIdentity {
        did,
        operation_cid,
        root_cid: root.to_string(),
        plc_registered,
        identity_event,
    })
}

/// Deleting a member failed. What failed is already in the log.
#[derive(Debug)]
pub struct DeletionFailed;

/// Delete a member and everything their account is: the pod, the user row
/// (sessions and tokens cascade with it) and, for a member with a DID, the
/// `#account` event that tells the network.
///
/// The pod goes first. If the user row went first and the `rm -rf` then
/// failed, the bytes would be left with nothing pointing at them and no
/// account able to ask for them again.
///
/// Shared by the dashboard's delete page and the service API's
/// `DELETE /internal/v1/accounts/{username}`.
pub async fn delete_account(
    pool: &PgPool,
    stores: &brolly_store::StoreManager,
    commits: &tokio::sync::broadcast::Sender<brolly_atproto::firehose::Event>,
    user: &db::User,
) -> Result<(), DeletionFailed> {
    if let Err(e) = stores.delete_pod(user.id) {
        tracing::error!(error = %e, user = %user.id, "deleting the pod failed");
        return Err(DeletionFailed);
    }

    // The user row and the `#account` event land in one transaction (1, E):
    // an event for a deletion that did not happen makes a relay drop a live
    // repo, and a deletion without its event leaves the network serving a
    // deleted one. The pod is already gone either way — `rm -rf` is not
    // transactional — so the transaction covers what can be covered.
    //
    // Only a member with a DID announces: an account that never finished
    // provisioning has no identity the network ever learned, and an event a
    // consumer cannot resolve is noise.
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = %e, user = %user.id, "the deletion could not begin");
            return Err(DeletionFailed);
        }
    };
    if let Err(e) = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(error = %e, user = %user.id, "deleting the user failed");
        return Err(DeletionFailed);
    }
    let account_event = match user.did_plc.as_deref() {
        Some(did) => {
            match brolly_atproto::firehose::record_account(&mut tx, did, false, Some("deleted"))
                .await
            {
                Ok(event) => Some(event),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        user = %user.id,
                        "recording the deletion's firehose event failed"
                    );
                    return Err(DeletionFailed);
                }
            }
        }
        None => None,
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, user = %user.id, "the deletion could not commit");
        return Err(DeletionFailed);
    }
    if let Some(event) = account_event {
        // The fast path (1, G): the transactional notify that rode the deletion
        // above is what the shared listener turns into a rebroadcast, so this
        // send is latency, not correctness. `send` fails only when nobody is
        // listening, which is normal.
        let _ = commits.send(brolly_atproto::firehose::Event::Account(event));
    }
    tracing::info!(user = %user.id, "account deleted");
    Ok(())
}

/// A status change that did not land.
#[derive(Debug)]
pub struct StatusChangeFailed;

/// Every statement that takes a member's live credentials away. Sessions,
/// unspent authorization codes and reset links are deleted; tokens are
/// revoked, so a refresh presented later reads as revoked rather than
/// unknown. Agent credentials hang off the member's linked WebIDs.
const REVOKE_EVERYTHING: &[&str] = &[
    "DELETE FROM sessions WHERE user_id = $1",
    "DELETE FROM password_resets WHERE user_id = $1",
    "DELETE FROM solid_auth_codes WHERE user_id = $1",
    "DELETE FROM atproto_auth_codes WHERE user_id = $1",
    "DELETE FROM mastodon_auth_codes WHERE user_id = $1",
    "UPDATE solid_refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    "UPDATE atproto_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    "UPDATE atproto_legacy_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    "UPDATE mastodon_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    "UPDATE solid_client_credentials SET revoked_at = now()
      WHERE revoked_at IS NULL
        AND webid IN (SELECT webid FROM solid_webid_links WHERE user_id = $1)",
];

/// Disable a member: the account stops serving and everything they hold
/// stops working, but nothing is deleted.
///
/// `status = 'disabled'` is what every surface checks — login, sessions,
/// the pod, the profile, the actor, the repo, the public timeline. The
/// revocations are belt to that braces: no token, session or code minted
/// before the disable can be presented after an enable either, so an app a
/// member authorised stays signed out until they sign it in again. All of
/// it is one transaction, with the `#account` event that tells relays the
/// repo is taken down.
pub async fn disable_account(
    pool: &PgPool,
    commits: &tokio::sync::broadcast::Sender<brolly_atproto::firehose::Event>,
    user: &db::User,
) -> Result<(), StatusChangeFailed> {
    set_status(pool, commits, user, false).await
}

/// Re-enable a disabled member. Their data was never touched; their
/// credentials stay revoked, so they log in again and re-authorise apps.
pub async fn enable_account(
    pool: &PgPool,
    commits: &tokio::sync::broadcast::Sender<brolly_atproto::firehose::Event>,
    user: &db::User,
) -> Result<(), StatusChangeFailed> {
    set_status(pool, commits, user, true).await
}

async fn set_status(
    pool: &PgPool,
    commits: &tokio::sync::broadcast::Sender<brolly_atproto::firehose::Event>,
    user: &db::User,
    active: bool,
) -> Result<(), StatusChangeFailed> {
    let failed = |e: &dyn std::fmt::Display, what: &str| {
        tracing::error!(error = %e, user = %user.id, active, "{what}");
        StatusChangeFailed
    };
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| failed(&e, "the status change could not begin"))?;
    sqlx::query("UPDATE users SET status = $2 WHERE id = $1")
        .bind(user.id)
        .bind(if active { "active" } else { "disabled" })
        .execute(&mut *tx)
        .await
        .map_err(|e| failed(&e, "setting the status failed"))?;
    if !active {
        for sql in REVOKE_EVERYTHING {
            sqlx::query(sql)
                .bind(user.id)
                .execute(&mut *tx)
                .await
                .map_err(|e| failed(&e, "revoking credentials failed"))?;
        }
    }
    // As for deletion: only a member with a DID ever told the network about
    // themselves, so only they announce.
    let event = match user.did_plc.as_deref() {
        Some(did) => Some(
            brolly_atproto::firehose::record_account(
                &mut tx,
                did,
                active,
                (!active).then_some("takendown"),
            )
            .await
            .map_err(|e| failed(&e, "recording the status's firehose event failed"))?,
        ),
        None => None,
    };
    tx.commit()
        .await
        .map_err(|e| failed(&e, "the status change could not commit"))?;
    if let Some(event) = event {
        let _ = commits.send(brolly_atproto::firehose::Event::Account(event));
    }
    tracing::info!(user = %user.id, active, "account status changed");
    Ok(())
}
