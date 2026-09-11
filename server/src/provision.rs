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
use brolly_solid::storage;
use brolly_store::write::{WriteError, insert_quads};
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

/// Create a member's storage root and the ACL that makes it theirs.
///
/// The grant carries **both** `acl:accessTo` and `acl:default`: the first
/// governs the container itself, the second governs everything inside it. They
/// are distinct scopes, and conflating them is how an ACL silently grants more
/// or less than intended.
pub fn pod(
    store: &brolly_store::Store,
    username: &str,
    base_domain: &str,
) -> Result<(), WriteError> {
    let root = routing::storage_root(username, base_domain);
    storage::init_storage_root(store, &root)?;

    let acl = format!("{root}.acl");
    let owner = format!("{acl}#owner");
    let member = webid::webid(username, base_domain);

    insert_quads(
        store,
        &[
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
        ],
    )?;
    Ok(())
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

    let operation_cid = identity::record_operation(pool, Some(user_id), &did, &operation).await?;

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
    let blocks = PodBlocks::new(
        stores
            .repo_blocks(user_id)
            .map_err(|e| DbError::Hash(format!("opening repo blocks: {e}")))?,
    );
    let root = repo::create(blocks, &did, &signing)
        .await
        .map_err(|e| DbError::Hash(format!("genesis commit: {e}")))?;
    state::create(pool, user_id, &root.to_string()).await?;

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
    })
}
