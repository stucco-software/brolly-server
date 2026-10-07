//! The member's ATProtocol repository: records in an MST under signed commits.
//!
//! Every structural piece is atrium's (D14, ADR 0002) — MST, DAG-CBOR, CAR,
//! commit shape. The predecessor hand-rolled these and it was the single
//! largest source of "works until it meets a real client", because the failures
//! are structural and silent: a repo that is subtly wrong still round-trips
//! against itself.
//!
//! What stays ours is the key and the root. Signing happens here, and the root
//! CID is persisted by the caller, because atrium holds a repo open but does
//! not decide where the pointer to it lives.

use atrium_api::types::string::{Did, Tid};
use atrium_repo::{Cid, Repository};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::blocks::PodBlocks;
use crate::keys::SigningKey;
use crate::tid;

#[derive(Debug)]
pub enum RepoError {
    /// atrium refused the operation — a malformed path, a missing block, a
    /// commit that does not apply.
    Repo(String),
    /// A signature could not be produced.
    Signing(String),
    /// The DID is not a well-formed `did:plc:` or `did:web:`.
    BadDid(String),
    /// A record path that is not `collection/rkey`.
    BadPath(String),
}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoError::Repo(e) => write!(f, "repo: {e}"),
            RepoError::Signing(e) => write!(f, "signing: {e}"),
            RepoError::BadDid(d) => write!(f, "not a usable DID: {d}"),
            RepoError::BadPath(p) => write!(f, "record path must be collection/rkey, got {p}"),
        }
    }
}

impl std::error::Error for RepoError {}

impl From<atrium_repo::repo::Error> for RepoError {
    fn from(e: atrium_repo::repo::Error) -> Self {
        RepoError::Repo(e.to_string())
    }
}

/// A record's location in a repo: `collection/rkey`.
///
/// Validated rather than formatted blind, because a path with the wrong shape
/// produces a repo that looks fine locally and is rejected by every consumer.
pub fn record_path(collection: &str, rkey: &str) -> Result<String, RepoError> {
    let path = format!("{collection}/{rkey}");
    // An NSID has at least three segments, and neither half may be empty or
    // carry a separator of its own.
    if collection.split('.').count() < 3
        || collection.contains('/')
        || rkey.is_empty()
        || rkey.contains('/')
    {
        return Err(RepoError::BadPath(path));
    }
    Ok(path)
}

fn did_for(did: &str) -> Result<Did, RepoError> {
    Did::new(did.to_string()).map_err(|_| RepoError::BadDid(did.to_string()))
}

/// Create a member's repo and sign its genesis commit.
///
/// Returns the root CID and the genesis commit's own rev, which the caller
/// persists together — that pointer is what makes the repo findable again,
/// and atrium does not decide where it lives. The rev travels with it so the
/// stored rev is the commit's own from the first row (1, A).
pub async fn create(
    blocks: PodBlocks,
    did: &str,
    key: &SigningKey,
) -> Result<(Cid, Tid), RepoError> {
    let builder = Repository::create(blocks, did_for(did)?).await?;

    // atrium hands out the bytes and takes back a signature; the private key
    // never crosses the boundary (ADR 0002).
    let payload = builder.bytes();
    let signature = key
        .sign(&payload)
        .map_err(|e| RepoError::Signing(e.to_string()))?;

    let repo = builder.finalize(signature).await?;
    Ok((repo.root(), repo.commit().rev()))
}

/// Write a record, returning `(record CID, new root CID, the commit's rev)`.
///
/// The rev is minted to clear `head_rev` — the stored head's — so a retry in
/// the same millisecond or a clock that stepped backwards still mints forward
/// (1, A); monotonicity itself is enforced where the head moves (1, C). It is
/// set on the commit before signing and read back from the signed commit
/// afterwards, so the rev that is stored and emitted is the commit's own —
/// one source of truth, not a counter beside it.
pub async fn put_record<T: Serialize>(
    blocks: PodBlocks,
    root: Cid,
    key: &SigningKey,
    collection: &str,
    rkey: &str,
    record: &T,
    head_rev: &Tid,
) -> Result<(Cid, Cid, Tid), RepoError> {
    let path = record_path(collection, rkey)?;
    let mut repo = Repository::open(blocks, root).await?;

    // `add_raw` is deliberate: it takes whatever serializes, so a lexicon we
    // have never seen writes exactly like one we have. That is the same
    // property the faithful layer gives the pod side (D7) — no mapping table
    // is a precondition for ingesting the network, not a convenience.
    let (mut commit, record_cid) = repo.add_raw(&path, record).await?;
    commit.rev(tid::mint_after(head_rev));

    let payload = commit.bytes();
    let signature = key
        .sign(&payload)
        .map_err(|e| RepoError::Signing(e.to_string()))?;
    let new_root = commit.finalize(signature).await?;

    Ok((record_cid, new_root, repo.commit().rev()))
}

/// Read a record back.
pub async fn get_record<T: DeserializeOwned>(
    blocks: PodBlocks,
    root: Cid,
    collection: &str,
    rkey: &str,
) -> Result<Option<T>, RepoError> {
    let path = record_path(collection, rkey)?;
    let mut repo = Repository::open(blocks, root).await?;
    Ok(repo.get_raw(&path).await?)
}

/// Remove a record, returning `(new root CID, the commit's rev)`.
///
/// The rev is minted and read back exactly as `put_record` does — one code
/// path, one source of truth (1, A).
pub async fn delete_record(
    blocks: PodBlocks,
    root: Cid,
    key: &SigningKey,
    collection: &str,
    rkey: &str,
    head_rev: &Tid,
) -> Result<(Cid, Tid), RepoError> {
    let path = record_path(collection, rkey)?;
    let mut repo = Repository::open(blocks, root).await?;
    let mut commit = repo.delete_raw(&path).await?;
    commit.rev(tid::mint_after(head_rev));

    let payload = commit.bytes();
    let signature = key
        .sign(&payload)
        .map_err(|e| RepoError::Signing(e.to_string()))?;
    let new_root = commit.finalize(signature).await?;

    Ok((new_root, repo.commit().rev()))
}

/// Export the repo as a CARv1 archive.
///
/// The archive is what `com.atproto.sync.getRepo` serves and what a member's
/// data export is: every block reachable from the root, framed with the root as
/// the CAR's single root. atrium writes it (D14) — CAR framing is exactly the
/// kind of structural detail that is easy to get subtly wrong and impossible to
/// notice locally, because a malformed archive still reads back with the same
/// code that wrote it.
pub async fn export_car(blocks: PodBlocks, root: Cid) -> Result<Vec<u8>, RepoError> {
    use atrium_repo::blockstore::CarStore;

    let mut repo = Repository::open(blocks, root).await?;

    // `CarStore` keeps its storage private, so the buffer is shared rather than
    // recovered afterwards.
    let buffer = SharedBuffer::default();
    let mut car = CarStore::create_with_roots(buffer.clone(), [root])
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?;

    repo.export_into(&mut car).await?;
    Ok(buffer.take())
}

/// An in-memory file the CAR writer can seek around in.
///
/// CAR writing seeks — it revisits offsets as it frames blocks — so a plain
/// `Vec` is not enough and the whole archive is built before anything is
/// returned. That is fine at a member's repo size and wrong at a large one;
/// when export needs to stream, this is the piece that changes.
#[derive(Clone, Default)]
struct SharedBuffer {
    inner: std::sync::Arc<std::sync::Mutex<std::io::Cursor<Vec<u8>>>>,
}

impl SharedBuffer {
    fn take(&self) -> Vec<u8> {
        self.lock().get_ref().clone()
    }

    /// Poisoning is recovered from rather than panicked on.
    ///
    /// A poisoned lock here means an earlier export panicked while holding it.
    /// The cursor is still a structurally valid buffer, the export that failed
    /// is already an error on its own path, and panicking a second time in a
    /// library crate would turn a failed export into a downed server.
    fn lock(&self) -> std::sync::MutexGuard<'_, std::io::Cursor<Vec<u8>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn with<T>(&self, f: impl FnOnce(&mut std::io::Cursor<Vec<u8>>) -> T) -> T {
        f(&mut self.lock())
    }
}

impl tokio::io::AsyncRead for SharedBuffer {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::io::Read;
        std::task::Poll::Ready(self.with(|cursor| {
            let read = cursor.read(buf.initialize_unfilled())?;
            buf.advance(read);
            Ok(())
        }))
    }
}

impl tokio::io::AsyncWrite for SharedBuffer {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::Write;
        std::task::Poll::Ready(self.with(|cursor| cursor.write(data)))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncSeek for SharedBuffer {
    fn start_seek(
        self: std::pin::Pin<&mut Self>,
        position: std::io::SeekFrom,
    ) -> std::io::Result<()> {
        use std::io::Seek;
        self.with(|cursor| cursor.seek(position)).map(|_| ())
    }

    fn poll_complete(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<u64>> {
        use std::io::Seek;
        std::task::Poll::Ready(self.with(|cursor| cursor.stream_position()))
    }
}

/// Every CID reachable from the root — the block set a CAR export carries.
pub async fn reachable(blocks: PodBlocks, root: Cid) -> Result<Vec<Cid>, RepoError> {
    let mut repo = Repository::open(blocks, root).await?;
    Ok(repo.export().await?.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture() -> (tempfile::TempDir, brolly_store::StoreManager, uuid::Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
        (dir, manager, uuid::Uuid::new_v4())
    }

    fn blocks(manager: &brolly_store::StoreManager, user: uuid::Uuid) -> PodBlocks {
        PodBlocks::new(manager.repo_blocks(user).unwrap())
    }

    #[tokio::test]
    async fn a_repo_is_created_and_its_root_is_stable() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();

        let (root, _rev) = create(blocks(&manager, user), DID, &key)
            .await
            .expect("create");
        assert!(
            root.to_string().starts_with("bafy"),
            "expected a CIDv1, got {root}"
        );
    }

    #[tokio::test]
    async fn a_record_written_reads_back_identically() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let record = json!({
            "$type": "app.bsky.feed.post",
            "text": "hello atproto",
            "createdAt": "2026-08-26T12:00:00Z",
        });
        let (_, new_root, _) = put_record(
            blocks(&manager, user),
            root,
            &key,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
            &record,
            &genesis,
        )
        .await
        .expect("put");

        let read: Option<serde_json::Value> = get_record(
            blocks(&manager, user),
            new_root,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .expect("get");
        assert_eq!(read, Some(record));
    }

    #[tokio::test]
    async fn a_write_advances_the_root() {
        // The root is the repo's version. A write that leaves it unchanged has
        // produced a commit nobody can observe.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let (_, new_root, _) = put_record(
            blocks(&manager, user),
            root,
            &key,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
            &json!({"$type": "app.bsky.feed.post", "text": "one"}),
            &genesis,
        )
        .await
        .unwrap();

        assert_ne!(root, new_root);
    }

    #[tokio::test]
    async fn the_stored_rev_is_the_signed_commits_own() {
        // One source of truth: the rev a write returns is the one the commit
        // block itself carries, and it clears the head it was minted past
        // (1, A). A counter invented beside the commits is the divergence this
        // replaces.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let (_, new_root, rev) = put_record(
            blocks(&manager, user),
            root,
            &key,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
            &json!({"$type": "app.bsky.feed.post", "text": "one"}),
            &genesis,
        )
        .await
        .unwrap();

        assert!(
            rev.as_str() > genesis.as_str(),
            "the commit's rev did not clear the head's: {} -> {}",
            genesis.as_str(),
            rev.as_str()
        );

        // Read back through atrium, from the root alone: the commit block
        // must carry that same rev.
        let repo = Repository::open(blocks(&manager, user), new_root)
            .await
            .unwrap();
        assert_eq!(repo.commit().rev(), rev);
    }

    #[tokio::test]
    async fn the_rev_mints_forward_across_writes() {
        // Chained writes, each minted past the previous commit's rev: strictly
        // increasing, the property the head's `rev <` guard enforces (1, C).
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (mut root, mut rev) = create(blocks(&manager, user), DID, &key).await.unwrap();

        for (n, rkey) in ["3kaaaaaaaaaaa", "3kbbbbbbbbbbb"].iter().enumerate() {
            let (_, next, minted) = put_record(
                blocks(&manager, user),
                root,
                &key,
                "app.bsky.feed.post",
                rkey,
                &json!({"$type": "app.bsky.feed.post", "text": format!("post {n}")}),
                &rev,
            )
            .await
            .unwrap();
            assert!(
                minted.as_str() > rev.as_str(),
                "a remint did not clear the previous rev: {} -> {}",
                rev.as_str(),
                minted.as_str()
            );
            root = next;
            rev = minted;
        }
    }

    #[tokio::test]
    async fn an_unmapped_third_party_lexicon_writes_like_any_other() {
        // Phase 7's third exit criterion, at the repo layer: there is no
        // mapping table, so a lexicon nobody has heard of is not a special
        // case — it is the same call.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let record = json!({
            "$type": "site.standard.doc",
            "text": "a wholly unrelated lexicon",
            "nested": {"depth": 2, "list": [1, 2, 3]},
        });
        let (_, new_root, _) = put_record(
            blocks(&manager, user),
            root,
            &key,
            "site.standard.doc",
            "3kbbbbbbbbbbb",
            &record,
            &genesis,
        )
        .await
        .expect("an unmapped lexicon must write");

        let read: Option<serde_json::Value> = get_record(
            blocks(&manager, user),
            new_root,
            "site.standard.doc",
            "3kbbbbbbbbbbb",
        )
        .await
        .unwrap();
        assert_eq!(read, Some(record), "nested structure must survive verbatim");
    }

    #[tokio::test]
    async fn two_records_coexist_and_both_read_back() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (mut root, mut rev) = create(blocks(&manager, user), DID, &key).await.unwrap();

        for (n, rkey) in ["3kaaaaaaaaaaa", "3kbbbbbbbbbbb"].iter().enumerate() {
            let (_, next, minted) = put_record(
                blocks(&manager, user),
                root,
                &key,
                "app.bsky.feed.post",
                rkey,
                &json!({"$type": "app.bsky.feed.post", "text": format!("post {n}")}),
                &rev,
            )
            .await
            .unwrap();
            root = next;
            rev = minted;
        }

        for (n, rkey) in ["3kaaaaaaaaaaa", "3kbbbbbbbbbbb"].iter().enumerate() {
            let read: Option<serde_json::Value> =
                get_record(blocks(&manager, user), root, "app.bsky.feed.post", rkey)
                    .await
                    .unwrap();
            assert_eq!(read.unwrap()["text"], format!("post {n}"));
        }
    }

    #[tokio::test]
    async fn a_deleted_record_is_gone_and_the_root_moves() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let (_, with_record, with_rev) = put_record(
            blocks(&manager, user),
            root,
            &key,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
            &json!({"$type": "app.bsky.feed.post", "text": "delete me"}),
            &genesis,
        )
        .await
        .unwrap();

        let (after, _) = delete_record(
            blocks(&manager, user),
            with_record,
            &key,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
            &with_rev,
        )
        .await
        .expect("delete");

        assert_ne!(with_record, after);
        let read: Option<serde_json::Value> = get_record(
            blocks(&manager, user),
            after,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(read, None);
    }

    #[tokio::test]
    async fn a_missing_record_is_none_rather_than_an_error() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, _) = create(blocks(&manager, user), DID, &key).await.unwrap();

        let read: Option<serde_json::Value> = get_record(
            blocks(&manager, user),
            root,
            "app.bsky.feed.post",
            "nothing-here",
        )
        .await
        .unwrap();
        assert_eq!(read, None);
    }

    #[tokio::test]
    async fn a_repo_reopens_from_its_root_alone() {
        // The property that makes persisting only the root sufficient: given
        // the CID and the blocks, the repo is fully recoverable.
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        let (root, genesis) = create(blocks(&manager, user), DID, &key).await.unwrap();
        let (_, root, _) = put_record(
            blocks(&manager, user),
            root,
            &key,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
            &json!({"$type": "app.bsky.feed.post", "text": "durable"}),
            &genesis,
        )
        .await
        .unwrap();

        // Nothing carried over but the CID and the on-disk blocks.
        let read: Option<serde_json::Value> = get_record(
            blocks(&manager, user),
            root,
            "app.bsky.feed.post",
            "3kaaaaaaaaaaa",
        )
        .await
        .unwrap();
        assert_eq!(read.unwrap()["text"], "durable");
    }

    #[test]
    fn a_malformed_record_path_is_refused() {
        // A wrong-shaped path produces a repo that looks fine locally and is
        // rejected by every consumer.
        assert!(record_path("app.bsky.feed.post", "3kaaa").is_ok());
        assert!(record_path("notanNSID", "3kaaa").is_err());
        assert!(record_path("app.bsky.feed.post", "").is_err());
        assert!(record_path("app.bsky.feed.post", "has/slash").is_err());
        assert!(record_path("has/slash.a.b", "3kaaa").is_err());
    }

    #[tokio::test]
    async fn a_bad_did_is_refused_before_anything_is_written() {
        let (_dir, manager, user) = fixture();
        let key = SigningKey::generate();
        assert!(
            create(blocks(&manager, user), "not-a-did", &key)
                .await
                .is_err()
        );
    }
}
