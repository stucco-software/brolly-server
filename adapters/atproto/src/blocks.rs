//! atrium's blockstore, backed by our per-member storage.
//!
//! ADR 0002 called this the constraint that mattered most: the old research
//! marked pluggable storage as passing *on inspection*, and the implementation
//! plan then had to be rewritten. The spike drove a whole repo — genesis
//! commit, record write, second commit — through a `HashMap` behind these two
//! methods, so the contract is known to hold when exercised rather than read.
//!
//! Blocks are content-addressed and so is the store underneath, which makes
//! the mapping direct: a CID carries a SHA-256 multihash, and that digest is
//! exactly the key the blob store already uses. Writing a block twice is a
//! no-op rather than a duplicate, which is what makes a re-applied commit
//! harmless.

use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite, Error as BsError};
use atrium_repo::{Cid, Multihash};
use brolly_store::BlobStore;

/// SHA-256, the only multihash code ATProtocol uses.
const SHA2_256: u64 = 0x12;

/// A member's repo blocks.
pub struct PodBlocks {
    blobs: BlobStore,
}

impl PodBlocks {
    pub fn new(blobs: BlobStore) -> Self {
        Self { blobs }
    }

    /// The blob-store key for a CID: its multihash digest, in hex.
    ///
    /// Keying on the digest rather than the CID string means the same bytes
    /// stored under two codecs share one copy, and it is the same key the blob
    /// store computes for itself.
    fn key(cid: &Cid) -> String {
        hex_encode(cid.hash().digest())
    }

    /// Is this block already stored?
    pub fn contains(&self, cid: &Cid) -> bool {
        self.blobs.contains(&Self::key(cid))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl AsyncBlockStoreRead for PodBlocks {
    async fn read_block_into(&mut self, cid: Cid, contents: &mut Vec<u8>) -> Result<(), BsError> {
        let bytes = self
            .blobs
            .get(&Self::key(&cid))
            .map_err(|_| BsError::CidNotFound)?
            .ok_or(BsError::CidNotFound)?;
        contents.clear();
        contents.extend_from_slice(&bytes);
        Ok(())
    }
}

impl AsyncBlockStoreWrite for PodBlocks {
    async fn write_block(
        &mut self,
        codec: u64,
        hash: u64,
        contents: &[u8],
    ) -> Result<Cid, BsError> {
        if hash != SHA2_256 {
            // Refuse rather than store under a key that does not describe the
            // bytes — a block filed under the wrong digest is unreadable and
            // the failure would surface much later, as a missing CID.
            return Err(BsError::CidNotFound);
        }
        let digest = self.blobs.put(contents).map_err(|_| BsError::CidNotFound)?;
        let raw = hex_decode(&digest).ok_or(BsError::CidNotFound)?;
        let mh = Multihash::wrap(hash, &raw).map_err(|_| BsError::CidNotFound)?;
        Ok(Cid::new_v1(codec, mh))
    }
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    text.len()
        .is_multiple_of(2)
        .then(|| {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
                .collect::<Option<Vec<u8>>>()
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Through the manager, because `BlobStore::open` is deliberately
    /// crate-private — a blob store should only ever come from the manager
    /// that knows where a member's data lives.
    fn store() -> (tempfile::TempDir, PodBlocks) {
        let dir = tempfile::tempdir().unwrap();
        let manager = brolly_store::StoreManager::open(dir.path(), 4, 60).unwrap();
        let blobs = manager.repo_blocks(uuid::Uuid::new_v4()).unwrap();
        (dir, PodBlocks::new(blobs))
    }

    #[tokio::test]
    async fn a_written_block_reads_back_byte_for_byte() {
        let (_dir, mut blocks) = store();
        let payload = b"a dag-cbor block, more or less";

        let cid = blocks.write_block(0x71, SHA2_256, payload).await.unwrap();

        let mut out = Vec::new();
        blocks.read_block_into(cid, &mut out).await.unwrap();
        assert_eq!(out, payload);
    }

    #[tokio::test]
    async fn the_cid_actually_describes_the_bytes() {
        // If the digest in the CID is not the digest of the content, the block
        // is unreadable and it fails much later as a missing CID.
        let (_dir, mut blocks) = store();
        let payload = b"content";
        let cid = blocks.write_block(0x71, SHA2_256, payload).await.unwrap();

        use sha2::{Digest, Sha256};
        assert_eq!(cid.hash().digest(), &Sha256::digest(payload)[..]);
    }

    #[tokio::test]
    async fn writing_the_same_block_twice_is_idempotent() {
        // What makes a re-applied commit harmless.
        let (_dir, mut blocks) = store();
        let first = blocks.write_block(0x71, SHA2_256, b"same").await.unwrap();
        let second = blocks.write_block(0x71, SHA2_256, b"same").await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn different_content_gets_different_cids() {
        let (_dir, mut blocks) = store();
        let a = blocks.write_block(0x71, SHA2_256, b"one").await.unwrap();
        let b = blocks.write_block(0x71, SHA2_256, b"two").await.unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn a_block_we_never_wrote_is_not_found() {
        let (_dir, mut blocks) = store();
        let cid = blocks.write_block(0x71, SHA2_256, b"one").await.unwrap();

        // A different member's blocks, same CID.
        let (_other_dir, mut empty) = store();
        let mut out = Vec::new();
        assert!(empty.read_block_into(cid, &mut out).await.is_err());
    }

    #[tokio::test]
    async fn an_unsupported_hash_is_refused_rather_than_misfiled() {
        let (_dir, mut blocks) = store();
        // 0x1e is blake3; ATProtocol does not use it and storing under the
        // sha256 key would file the block under a digest that is not its own.
        assert!(blocks.write_block(0x71, 0x1e, b"content").await.is_err());
    }

    #[tokio::test]
    async fn contains_reports_what_was_written() {
        let (_dir, mut blocks) = store();
        let cid = blocks.write_block(0x71, SHA2_256, b"here").await.unwrap();
        assert!(blocks.contains(&cid));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(hex_decode(&hex_encode(&bytes)), Some(bytes));
        assert_eq!(hex_decode("odd"), None);
        assert_eq!(hex_decode("zz"), None);
    }
}
