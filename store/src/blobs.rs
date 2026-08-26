//! Content-addressed byte storage, one directory per pod.
//!
//! Bytes live beside the graph, never inside it (plan §2.2). An Oxigraph store
//! is a triple store; a 4 MB image encoded as a base64 literal is a row every
//! query has to step over, and the predecessor's pods slowed down exactly that
//! way. The graph keeps a digest and a media type; the bytes live here.
//!
//! Addressing is `sha256(content)`, so the same file stored twice costs one
//! copy and a re-upload of unchanged media is free. The digest is **not** a
//! capability: it is derived from the content, so anyone who has the file can
//! compute it. Every read is scoped to one pod's directory for that reason.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::manager::StoreError;

/// One pod's blobs.
pub struct BlobStore {
    dir: PathBuf,
}

/// A hex SHA-256, and nothing else.
///
/// The digest reaches `get`/`remove` from a triple in the pod, and a pod's
/// triples are writable by any app the member has authorised — so it is
/// untrusted input that is about to become a filesystem path. Validating the
/// alphabet and the length is what stops `../../` from being one.
fn is_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

impl BlobStore {
    pub(crate) fn open(dir: PathBuf) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Two levels of fanout, so a pod with many blobs does not end up with one
    /// directory holding every file.
    fn path(&self, digest: &str) -> Option<PathBuf> {
        is_digest(digest).then(|| self.dir.join(&digest[..2]).join(&digest[2..]))
    }

    /// Store bytes, returning their digest.
    ///
    /// Writing the same content twice is a no-op beyond the hash: the path is
    /// derived from the content, so there is nothing to overwrite and nothing
    /// to race over.
    pub fn put(&self, bytes: &[u8]) -> Result<String, StoreError> {
        let digest = hex(&Sha256::digest(bytes));
        let Some(path) = self.path(&digest) else {
            return Err(StoreError::Io("computed digest was not a digest".into()));
        };
        if path.exists() {
            return Ok(digest);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, bytes)?;
        Ok(digest)
    }

    /// Read bytes back. `None` when this pod does not hold them — including
    /// when the digest is malformed, which is a missing blob rather than an
    /// error to a caller that is just resolving a triple.
    pub fn get(&self, digest: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(path) = self.path(digest) else {
            return Ok(None);
        };
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete bytes. Idempotent, because a resource and its bytes are removed
    /// in two steps and a retry after a crash between them must converge.
    ///
    /// A malformed digest is an error here rather than a silent success: it
    /// means a caller is about to believe it deleted something.
    pub fn remove(&self, digest: &str) -> Result<(), StoreError> {
        let Some(path) = self.path(digest) else {
            return Err(StoreError::Io(format!("{digest:?} is not a digest")));
        };
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn contains(&self, digest: &str) -> bool {
        self.path(digest).is_some_and(|p| p.exists())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        // Writing to a String cannot fail; the Result is an artefact of the
        // trait, and there is no error path to propagate.
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Bytes on disk under `path`, for quota accounting.
pub(crate) fn dir_bytes(path: &Path) -> std::io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Ok(meta.len());
    }
    let mut total = 0;
    for entry in std::fs::read_dir(path)? {
        total += dir_bytes(&entry?.path())?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_hex_and_exactly_thirty_two_bytes() {
        assert!(is_digest(&"a".repeat(64)));
        assert!(is_digest(&"0123456789abcdefABCDEF".repeat(3)[..64]));
        assert!(!is_digest(&"a".repeat(63)));
        assert!(!is_digest(&"a".repeat(65)));
        assert!(!is_digest(""));
        assert!(!is_digest("../../../etc/passwd"));
        assert!(!is_digest(&"z".repeat(64)));
    }

    #[test]
    fn hex_pads_single_digit_bytes() {
        // Without the 02 width, 0x0a would render as "a" and two different
        // hashes could collide onto one path.
        assert_eq!(hex(&[0x00, 0x0a, 0xff]), "000aff");
    }
}
