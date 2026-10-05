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

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::manager::StoreError;
use crate::resources::fresh_ulid;

/// No legitimate temp is an hour old (spec 4, H7). The bound is what makes
/// the sweep safe against a second process sharing the pod directory: within
/// one process a live handle pins the pod, so the sweep cannot race an upload
/// — but another process could be mid-`put` into the same fanout, and its
/// in-flight temp is minutes old at worst.
///
/// Public because the tests that pin the sweep's behaviour — stale goes,
/// fresh stays, on the bound `Pod::open` actually uses — are integration
/// tests in another crate.
pub const TEMP_MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// One pod's blobs.
pub struct BlobStore {
    dir: PathBuf,
}

/// A blob on disk that no record in the metadata graph names (spec 4, H7):
/// one side of ADR 0013's promised orphan diff, the other being
/// [`Pod::referenced_blob_digests`](crate::resources::Pod::referenced_blob_digests).
pub struct Orphan {
    pub digest: String,
    pub bytes: u64,
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
    ///
    /// The write is atomic (spec 4, H1): the bytes land in a temp file in the
    /// same fanout directory, are flushed and `fsync`ed, then `rename`d onto
    /// the digest path — `rename(2)` on the same filesystem is atomic, so a
    /// crash leaves either the old bytes or no file, never a partial at the
    /// digest path. That is the invariant the dedup short-circuit below
    /// depends on: `path.exists()` may only ever mean "the complete bytes of
    /// this digest are on disk". A concurrent `put` of the same content racing
    /// the rename is harmless — same bytes, atomic replace. The fanout
    /// directory is `fsync`ed after the rename because a rename is durable
    /// only once its directory entry is: without it, a power loss after the
    /// graph commit can leave the graph naming bytes no disk ever held.
    pub fn put(&self, bytes: &[u8]) -> Result<String, StoreError> {
        let digest = hex(&Sha256::digest(bytes));
        let Some(path) = self.path(&digest) else {
            return Err(StoreError::Io("computed digest was not a digest".into()));
        };
        if path.exists() {
            return Ok(digest);
        }
        let Some(parent) = path.parent() else {
            return Err(StoreError::Io(
                "a digest path has no fanout directory".into(),
            ));
        };
        std::fs::create_dir_all(parent)?;
        let temp = parent.join(format!("{}.tmp-{}", &digest[2..], fresh_ulid()));
        if let Err(error) = write_durable(&temp, &path, bytes, parent) {
            // Best effort: an abandoned temp is swept at the next open (H7),
            // but not littering on the error path costs nothing. After a
            // successful rename the temp no longer exists, so this is a
            // no-op exactly when the bytes are already safe at the digest
            // path.
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
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

    /// Delete `.tmp-*` files in the fanout older than `older_than`, returning
    /// how many (spec 4, H7).
    ///
    /// Closes H1's orphan class at startup: a crash between temp-write and
    /// rename leaves a `.tmp-*` file, never a partial at a digest path. A
    /// digest path can never match — a temp carries `.tmp-` after 62 hex
    /// characters, a digest is exactly 64 — so the sweep cannot touch stored
    /// bytes. A temp whose mtime reads as the future (a clock step between
    /// write and sweep) is kept, not deleted: the bound exists to protect
    /// in-flight writes, and erring toward keeping costs disk only.
    pub fn sweep_temp(&self, older_than: Duration) -> Result<usize, StoreError> {
        let mut swept = 0;
        for fanout in self.fanouts()? {
            for entry in std::fs::read_dir(&fanout)? {
                let entry = entry?;
                if !entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".tmp-"))
                {
                    continue;
                }
                let stale = entry.metadata().and_then(|m| m.modified()).is_ok_and(
                    |modified| matches!(modified.elapsed(), Ok(age) if age >= older_than),
                );
                if stale && std::fs::remove_file(entry.path()).is_ok() {
                    swept += 1;
                }
            }
        }
        Ok(swept)
    }

    /// Every blob on disk that `referenced` does not name (spec 4, H7),
    /// sorted by digest. `referenced` is every digest the metadata graph
    /// names; the diff is ADR 0013's promised orphan sweep, delivered for the
    /// operator as `brolly-admin blob-sweep` because running it on every pod
    /// open spends gigabytes of walking to save kilobytes of disk.
    ///
    /// Temps are never orphans: they are not blobs yet, and removing them is
    /// [`sweep_temp`](Self::sweep_temp)'s job, bounded by age so a concurrent
    /// writer is never swept under.
    pub fn orphans(&self, referenced: &[String]) -> Result<Vec<Orphan>, StoreError> {
        let referenced: HashSet<&str> = referenced.iter().map(String::as_str).collect();
        let mut orphans = Vec::new();
        for fanout in self.fanouts()? {
            let Some(prefix) = fanout.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            for entry in std::fs::read_dir(&fanout)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                // A digest on disk is the fanout directory's two characters
                // plus the file name's sixty-two. Anything else — a `.tmp-*`
                // from a crashed write, a stray file — is not a blob.
                let digest = format!("{prefix}{name}");
                if !is_digest(&digest) || referenced.contains(digest.as_str()) {
                    continue;
                }
                orphans.push(Orphan {
                    digest,
                    bytes: entry.metadata()?.len(),
                });
            }
        }
        orphans.sort_by(|a, b| a.digest.cmp(&b.digest));
        Ok(orphans)
    }

    /// The fanout directories under the blob directory, whatever they are
    /// named: both walks are over names the store itself mints, so the exact
    /// fanout set stays this module's business.
    fn fanouts(&self) -> Result<Vec<PathBuf>, StoreError> {
        std::fs::read_dir(&self.dir)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                entry.file_type().ok()?.is_dir().then_some(Ok(entry.path()))
            })
            .collect()
    }
}

/// H1's durable write: temp file, `fsync`, rename onto the digest path, then
/// the fanout directory `fsync` that makes the rename itself durable. A
/// failure before the rename leaves only a temp (sweepable, H7); a failure
/// after it leaves the bytes safe at the digest path and the caller's retry
/// converging on the dedup short-circuit.
fn write_durable(
    temp: &Path,
    digest_path: &Path,
    bytes: &[u8],
    fanout: &Path,
) -> Result<(), StoreError> {
    let mut file = std::fs::File::create(temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temp, digest_path)?;
    std::fs::File::open(fanout)?.sync_all()?;
    Ok(())
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
