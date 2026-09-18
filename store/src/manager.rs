//! Store lifecycle: one on-disk Oxigraph database per user, plus the
//! instance's own.
//!
//! Pods are opened lazily and cached in an LRU, so an idle subdomain does not
//! keep its store mapped forever. Eviction drops the in-memory handle only; the
//! on-disk data stays.
//!
//! The LRU ceiling is a real budget line at thousands of users — each open
//! store carries its own memtables and file handles. `benches/` measures it;
//! the predecessor shipped 500/1h defaults that were never validated against a
//! number.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use moka::sync::Cache;
use oxigraph::store::Store;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum StoreError {
    Io(String),
    Backend(String),
    NotFound,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Backend(e) => write!(f, "store backend: {e}"),
            StoreError::NotFound => write!(f, "store not found"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

impl From<oxigraph::store::StorageError> for StoreError {
    fn from(e: oxigraph::store::StorageError) -> Self {
        StoreError::Backend(e.to_string())
    }
}

impl From<oxigraph::store::LoaderError> for StoreError {
    fn from(e: oxigraph::store::LoaderError) -> Self {
        StoreError::Backend(e.to_string())
    }
}

/// Opens and caches per-user pods, and owns the instance store.
pub struct StoreManager {
    base: PathBuf,
    pods: Cache<Uuid, Arc<Store>>,
    /// Every pod handle still alive anywhere, cached or not.
    ///
    /// RocksDB lets a process open a directory once. The cache can evict a pod
    /// while a request still holds its `Arc`, and a second `Store::open` on
    /// that directory is then refused by the lock. So a cache miss looks here
    /// first and hands back the live handle. The lock covers only the map;
    /// concurrent opens of one pod are deduplicated by the cache itself.
    live: Mutex<HashMap<Uuid, Weak<Store>>>,
    instance: Arc<Store>,
}

impl StoreManager {
    /// Open (or create) the store tree under `base`.
    ///
    /// `max_open` bounds resident pods; `idle_secs` evicts handles that have
    /// gone quiet. Both are budget numbers — see `benches/store_open.rs`.
    pub fn open(
        base: impl Into<PathBuf>,
        max_open: u64,
        idle_secs: u64,
    ) -> Result<Self, StoreError> {
        let base = base.into();
        std::fs::create_dir_all(base.join("users"))?;
        let instance_dir = base.join("instance");
        std::fs::create_dir_all(&instance_dir)?;

        Ok(Self {
            instance: Arc::new(Store::open(&instance_dir)?),
            pods: Cache::builder()
                .max_capacity(max_open)
                .time_to_idle(std::time::Duration::from_secs(idle_secs))
                .build(),
            live: Mutex::new(HashMap::new()),
            base,
        })
    }

    fn pod_dir(&self, user: Uuid) -> PathBuf {
        self.base.join("users").join(user.to_string())
    }

    /// The user's blob directory, creating it on first use.
    ///
    /// Under the pod directory, so `delete_pod` takes the bytes with it and
    /// `pod_bytes` counts them — media has to sit inside the same quota and the
    /// same delete as the triples, or neither number means anything.
    pub fn blobs(&self, user: Uuid) -> Result<crate::blobs::BlobStore, StoreError> {
        crate::blobs::BlobStore::open(self.pod_dir(user).join("blobs"))
    }

    /// Content-addressed storage for the member's ATProtocol repo blocks.
    ///
    /// Separate from `blobs` even though both are content-addressed immutable
    /// bytes: media and repo blocks have different lifecycles — a blob is
    /// deleted when its last resource goes, a repo block is history — and
    /// mixing them would make either sweep reason about the other.
    pub fn repo_blocks(&self, user: Uuid) -> Result<crate::blobs::BlobStore, StoreError> {
        crate::blobs::BlobStore::open(self.pod_dir(user).join("repo"))
    }

    /// The user's pod, opening it if necessary. Creates on first use.
    pub fn pod(&self, user: Uuid) -> Result<Arc<Store>, StoreError> {
        // `try_get_with` runs `open_pod` at most once per user at a time, and
        // concurrent requests for that user wait for its result. Requests for
        // different users open in parallel: opening costs milliseconds (ADR
        // 0006), so one lock across every open would queue members behind each
        // other on a burst of cache misses.
        self.pods
            .try_get_with(user, || self.open_pod(user))
            .map_err(|e| StoreError::clone(&e))
    }

    /// Hand back the live handle if the cache evicted one a request still
    /// holds, and open the database only when nothing does.
    fn open_pod(&self, user: Uuid) -> Result<Arc<Store>, StoreError> {
        if let Some(store) = self.live_handles().get(&user).and_then(Weak::upgrade) {
            return Ok(store);
        }
        // The graph lives in its own subdirectory: Oxigraph owns that
        // directory's layout, and `blobs/` alongside it would be a stray
        // directory inside a database it manages.
        let dir = self.pod_dir(user).join("rdf");
        std::fs::create_dir_all(&dir)?;
        let store = Arc::new(Store::open(&dir)?);
        let mut live = self.live_handles();
        // Drop entries whose pods have closed, so the map tracks what is open
        // rather than everyone who was ever served.
        live.retain(|_, handle| handle.strong_count() > 0);
        live.insert(user, Arc::downgrade(&store));
        Ok(store)
    }

    /// The live-handle map. A poisoned lock only means another thread panicked
    /// while holding it; the map holds weak handles, so nothing in it can be
    /// half-written.
    fn live_handles(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Weak<Store>>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The server agent's own store — the cross-user query surface (ADR 0005).
    pub fn instance(&self) -> &Arc<Store> {
        &self.instance
    }

    /// Delete a user's pod outright.
    ///
    /// This is the whole delete story: content lives in exactly one place, so
    /// removing the directory removes it. The instance index is left holding
    /// dangling pointers, which is the correct steady state — they sweep lazily
    /// on dereference (D5).
    pub fn delete_pod(&self, user: Uuid) -> Result<(), StoreError> {
        self.pods.invalidate(&user);
        self.live_handles().remove(&user);
        let dir = self.pod_dir(user);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    pub fn pod_exists(&self, user: Uuid) -> bool {
        self.pod_dir(user).exists()
    }

    /// Resident pod count. Exposed for the benchmark and for operational
    /// metrics — the LRU ceiling is only meaningful if it can be observed.
    pub fn open_pods(&self) -> u64 {
        self.pods.run_pending_tasks();
        self.pods.entry_count()
    }

    /// Bytes on disk for one user, for quota accounting. Cheap because pods are
    /// physically separate — the property that per-user isolation buys.
    pub fn pod_bytes(&self, user: Uuid) -> std::io::Result<u64> {
        crate::blobs::dir_bytes(&self.pod_dir(user))
    }
}
