# 0006 — Store budget: what a pod actually costs

**Status:** Accepted (2026-08-18)
**Closes:** open decision O5.

## Context

Per-user isolation (D2) means one on-disk Oxigraph database per user, opened
lazily and held in an LRU. The predecessor shipped a ceiling of 500 open stores
with a 1h idle timeout and **never validated either number against a
measurement**. At the thousands-of-users target (D16) those are capacity
decisions, not defaults.

`store/examples/store_budget.rs` measures them.

## Measurements

200 pods × 20 records, release build, Apple Silicon, local SSD:

| | total | per pod |
|---|---|---|
| create + write | 1.4 s | **6.98 ms** |
| cold open (LRU miss) | 1.6 s | **8.10 ms** |
| warm (LRU hit) | 108 µs | **541 ns** |
| disk | 85.0 MB | **435 KB** |

## What follows

**An LRU miss costs ~8 ms; a hit costs ~0.5 µs.** That is a factor of ~15,000.
The cache is not an optimization, it is the difference between a request that
feels instant and one that does not. Size the ceiling to hold the active
working set, not a round number.

**Per-pod disk overhead is ~435 KB for an essentially empty pod.** Twenty small
records do not account for it — this is RocksDB's floor per instance (manifest,
WAL, initial SSTs). At 10,000 users that is **~4.4 GB before any user stores
anything**. Capacity planning starts from that floor, and it is the concrete
price of physical isolation.

**Starting configuration:** keep `max_open = 500` but treat it as a working-set
estimate to be revised against production hit rate, and instrument
`StoreManager::open_pods()` plus a miss counter so the number can be revised
from data rather than guessed twice.

## Also found: RocksDB holds an exclusive per-directory process lock

Two `StoreManager`s cannot open the same tree, even in one process — the second
fails with `lock hold by current process`. Consequences:

- **One process owns the data directory.** This is consistent with D1 (single
  binary, single image) and with horizontal scale-out being a non-goal, but it
  is now a hard constraint rather than a preference: no sidecar can read the
  files, and two server instances cannot share a volume.
- **Tests and benchmarks must drop a manager before reopening its directory.**
- **Backups need either a stopped process or an explicit snapshot endpoint.**

## Not yet measured

Resident **memory** per open store. Disk is a proxy, not a substitute — RocksDB
memtables and block cache are the real RSS driver and they scale with the LRU
ceiling. Measure before raising `max_open` above 500.
