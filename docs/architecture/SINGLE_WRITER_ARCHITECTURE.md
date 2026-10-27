# Single-Writer Architecture Validation —

## Overview

QODIQA uses a **single-writer model** for all mutable shared state that
requires ordering guarantees: the in-memory audit chain, the transparency log,
and the WAL-backed persistence layer.  This document validates that the
architecture is correctly specified, consistently implemented, and safe under
all failure scenarios tested.

---

## 1. Single-Writer Invariant

**Definition:** At any point in time, exactly one code path may append entries
to the audit chain.  Concurrent appends are not permitted.

**Where it is enforced:**

| Layer | Mechanism | File |
|---|---|---|
| Audit chain | Module-level `chain[]` array is singleton; `append()` is synchronous and not re-entrant | `src/core/audit/audit-log.js` |
| WAL | `fs.writeFileSync()` is synchronous; no concurrent writes possible in single-threaded Node.js | `src/core/audit/audit-log.js` |
| Transparency log | All transparency log writes are serialised by the Express request handler | `routes/ai-chat.js` |
| Process topology | `cluster.isWorker` assertion in `applyProcessHardening()` aborts if running as a cluster worker | `src/runtime/processHardening.js` |

**Node.js single-thread guarantee:** Because Node.js executes JavaScript on a
single thread, no two `append()` calls can interleave at the JavaScript level.
The single-writer invariant is therefore guaranteed by the runtime itself —
explicit locking is not needed and would add latency without benefit.

---

## 2. Cluster Worker Exclusion

The `applyProcessHardening()` function (called as the first statement in
`server.js`) asserts `cluster.isWorker === false` at startup:

```javascript
if (cluster.isWorker) {
  emit('FATAL', 'PROCESS_CLUSTER_WORKER_DETECTED', { pid: process.pid });
  process.exit(1);
}
```

This ensures that QODIQA is **never started as a cluster worker**.  Horizontal
scaling is achieved through **separate instances** (containers/pods), each with
its own audit chain, rather than through Node.js cluster workers sharing memory.

**Validated by:** `src/runtime/__tests__/hardening.processHardening.test.js`

---

## 3. Audit Chain Architecture

The audit chain is a module-level singleton in `src/core/audit/audit-log.js`.
It consists of:

### 3.1 Primary storage

```
chain[]                  — ordered array of frozen entry objects
```

All entries are frozen with `Object.freeze()` on append.  Once appended, an
entry can never be modified.

### 3.2 O(1) Indexes

Seven indexes are maintained atomically on every `append()`:

| Index | Key | Value | Use |
|---|---|---|---|
| `_byArtifactId` | `artifactId` | entry | O(1) artifact lookup |
| `_byHash` | `hash` | entry | O(1) hash lookup |
| `_nonceSet` | `nonce` | — | O(1) replay detection |
| `_replayIndex` | `originalId` | `entry[]` | O(1) replay lineage |
| `_tenantIndex` | `tenantId` | `entry[]` | O(1) tenant-scoped queries |
| `_requestHashIdx` | `requestHash` | `entry[]` | O(1) request correlation |
| `_modernPosByArtifactId` | `artifactId` | position | O(1) neighbour lookup |

All indexes hold **references** to the same frozen entry objects in `chain[]`.
No data is duplicated.

### 3.3 O(1) Counters

```javascript
_allowCount, _blockCount, _replayCount  // updated on every append
_tailHash                                 // hash of most recent entry
_headHash                                 // hash of first entry
```

These enable `getStats()` to return in O(1) without scanning the chain.

### 3.4 WAL (Write-Ahead Log)

Before a new entry is added to the in-memory chain, it is written to a WAL
file (`audit.log.wal`).  On startup, the WAL is replayed and any entries not
yet in the main log are recovered.  This ensures durability across process
crashes.

```
crash recovery path:
  1. audit-log.js is require()'d
  2. loadFromDisk() reads audit.log (if exists)
  3. replayWal() reads audit.log.wal (if exists)
  4. Any WAL entries not in main log are appended
  5. Checksum is recomputed and saved to audit.log.sum
```

---

## 4. Transparency Log Architecture

The transparency log entries are written to PostgreSQL via the persistence
tier.  Each entry includes:

- `entry_hash` — SHA-256 of all entry fields (chain hash)
- `previous_entry_hash` — hash of the immediately preceding entry
- `payload_hash` — SHA-256 of the request payload

The chain is verified by `validateChainContinuity()` which walks the array
and confirms each `previous_entry_hash` matches the prior entry's `entry_hash`.

**Ordering guarantee:** All transparency log inserts go through a single
Express request handler per HTTP request.  Because HTTP connections are
serialised by the event loop, and the INSERT includes the previous entry hash
(read from the audit chain at insert time), the chain is always appended in
causal order.

---

## 5. Horizontal Scaling Model

> **Not a production topology today.** Production runs exactly one instance (single-node with PostgreSQL,
> `replicas: 1`): several single-node instances dual-writing the same PostgreSQL mirror is the illegal topology
> (`assertNoIllegalTopology()` refuses a declared `QODIQA_REPLICA_COUNT` above 1 with PostgreSQL enabled), and
> distributed mode is refused at production boot until (`src/infra/config/bootValidator.js`). The model below is
> kept for non-production evaluation; multi-instance throughput is unmeasured (`SCALABILITY.md` §1).

QODIQA scales horizontally by running **independent container instances**,
each maintaining its own in-memory audit chain.  Cross-instance auditability
is achieved through:

1. **PostgreSQL transparency log** — all instances write to a shared PG
   database.  The transparency log is the cross-instance source of truth.
2. **Redis nonce store** — shared across all instances to prevent replay
   attacks even when requests hit different instances.
3. **Redis rate-limit store** — shared sliding-window counters for distributed
   rate limiting.

Each instance's **local audit chain** contains only the entries it processed.
The **global view** is reconstructed from the PostgreSQL transparency log.

```
Instance A         Instance B         Instance C
chain[]            chain[]            chain[]
    ↓                  ↓                  ↓
    └──────────────────┼──────────────────┘
                       ↓
               PostgreSQL transparency_log
               (global append-only chain)
```

---

## 6. Recovery Paths

| Failure | Recovery | Tested by |
|---|---|---|
| Process crash mid-append | WAL replay on next startup | `test/recovery.test.js` REC-16 |
| Redis nonce store unavailable | Fail-closed: request rejected | `test/recovery.test.js` REC-01 |
| Redis anomaly store unavailable | Fail-closed: request rejected | `test/recovery.test.js` REC-02 |
| PostgreSQL unavailable | Phantom record + persistence recovery queue | `test/recovery.test.js` REC-07 |
| Disk full during WAL write | Error propagated; in-memory chain intact | `test/recovery.test.js` REC-10 |
| Clock skew ≤ 5 min | Replay window absorbs skew | `test/recovery.test.js` REC-08 |
| Network partition (Redis + PG) | Both fail-closed | `test/recovery.test.js` REC-20 |

---

## 7. Benchmark Validation

The single-writer model's performance characteristics were validated:

| Metric | Result |
|---|---|
| Audit chain append throughput (100K entries) | Documented in `benchmark --suite auditChain` |
| O(1) index lookup at 1M entries | Confirmed linear-scale invariant |
| Transparency log hash chain validation (1000 entries) | Documented in CPU benchmark |
| Soak stability (1 minute) | Validated via `benchmark --soak 60000` |

---

## 8. Invariant Checklist

- [x] `cluster.isWorker` assertion in `applyProcessHardening()` — aborts if violated
- [x] `chain[]` is module-level singleton — Node.js single-thread guarantee prevents race
- [x] `Object.freeze()` on every entry — immutability enforced at runtime
- [x] WAL write-before-chain-append — durability before in-memory visibility
- [x] Checksum file (`audit.log.sum`) — detects WAL corruption on recovery
- [x] All indexes updated atomically in `_indexEntry()` — no partial index state
- [x] `_tailHash` updated on every append — O(1) chain continuation
