# Reliability Guide —

## Overview

This guide documents QODIQA's reliability architecture, failure injection
framework, recovery procedures, and the test coverage for all failure
scenarios.

---

## 1. Failure Injection Framework

**Module:** `src/testing/failureInjection.js`

The failure injection framework wraps store and pool interfaces to simulate
infrastructure failures without requiring real infrastructure.

### 1.1 Redis Faults

| Function | Effect |
|---|---|
| `redisDownNonceStore()` | All operations reject immediately with `ECONNREFUSED` |
| `redisLatencyNonceStore(store, ms)` | All operations are delayed by `ms` before resolving |
| `redisTimeoutNonceStore(store, ms)` | All operations hang for `ms` then reject with `ETIMEDOUT` |
| `redisDownAnomalyStore()` | All operations reject immediately |
| `redisLatencyAnomalyStore(store, ms)` | All operations are delayed |
| `redisTimeoutAnomalyStore(store, ms)` | All operations hang then reject |

### 1.2 PostgreSQL Faults

| Function | Effect |
|---|---|
| `pgDownPool()` | All `query()` calls reject immediately |
| `pgLatencyPool(pool, ms)` | All `query()` calls are delayed by `ms` |
| `pgSaturationPool(pool, ms)` | All `connect()` calls hang for `ms` then reject |

### 1.3 System Faults

| Function | Effect |
|---|---|
| `injectDiskFull()` | `fs.writeFileSync`, `fs.writeFile`, `fs.renameSync` throw `ENOSPC` |
| `injectClockSkew(ms)` | `Date.now()` returns value offset by `ms` |
| `withMemoryPressure(fn, bytes)` | Allocates `bytes` before each `fn()` call |
| `networkPartition()` | Returns failing nonce store + anomaly store + PG pool |

### 1.4 FaultInjector Class

```javascript
const { FaultInjector } = require('./src/testing/failureInjection');

const injector = new FaultInjector();
injector.diskFull();       // inject ENOSPC
injector.clockSkew(5000);  // offset time by +5s

// ... run test ...

injector.restore();  // remove all faults
```

Always call `injector.restore()` in a `finally` block or `afterEach` hook.

---

## 2. Recovery Test Coverage

**File:** `test/recovery.test.js`

| Test | Scenario | Expected behaviour |
|---|---|---|
| REC-01 | Nonce store down | `register()` rejects with `ECONNREFUSED` |
| REC-02 | Anomaly store down | `record()` rejects with `ECONNREFUSED` |
| REC-03 | Store recovery | Switching to live store succeeds immediately |
| REC-04 | Redis latency | Delayed resolve, not silent failure |
| REC-05 | Network partition | All stores reject simultaneously |
| REC-06 | Post-partition | Fresh stores service requests correctly |
| REC-07 | PG down | `isPersistenceFailure()` classifies correctly |
| REC-08 | Clock skew ±3 min | Nonce registration still works |
| REC-09 | Clock skew +24 hr | System does not crash |
| REC-10 | Disk full | `writeFileSync` throws `ENOSPC` |
| REC-11 | Disk full recovery | After `restore()`, writes succeed |
| REC-12 | Memory pressure | `withMemoryPressure` wraps fn correctly |
| REC-13 | Transient PG error | Classified as retryable, phantom returned |
| REC-14 | PG data error | Constraint violation not retried |
| REC-15 | Exceeds MAX_RETRIES | Moved to DLQ |
| REC-16 | Audit chain WAL | Module loads safely (WAL recovery on startup) |
| REC-17 | Corrupted WAL | SHA-256 detects tampered entries |
| REC-18 | Rate-limit store down | Dead store rejects all calls (fail-closed) |
| REC-19 | Redis timeout | Surfaces as `ETIMEDOUT` rejection, not hang |
| REC-20 | Redis + PG both down | All stores fail simultaneously |

---

## 3. Backup & Restore Validation

**Unit tests (HMAC-seal algorithm only):** `test/pgBackupSealPrimitive.test.js`
(renamed from `backup-restore.test.js` — BACKUP-2 remediation; that name/header
previously implied it validates the backup script itself, which it never did).

**Real script execution (actual `pg_dump`/`pg_restore`, against a live
Postgres container):** `.github/workflows/backup-restore.yml`'s `dr-postgres`
job, "pg-backup.sh — real full backup..." / "...real restore path..." steps.

**Separate JSON-based file-store DR framework** (audit chain, key store,
policy store — not PostgreSQL): `test/backupRestore.test.js`, real
end-to-end, see §BACKUP-1.

### 3.1 Backup script

**File:** `scripts/pg-backup.sh`

Modes (`scripts/pg-backup.sh` usage line):
- `full` — `pg_dump` with custom format, parallel jobs; encrypted to `*.dump.enc` when
  `QODIQA_BACKUP_ENCRYPTION_KEY` is set (`QODIQA_BACKUP_REQUIRE_ENCRYPTION=true` refuses plaintext); written under
  `${QODIQA_BACKUP_DIR}/full/`, or `full/<daily|weekly|monthly>/` when a tier argument is given
- `incremental` — **unsupported**: exits 2 with `BACKUP_INCREMENTAL_UNSUPPORTED` (`pg_basebackup` needs the
  `REPLICATION` attribute on `qodiqa_backup`, deliberately not granted — design decision; PITR is unavailable until
  an administrator grants it)
- `verify` — seal check and `pg_restore --list` (non-destructive) of the **newest** backup only (in `full/` or the given tier), not a named file
- `restore [backup_file]` — seal verification of the chosen file, then `pg_restore`
- `pitr-restore` — prepares a PGDATA from a base backup; usable only once base backups exist (see `incremental`)

 Previously listed `incremental` as a working `pg_basebackup` mode and omitted encryption and
`pitr-restore`.

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `QODIQA_BACKUP_DIR` | `/var/backups/qodiqa` | Base backup directory |
| `QODIQA_BACKUP_RETAIN_DAYS` | `30` | Days to keep full backups |
| `QODIQA_BACKUP_HMAC_KEY` | — | 32+ char key for HMAC-SHA256 seal |
| `QODIQA_BACKUP_JOBS` | `4` | pg_dump parallel jobs |
| `ALERT_WEBHOOK_URL` | — | Slack/PagerDuty alert endpoint |

### 3.2 Integrity seal

Each backup file `qodiqa-full-<timestamp>.dump` is accompanied by
`qodiqa-full-<timestamp>.dump.seal` containing the HMAC-SHA256 digest
computed using `QODIQA_BACKUP_HMAC_KEY`.

**Seal algorithm:**
```
seal = HMAC-SHA256(key=QODIQA_BACKUP_HMAC_KEY, message=<backup file bytes>)
```

If `QODIQA_BACKUP_HMAC_KEY` is not set, falls back to plain SHA-256 checksum
(no authentication — warns to the audit log).

**Restore gate:** `scripts/pg-backup.sh restore` verifies the HMAC seal
before allowing `pg_restore` to run.  A mismatched seal (tamper or wrong key)
aborts with `BACKUP_SEAL_INVALID`.

### 3.3 Audit log format

Every backup operation appends a structured JSON line to
`<BACKUP_DIR>/backup-audit.jsonl`:

```json
{"ts":"2026-07-02T02:00:01Z","level":"INFO","event":"BACKUP_COMPLETED","mode":"full","sizeBytes":104857600,"durationMs":45320}
```

Events: `BACKUP_STARTED`, `BACKUP_COMPLETED`, `BACKUP_FAILED`, `SEAL_WRITTEN`,
`SEAL_VERIFIED`, `SEAL_INVALID`, `RETENTION_ENFORCED`, `RESTORE_STARTED`,
`RESTORE_COMPLETED`.

### 3.4 Backup validation tests (BR-01 to BR-20)

| Test | Coverage |
|---|---|
| BR-01 | HMAC seal is deterministic |
| BR-02 | Tampered content changes seal |
| BR-03 | Valid seal passes verification |
| BR-04 | Tampered content fails verification |
| BR-05 | Wrong key fails verification |
| BR-06 | Audit log entry has required fields |
| BR-07 | JSONL format — each line parses |
| BR-08 | Retention: stale files identified |
| BR-09 | Filename encodes ISO 8601 timestamp |
| BR-10 | Seal file naming `<backup>.seal` |
| BR-11 | Directory structure: full/wal/verify |
| BR-12 | Restore validates seal before permitting |
| BR-13 | Missing seal blocks restore |
| BR-14 | Metadata includes schema version |
| BR-15 | Default parallel jobs is 4 |
| BR-16 | No HMAC key falls back to SHA-256 |
| BR-17 | All log entry fields have correct types |
| BR-18 | Multiple seals verify independently |
| BR-19 | HMAC-SHA256 output is 64 hex chars |
| BR-20 | Content round-trips correctly via temp file |

---

## 4. Recommended Monitoring

### 4.1 SLO thresholds

| Metric | Target | Alert threshold |
|---|---|---|
| Enforcement pipeline error rate | < 0.01% | > 0.1% |
| Redis latency p99 | < 5 ms | > 20 ms |
| PG query latency p99 | < 100 ms | > 500 ms |
| Audit chain WAL write latency | < 10 ms | > 100 ms |
| Nonce store reject rate | 0% (expected) | > 0 (fail-closed firing) |

### 4.2 Key alert events

Monitor `level: "FATAL"` events in structured logs:
- `PROCESS_CLUSTER_WORKER_DETECTED` — single-writer invariant violated
- `UNHANDLED_REJECTION` — uncaught async error
- `UNCAUGHT_EXCEPTION` — process about to exit

### 4.3 Backup monitoring

Monitor `backup-audit.jsonl` for:
- `BACKUP_FAILED` events → page on-call
- `SEAL_INVALID` events → investigate immediately (potential tamper)
- `RETENTION_ENFORCED: removed > 0` → normal (log for audit trail)
