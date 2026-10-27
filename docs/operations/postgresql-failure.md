# QODIQA PostgreSQL Failure Runbook

**Operations & Production Readiness**

| Field | Value |
|-------|-------|
| Document | PostgreSQL Failure Runbook |
| Version | 1.0.0 |
| Owner | Platform Engineering / SRE |
| Audience | SRE, On-Call, DBA |
| Classification | Internal — Operational |
| Last Updated | 2026-07-03 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [PostgreSQL Role in QODIQA](#2-postgresql-role-in-qodiqa)
3. [Database Unavailable](#3-database-unavailable)
4. [Replication Issues](#4-replication-issues)
5. [Disk Full](#5-disk-full)
6. [Corruption](#6-corruption)
7. [Slow Queries](#7-slow-queries)
8. [Deadlocks](#8-deadlocks)
9. [Recovery](#9-recovery)
10. [Verification](#10-verification)
11. [Post-Recovery Validation](#11-post-recovery-validation)

---

## 1. Overview

> **CORRECTION:** this overview predates the work and is only partly true today. In production the
> gateway REFUSES TO START without PostgreSQL (`QODIQA_PG_ENABLED` is required by the boot validator), the control plane (RBAC,
> signing identities, key-status timeline, tenants) lives in PostgreSQL, and a failed mandatory audit append returns
> `AUDIT_PERSISTENCE_FAILED` (503) and takes the instance out of `/ready` — so a PostgreSQL outage IS an enforcement outage for
> new decisions. The "best-effort" description below applies only to the observability/queryability surfaces listed in the table.

PostgreSQL is **not on the critical enforcement path** for QODIQA. The audit chain is file-authoritative: QODIQA can serve enforcement requests and record decisions even if PostgreSQL is completely unavailable. PostgreSQL outages degrade observability and queryability but do not cause enforcement failures.

**The PG-best-effort / Redis-fail-closed asymmetry.** This is a deliberate architectural pattern, not an inconsistency: PostgreSQL is treated as **best-effort** (see the impact table below — every affected surface degrades gracefully, nothing blocks enforcement), while [Redis is fail-closed](redis-failure.md) (an unreachable nonce store, or a disconnected consent-revocation subscriber, actively **blocks** enforcement traffic rather than degrading). The reasoning: Redis backs security-critical, real-time control planes (replay protection, consent-revocation propagation) where continuing to serve traffic on stale/missing state would itself be the security failure; PostgreSQL backs compliance/observability surfaces (transparency log, policy history, investigations, reporting) where a temporary gap is an operational inconvenience, not a security exposure, and the file-authoritative audit chain remains the evidentiary source of truth regardless. **Operational consequence:** a PostgreSQL outage is a P2/P3 (degraded queryability — see the impact table), while an equivalent-duration Redis outage is a P1 (active enforcement outage) — do not triage them with the same urgency. See § for the source finding and cross-reference [Redis Failure Runbook §1](redis-failure.md#1-overview) for the mirror-image framing.

**PostgreSQL failure impact:**

| Component | Impact When PG Down | Severity |
|-----------|--------------------|---------|
| `POST /ai/chat` enforcement | **Not affected** — file audit chain continues | None |
| Audit chain (file) | **Not affected** — writes to local NDJSON file | None |
| Audit chain (PG replica) | Sync gap grows; see §3.4 for exactly what does and does not auto-heal | Medium |
| Transparency log | New entries cannot be written | Medium |
| Policy management | Policy reads and writes fail | Medium |
| Consent lookups | Falls through to DB miss (enforcement depends on policy) | Low-High |
| Compliance reporting | Not available | Low |
| Investigations/evidence | Not available | Low |

---

## 2. PostgreSQL Role in QODIQA

QODIQA uses PostgreSQL for:

1. **Audit chain replica** (`audit_chain` table) — fire-and-forget async writes from the file-authoritative log.
2. **Transparency log** (`transparency_log_entries`, `transparency_roots`) — on-path writes during enforcement (but failure is caught and logged, not fatal).
3. **Signing keys** (`signing_keys`) — key store (but keys are also in `keys.json` on disk — PG is a replica).
4. **Policy store** (`policies`) — policy reads (but QODIQA hot-loads policies from file, not PG on every request).
5. **Consent registry** (`consent_registry`) — positive and negative consent lookups.
6. **RBAC** (`rbac_users`) — operator authentication.
7. **Evidence, investigations, compliance** — various admin functions.

**PostgreSQL connectivity is monitored by `pgLagMonitor.js`**, which emits:
- `AUDIT_PG_SYNC_LAG` — when the PG replica is falling behind
- `AUDIT_PG_UNAVAILABLE` — when PG cannot be reached
- `AUDIT_PG_RECOVERED` — when PG reconnects

These events are logged but do not affect enforcement.

---

## 3. Database Unavailable

### 3.1 Detection

```bash
# Test PostgreSQL connectivity
psql "$QODIQA_PG_URL" -c "SELECT 1;" 2>&1
# Failure: psql: error: connection to server ... failed: ...

# Check QODIQA logs for PG unavailability events
grep 'AUDIT_PG_UNAVAILABLE\|PG connection\|pg.*error' \
  "$QODIQA_AUDIT_LOG" | tail -20

# Check the metrics for PG-related lag
# /metrics is ops-authenticated (src/app.js:179): OPS_AUTH_HEADER_FILE is a 0600 file holding one line
# "Authorization: Bearer <operator API key>" (curl -H @file keeps the key out of argv; docs/operations/deployment-runbook.md §8).
curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep qodiqa_audit
```

Expected log when PG becomes unavailable:
```json
{"level":"warn","msg":"AUDIT_PG_UNAVAILABLE","error":"ECONNREFUSED 5432","ts":"..."}
{"level":"info","msg":"Enforcement continues — file audit chain is authoritative","ts":"..."}
```

### 3.2 Confirm Enforcement Is Continuing

```bash
# Verify enforcement is still working (this is the most important check)
curl -sf http://localhost:3000/ready
# Expected: 200 (enforcement continues despite PG outage)

curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep qodiqa_execution_integrity_full
# Expected: 1 (PG outage does not affect execution integrity)
```

### 3.3 Identify Cause

```bash
# Is PostgreSQL running?
systemctl status postgresql
# OR
docker ps | grep postgres

# Is the network reachable?
nc -zv "$QODIQA_PG_HOST" "$QODIQA_PG_PORT"
# Expected: Connection to ... succeeded!

# Are PostgreSQL connections exhausted?
psql -U postgres -h "$QODIQA_PG_HOST" -c "
  SELECT COUNT(*), datname
  FROM pg_stat_activity
  GROUP BY datname;
"

# Is PostgreSQL in crash recovery mode?
# Check PG logs for FATAL or PANIC messages
tail -100 /var/log/postgresql/postgresql-*.log | grep -E 'FATAL|PANIC|ERROR'
```

### 3.4 Persistence Recovery Queue Monitoring

The persistence recovery queue's durable store is PostgreSQL itself — the
`persistence_recovery_queue` table (migration 032), not Redis. Redis outages
have zero effect on this queue at all — see `docs/operations/redis-failure.md`.

left one disclosed residual risk: a *sustained, full* PostgreSQL
outage meant the queue's own `INSERT` failed right alongside the original
write it would have queued, with no third, independent store to fall back
to. **closes this gap** with a filesystem-backed durable journal
(`src/core/persistenceRecovery/journal.js`):

- **Brief/transient PG blips** (a dropped connection, a momentary failover):
  the individual retry `INSERT` into `persistence_recovery_queue` typically
  still succeeds even while the *original* write it's retrying failed, so
  the failed operation is durably queued and auto-replays once PG is fully
  responsive again — unchanged from .
- **A sustained, full PG outage**: when the queue's own `INSERT` also fails,
  `recoveryManager.enqueue()` now falls back to a local, disk-backed,
  crash-safe journal (`data/prq-journal/` by default, override via
  `QODIQA_PRQ_JOURNAL_DIR`) instead of dropping the operation. A background
  worker (`journalWorker.js`, `PRQ_JOURNAL_POLL_INTERVAL_MS`, default 5s)
  continuously scans this journal and replays each entry back into
  `persistence_recovery_queue` as soon as PostgreSQL is reachable again —
  at which point the existing retry/backoff/DLQ pipeline in `worker.js`
  takes over exactly as it would for any other queued operation. This
  applies uniformly to every operation type
  (`ATTESTATION_SAVE`, `CERTIFICATION_SAVE`, `PORTAL_VERIFICATION_SAVE`,
  `WEBHOOK_DELIVERY`, `AUDIT_CHAIN_PG_SAVE`, `EVIDENCE_CHAIN_SAVE`) — the
  first four previously had no independent durability path at all during a
  simultaneous PG+recovery-queue failure; the last two were already
  backstopped by the always-active file-based audit chain, and the journal
  is simply additive there.
- **The one remaining unrecoverable case**: PostgreSQL AND the local disk
  volume backing the journal both unavailable at the same instant (e.g. the
  node's own disk is full or unmounted while PG is also down). This is
  loudly surfaced via `JOURNAL_WRITE_FAILED` log events and the
  `qodiqa_prq_journal_write_failed_total` counter (should be ~0 in normal
  operation) — never silently swallowed. Two independent infrastructure
  failures occurring simultaneously is the only scenario this remediation
  cannot cover; ensure `data/prq-journal/` sits on the same durable,
  persistent volume as `audit.log` (in Kubernetes, the same PersistentVolumeClaim
  mounted at `QODIQA_AUDIT_LOG`'s parent directory — a pod restart onto
  ephemeral local storage would lose both).

Monitor queue/DLQ/journal depth via the admin API (requires `READ_RECOVERY_QUEUE`):

```bash
curl -s "$QODIQA_BASE_URL/v1/prq/stats" \
  -H "Authorization: Bearer $QODIQA_OPS_TOKEN" | jq .
# { "queueDepth": ..., "dlqDepth": ..., "journalDepth": ..., "journalOldestEntryAgeSeconds": ..., "journalBytes": ..., "pgReady": true, ... }
# queueDepth increases while PG is unavailable (for writes that did land in
# the queue before or after the exact outage window); it drains back down
# once PG recovers and the worker resumes processing.
# journalDepth is nonzero ONLY during the narrow window where PostgreSQL was
# unreachable at the exact moment the recovery-queue INSERT itself was
# attempted; journalWorker.js drains it back to 0 automatically once
# PostgreSQL is reachable again — it should not need manual intervention.
```

```sql
-- Direct inspection (equivalent to the admin API above), broken down by
-- operation type — useful when the API itself is unreachable.
SELECT operation_type, count(*)
FROM persistence_recovery_queue
WHERE status = 'PENDING'
GROUP BY operation_type
ORDER BY count(*) DESC;
```

```bash
# Inspect the filesystem journal directly (equivalent to journalDepth above)
# — each file is one pending operation, named by a SHA-256 hash of its
# operationId. A ".corrupt" suffix means listEntries() quarantined a
# malformed/tampered entry — inspect it manually, it will never auto-replay.
ls -la "${QODIQA_PRQ_JOURNAL_DIR:-./data/prq-journal}"
```

---

## 4. Replication Issues

### 4.1 Primary-Replica Lag

If running PostgreSQL with streaming replication:

```bash
# Check replication lag on the primary
psql -U postgres -h PRIMARY_HOST -c "
  SELECT
    client_addr,
    state,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    pg_wal_lsn_diff(sent_lsn, replay_lsn) AS replay_lag_bytes
  FROM pg_stat_replication;
"

# On the replica:
psql -U postgres -h REPLICA_HOST -c "
  SELECT
    now() - pg_last_xact_replay_timestamp() AS replication_lag,
    pg_is_in_recovery() AS is_replica,
    pg_last_wal_receive_lsn() AS receive_lsn,
    pg_last_wal_replay_lsn() AS replay_lsn;
"
```

### 4.2 QODIQA Writes to Primary Only

QODIQA's `QODIQA_PG_URL` should always point to the primary PostgreSQL node. If it is accidentally pointing to a replica:

```bash
# Verify the connected host is the primary
psql "$QODIQA_PG_URL" -c "SELECT pg_is_in_recovery();"
# Expected: f (false = primary)
# If 't' (true = replica): QODIQA is writing to a replica — reads may work but writes fail
```

Update `QODIQA_PG_URL` to the primary host and restart QODIQA.

---

## 5. Disk Full

### 5.1 Detection

```bash
# Check disk space on the PostgreSQL data directory
df -h $(psql -U postgres -t -c "SHOW data_directory;")

# Check the size of the WAL directory (can grow rapidly under high load)
du -sh $(psql -U postgres -t -c "SHOW data_directory;" | tr -d ' ')/pg_wal/

# Check for large databases
psql -U postgres -c "
  SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size
  FROM pg_database
  ORDER BY pg_database_size(datname) DESC;
"
```

### 5.2 Emergency Disk Space Recovery

```bash
# 1. Identify large tables
psql "$QODIQA_PG_URL" -c "
  SELECT
    schemaname || '.' || tablename AS table,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS total_size,
    pg_size_pretty(pg_relation_size(schemaname || '.' || tablename)) AS table_size,
    pg_size_pretty(pg_indexes_size(schemaname || '.' || tablename)) AS index_size
  FROM pg_tables
  WHERE schemaname = 'public'
  ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC
  LIMIT 20;
"

# 2. Check for bloat (dead tuples after deletes/updates)
psql "$QODIQA_PG_URL" -c "
  SELECT relname, n_dead_tup, n_live_tup,
         round(n_dead_tup * 100.0 / GREATEST(n_live_tup + n_dead_tup, 1), 2) AS dead_pct
  FROM pg_stat_user_tables
  WHERE n_dead_tup > 1000
  ORDER BY n_dead_tup DESC;
"

# 3. VACUUM to reclaim dead tuple space
psql "$QODIQA_PG_URL" -c "VACUUM ANALYZE;" &
# Run in background as it may take time for large tables

# 4. Archive or delete old partitions (if table partitioning is in use)
# (QODIQA does not currently use partitioning — manage retention manually)

# 5. If WAL directory is large: check for long-running transactions holding WAL
psql -U postgres -c "
  SELECT pid, now() - xact_start AS duration, query
  FROM pg_stat_activity
  WHERE xact_start IS NOT NULL
  ORDER BY xact_start
  LIMIT 10;
"
# Kill long-running transactions if necessary
psql -U postgres -c "SELECT pg_terminate_backend(PID);"
```

### 5.3 QODIQA-Specific Large Tables

The tables most likely to grow large in QODIQA deployments:

| Table | Growth Driver | Mitigation |
|-------|--------------|-----------|
| `audit_chain` | One row per enforcement request | Partition by month; archive old data |
| `transparency_log_entries` | One row per enforcement + verification | Partition; compress old entries |
| `platform_audit_events` | All audit events across all categories | Apply retention policy; archive |
| `nonce_store` (if using PG fallback) | One row per request | TTL-based cleanup job |

```bash
# Check retention policy status
psql "$QODIQA_PG_URL" -c "
  SELECT policy_name, table_name, retention_days, last_run
  FROM audit_retention_policies
  ORDER BY last_run;
"
```

---

## 6. Corruption

### 6.1 Detection

```bash
# PostgreSQL will log errors like:
# ERROR: invalid page header in block N of relation base/.../
# FATAL: database file appears to contain N database files

# Run checksums validation (PostgreSQL 12+ with data checksums enabled)
pg_dumpall -U postgres --schema-only > /dev/null 2>&1 || \
  echo "CRITICAL: Schema dump failed — potential corruption"

# Check for invalid pages
psql -U postgres -c "
  CREATE EXTENSION IF NOT EXISTS pageinspect;
  -- Check a specific table page (adjust table and block number)
  SELECT * FROM page_header(get_raw_page('audit_chain', 0));
"
```

### 6.2 Containment

```bash
# Stop QODIQA immediately to prevent further writes to corrupted storage
kubectl scale deployment qodiqa --replicas=0 -n qodiqa

# Preserve forensic state
pg_dumpall -U postgres --globals-only \
  > "/opt/qodiqa/forensic/globals-pre-recovery-$(date +%Y%m%d).sql" 2>/dev/null || true
```

### 6.3 Recovery

Follow the Database Restore procedure in the [Restore Runbook](restore-runbook.md) Section 5.

If only a single table is corrupted and the rest of the database is intact:

```bash
# Try to dump all other tables (excluding the corrupted one)
pg_dump "$QODIQA_PG_URL" \
  --exclude-table=audit_chain \
  --format=custom --compress=9 \
  > "/opt/qodiqa/backups/pg/partial-post-corruption-$(date +%Y%m%d).dump.gz"

# Restore the corrupted table from backup
# (follow Restore Runbook Section 4.1 — Partial Restore)
```

---

## 7. Slow Queries

### 7.1 Detection

```bash
# Identify slow queries (> QODIQA_PG_SLOW_MS = 1000ms default)
psql "$QODIQA_PG_URL" -c "
  SELECT
    pid,
    now() - query_start AS duration,
    state,
    LEFT(query, 100) AS query_snippet
  FROM pg_stat_activity
  WHERE state = 'active'
  AND now() - query_start > interval '1 second'
  ORDER BY query_start;
"

# Check pg_stat_statements for historical slow query analysis
psql "$QODIQA_PG_URL" -c "
  SELECT
    LEFT(query, 80) AS query,
    calls,
    round(total_exec_time::numeric / calls, 2) AS avg_ms,
    round(total_exec_time::numeric, 2) AS total_ms,
    rows
  FROM pg_stat_statements
  WHERE calls > 10
  ORDER BY avg_ms DESC
  LIMIT 20;
"
```

### 7.2 Common Slow Query Causes in QODIQA

| Query Pattern | Cause | Remediation |
|--------------|-------|------------|
| `audit_chain` sequential scan | Missing index on `artifact_id` | Migration 021 adds indexes — verify |
| `transparency_log_entries` slow join | Index not used for date range | Add index on `created_at` |
| `consent_registry` lookup | High cardinality tenant lookups | Verify composite index on `(actor_id, action, tenant_id)` |
| `platform_audit_events` count | Table size > 100M rows | Apply retention; partition |

```bash
# Verify critical indexes exist
psql "$QODIQA_PG_URL" -c "
  SELECT indexname, tablename, indexdef
  FROM pg_indexes
  WHERE tablename IN ('audit_chain','transparency_log_entries','consent_registry')
  ORDER BY tablename, indexname;
"

# Run EXPLAIN ANALYZE on a slow query
psql "$QODIQA_PG_URL" -c "
  EXPLAIN (ANALYZE, BUFFERS)
  SELECT * FROM audit_chain WHERE artifact_id = 'test-id' LIMIT 1;
"
```

### 7.3 Statement Timeout

QODIQA sets a statement timeout (`QODIQA_PG_STATEMENT_TIMEOUT_MS=30000`). Queries exceeding 30 seconds are automatically killed. If many queries are hitting this timeout:

```bash
grep 'statement_timeout\|canceling statement due to statement timeout' \
  /var/log/postgresql/postgresql-*.log | tail -20
```

---

## 8. Deadlocks

### 8.1 Detection

```bash
# Check for deadlocks in PG logs
grep 'deadlock' /var/log/postgresql/postgresql-*.log | tail -20

# Monitor current locks
psql "$QODIQA_PG_URL" -c "
  SELECT
    bl.pid AS blocked_pid,
    a.usename AS blocked_user,
    kl.pid AS blocking_pid,
    ka.usename AS blocking_user,
    a.query AS blocked_query
  FROM pg_catalog.pg_locks bl
  JOIN pg_catalog.pg_stat_activity a ON a.pid = bl.pid
  JOIN pg_catalog.pg_locks kl ON kl.transactionid = bl.transactionid AND kl.pid != bl.pid
  JOIN pg_catalog.pg_stat_activity ka ON ka.pid = kl.pid
  WHERE NOT bl.granted;
"
```

### 8.2 QODIQA Deadlock Scenarios

QODIQA's `audit_chain` and `transparency_log_entries` tables are INSERT-only. Deadlocks on these tables indicate:
- Multiple concurrent inserts acquiring row locks in different orders (unusual for INSERT-only tables).
- Background VACUUM competing with an INSERT (transient — resolves automatically).
- An application-layer bug in a new feature.

```bash
# Log deadlock details for the last 7 days
psql "$QODIQA_PG_URL" -c "
  SELECT query, state, wait_event_type, wait_event, query_start
  FROM pg_stat_activity
  WHERE wait_event = 'deadlock';
"
```

### 8.3 Resolving Deadlocks

```bash
# Kill the blocking process (if it's safe to do so)
psql -U postgres -c "SELECT pg_terminate_backend(BLOCKING_PID);"

# If deadlocks are frequent, check for missing indexes that cause lock escalation
# and review the application code path that triggered the deadlock
```

---

## 9. Recovery

### 9.1 Restart PostgreSQL

```bash
# systemd
systemctl restart postgresql@15-main

# Docker
docker-compose -f deploy/docker/docker-compose.prod.yml restart postgres

# Kubernetes
kubectl delete pod <postgres-pod> -n qodiqa

# Wait for readiness
until psql "$QODIQA_PG_URL" -c "SELECT 1;" > /dev/null 2>&1; do
  echo "Waiting for PostgreSQL..."
  sleep 2
done
echo "PostgreSQL: READY"
```

### 9.2 QODIQA Automatic Recovery

When PostgreSQL recovers:
1. QODIQA's PostgreSQL connection pool reconnects automatically.
2. `pgLagMonitor.js` emits `AUDIT_PG_RECOVERED` log.
3. `journalWorker.js` drains the filesystem journal first —
   any operation that fell back to local disk during the outage (because
   the recovery-queue INSERT itself failed) is replayed into
   `persistence_recovery_queue`.
4. The persistence recovery queue drains — all queued writes (both the ones
   queued normally and the ones just replayed from the journal) are applied
   to the database.
5. Transparency log sync resumes.

Monitor the recovery:

```bash
# Watch the persistence recovery queue AND journal drain together
# (PostgreSQL-backed queue — see §3.4; filesystem journal — FAILOVER-1)
watch -n 5 "curl -s '$QODIQA_BASE_URL/v1/prq/stats' -H 'Authorization: Bearer $QODIQA_OPS_TOKEN' | jq '{queueDepth, journalDepth}'"

# Watch for the PG recovered log message
grep 'AUDIT_PG_RECOVERED' "$QODIQA_AUDIT_LOG" | tail -5
```

### 9.3 Full Database Restore

If the database cannot be recovered through restart, follow the [Restore Runbook](restore-runbook.md) Section 5.

---

## 10. Verification

```bash
# 1. PostgreSQL connectivity
psql "$QODIQA_PG_URL" -c "SELECT version();"

# 2. Schema version
node src/infra/postgres/migrate.js --status
# or: psql "$QODIQA_PG_URL" -c "SELECT version, name, applied_at FROM qodiqa_migrations ORDER BY version DESC LIMIT 3;"

# 3. RLS is enabled
psql "$QODIQA_PG_URL" -c "
  SELECT tablename, rowsecurity
  FROM pg_tables
  WHERE tablename IN ('audit_chain','transparency_log_entries','signing_keys');
"
# All three must have rowsecurity = 't'

# 4. Audit chain row count matches file line count
FILE_COUNT=$(wc -l < "$QODIQA_AUDIT_LOG")
PG_COUNT=$(psql "$QODIQA_PG_URL" -t -c "SELECT COUNT(*) FROM audit_chain;" | tr -d ' \n')
echo "File: $FILE_COUNT, PG: $PG_COUNT"
# Note: PG may be slightly behind file (queued writes) — difference should be < 100

# 5. Persistence recovery queue is draining (PostgreSQL-backed — see §3.4)
psql "$QODIQA_PG_URL" -t -c "SELECT count(*) FROM persistence_recovery_queue WHERE status = 'PENDING';"
# Should be decreasing over time

# 6. Filesystem recovery journal is empty or draining (FAILOVER-1 — see §3.4)
ls "${QODIQA_PRQ_JOURNAL_DIR:-./data/prq-journal}" 2>/dev/null | wc -l
# Should reach 0 shortly after step 5 stabilizes; a nonzero, non-decreasing
# count after PostgreSQL has been confirmed healthy means journalWorker.js
# is not running — check its logs for JOURNAL_WORKER_STARTED / JOURNAL_ENTRY_REPLAY_FAILED
```

---

## 11. Post-Recovery Validation

```
POSTGRESQL RECOVERY VALIDATION CHECKLIST
Date: __________  Operator: __________
Failure Type: __________  Duration: __________
Data Loss: __________ (file audit chain continues independently)

POSTGRESQL HEALTH
[ ] psql connectivity: SELECT 1 → success
[ ] PostgreSQL version: __________
[ ] Schema version (last migration): __________
[ ] RLS enabled on audit_chain: confirmed
[ ] RLS enabled on transparency_log_entries: confirmed
[ ] RLS enabled on signing_keys: confirmed
[ ] Disk space adequate: __________ free
[ ] Active connections within normal range: __________

QODIQA HEALTH
[ ] PG lag monitor: AUDIT_PG_RECOVERED logged
[ ] Enforcement: /ready → 200 (was never affected)
[ ] qodiqa_execution_integrity_full{} = 1

DATA CONSISTENCY
[ ] Persistence recovery queue drained (persistence_recovery_queue PENDING count = 0 or decreasing)
[ ] Filesystem recovery journal drained (journalDepth = 0 or decreasing — FAILOVER-1)
[ ] No qodiqa_prq_journal_write_failed_total increase during the incident (0 = no unrecoverable loss)
[ ] Audit chain file count vs PG count: file=_____, PG=_____ (delta ≤ 100)
[ ] Transparency log sync current (latest entry ≤ 5 min behind)
[ ] No duplicate entries in audit_chain (ON CONFLICT prevents this)

SIGN-OFF
Operator: __________  Time: __________
```

---

*Cross-references: [Restore Runbook](restore-runbook.md) | [Backup Runbook](backup-runbook.md) | [Disaster Recovery](disaster-recovery.md) | [Transparency Recovery](transparency-recovery.md) | Audit Chain Architecture ADR*
