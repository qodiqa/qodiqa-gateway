# QODIQA Live Audit Chain Integrity Verification Runbook

**— Live Audit Chain Integrity Verifier**

| Field | Value |
|-------|-------|
| Document | Audit Chain Integrity Verification Runbook |
| Version | 1.0.0 |
| Owner | Platform Engineering / Security |
| Audience | SRE, Security Engineer, Incident Commander |
| Classification | Internal — Confidential |
| Last Updated | 2026-07-20 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [What This Verifies vs. the Other Three Detectors](#2-what-this-verifies-vs-the-other-three-detectors)
3. [Violation Reasons Reference](#3-violation-reasons-reference)
4. [Reading `GET /audit/chain/verifier/status`](#4-reading-get-auditchainverifierstatus)
5. [Triggering a Manual Scan](#5-triggering-a-manual-scan)
6. [Metrics and Alerting](#6-metrics-and-alerting)
7. [Startup Failure and the Recovery-Mode Escape Hatch](#7-startup-failure-and-the-recovery-mode-escape-hatch)
8. [Non-Repair Policy](#8-non-repair-policy)
9. [Post-Recovery Verification](#9-post-recovery-verification)

---

## 1. Overview

The live audit chain integrity verifier (`src/core/audit/verifier/`) continuously
monitors the **production execution audit chain** — `audit.log` (single-node
file mode) or the `audit_chain` table (PG-authoritative/distributed mode) —
the actual enforcement record of every ALLOW/BLOCK decision QODIQA has made.
This is distinct from the separate RFC6962 Merkle **transparency log**, which
the pre-existing `GapScanner` (`src/core/transparency/scanner/`) covers.

It runs automatically as a background service, started post-`app.listen()`
in `server.js` and controlled by `QODIQA_AUDIT_VERIFIER_*` environment
variables (see `docs/configuration/reference.md`). It is **enabled by
default** — Decision Update
for why this differs from the opt-in Transparency Gap Scanner.

It never repairs, rewrites, or reconciles anything. Every capability in this
runbook is diagnostic. Repair is always a manual, out-of-band, audited
operator action — see [§8](#8-non-repair-policy).

## 2. What This Verifies vs. the Other Three Detectors

Four detectors now exist for this chain. Each answers a different question —
know which one you're looking at before drawing a conclusion from its output:

| Detector | Question | Cadence |
|---|---|---|
| `audit-log.js`'s `loadFromDisk()` / `hydrateFromPgIfDistributed()` | Is the chain internally valid, right now, as this process boots? | Once, at startup |
| `mirrorConsistencyCheck.js` | Do the file chain and PG mirror agree, right now, as this process boots? | Once, at startup |
| **This verifier's startup gate** (`verifierStartupGate.js`) | Does the chain just loaded still agree with what a *previous run of this deployment* already confirmed? | Once, at startup — O(1) |
| **This verifier's background runner** | Is the chain still valid, and still PG-consistent, *continuously while running*? | Every `QODIQA_AUDIT_VERIFIER_*` interval |

If you're investigating a startup failure, check which gate fired — the
event name tells you (`AUDIT_MIRROR_*` vs. `AUDIT_CHAIN_VERIFIER_CONTINUITY_*`).
If you're investigating a live alert with no restart involved, it came from
the background runner.

## 3. Violation Reasons Reference

Full mapping lives in `src/core/audit/verifier/diagnostics.js`. Every
violation includes, where applicable: `offendingIndex`/`offendingSeq`,
`offendingArtifactId`, `expectedPrevHash`/`actualPrevHash`,
`expectedHash`/`actualHash`, and `previousValidIndex`/`previousValidSeq` —
enough to locate the exact record without re-deriving anything by hand.

| Reason | Severity | Meaning | First response |
|---|---|---|---|
| `HASH_MISMATCH` | CRITICAL | A record's stored hash no longer matches its canonical payload. | Treat as tampering. Stop investigating alone — page security. |
| `PREV_HASH_MISMATCH` | CRITICAL | A record's `prevHash` doesn't match the actual predecessor's hash. | Same as above — this is how reordering/deletion manifests. |
| `INVALID_GENESIS` | CRITICAL | The first record's `prevHash` isn't the `'GENESIS'` sentinel. | Investigate whether the chain was truncated from the front. |
| `MULTIPLE_GENESIS` | CRITICAL | More than one record claims `prevHash='GENESIS'` (PG mode). | An unexpected chain restart — see §3.1 below; requires the `idx_audit_chain_prev_hash_unique` index (migration 026) to have been bypassed or predate the table. |
| `DUPLICATE_ARTIFACT_ID` | CRITICAL | The same `artifactId` appears twice in the modern chain. | Investigate whether a replay-protection bypass occurred. |
| `DUPLICATE_SEQUENCE` | CRITICAL | Two PG rows share the same `seq` (schema permits it — no UNIQUE constraint). | Never a benign artifact (see §3.1) — investigate immediately. |
| `MALFORMED_RECORD` | CRITICAL | A required field is missing, or the record failed to parse as JSON. | Check for partial/torn writes or disk-level corruption. |
| `TRUNCATION` | CRITICAL | The chain is shorter than a previously confirmed watermark. | Check for a restored-from-backup file/table, or accidental deletion. |
| `ORPHAN_RECORD` | CRITICAL | A row's `prevHash` matches no existing hash (PG mode, via `validateChainLinks()`). | Investigate a partial delete or a bypassed insert. |
| `FILE_MEMORY_DIVERGENCE` | CRITICAL | A fresh disk re-read disagrees with the in-memory chain, with no restart between. | The file was modified externally while the process kept running — this is exactly the live-tampering blind spot exists to close. |
| `PG_MIRROR_*` (6 reasons) | CRITICAL | The file chain and its PG dual-write mirror have diverged (see `mirrorConsistencyCheck.MISMATCH_REASON`). | Check the Persistence Recovery Queue / `PG_AUDIT_PERSIST_FAILED` logs first — a lagging-but-catching-up mirror looks like this transiently. |
| `SEQUENCE_GAP` | MEDIUM | A PG `seq` value was skipped. | See §3.1 — usually not an incident. Trend it; investigate only if the gap rate changes noticeably. |

### 3.1 Why `SEQUENCE_GAP` is MEDIUM, not CRITICAL

`audit_chain.seq` is `BIGSERIAL` with **no uniqueness constraint**
(migration 001), and PostgreSQL's `nextval()` is non-transactional — a
statement that reserves a sequence value and then rolls back (e.g. a
retried `ON CONFLICT`/constraint violation elsewhere in the same
transaction) permanently burns that value. This is expected, routine
background noise in normal operation, not tamper evidence. Escalating every
gap to the same CRITICAL alert as a broken hash chain would train operators
to ignore the alert entirely. `DUPLICATE_SEQUENCE`, by contrast, can never
arise this way — it requires an explicit non-default-sourced INSERT — so it
stays CRITICAL.

## 4. Reading `GET /audit/chain/verifier/status`

Mounted under the same admin protection as the rest of `/audit`
(`_adminStack('READ_AUDIT')` — ops API key or RBAC `READ_AUDIT` permission).
Cheap: returns the background runner's current snapshot, no live
computation.

```
GET /audit/chain/verifier/status
```

Key fields: `running`, `scanning`, `enabled`, the three interval settings,
`totalRuns`/`totalSuccess`/`totalFailed`, `lastResult` (the most recent
scan's mode/trigger/duration/violations), and the fixed
`repairAttempts: 0, repairSupported: false`.

## 5. Triggering a Manual Scan

```
POST /audit/chain/verifier/verify
Content-Type: application/json

{ "mode": "FULL" }
```

`mode` is `"INCREMENTAL"` (default) or `"FULL"`. Rate-limited to 5 requests
per 5 minutes (a `FULL` scan is real work — a fresh disk re-read or a
paginated PG table scan) — don't script repeated polling against this
endpoint; use `GET /audit/chain/verifier/status` for that instead. Timeout
is `QODIQA_AUDIT_VERIFIER_MANUAL_TIMEOUT_MS` (default 30s).

Use this after any operation that touched the audit store out of band (a
restore, a manual row edit, a backfill) — see [§9](#9-post-recovery-verification).

## 6. Metrics and Alerting

Prometheus metrics (`GET /metrics`, ops-only): `qodiqa_audit_chain_verifier_runs_total`,
`_success_total`, `_failure_total`, `_violations_total` (labeled by reason and
severity), `_active`, `_runner_active`, `_last_success_timestamp_seconds`,
`_last_violation_timestamp_seconds`, `_duration_seconds`,
`_entries_checked_total`, `_watermark_position`, `_skipped_total`,
`_retries_total`, and `_repair_attempts` (always 0).

Alerting: CRITICAL violations reuse the existing `AUDIT_CHAIN_CORRUPTED`
alert rule (`src/alerting/detection/OperationalDetector.js`); MEDIUM
(`SEQUENCE_GAP`) findings route through the new `AUDIT_CHAIN_STRUCTURAL_ANOMALY`
rule. See `docs/operations/alerting.md`'s "Audit Chain Integrity Alerts"
section for the full severity/channel mapping.

### 6.1 Checksum anchor isolation

This verifier's file-based chain walk is a distinct check from the checksum
anchor's own isolation-verification path — `verifyChecksumAnchorIsolation()`
(`src/core/audit/audit-log.js`), surfaced as an additive `checksumAnchor`
field on `GET /audit/chain/integrity`'s response, and as
`qodiqa_audit_checksum_anchor_backend`/`_last_write_timestamp_seconds`/
`_mismatch_total` metrics. Unlike every other check on this page, it makes
no filesystem calls at all — it compares the in-memory chain tail against an
isolated PostgreSQL row (`audit_checksum_anchor`, migration 036), so it
remains meaningful even if the audit-log directory itself is unavailable.
Only active when `QODIQA_PG_ENABLED=true`; "Checksum Anchor Isolation"
decision update for the full design rationale.

**Write ordering and stale writes.** The PG anchor row is
forward-only (migration 062: the count may not decrease, and an equal count may
not change the tail hash; a refusal is SQLSTATE 42501). The write itself stays
best-effort and fire-and-forget from the audit append, but
`checksumAnchor.saveChecksumPg()` now issues the writes **in call order, one at
a time**, collapsing a queued write when a strictly higher one supersedes it.
Before this, each write took its own pool connection, so two consecutive
writes could commit in reverse order. The trigger refused the stale one and
kept the anchor correct, but the refusal was logged as
`AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED` and set
`qodiqa_audit_checksum_anchor_backend` to 0: a false durability signal.

How to read the signals now:

- `AUDIT_CHECKSUM_ANCHOR_PG_STALE_WRITE_REFUSED` (INFO) means the guard refused
  a lower count while the row holds a count **this process** already wrote. The
  newer anchor is committed and nothing was lost, so the backend gauge and
  `lastPgWriteOk` are left unchanged. With ordered writes this should not
  occur; a steady rate means a caller issued counts out of order.
- `AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED` (WARN) plus gauge 0 is unchanged for
  everything else, and these cases need attention:
  - connection or other database errors;
  - any other 42501 (for example a revoked grant);
  - a refusal against a row this process never wrote (another writer, or a log
    that went backwards);
  - an equal count with a different tail hash (a fork).
- `checksumAnchor.getBackendStatus()` (also in the bench sampler) adds
  `pgHighestWrittenCount`, `pgWritesQueued`, `pgWritesCoalesced` and
  `pgStaleWritesRefused`.

**Bounded writes.** Because the writes are serialized, a
single query that never answers would stall the writer silently. That is a
silent partition: the server stops responding on an open connection, its
`statement_timeout` cannot fire, and the pool has no client-side timeout. Each
anchor write is therefore bounded by a deadline derived from the pool's own
timeouts:

`QODIQA_PG_STATEMENT_TIMEOUT_MS` + `QODIQA_PG_ACQUIRE_TIMEOUT_MS` + 2,000 ms
(default **33,500 ms**)

A healthy server answers or cancels any statement by `statement_timeout`, so a
write still unanswered after the deadline is lost, not slow. At the deadline:

- the write takes the normal failure path: `AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED`
  ("did not complete within … ms"), gauge 0, `lastPgWriteOk` false;
- its callers settle, and the next queued write is issued;
- the abandoned query is not cancelled.

If the abandoned query ever answers, the result is recorded as
`AUDIT_CHECKSUM_ANCHOR_PG_LATE_RESULT` (INFO). It never changes `lastPgWriteOk`,
`lastPgWriteAt` or the gauge, so a late success cannot restore health; only a
new, on-time write can. A late write that reaches the server after a newer
anchor is refused by the forward-only guard as usual.

During a long partition each timed-out write keeps its pool connection until
the operating system drops the TCP connection, and later writes then fail at
the pool's 1.5 s acquire timeout. `getBackendStatus()` adds
`pgWriteDeadlineMs`, `pgWritesTimedOut` and `pgLateResults`.

Tests:

- `src/core/audit/__tests__/checksumAnchor.outOfOrder.test.js` (N03-01..13);
- `src/core/audit/__tests__/checksumAnchor.hungWrite.test.js` (N04-01..11) and
  `test/integration/anchorHang.integration.test.js` (real PostgreSQL behind a
  stalling proxy; N04-PG-01..10);
- `test/integration/anchorRace.integration.test.js` (real PostgreSQL, the real
  trigger, as `qodiqa_app`).

## 7. Startup Failure and the Recovery-Mode Escape Hatch

If the process fails to start with `AUDIT_CHAIN_VERIFIER_CONTINUITY_VIOLATION`
(FATAL, written to stderr, process exits 1): the durable chain this process
just loaded no longer matches what a *previous run of this deployment*
already confirmed. This most often means the file or PG table was restored
from an older backup, truncated, or replaced — including a **coordinated
rollback of both the file and its PG mirror together**, which the
mirror-consistency check alone cannot detect (see [§2](#2-what-this-verifies-vs-the-other-three-detectors)).

**Do not restart with `QODIQA_AUDIT_VERIFIER_RECOVERY_MODE=true` as a
reflex.** First:

1. Read the FATAL record's `violationType` (`TRUNCATION`, `HASH_DIVERGENCE`,
   or `WATERMARK_RECORD_MISSING`), `watermarkIndex`/`watermarkSeq`, and
   `expectedHash`/`actualHash`.
2. Confirm whether this was an expected operation (an intentional restore,
   a planned backfill) or unexpected.
3. If expected and you've already verified the restored data's provenance:
   set `QODIQA_AUDIT_VERIFIER_RECOVERY_MODE=true` and restart. The process
   will boot in a supervised degraded state, log
   `AUDIT_CHAIN_VERIFIER_RECOVERY_MODE_ENGAGED` at WARN, and (unless
   `QODIQA_AUDIT_VERIFIER_FULL_ON_WATERMARK_MISMATCH=false`) immediately run
   a FULL forensics scan so every violation — not just the first one the
   O(1) startup gate found — is available right away.
4. **Unset the flag once resolved.** It must never be left enabled as
   standing configuration — there is no automatic exit from recovery mode.
5. If unexpected: treat as a potential security incident. Do not restart at
   all until you've completed a forensic review of the divergence.

## 8. Non-Repair Policy

This verifier — like every other integrity check for this chain
(`mirrorConsistencyCheck.js`, `audit-log.js`'s own load-time validation) —
**never** rewrites the file, never overwrites PostgreSQL rows, never picks a
"newer" or "more likely correct" copy, and never advances its watermark past
a detected violation (so the next scan keeps re-detecting and re-alerting on
it, rather than silently moving on). `repairAttempts` in every status
response is a fixed `0`; `repairSupported` is a fixed `false`.

Reconciliation is always an explicit, out-of-band, audited operator action —
outside this verifier's code path entirely. There is no `/repair` endpoint
and there never will be one for this chain; the audit chain's entire value
as evidence depends on it never being auto-mutated by the system that
produced it.

## 9. Post-Recovery Verification

The codebase's established recovery model for this chain is "operator
follows a runbook (e.g. `docs/operations/postgresql-failure.md`,
`docs/operations/restore-runbook.md`), then restarts the process" — there is
no live "recovery completed" hook this verifier subscribes to. Two things
satisfy "verify the recovery worked":

1. **The startup watermark-continuity gate** ([§7](#7-startup-failure-and-the-recovery-mode-escape-hatch))
   runs on every restart, including the one immediately following your
   recovery runbook.
2. **`POST /audit/chain/verifier/verify` with `mode: "FULL"`**
   ([§5](#5-triggering-a-manual-scan)) — the recommended manual step
   immediately after completing any recovery runbook that touched the audit
   store, without requiring a full process restart.

## 10. Retention role separation

Distinct from chain *integrity* (covered above), the automated audit-*retention*
cleanup cycle (`src/core/audit/retention.js`'s `runRetentionCycle()` — stamping
`retain_until` and deleting expired `platform_audit_events` rows on a schedule)
runs under its own dedicated, least-privilege PostgreSQL role, `qodiqa_retention`
(migration `038_retention_dedicated_role.sql`), via a separate connection pool
(`src/infra/postgres/retentionPool.js`) rather than the general-purpose
`qodiqa_app` role every other write path uses.

`qodiqa_retention` holds exactly: `SELECT` on `audit_retention_policies`;
`SELECT`/`INSERT` on `audit_retention_runs`; `SELECT`/`UPDATE`/`DELETE` on
`platform_audit_events` (plus the three matching RLS policies —
`pae_retention_select`/`pae_retention_update`/`pae_retention_delete` — since
PostgreSQL RLS requires a row be visible under an applicable `SELECT` policy
before an `UPDATE`/`DELETE` policy is even consulted). No other table, no DDL
rights, no administrative access. `qodiqa_app`'s own grants (including the
`UPDATE`/`DELETE` on `platform_audit_events` migration 027 already granted it)
are unaffected — migration 038 is purely additive.

`src/core/audit/retentionPrivilegeCheck.js` verifies these exact grants and
policies once at startup (via `has_table_privilege()` and a `pg_policies`
catalog read against the live `retentionPool` connection) and fails closed
(`process.exit(1)`) if any are missing — see that module's header for why this
is a catalog check rather than a live functional probe (a rolled-back
functional probe across two different roles is structurally impossible without
either persisting a synthetic row to the audit ledger or granting cross-role
trust, both rejected). Credential provisioning: `docs/security/secrets-management.md`.
