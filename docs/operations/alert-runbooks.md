# QODIQA Alert Runbooks

Last verified: 2026-10-06

Runbook sections for the Prometheus alerts shipped in `deploy/kubernetes/overlays/examples/monitoring/prometheusrule.yaml`
that had no runbook anywhere in `docs/` (observability audit,
). Every rule's `runbook_url` annotation points either at a section below or at the existing runbook section
that already covers it; `src/observability/__tests__/prometheusRuleStructure.test.js` fails if a `runbook_url` file or
heading does not exist. The full alert list, severities and metric meanings are in
[Metrics & Alerting §11.8](metrics-and-alerting.md#118-shipped-prometheus-alerts).

General rules for every section:

- `/metrics` is authenticated and scraped per pod. All counters are per process and reset on restart.
- Never "fix" an integrity alert by restarting, deleting or rewriting audit, transparency or anchor data. QODIQA never
  repairs evidence automatically (see [Non-Repair Policy](audit-chain-integrity-verification.md#8-non-repair-policy)).
- Correlate with the structured log event named in the alert summary (`eventType` field). The log is the detail; the
  metric is the trigger.

---

## Kill switch

Alerts: `QodiqaKillSwitchActive`, `QodiqaKillSwitchTampered`, `QodiqaKillSwitchStateUnavailable`.

**What it is.** One signed control-plane record. While it is active every `/sign` and `/ai/chat` request (all aliases, streaming included) is answered `503 BLOCK KILL_SWITCH_ACTIVE` (`Retry-After: 30`) *before anything else runs*: nothing is signed, no nonce is consumed, no provider is called, nothing is written for the refused request. Health, readiness, verification and the admin plane are not affected.

**QodiqaKillSwitchActive** — an operator raised it. `GET /v1/admin/kill-switch` shows who (`operatorId`), why (`reason`), when (`changedAt`) and the `eventId`; the audit chain holds a `KILL_SWITCH` entry (decision BLOCK, reason `KILL_SWITCH_ON`, tenant `*`, `executionContext.killSwitch.stateHash`) when audit schema v8 is enabled. To resume: `POST /v1/admin/kill-switch/release` (permission `MANAGE_KILL_SWITCH`, operator MFA step-up `X-QODIQA-OTP`). Release is idempotent and audited the same way. Every replica follows within 5 s (typically < 100 ms with Redis notifications, ~1 s by polling alone).

**QodiqaKillSwitchTampered** — the stored record failed its MAC. Someone changed it with database access instead of the API. It is treated as ACTIVE (a database write can raise the switch, never lower it). Find out who wrote to `control_plane_records` (`store = 'kill_switch'`), check the MAC keyring (`QODIQA_MAC_KEYS_PATH`) is the one every replica shares, then restore a signed record with `POST /v1/admin/kill-switch/release` — that writes a properly signed record and clears the flag everywhere.

**QodiqaKillSwitchStateUnavailable** — a replica's control-plane snapshot is older than 5 s, so it cannot say the switch is off and refuses (`503 BLOCK KILL_SWITCH_STATE_UNAVAILABLE`). Check PostgreSQL reachability from that replica (`qodiqa_control` role) and `GET /ready`; the replica recovers on its next successful pull (1 s interval).

**If the audit entry is missing.** `KILL_SWITCH_AUDIT_ENTRY_SKIPPED` (audit schema v8 is off) or `KILL_SWITCH_AUDIT_FAILED` (append failed) are logged at CRITICAL; the change itself stands — an emergency stop never waits for the audit. Enable `QODIQA_AUDIT_SCHEMA_V8` (one-way, see the configuration reference) to get the chain entry.

## Transparency evidence store unavailable

Alerts: `QodiqaTransparencyJournalUnavailable`, `QodiqaTransparencyExecuteRefused`. Events: `TRANSPARENCY_JOURNAL_UNAVAILABLE`, `TRANSPARENCY_JOURNAL_REFUSING_EXECUTE`, `TRANSPARENCY_LEAF_LOST`, `TRANSPARENCY_JOURNAL_RECOVERED`. Metrics: `qodiqa_transparency_journal_unavailable`, `qodiqa_transparency_journal_buffered`, `qodiqa_transparency_journal_refused_total`, `qodiqa_transparency_unrecorded_total`.

**What it is.** Every decision owes the transparency log one leaf. If registering it fails, the leaf goes to the PostgreSQL recovery queue and, if PostgreSQL refuses that, to the append-only file journal on the persistent volume (`QODIQA_PRQ_JOURNAL_DIR`); a worker replays it when the database is back. These leaves are **marked** `payload.recovery = { late: true, replica, seq, queuedAt }` (signed with the leaf) and keep their original `recordedAt`, so a verifier can see they entered the log after an interruption and in which order they were decided. The alerts fire in the one case that remains: **neither** the queue **nor** the journal can take a leaf.

**What happens meanwhile.** Leaves of BLOCK decisions and of delivered streams are kept in a bounded in-memory buffer (10,000) and retried every second, in order. Past `QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS` (default 60 s, 1 s–1 h) **new EXECUTE decisions are refused** (`503 TRANSPARENCY_JOURNAL_UNAVAILABLE`, `Retry-After: 30`, before the provider is called) and `/ready` reports `transparencyJournal: false`; BLOCK decisions keep being answered. A non-streamed answer whose leaf cannot be stored anywhere is withheld (503, no content), as before.

**What to do.** Find out why the journal cannot be written: the volume at `QODIQA_PRQ_JOURNAL_DIR` is missing, read-only or full (`df`, mount, permissions), or PostgreSQL is down at the same time. The state clears by itself: every second a probe asks whether PostgreSQL answers or the journal volume is writable again, the buffered leaves drain, and only then (`TRANSPARENCY_JOURNAL_RECOVERED`) are executions served again — no traffic is needed to heal it. A failure that a retry cannot fix (a signer / KMS outage, a malformed registration) is **not** queued: it is counted (`qodiqa_transparency_unrecorded_total{reason="not_queueable"}`), escalated (`TRANSPARENCY_LEAF_UNRECORDED`) and opens the same window, so executions stop after the bound until the signer is back. A refused execution has already consumed its artifact's nonce: the client signs a new artifact. **`TRANSPARENCY_LEAF_LOST` is the residual risk**: the buffer was full, or the process died inside the window — those decisions have an audit entry but no transparency leaf; record the incident. It is also emitted (reason `shutdown`) when the process exits with leaves still in the buffer; the replicas of a deployment share the journal directory when it is a shared (RWX) volume, which is safe — entries are keyed by operation id and replay is idempotent. The journal must be on a persistent volume: boot validation refuses a path inside the application directory or on a container's root filesystem.

## External anchor failing

Alerts: `QodiqaExternalAnchorFailing`, `QodiqaExternalAnchorStale`. Event: `EXTERNAL_ANCHOR_FAILED`. Metrics: `qodiqa_external_anchor_total{kind,outcome}`, `qodiqa_external_anchor_pending`, `qodiqa_external_anchor_oldest_pending_seconds`.

**What it is.** After a signed checkpoint, the gateway records one `external_anchors` row per configured kind — a signed commit in the anchors git repository (`QODIQA_ANCHOR_GIT_REPO`), an OpenTimestamps stamp (`QODIQA_ANCHOR_OTS_EXEC`), an RFC 3161 token (`QODIQA_ANCHOR_TSA_EXEC`) — and publishes it in the background. It never blocks a request or a checkpoint. A row that fails stays `pending` with `last_error` and `attempts`, is retried every minute and becomes `failed` after 10 attempts.

**What to do.** `SELECT kind, status, attempts, last_error, created_at FROM external_anchors WHERE status <> 'confirmed' ORDER BY id;` — then fix the cause: the repository path is not a git working tree or not writable, the signing key is missing or locked (`QODIQA_ANCHOR_GIT_SIGN=true`), the adapter executable is missing or its calendar / TSA is unreachable (run it by hand with a JSON statement on stdin). A `pending` row is retried by itself once the cause is fixed; a `failed` row is not retried again: the next checkpoint raises a new anchor, which covers a longer chain than the failed one. Until an anchor is confirmed the checkpoint is protected only by its witness cosignatures (if configured). The anchors repository must be mirrored somewhere the gateway operator cannot rewrite, or the git anchor proves nothing.

**Known limits of the transparency journal.** (1) If a leaf INSERT commits but its acknowledgement is lost, the `payloadHash` returned to the caller is the hash of the payload that carried the late marker, while the stored leaf (written by the original attempt) does not carry the marker: the two differ for that one request; the leaf itself is complete and verifies. (2) `QODIQA_PRQ_JOURNAL_DIR` must be a PERSISTENT volume; the boot rule can only warn when it is unset and cannot tell a Kubernetes `emptyDir` (lost with the pod) from a real volume - use a PersistentVolumeClaim. (3) The independent verifier checks duplicate late-leaf sequence numbers, not their order.

## COMMIT entry not written

Events: `AUDIT_COMMIT_FAILED` at CRITICAL, `AUDIT_COMMIT_QUEUED` and `AUDIT_COMMIT_RECONCILED_AT_BOOT` at WARN; metric `qodiqa_audit_commits_total{outcome}` (`recorded`, `skipped`, `duplicate`, `failed`, `queued`).

**What it is.** With audit schema v8 on, every request whose provider executed ends with a `COMMIT` audit entry written *after* the client was answered: the exact number of output bytes delivered, the hash of the delivered text and how the delivery ended (`COMPLETE`, `CLIENT_DISCONNECTED`, `TIMEOUT`, `CANCELLED`, `ERROR`). It never delays a response. If the audit store refuses it, the response has already gone; the exact record is retried every few seconds by the lifecycle reconciler (`AUDIT_LIFECYCLE_OPEN` with `kind: commit`, then `AUDIT_LIFECYCLE_RECONCILED`). Until it lands, a verifier reports that request as an `ORPHAN_DECISION` *warning* (after a 10 minute grace), never a failure.

**What to do.** Treat it like an audit append failure (below): find out why the audit store refused appends. If `qodiqa_audit_commits_total{outcome="skipped"}` rises, audit schema v8 is off (`QODIQA_AUDIT_SCHEMA_V8`), which is the default: no COMMIT is expected. A stream whose DECISION could not be written has no COMMIT until the DECISION is reconciled.

**Durability.** A COMMIT the audit store refuses is queued *durably* (`AUDIT_COMMIT_WRITE` in the persistence recovery queue, or the file journal when PostgreSQL is down) and replayed by the recovery worker — `AUDIT_COMMIT_QUEUED`, `outcome="queued"`; it survives a crash. Only when neither is available does the in-process retry of the lifecycle reconciler hold it. If the process dies between the DECISION and the COMMIT, the next boot finds the executed request without a COMMIT and writes one itself: `completionStatus` **`OUTCOME_UNKNOWN`**, reason `RESPONSE_FAILED`, `bytesDelivered` **0 meaning unknown** (what reached the client cannot be known), empty output hash — never "delivered" (`AUDIT_COMMIT_RECONCILED_AT_BOOT`). A request whose real COMMIT is waiting in the queue is left to that replay. A burst of `AUDIT_COMMIT_RECONCILED_AT_BOOT` after a restart is the crash's footprint, not a new fault; investigate why the previous process died.

## Audit append failure

Alerts: **QodiqaAuditFailClosedRejections** (critical), **QodiqaAuditAppendFailed** (critical),
**QodiqaAuditDiskFull** (critical), **QodiqaAuditWalFsyncSlow** (warning),
**QodiqaCheckpointTransparencyAnchorFailed** (warning).

What it means: a mandatory audit append (`appendMandatory`, `src/core/audit/audit-log.js`) failed after its retries.
Requests on the mandatory-audit path are refused (fail closed: 503, no provider call). `stage` on
`qodiqa_audit_fail_closed_rejections_total` is the request stage that was refused (`INTENT`, `ALLOW`,
`STREAM_LIFECYCLE`). A slow WAL fsync precedes most append failures. **QodiqaAuditDiskFull** fires on
`qodiqa_audit_disk_full_total{stage}`, which counts the append failures whose last error was ENOSPC (the audit volume
is full). **QodiqaCheckpointTransparencyAnchorFailed** fires on
`qodiqa_audit_anchor_events_total{outcome="transparency_anchor_failed"}`: a signed audit checkpoint was written but could
not be registered in the transparency log (log event `AUDIT_CHECKPOINT_ANCHOR_FAILED`, `src/core/audit/checkpoint/checkpointWriter.js`);
requests are not refused, but that checkpoint has no transparency anchor — check PostgreSQL and the transparency log
([Transparency recovery](transparency-recovery.md)).

Log events: `AUDIT_APPEND_FAILED`, `AUDIT_DISK_FULL` (ENOSPC on the audit volume), `AUDIT_CHECKPOINT_ANCHOR_FAILED`.

Steps:
1. Check the audit volume (`QODIQA_AUDIT_LOG` directory): free space, inode use, and I/O errors in the node's kernel
   log. `AUDIT_DISK_FULL` means free space first, nothing else will help.
2. Check `qodiqa_audit_append_failed_total` by `stage` and `qodiqa_audit_wal_fsync_duration_seconds` p99. A rising
   fsync latency with no errors is a storage-performance problem (noisy neighbour, throttled volume).
3. Do not move, truncate or edit the audit file. After the volume recovers, confirm the counters stop rising and run
   the chain verifier ([§5 Triggering a Manual Scan](audit-chain-integrity-verification.md#5-triggering-a-manual-scan)).
4. If refusals continue after the volume is healthy, treat as an incident (P1): collect the `AUDIT_APPEND_FAILED`
   events with their `error` field.

ENOSPC has its own counter, `qodiqa_audit_disk_full_total{stage}` (alert **QodiqaAuditDiskFull**), and is also counted
in `qodiqa_audit_append_failed_total`. Both fire only after an append has already failed; an early-warning
filesystem free-space alert on the audit volume needs node-exporter (EXTERNAL).

---

## Witness refusal

Alert: **QodiqaAnchorWitnessRefused** (critical).

What it means: an external witness refused to co-sign a signed audit checkpoint because the checkpoint contradicts one
it already co-signed: a rollback (`WITNESS_ROLLBACK_REFUSED`) or an equivocation (`WITNESS_EQUIVOCATION_REFUSED`).
Log event: `AUDIT_ANCHOR_WITNESS_REFUSED`. **Treat as a possible audit-history rewrite until proven otherwise.**

Steps:
1. Do not restart the gateway, do not delete checkpoints or the anchor export, do not reset the witness's state.
2. Preserve: the gateway's checkpoint files, the customer-held anchor export (`QODIQA_ANCHOR_EXPORT_PATH`), the
   witness's own state and logs, and the `AUDIT_ANCHOR_WITNESS_REFUSED` event (it carries the witness's error).
3. Compare the refused checkpoint's tree size and root with the last checkpoint the witness accepted. A smaller tree
   or a different root at the same size is the evidence of rollback or equivocation.
4. Run the audit-chain verifier and the mirror cross-check
   ([audit-chain integrity](audit-chain-integrity-verification.md#5-triggering-a-manual-scan)); escalate as a security
   incident ([Incident Response](incident-response.md)). A restore from backup is a legitimate rollback that a
   witness will also refuse: if one happened, record it and follow [Disaster Recovery](disaster-recovery.md) with the
   witness operator, never by resetting the witness silently.

Configuration and semantics: [Audit anchoring](../security/audit-anchoring.md#configuration).

---

## Witness unavailable or anchor export failed

Alerts: **QodiqaAnchorWitnessFailed** (warning), **QodiqaAnchorExportFailed** (critical),
**QodiqaCheckpointTickFailed** (warning).

What it means: the witness could not be reached or errored (`AUDIT_ANCHOR_WITNESS_FAILED`), the customer-held anchor
export could not be written (`AUDIT_ANCHOR_EXPORT_FAILED`), or the checkpoint background task failed outright
(`qodiqa_background_tasks_failed_total{task="audit-checkpoint"}`). Requests are not affected, but anchors without
cosignatures fail the next production boot check.

Steps:
1. Witness: check the `exec` command (`QODIQA_WITNESS_EXEC`), its 10 s timeout, and the witness's own health. The
   command receives only the allow-listed environment
   ([Audit anchoring — configuration](../security/audit-anchoring.md#configuration)).
2. Export: check `QODIQA_ANCHOR_EXPORT_PATH` exists, is writable by the gateway user and has space.
3. Confirm `qodiqa_audit_anchor_events_total{outcome="anchored"}` increases again on the next tick. There is no
   "anchoring stalled" alert yet (its threshold depends on traffic and is an operator decision).

---

## Mirror drift

Alerts: **QodiqaMirrorCrosscheckDivergence** (critical), **QodiqaMirrorCrosscheckFailed** (warning),
**QodiqaMirrorCountDrift** (critical), **QodiqaAuditPgHydrationFailed** (warning).

What it means:
- `qodiqa_audit_crosscheck_failure_total{reason}`: the file-chain ↔ PostgreSQL mirror cross-check
  (`src/core/audit/mirrorConsistencyCheck.js`) found `DIVERGENCE`, or could not complete (`PG_UNREACHABLE`,
  `PG_CHAIN_INVALID`, `FILE_CHAIN_INVALID`).
- `qodiqa_audit_mirror_count_drift_total{reason}`: the row-counter reconciliation (`mirrorCountReconciler.js`, at boot
  and every 6 h) found `audit_chain_mirror_count` different from `count(*)` of `audit_chain` (`MISMATCH`) or the
  counter row missing (`COUNTER_MISSING`). Log event `AUDIT_MIRROR_COUNT_DRIFT`, re-raised on every run while it
  persists. A trigger-maintained counter only drifts when `audit_chain` was changed with its triggers bypassed
  (table-owner `DISABLE TRIGGER` or `session_replication_role = replica`).
- `qodiqa_audit_pg_hydration_failed_total`: the audit tail could not be read back from PostgreSQL at start.

Steps:
1. The file chain is authoritative. Do not edit either side to make them agree.
2. `DIVERGENCE` or `*_CHAIN_INVALID`: run the verifier and follow
   [audit-chain integrity §7](audit-chain-integrity-verification.md#7-startup-failure-and-the-recovery-mode-escape-hatch);
   treat as an integrity incident.
3. Count drift: investigate who changed `audit_chain` with triggers bypassed (PostgreSQL logs, role audit). Only after
   that, the **owner** runs the owner-only `qodiqa_audit_chain_mirror_count_rebuild()` (migration 073). It is never run
   automatically and never by an on-call operator alone. Until then the 60 s lag figure is wrong.
4. `PG_UNREACHABLE` / hydration failures: follow [PostgreSQL failure §3](postgresql-failure.md#3-database-unavailable).

---

## Audit backlog

Alerts: **QodiqaAuditMirrorBacklogHigh** (warning), **QodiqaAuditBacklogShedding** (critical),
**QodiqaAuditPgSyncLag** (warning).

What it means: the in-process PostgreSQL audit-mirror writer is falling behind (`qodiqa_audit_mirror_writer_depth`),
or PostgreSQL holds fewer audit rows than the file chain (`qodiqa_audit_pg_lag_entries`, from the 60 s lag monitor,
log event `AUDIT_PG_SYNC_LAG`). At `QODIQA_AUDIT_MIRROR_MAX_DEPTH` (default 20,000) back-pressure engages: admission
refuses new `/sign` and `/ai/chat` work (503 `SERVER_OVERLOADED`, cause `audit_backlog`) and `/ready` reports
`auditBacklog: false` until the backlog drains to half. See
[Metrics & Alerting §11.7](metrics-and-alerting.md#117-audit-mirror-backlog-bound).

Steps:
1. PostgreSQL is slow but up: check `qodiqa_pg_pool_waiting`, slow queries and I/O
   ([PostgreSQL failure §7](postgresql-failure.md#7-slow-queries)).
2. PostgreSQL is down: the persistence recovery queue takes over
   ([§3.4](postgresql-failure.md#34-persistence-recovery-queue-monitoring)).
3. Do not raise `QODIQA_AUDIT_MIRROR_MAX_DEPTH` to stop shedding without capacity evidence: the bound exists to keep
   the heap bounded.

---

## Admission saturation

Alerts: **QodiqaAdmissionRejecting** (warning; above 1 refusal/s for 10 minutes), **QodiqaHigh5xxRate** (warning;
more than 5% of responses on a route family are 5xx for 10 minutes, from
`qodiqa_http_responses_total{route_family,status_class}` — this includes the 503 admission refusals below, so check
`qodiqa_admission_rejected_total` first; if admission is not refusing, the 5xx come from elsewhere and the route
family's error logs are the place to look).

What it means: the per-route admission queue (`src/api/admission.js`; `QODIQA_ADMISSION_SIGN`,
`QODIQA_ADMISSION_AI_CHAT`) is full or its queue wait timed out, so new requests get a fast 503
`SERVER_OVERLOADED` with `Retry-After` (`QODIQA_ADMISSION_RETRY_AFTER_SEC`).
`qodiqa_admission_rejected_total{route,cause}` says which route and why (`queue_full`, `queue_timeout`;
`audit_backlog` is the [Audit backlog](#audit-backlog) case). `/ready` reports `admission: false` while a queue is full,
so a load balancer moves traffic away from this instance.

Steps:
1. Check `qodiqa_admission_inflight` / `qodiqa_admission_queued` per route and the event loop
   ([Event loop](#event-loop)): a saturated instance with a healthy event loop needs more instances; a blocked event
   loop needs the cause removed first.
2. Check downstream latency (provider, PostgreSQL, Redis): slow dependencies hold admission slots longer.
3. Measured capacity and the overload behaviour are in PERFORMANCE.md §0.2.
   Raise limits only with a measurement.

---

## Provider failures

Alert: **QodiqaProviderFailures** (warning; above 0.1 failures/s per provider for 5 minutes).

What it means: AI provider calls are failing (`qodiqa_provider_failures_total{provider,code}`). Counts streaming
(`/ai/chat` with `stream: true`, event `STREAM_PROVIDER_ERROR`, `src/streaming/streamEnforcer.js`) and non-streaming
(the `/ai/chat` provider catch) failures; client disconnects and stream timeouts are not provider failures
(`qodiqa_streaming_cancelled_total`), and non-streaming route-level cancellations are counted in
`qodiqa_provider_execution_cancelled_total`. A non-streaming failure is recorded as a BLOCK with stage
`PROVIDER_EXECUTION`; a streaming failure terminates the stream with the provider's error code as its reason.

Steps:
1. Group by `code` to separate upstream errors (provider outage, rate limit, auth) from network errors.
2. Check the provider's status and the configured credentials; for the local provider, the Ollama process.
3. Change provider routing only through the normal configuration path; do not edit signed artifacts or policies to
   route around a failing provider.

---

## Replay and nonce

Alerts: **QodiqaReplaySpike** (warning), **QodiqaNonceViolation** (critical).

What it means: `qodiqa_security_events_total{event="replay_detected"}` counts blocked replays (an attack or a
retrying client); `{event="nonce_violation"}` counts requests refused because the nonce store failed
(`NONCE_STORE_ERROR`) or the replay state could not be proven (`REPLAY_STATE_UNPROVABLE`, 503). Both are fail-closed:
nothing is executed twice.

Steps:
1. Nonce violation: follow [Redis failure §3](redis-failure.md#3-detection-and-health-verification) — it is almost
   always the nonce store, not an attacker.
2. Replay spike: identify the caller (`NONCE_V2_REPLAY_DETECTED` events), distinguish a buggy
   retrying client from an attack, and use rate limiting or key revocation for the latter.

---

## Operator auth failures

Alerts: **QodiqaMfaLockouts** (warning), **QodiqaOpsAuthFailureBurst** (warning), **QodiqaRbacDenialBurst**
(warning), **QodiqaAuthLockoutStorageFailures** (warning).

What it means: on the operator (admin) surface — `qodiqa_mfa_events_total{outcome}` (`failed`, `locked`,
`step_up_denied`, `step_up_error`), `qodiqa_ops_auth_failures_total{reason}` (`missing_credentials`,
`invalid_token`), `qodiqa_rbac_denials_total{action,reason}`, and failures of the Redis-held auth-lockout store.
Log events: `RBAC_MFA_FAILED`, `RBAC_MFA_LOCKED`, `RBAC_MFA_STEP_UP_DENIED`, `RBAC_MFA_STEP_UP_ERROR`,
`OPS_AUTH_INVALID_TOKEN`, `OPS_AUTH_MISSING_CREDENTIALS`, `RBAC_DENY`.

Steps:
1. Identify the operator and source IP from the log events (the metrics never carry identities).
2. An MFA lock that the operator did not cause, or bursts of invalid tokens from one source, is a credential attack:
   follow [Incident Response §7.3](incident-response.md#73-data-access-containment) and revoke the operator's API key
   ([Control plane](control-plane.md)).
3. RBAC denial bursts from a legitimate operator usually mean a missing role assignment; never widen a role to stop
   the alert without confirming the request was legitimate.
4. Lockout-store failures: brute-force protection is degraded — follow [Redis failure](redis-failure.md).

---

## Event loop

Alerts: **QodiqaEventLoopUnhealthy** (critical, state 2 for 2 minutes), **QodiqaEventLoopDegraded** (warning,
state ≥ 1 for 10 minutes).

What it means: `qodiqa_event_loop_delay_state_code` (0 healthy, 1 degraded, 2 unhealthy) from
`src/runtime/eventLoopMonitor.js`: mean delay at or above `QODIQA_EVENT_LOOP_WARN_MS` (default 100) is degraded, at
or above `QODIQA_EVENT_LOOP_CRITICAL_MS` (default 500) is unhealthy (log event `EVENT_LOOP_DELAY_CRITICAL`). Every
request on the instance waits on the loop. `/ready` does **not** reflect this (design decision pending).

Steps:
1. Check CPU throttling (container limits) and `qodiqa_event_loop_delay_p99_ms` / `_window_max_ms`.
2. Correlate with load (`qodiqa_admission_inflight`) and with synchronous work: large policy reloads, big audit
   verifications, GC pressure (heap near the limit).
3. If one instance is affected, drain it (remove from rotation) and capture a CPU profile before restarting.

---

## Background tasks

Alert: **QodiqaBackgroundTaskFailing** (warning; more than 3 failures of one task in 30 minutes).

What it means: a task run by `src/runtime/backgroundTasks/BackgroundTaskRunner.js` (`task` label, e.g.
`audit-checkpoint`, `audit-mirror-count-reconcile`, `audit-pg-lag-monitor`) timed out or rejected repeatedly. Failures are
isolated from requests, but the task's own guarantee (anchoring, reconciliation, monitoring) is not being delivered.

Steps: read the `BACKGROUND_TASK_FAILED` events for that task (they carry the error), then follow the runbook of the
subsystem the task belongs to.

---

## Signing keys

Alerts: **QodiqaKeyRotationOverdue** (warning), **QodiqaKeyExpiringSoon** (info), **QodiqaKeyRotationSchedulerFailed**
(warning), **QodiqaSigningProviderUnavailable** (critical).

What it means: from `keyExpiryMonitor` (`qodiqa_key_rotation_overdue_count`, `qodiqa_key_expiry_approaching_count`),
the rotation scheduler (`qodiqa_key_rotation_scheduler_failures_total{trigger,provider}`), and the signing-provider
health monitor (`qodiqa_signing_health_state{provider}`: 0 unavailable, 1 degraded, 2 healthy). An unavailable signing
provider means artifacts cannot be signed.

Steps:
1. Provider unavailable: check the KMS / Vault / HSM endpoint, credentials and network; the log events
   `SIGNING_OPERATION_FAILED` and `SIGNING_CIRCUIT_BREAKER_REJECTED` (`src/infra/keys/resilience/executor.js`) and
   `SIGNING_HEALTH_DEGRADED` (`src/infra/keys/resilience/healthMonitor.js`) carry the provider and error.
   (`SIGNING_FAILED` is the `/sign` BLOCK reason a client sees and `SIGNING_CIRCUIT_OPEN` an error code, not log events.)
2. Overdue / expiring / scheduler failed: rotate manually
   ([Key Compromise Runbook §6](key-compromise-runbook.md#6-key-rotation) for the procedure) and find out why automatic
   rotation did not run (rotation lock contention, scheduler disabled, provider errors).
3. The two gauges also count the **transparency and checkpoint** Ed25519 keys (`KEY_EXPIRING_SOON` /
   `KEY_ROTATION_OVERDUE` with a `store` field, and `KEY_EXPIRED` at ERROR once one has expired). Treat these as
   **urgent**: nothing rotates these stores automatically, and an expired one makes the **next restart fail**
   (`*_EXPIRED` at startup). Do not restart the gateway to "clear" the alert. **No shipped route, scheduler or CLI
   rotates these stores today** (`scripts/keys/rotate-offline.js` covers artifact keys only): escalate to the owner at
   once. The rotation/recovery path is not automated; the alert gives at least 30 days' notice
   (`EXPIRY_WARNING_DAYS`).

---

## Scrape health

Alerts: **QodiqaScrapeDown** (critical), **QodiqaMetricsAbsent** (critical).

What it means: Prometheus cannot scrape `/metrics` (`up == 0`) or sees no QODIQA series at all. While this fires
**every other QODIQA alert is blind**.

Steps:
1. `/metrics` is on the authenticated ops surface: check the `qodiqa-prometheus-scrape` Secret's token is a valid,
   non-expired viewer API key (a 401/403 makes `up` 0), and that Prometheus' source range is in
   `QODIQA_OPS_IP_ALLOWLIST` and the NetworkPolicy.
2. Check `QODIQA_DIAGNOSTICS_ENABLED=true` (otherwise `/metrics` answers 404) and that the ServiceMonitor still
   selects the gateway Service.
3. Both rules assume the Prometheus Operator's `namespace`/`service` target labels; adjust them if the gateway runs
   in another namespace or under another Service name.

---

## Backups

Alerts (`backup-prometheusrule.yaml`): **QodiqaBackupStale** (warning), **QodiqaBackupVerifyFailed** (critical),
**QodiqaBackupVerifyStale** (warning). QodiqaBackupFailed and QodiqaBackupMetricsAbsent are covered by
[Backup Runbook §3.2](backup-runbook.md#32-kubernetes-cronjob-for-database-backup).

What it means: these are textfile-collector metrics written by `scripts/pg-backup.sh`, one file per mode and tier
(`qodiqa_pg_backup_{success,last_run_timestamp_seconds,size_bytes}{mode,tier}`), not gateway metrics.

- **QodiqaBackupStale**: a full-backup tier has not run within its limit: daily 26 h, weekly 8 d, monthly 32 d (the
  same defaults `pg-backup.sh verify` enforces). The CronJob or systemd timer for that tier has stopped. A run that
  failed is reported by QodiqaBackupFailed instead.
- **QodiqaBackupVerifyFailed**: `pg-backup.sh verify <tier>` failed. The seal did not match, the backup did not decrypt,
  table coverage was incomplete, a plaintext `.partial` was found, or the newest backup was older than its tier limit.
  The newest backup is **not proven restorable**.
- **QodiqaBackupVerifyStale**: the daily verify job has not run for 26 hours.

Steps:
1. Read the job's structured log: `BACKUP_FAILED`, `BACKUP_DECRYPT_FAILED`, `BACKUP_ENCRYPTION_FAILED` or
   `BACKUP_OFFSITE_FAILED` carry the reason. For verify, the line before `BACKUP_FAILED` names the failed check.
2. Stale: check the CronJob (`kubectl -n qodiqa get cronjob qodiqa-pg-backup-<tier>`, last schedule time, failed Jobs)
   or the systemd timer (`systemctl list-timers 'qodiqa-pg-backup-*'`). Then check that node-exporter's textfile collector
   still reads the backup metrics directory.
3. Verify failed: do not rely on that backup. Run a fresh `pg-backup.sh full <tier>`, then `pg-backup.sh verify <tier>`.
   If the seal mismatches, treat the backup store as possibly tampered with and keep the artifact for investigation.
   Never delete it to clear the alert.

---

## WAL archiving

Alerts: **QodiqaWalArchiveVerifyFailed** (critical), **QodiqaWalArchiveMetricsStale** (warning).

What it means: `scripts/pg-wal-archive.sh` (PostgreSQL `archive_command`, plus the 5-minute `--verify` CronJob or
timer) writes unlabelled `qodiqa_wal_archive_{success,last_segment_timestamp_seconds}` on every run, and
`qodiqa_wal_archive_verify_{success,age_seconds}` on `--verify`. Every failure logs one `WAL_ARCHIVE_VERIFY_FAILED` and sets
both success gauges to 0. A segment failed to archive, the newest archived segment is older than
`QODIQA_WAL_ARCHIVE_MAX_AGE_SECONDS` (default 600), or sealing failed: point-in-time recovery has a gap from that moment.
QodiqaWalArchiveMetricsStale means nothing has written the file for 30 minutes, i.e. the verify job itself has stopped.

Steps:
1. Read the `WAL_ARCHIVE_VERIFY_FAILED` message.
2. Stale newest segment: check PostgreSQL `archive_mode`/`archive_command` and `pg_stat_archiver` (`failed_count`,
   `last_failed_wal`), and check that the archive directory is the storage the verify job reads
   ([Backup Runbook §3.5](backup-runbook.md#35-continuous-wal-archiving)).
3. After archiving resumes, take a fresh full backup. PITR across the gap is not possible.

---

## Audit-log backup

Alerts: **QodiqaAuditLogBackupFailed** (critical), **QodiqaAuditLogBackupStale** (warning).

What it means: `scripts/backup-audit-log.sh` (self-hosted single-node only, from the systemd timers
`qodiqa-audit-log-backup.timer` and `-verify.timer`, every 5 minutes) writes unlabelled
`qodiqa_audit_log_backup_{success,last_run_timestamp_seconds,size_bytes}`. There is no Kubernetes CronJob for it (the audit
volume is per-pod), so these series are absent there and the alerts never fire. A failure logs `AUDIT_LOG_BACKUP_FAILED`
(seal missing or mismatched, no HMAC key, a copy error, or the newest backup older than
`QODIQA_AUDIT_BACKUP_MAX_AGE_SECONDS`). The file-authoritative audit chain is then not being backed up.

Steps:
1. Read `AUDIT_LOG_BACKUP_FAILED` / `AUDIT_LOG_BACKUP_SEAL_MISMATCH` / `AUDIT_LOG_BACKUP_NO_HMAC_KEY`.
2. Stale: `systemctl list-timers 'qodiqa-audit-log-backup*'` and `journalctl -u qodiqa-audit-log-backup.service`.
3. A seal mismatch on an existing copy is an integrity event: keep the copy, run the audit-chain verifier
   ([Audit Chain Integrity §4](audit-chain-integrity-verification.md#4-reading-get-auditchainverifierstatus)), and never
   overwrite or delete backups to clear the alert.
