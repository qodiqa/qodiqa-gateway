# QODIQA Metrics & Alerting — Unified Operational Model

**Operations & Production Readiness**

| Field | Value |
|-------|-------|
| Document | Metrics & Alerting — Unified Operational Model |
| Version | 1.0.0 |
| Owner | Platform Engineering / SRE |
| Audience | SRE, Platform Engineer, On-Call, Security |
| Classification | Internal — Operational |
| Last Updated | 2026-07-06 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Metrics Taxonomy](#3-metrics-taxonomy)
4. [Naming Conventions](#4-naming-conventions)
5. [Alert Taxonomy & Severity Model](#5-alert-taxonomy--severity-model)
6. [Alert Catalog](#6-alert-catalog)
7. [Dashboard Recommendations](#7-dashboard-recommendations)
8. [Prometheus / Grafana / Alertmanager Integration](#8-prometheus--grafana--alertmanager-integration)
9. [Incident Response Workflow](#9-incident-response-workflow)
10. [Operational Best Practices](#10-operational-best-practices)
11. [Known Architectural Notes](#11-known-architectural-notes)
12. [Exit Criteria](#12-exit-criteria)

---

## 1. Overview

QODIQA exposes three complementary signal surfaces that together form its
operational model:

1. **Metrics** — `GET /metrics`, a Prometheus text-exposition-format endpoint
   backed by [src/observability/metrics.js](../../src/observability/metrics.js)
   (Counters, Gauges, Histograms — no external dependency, hand-rolled to the
   Prometheus v0.0.4 text format).
2. **Alerting** — the [Alerting & Notification Framework](alerting.md),
   which detects security- and reliability-relevant events from the structured
   log stream, scores them, assigns severity, correlates them into incidents,
   and dispatches notifications across 7 channels.
3. **Health/readiness/diagnostics** — `GET /health`, `GET /ready`, and
   `GET /diagnostics`, the liveness/readiness/self-description surface used by
   orchestrators (Kubernetes) and operators.

This document is the **single index** that ties these three surfaces into one
coherent operational model: what is measured, how it is named, what triggers
an alert, how severe it is, and what an operator does about it. It does not
replace the detailed references it links to — [ALERTING_FRAMEWORK.md](alerting.md)
remains the authoritative deep-dive on detection/correlation/notification
internals, and `src/observability/metrics.js` remains the source of truth for
exact metric definitions.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          QODIQA APPLICATION                              │
│                                                                            │
│  Request path        Security path        Reliability path              │
│  (metricsMiddleware)  (validation/*)       (DR probes, PRQ, gap scanner)  │
└──────────┬───────────────────┬──────────────────────┬────────────────────┘
           │                   │                       │
           ▼                   ▼                       ▼
┌────────────────────┐ ┌──────────────────────┐ ┌───────────────────────────┐
│  METRICS REGISTRY   │ │  services/logger.js   │ │  Ad-hoc component metrics │
│  (Counter/Gauge/    │ │  (structured log +    │ │  (rate limit, webhooks —  │
│   Histogram)        │ │   eventBus)           │ │   mirrored into registry) │
│  src/observability/ │ └──────────┬────────────┘ └───────────────────────────┘
│  metrics.js          │            │
└──────────┬───────────┘            ▼
           │              ┌───────────────────────┐
           │              │   DETECTION ENGINE     │
           │              │ (src/alerting/detection)│
           │              └──────────┬─────────────┘
           │                         ▼
           │              ┌───────────────────────┐
           │              │     ALERT ENGINE        │──▶ AlertStore (PG + memory)
           │              │ (risk score, severity)  │
           │              └──────────┬─────────────┘
           │                         ▼
           │              ┌──────────────────────────┐
           │              │ CORRELATION + NOTIFICATION │──▶ Slack/Teams/PagerDuty/
           │              │  (incidents, 7 channels)   │    SIEM/Email/SMS/Webhook
           │              └──────────────────────────┘
           ▼
   GET /metrics (Prometheus text)      GET /health, /ready, /diagnostics
   scraped by Prometheus                polled by orchestrator / operator
           │                                       │
           ▼                                       ▼
      Grafana dashboards                    Kubernetes liveness/readiness
      Alertmanager (metric-based alerts)    probes; manual operator checks
```

**Two independent alerting paths exist by design** and are both part of the
unified model:

- **Metric-based alerting** — Prometheus/Alertmanager rules evaluated against
  `/metrics` (e.g. "`qodiqa_redis_store_up == 0` for 30s"). Good for
  threshold/rate conditions on numeric time series.
- **Event-based alerting** — the QODIQA Alerting Framework, which reacts to
  discrete security/operational *events* emitted via `services/logger.js`
  (e.g. a single invalid-signature attempt, a nonce reuse, a policy fail-open).
  Good for semantic, per-request security signals that a numeric threshold
  cannot express cleanly.

Section 6 catalogs alerts from **both** paths under one severity model so an
operator does not need to know which subsystem raised a given alert to know
how to respond.

---

## 3. Metrics Taxonomy

All metrics below are served at `GET /metrics` (Prometheus text format,
`Cache-Control: no-store`, gated by the ops-only middleware stack — IP allowlist,
ops authentication and the diagnostics gate — see `ctx.opsOnlyStack()` at
`src/app.js:179`). They are grouped into the 7 operational categories
required for a unified model. Full definitions (help text, label sets,
histogram buckets) live in [src/observability/metrics.js](../../src/observability/metrics.js).

### 3.1 Runtime

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `qodiqa_requests_total` | Counter | — | Total enforcement requests processed |
| `qodiqa_blocks_total` | Counter | — | Total requests blocked by policy |
| `qodiqa_request_duration_ms` | Histogram | — | Enforcement request processing latency |
| `qodiqa_active_requests` | Gauge | — | Requests currently in flight |
| `qodiqa_verification_requests_total` | Counter | — | Total `/verify/v2` requests |
| `qodiqa_verification_blocks_total` | Counter | — | Total verification rejections |
| `qodiqa_verification_duration_ms` | Histogram | — | Verification processing latency |
| `qodiqa_streaming_active_streams` | Gauge | — | Currently open streaming enforcement sessions |
| `qodiqa_streaming_duration_ms` / `qodiqa_streaming_provider_latency_ms` | Histogram | — | Streaming session and upstream-provider latency |
| `qodiqa_process_uptime_seconds` | Gauge | — | Process uptime |

### 3.2 Security

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `qodiqa_security_events_total` | Counter | `event` (`invalid_signature`\|`expired_artifact`\|`malformed_artifact`\|`replay_detected`\|`nonce_violation`\|`anomaly_detected`) | Security-relevant events, mapped from the block reason (see the `REASON_SECURITY_EVENT` map, `src/observability/metricsMiddleware.js`) |
| `qodiqa_rate_limit_limited_total` | Counter | `surface`, `reason` | Requests rejected (HTTP 429) — SUSTAINED / BURST / DISABLED / BACKEND |
| `qodiqa_rate_limit_burst_consumed_total` | Counter | `surface`, `dimension` | Burst-capacity-consumed events |
| `qodiqa_org_blocks_total` | Counter | `org` | Per-tenant policy blocks |
| `qodiqa_streaming_rejected_total` / `qodiqa_streaming_enforcement_failures_total` | Counter | — | Streaming-path policy rejections / enforcement failures |

Replay attacks, invalid signatures, and policy denials are additionally
tracked as discrete **alert events** (not just counters) — see
[§6.1](#61-critical) and [§6.2](#62-high). The Detection Engine's
`ReplayDetector` and `SignatureDetector` are the authoritative source for
replay/signature security signals; `qodiqa_security_events_total{event=...}`
is the aggregate metric view of the same underlying events.

### 3.3 Cryptography

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `qodiqa_transparency_signer_signatures_total` | Counter | — | Transparency-log signing operations |
| `qodiqa_transparency_signer_failures_total` | Counter | — | Signing failures |
| `qodiqa_transparency_signer_key_rotations_total` | Counter | — | Signer key rotations |
| `qodiqa_transparency_verifications_total` / `qodiqa_transparency_verification_failures_total` | Counter | — | Transparency entry verification attempts/failures |
| `qodiqa_evidence_chain_verification_failures_total` | Counter | — | Evidence-chain verification failures |
| `qodiqa_attestation_evidence_verifications_total` / `qodiqa_attestation_chain_verifications_total` | Counter | — | Attestation evidence/chain verification counts |
| `qodiqa_portal_verification_failures_total` | Counter | — | Portal artifact verification failures |

Signing-provider (HSM/KMS/Vault) failures have dedicated metrics:
`qodiqa_signing_failures_total{provider,operation,...}` (failed operations),
`qodiqa_signing_health_state{provider}` (2 healthy, 1 degraded, 0 unavailable; alert
**QodiqaSigningProviderUnavailable**), plus the `qodiqa_signing_circuit_*`, `qodiqa_signing_retries_total`,
`qodiqa_signing_timeouts_total` and `qodiqa_signing_latency_ms` series (`src/observability/metrics.js`).
The three `qodiqa_transparency_signer_*` rows above are registered but never written (they always read 0 — see
[§11.8]).

### 3.4 Provider

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `qodiqa_streaming_provider_latency_ms` | Histogram | — | Upstream AI provider latency (streaming path) |
| `qodiqa_webhook_delivery_duration_ms` | Histogram | `event_type` | Outbound webhook delivery latency |
| `qodiqa_webhook_delivery_failures_total` | Counter | `event_type` | Webhook delivery failures (non-2xx, timeout, blocked) |
| `qodiqa_webhook_retries_total` | Counter | `event_type` | Webhook delivery retry attempts |

Non-streaming provider call failures are broken out per upstream provider in
`qodiqa_provider_failures_total{provider,code}` (cancellations are counted separately in
`qodiqa_provider_execution_cancelled_total`; alert **QodiqaProviderFailures**). Non-streaming provider
*latency* is not broken out — it is inside `qodiqa_request_duration_ms`.

### 3.5 Infrastructure

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `qodiqa_redis_store_up` | Gauge | `store` (`nonce`\|`anomaly`\|`rate_limit`) | Redis-backed store availability. **Does not currently cover `consentCache`/`revocationSubscriber`/`revocationPublisher`** — poll `GET /health/redis` or `GET /ready`'s `components.consentSubscriber` for those (see [Redis Failure Runbook §12](redis-failure.md#12-consent-subsystem-consentcache-and-revocation-subscriber); extending this gauge's label set is filed there as a follow-up, not yet implemented) |
| `qodiqa_execution_integrity_full` | Gauge | — | 1 when all critical stores are ready, 0 otherwise. **Does not include the consent revocation subscriber** — that dependency gates `/ready` directly (`REQUIRED_COMPONENTS` in `src/api/routes/ready.js`), independent of this metric |
| `qodiqa_build_info` | Gauge | version labels | Build/version identification |
| `qodiqa_rate_limit_redis_failures_total` | Counter | `surface` | Rate-limit backend (Redis) failures causing fail-closed 429s |
| `qodiqa_prq_dlq_depth` / `qodiqa_prq_archived_depth` | Gauge | — | Persistence-recovery-queue dead-letter/archived depth |
| `qodiqa_consent_revocation_published_total` / `_received_total` | Counter | `result` (`ok`\|`skipped`\|`error`\|`invalid`\|`duplicate`) | Revocation pub/sub events sent / received across the cluster |
| `qodiqa_consent_revocation_cache_invalidations_total` | Counter | `scope` (`targeted`\|`actor`) | Local `ConsentCache` invalidations triggered by a received revocation event |
| `qodiqa_consent_revocation_propagation_latency_ms` | Histogram | — | Receive → local cache-invalidation latency; watch p99 against `REVOCATION_MAX_EVENT_AGE_MS` (default 30s) |
| `qodiqa_consent_subscriber_reconnects_total` | Counter | `type` (`subscriber`\|`publisher`) | Redis pub/sub client reconnect events for the revocation subscriber/publisher |
| `qodiqa_redis_subscription_recovery_total` | Counter | `purpose` | Successful pub/sub re-`SUBSCRIBE` after a reconnect — for `purpose="revocationSubscriber"` this is the signal that the revocation channel subscription (not just the socket) recovered |

CPU/memory/disk are intentionally **not** emitted by the application itself —
they belong to the infrastructure layer (node exporter / cAdvisor / cloud
provider metrics) per [§11](#11-known-architectural-notes). Database
(PostgreSQL) availability is exposed through DR probes
(`scripts/dr/probes/*`) and the `/ready` endpoint's `components` block, not a
Prometheus gauge — see [Reliability](#36-reliability) below.

### 3.6 Reliability

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `qodiqa_transparency_gap_total` / `qodiqa_transparency_gap_active` | Counter/Gauge | — | Transparency-log gaps detected / currently unresolved |
| `qodiqa_transparency_gap_resolved_total` / `_critical_total` | Counter | — | Gaps resolved / gaps that reached critical age |
| `qodiqa_gap_scanner_runs_total` / `_success_total` / `_failures_total` | Counter | — | Gap-scanner run outcomes |
| `qodiqa_transparency_root_scheduler_*` | Counter/Gauge | — | Transparency root generation scheduler health |
| `qodiqa_prq_dlq_replay_total` / `_archive_total` | Counter | — | Dead-letter-queue replay/archive actions |
| `qodiqa_prq_dlq_oldest_item_age_seconds` | Gauge | — | Oldest unresolved DLQ item age |

Backup and DR job status is exposed as **textfile-collector** gauges (written by the
jobs, read by node_exporter — not served by the gateway's `/metrics`):
`qodiqa_pg_backup_success` / `_last_run_timestamp_seconds` / `_size_bytes` (`scripts/pg-backup.sh`,
labels `mode`, `tier`) and the `qodiqa_dr_backup_*`, `qodiqa_dr_backup_verify_*` and
`qodiqa_dr_restore_validation_*` gauges (`scripts/dr/*`). Their alerts are in
`deploy/kubernetes/overlays/examples/monitoring/backup-prometheusrule.yaml` (groups `qodiqa.backup`, `qodiqa.dr`;
see [§11.8]). The DR framework's own exit codes and reports
(`scripts/dr/validate.js`, [Backup → Restore Validation](backup-restore-validation.md) §5–6, run on a
schedule via the CI workflow) remain the detailed pass/fail record.
Audit-chain and policy-store validation are not exported as metrics.

### 3.7 Application

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `qodiqa_provenance_versions_total` / `_modifications_total` / `_rollbacks_total` | Counter | — | Content-provenance lifecycle events |
| `qodiqa_provenance_integrity_failures_total` / `_attribution_failures_total` / `_diff_failures_total` | Counter | — | Provenance validation failures |
| `qodiqa_certifications_total` / `qodiqa_certification_failures_total` | Counter | — | Certification issuance outcomes |
| `qodiqa_simulations_total` / `qodiqa_simulation_duration_ms` / `qodiqa_simulation_failures_total` | Counter/Histogram | — | Policy simulation runs |
| `qodiqa_policy_comparisons_total` / `qodiqa_batch_simulations_total` | Counter | — | Policy comparison / batch simulation runs |
| `qodiqa_webhook_deliveries_total` | Counter | `event_type` | Successful webhook deliveries (consumer-facing event notification) |
| `qodiqa_org_requests_total` / `qodiqa_org_active_sessions` | Counter/Gauge | `org` | Per-tenant request volume / active sessions |

Consent *resolution* itself (the ALLOW/DENY decision within a single
enforcement request) is folded into the enforcement request path
(`qodiqa_requests_total` / `qodiqa_blocks_total`) rather than broken out as a
separate counter, since every enforcement request resolves consent as an
inseparable step of policy evaluation. Cross-node consent *revocation
propagation*, by contrast, is a distinct async control plane with its own
metrics — see the `qodiqa_consent_revocation_*` / `qodiqa_consent_subscriber_*`
rows in [§3.5](#35-infrastructure) and [Redis Failure Runbook §12](redis-failure.md#12-consent-subsystem-consentcache-and-revocation-subscriber).

---

## 4. Naming Conventions

All application metrics follow: **`qodiqa_<subsystem>_<name>_<unit>`**

- `<subsystem>` — the owning component (`rate_limit`, `webhook`, `transparency`,
  `gap_scanner`, `prq` [persistence recovery queue], `org` [organization/tenant], etc).
- `<name>` — what is being measured, in `snake_case`.
- `<unit>` — required suffix for non-dimensionless metrics: `_total` (monotonic
  counter), `_ms` (duration), `_seconds` (duration/timestamp), `_active` /
  no suffix (current-value gauge).
- Labels are `snake_case` and drawn from **fixed, bounded enums** only
  (e.g. `surface`, `event_type`, `reason`, `store`) — never unbounded
  per-request values (user IDs, IPs, request IDs) are used as label values,
  to keep Prometheus cardinality bounded.

This convention was already established by the pre-existing ~102 metrics; the
two additions made under this task (`qodiqa_rate_limit_*`,
`qodiqa_webhook_*` — see [§11.1](#111-newly-added-metrics-this-task)) simply
extend it, rather than introducing a new one.

---

## 5. Alert Taxonomy & Severity Model

Severity definitions are authoritative in
[src/alerting/engine/SeverityModel.js](../../src/alerting/engine/SeverityModel.js)
and [src/alerting/constants.js](../../src/alerting/constants.js). This section
restates them for operational reference; see
[ALERTING_FRAMEWORK.md § Severity Levels](alerting.md) for the
full detection/scoring pipeline.

| Severity | Ack SLA | Resolution SLA | Notification channels | Escalation |
|----------|---------|-----------------|------------------------|------------|
| **CRITICAL** | 15 min | 2 hours | Slack, Teams, PagerDuty, Webhook, SIEM, Email, SMS | L3 → L4 (executive) at 30 min |
| **HIGH** | 30 min | 4 hours | Slack, Teams, PagerDuty, Webhook, SIEM, Email | L2 → L3 at 30/60 min |
| **MEDIUM** | 2 hours | 24 hours | Slack, Webhook, SIEM | L1 → L2 at 2 hours |
| **LOW** | 4 hours | 72 hours | Webhook, SIEM | L1 only, at 4 hours |
| **INFO** | — (not required) | — | stored only, not dispatched | none |

Alert *types* (`REPLAY_ATTACK`, `SIGNATURE_FAILURE`, `POLICY_FAILURE`,
`ANOMALY`, `OPERATIONAL`, `GOVERNANCE`) and their subtypes are enumerated in
`src/alerting/constants.js` and produced by the 5 detectors in
`src/alerting/detection/` (Replay, Signature, Policy, Operational, Anomaly).

---

## 6. Alert Catalog

Named alert conditions, grouped by severity. Each includes trigger condition,
operational impact, and recommended operator action. Sources are either the
Alerting Framework (event-based) or a Prometheus/Alertmanager rule
(metric-based) — both feed the same severity/response model.

### 6.1 Critical

| Alert | Trigger | Impact | Operator action |
|-------|---------|--------|------------------|
| Audit chain corrupted | `OPERATIONAL/AUDIT_CHAIN_CORRUPTED` — hash-chain break detected | Audit trail integrity compromised; compliance/legal exposure | Follow [Disaster Recovery §Audit Chain](disaster-recovery.md); halt writes; restore from last-known-good backup |
| Policy fail-open detected | `POLICY_FAILURE/FAIL_OPEN_DETECTED` | Enforcement may be silently bypassed | Immediately verify policy engine state; consider traffic isolation; page security on-call |
| Redis nonce store down | `qodiqa_redis_store_up{store="nonce"} == 0` (metric; shipped as **QodiqaRedisStoreDown**, 1 min, after 120 s uptime because the gauge is preset to 0 at load) / `OPERATIONAL/NONCE_STORE_DEGRADED` (event) | Replay protection unavailable; enforcement fails closed | Follow [Redis Failure Runbook](redis-failure.md); confirm fail-closed behavior is active |
| Consent revocation subscriber disconnected | `GET /ready` → `components.consentSubscriber == false` for > 30s (also visible as `revocationSubscriberReady == false` via `/consent/health`, or sustained `REVOCATION_SUBSCRIBER_RECONNECTING` logs) | All `REQUIRE_CONSENT` requests on the affected node(s) denied (`CONSENT_REVOCATION_SYNC_UNAVAILABLE`) — fail-closed, no grace period | Follow [Redis Failure Runbook §12.2](redis-failure.md#122-revocation-subscriber--the-control-that-actually-matters); confirm Redis reachability; do not bypass the check |
| Execution integrity lost | `qodiqa_execution_integrity_full == 0` for > 60s (shipped as **QodiqaExecutionIntegrityDegraded**, same uptime guard) | One or more critical stores unavailable | Check `/diagnostics` `components` block; follow relevant component runbook |
| Cross-tenant replay | `REPLAY_ATTACK/CROSS_TENANT_REPLAY` | Possible tenant isolation breach | Immediate security review; consider tenant-level traffic block |
| Signing key compromise indicators | `SIGNATURE_FAILURE/REVOKED_KEY` or `MULTIPLE_ACTIVE_KEYS` at volume | Signing integrity at risk | Follow [Key Compromise Runbook](key-compromise-runbook.md) |
| Audit disk full | `OPERATIONAL/AUDIT_DISK_FULL` — ENOSPC on `appendMandatory()` retry exhaustion (event) and `qodiqa_audit_disk_full_total{stage}` (metric; also counted in `qodiqa_audit_append_failed_total`), shipped as **QodiqaAuditDiskFull**, runbook [Audit append failure](alert-runbooks.md#audit-append-failure) | Audit evidence cannot be durably recorded; requests on the mandatory-audit path fail closed | Free disk space immediately on the audit log volume; confirm `qodiqa_audit_disk_full_total` and `qodiqa_audit_append_failed_total` stop climbing |
| PostgreSQL circuit breaker OPEN | `OPERATIONAL/PG_POOL_EXHAUSTED` — `PG_CIRCUIT_BREAKER_STATE` transitioning to `OPEN` (metric: `qodiqa_pg_circuit_opens_total`, shipped as **QodiqaPgCircuitOpen**) | PG-dependent operations fast-failing; PG-backed features (dual-write, distributed ordering, compliance reporting) degraded | Check PG connection pool saturation (`pgPool.poolStats()` via `/diagnostics`); investigate slow queries or connection leaks |

### 6.2 High

| Alert | Trigger | Impact | Operator action |
|-------|---------|--------|------------------|
| Invalid signature spike | `SIGNATURE_FAILURE/INVALID_SIGNATURE` above baseline | Possible forged artifacts or client bug | Investigate source; check `qodiqa_verification_blocks_total` trend |
| Sustained replay attempts | `REPLAY_ATTACK/NONCE_REUSE` or `REPEATED_REQUEST_HASH` above baseline | Active replay attack in progress | Confirm rate limiting engaged; review `qodiqa_rate_limit_limited_total{reason}` |
| Provider failure | `qodiqa_provider_failures_total{provider,code}` rate > 0.1/s for 5 min (shipped as **QodiqaProviderFailures**). The event subtype `OPERATIONAL/PROVIDER_FAILURE` is defined in `src/alerting/constants.js` but **nothing emits it** — the metric is the only signal | Upstream AI provider degraded; requests failing | [Provider failures](alert-runbooks.md#provider-failures) |
| Redis backend failures (rate limit) | `qodiqa_rate_limit_redis_failures_total` rate increasing | Rate limiting fail-closed, legitimate traffic rejected | Follow [Redis Failure Runbook](redis-failure.md) |
| RBAC / governance violation | `GOVERNANCE/RBAC_VIOLATION`, `UNAUTHORIZED_KEY_ADMIN` | Unauthorized administrative action attempted | Review `/audit` trail; confirm no privilege escalation succeeded |
| Webhook delivery failures spike | `qodiqa_webhook_delivery_failures_total{event_type}` rate increasing | Downstream consumers not receiving events | Check target endpoint health; review `webhookCircuitBreaker` state |
| Transparency verification failures | `qodiqa_transparency_verification_failures_total` increasing | Transparency log entries failing verification | Follow [Transparency Recovery](transparency-recovery.md) |
| Request latency SLA breach | `OPERATIONAL/LATENCY_SLA_BREACH` — mean `requestDurationMs` (EXECUTE) exceeds `QODIQA_SLA_LATENCY_MS` (default 2000ms) | Callers experiencing sustained slow responses | Check provider latency, event-loop delay (`/diagnostics` `eventLoop`), and Redis/PG round-trip times |
| Request latency p99 breach | `OPERATIONAL/LATENCY_P99_BREACH` — estimated p99 exceeds `QODIQA_P99_LATENCY_MS` (default 5000ms) | A minority of requests suffering severe latency even if the mean is healthy | Investigate long-tail causes (GC pauses, provider retries, cold-start effects) independently of the mean-latency alert above |

### 6.3 Medium

| Alert | Trigger | Impact | Operator action |
|-------|---------|--------|------------------|
| Policy denial rate above baseline | `qodiqa_blocks_total` / `qodiqa_requests_total` ratio spike > 10% (metric, [README §Key Operational Metrics](README.md)) | Possible policy misconfiguration or client-side bug | Review recent policy changes; check `qodiqa_policy_comparisons_total` for simulation drift |
| Anomaly — volume/traffic spike | `ANOMALY/VOLUME_SPIKE`, `TRAFFIC_SPIKE`, `BURST_DETECTION` | Unusual load pattern, possible abuse | Correlate with `qodiqa_org_requests_total{org}`; consider tenant-level rate limit review |
| Rate limit burst consumption elevated | `qodiqa_rate_limit_burst_consumed_total` trending up for a surface | Clients repeatedly hitting burst ceiling | Review policy `burstCapacity` for the surface; check for legitimate traffic growth |
| Gap scanner failures | `qodiqa_gap_scanner_failures_total` increasing | Transparency gap detection degraded | Check gap scanner logs; verify PostgreSQL connectivity |
| Certification/attestation failures | `qodiqa_certification_failures_total`, `qodiqa_attestation_failures_total` increasing | Downstream compliance artifacts not being produced | Review certification service logs; not on enforcement critical path |
| Key rotation overdue | `OPERATIONAL/KEY_ROTATION_OVERDUE` | A signing key is past its rotation-due deadline — automatic rotation may be disabled or failing | Check `keyRotationScheduler` status (`/diagnostics` or `GET /key-admin/rotation-scheduler/status`); rotate manually if needed |

### 6.4 Low

| Alert | Trigger | Impact | Operator action |
|-------|---------|--------|------------------|
| DLQ depth non-zero | `qodiqa_prq_dlq_depth > 0` (shipped as **QodiqaPrqDlqNonEmpty**, 30 min, severity info) | Some async operations (e.g. webhook retries) parked for manual review | Review DLQ via persistence-recovery admin tooling during business hours |
| DLQ item aging | `qodiqa_prq_dlq_oldest_item_age_seconds` above baseline | Oldest unresolved item is stale | Investigate root cause of stuck retries; replay or archive as appropriate |
| Provenance rollback recorded | `qodiqa_provenance_rollbacks_total` incremented | Expected user-driven action, but worth trend-watching | No immediate action; review in daily operational summary if rate is unusual |
| Simulation failures | `qodiqa_simulation_failures_total` increasing | Policy simulation tooling (non-production-path) degraded | Investigate at next convenient maintenance window |
| Key expiry approaching | `OPERATIONAL/KEY_EXPIRY_APPROACHING` — `KEY_EXPIRING_SOON` within `EXPIRY_WARNING_DAYS` (default 30) | A signing key will stop working for new signatures once expired | Rotate the key (see [Key rotation](runbook.md#key-rotation)) before the deadline |

---

## 7. Dashboard Recommendations

Recommended Grafana dashboard panels, grouped to match the 7 metrics
categories in [§3](#3-metrics-taxonomy):

1. **Runtime overview** — `qodiqa_requests_total` (rate), `qodiqa_blocks_total`
   (rate), `qodiqa_request_duration_ms` (p50/p95/p99 via histogram_quantile),
   `qodiqa_active_requests` (current).
2. **Security** — `qodiqa_security_events_total` by `event` (stacked rate
   graph; the label is `event`, one of `invalid_signature`, `expired_artifact`, `malformed_artifact`,
   `replay_detected`, `nonce_violation`, `anomaly_detected`), `qodiqa_rate_limit_limited_total` by `reason`, alert volume by
   severity (from AlertStore — see [ALERTING_FRAMEWORK.md § API](alerting.md)).
3. **Cryptography** — signature/verification failure rates
   (`qodiqa_transparency_verification_failures_total`,
   `qodiqa_evidence_chain_verification_failures_total`), key rotation events.
4. **Provider** — `qodiqa_streaming_provider_latency_ms` (p95),
   `qodiqa_webhook_delivery_duration_ms` (p95), `qodiqa_webhook_delivery_failures_total` (rate).
5. **Infrastructure** — `qodiqa_redis_store_up` by `store` (single-stat, red
   when 0), `qodiqa_execution_integrity_full`, `qodiqa_process_uptime_seconds`.
6. **Reliability** — `qodiqa_transparency_gap_active` (**unused — never written, reads 0**; use
   `qodiqa_gap_scanner_gaps_detected_total` / `_unrecoverable_total` instead),
   `qodiqa_prq_dlq_depth`, `qodiqa_prq_dlq_oldest_item_age_seconds`, most
   recent DR validation result (external annotation from CI, since DR
   validation is not itself a scraped metric — see [§11](#11-known-architectural-notes)).
7. **Application** — per-tenant panels: **not available today.** `qodiqa_org_requests_total` /
   `qodiqa_org_blocks_total` / `qodiqa_org_active_sessions` are registered but **never written** (they always
   read 0; see [§11.8]).

`TENANT_METRICS_ENABLED` is **not honoured** anywhere (it appears only in a comment in
`src/observability/metrics.js`; `src/api/routes/metrics.js` does not read it). Corrected 2026-10-06.

---

## 8. Prometheus / Grafana / Alertmanager Integration

- **Scrape config**: point Prometheus at `GET /metrics` on the QODIQA
  instance. The endpoint requires the same operator-auth gate as
  `/diagnostics` (`ctx.opsOnlyStack()` — IP allowlist, ops auth, diagnostics gate — see `src/app.js:179`);
  configure the Prometheus scrape job with the appropriate bearer token /
  network allowlist entry.
- **Recording rules**: pre-aggregate ratios used in Section 6 (e.g.
  `qodiqa:block_ratio = rate(qodiqa_blocks_total[5m]) / rate(qodiqa_requests_total[5m])`)
  to keep Alertmanager rule expressions simple.
- **Alertmanager rules**: implement the metric-based triggers in
  [§6](#6-alert-catalog) as standard Prometheus alerting rules (`ALERT ...
  IF ... FOR ...`), routing by severity label to the same channels documented
  in [§5](#5-alert-taxonomy--severity-model) — this keeps a single mental
  model even though the dispatch mechanism (Alertmanager vs. QODIQA
  NotificationService) differs per alert source.
- **Grafana**: import panels per [§7](#7-dashboard-recommendations); use
  `histogram_quantile` over the `_ms` histograms for latency percentiles
  (buckets are `DEFAULT_LATENCY_BUCKETS` / `FAST_LATENCY_BUCKETS` — see
  `src/observability/metrics.js`).
- **Event-based alerts** (the QODIQA Alerting Framework) do not need
  Alertmanager — they are dispatched directly by `NotificationService` to the
  same downstream tools (Slack, Teams, PagerDuty, SIEM, Email, SMS, generic
  Webhook) using severity-appropriate channel sets from
  `SeverityModel.js`. Route both alert sources into the **same** Slack
  channel / PagerDuty service per severity so on-call does not need to watch
  two separate tools.

---

## 9. Incident Response Workflow

1. **Detection** — an alert fires from either path (metric threshold via
   Alertmanager, or event-based via the Detection Engine).
2. **Triage** — consult [§6](#6-alert-catalog) for the named alert's impact
   and recommended action; consult `/diagnostics` for current component
   health if the alert is operational in nature.
3. **Acknowledge** — within the SLA window for the alert's severity
   ([§5](#5-alert-taxonomy--severity-model)); event-based alerts are
   acknowledged via the `/alerts` API (`src/alerting/api/alertRoutes.js`).
4. **Contain / remediate** — follow the linked runbook (Redis Failure, Key
   Compromise, Transparency Recovery, Disaster Recovery, etc. — see
   [docs/operations/README.md](README.md) for the full runbook index).
5. **Resolve** — within the resolution SLA; HIGH/CRITICAL alerts require a
   post-incident report (`sla.reportRequired: true` in `SeverityModel.js`).
6. **Post-mortem** — for HIGH/CRITICAL incidents, follow
   [Incident Response Guide](incident-response.md) for the full post-mortem
   process; cross-reference correlated alerts via the Correlation Engine's
   incident grouping (`src/alerting/correlation/CorrelationEngine.js`).

---

## 10. Operational Best Practices

- **Treat `/metrics` and the Alerting Framework as complementary, not
  redundant.** Metrics answer "what is the current rate/value?"; alerts
  answer "did something specific and actionable just happen?". Both should
  be visible on the same on-call dashboard.
- **Do not add new ad-hoc metric systems.** Any new metric should be added to
  the central registry in `src/observability/metrics.js` following the
  `qodiqa_<subsystem>_<name>_<unit>` convention ([§4](#4-naming-conventions)),
  not a new Map-based counter module — see [§11.2](#112-consolidation-decision)
  for why the two pre-existing exceptions (rate limit, webhooks) were
  mirrored rather than migrated outright.
- **Keep label cardinality bounded.** Only use fixed enums as label values
  (surface names, event types, tenant/org IDs *if* tenant count is bounded
  and `TENANT_METRICS_ENABLED` is deliberately turned on) — never request
  IDs, IPs, or other unbounded values.
- **Route both alert sources to the same channel per severity** so on-call
  does not need to monitor two separate tools during an incident.
- **Prefer the DR framework's own validation reports over inventing
  synthetic reliability metrics** for backup/restore health — the exit-code
  contract in `scripts/dr/validate.js` is deterministic and already
  CI-scheduled; duplicating it as a scraped gauge would add a second source
  of truth for the same fact.

---

## 11. Known Architectural Notes

This section documents intentional design decisions and known gaps
identified while producing this unified model, per the instruction to
"consolidate existing functionality whenever possible" and avoid
introducing breaking changes.

### 11.1 Newly added metrics (this task)

Two ad-hoc, Map-based metrics modules existed with **no Prometheus
exposure**: `src/core/rateLimit/metrics.js` (`rl_*` counters/gauges) and
`src/core/webhooks/webhookMetrics.js` (`webhook_*` counters). Both are
consumed only via an internal `snapshot()` accessor and were never reachable
from `/metrics`.

To close this gap **without removing or renaming the existing internal
API** (backward compatible, per Step 5), the following were added to
`src/observability/metrics.js` and wired at the *same call sites* as the
existing internal counters:

- `qodiqa_rate_limit_requests_total`, `_allowed_total`, `_limited_total`,
  `_redis_failures_total`, `_burst_consumed_total`, `_quota_utilization`,
  `_latency_ms` (mirrors `src/core/rateLimit/metrics.js`, wired in
  `src/core/rateLimit/middleware.js`).
- `qodiqa_webhook_deliveries_total`, `_delivery_failures_total`,
  `_retries_total`, `_delivery_duration_ms` (mirrors
  `src/core/webhooks/webhookMetrics.js`, wired in
  `src/core/webhooks/webhookDelivery.js`).

The internal `rl_*` / `webhook_*` counters are untouched — this is a
**purely additive** change; nothing that previously read `.snapshot()`
observes any behavior change.

### 11.2 Consolidation decision

Three separate metrics surfaces exist in the codebase:

1. `src/observability/metrics.js` — the Prometheus registry (this document's focus).
2. `src/dashboard/*` (`MetricsEngine.js`, `AggregationStore.js`) — a
   dashboard-specific aggregation system, intentionally separate, serving
   the operator dashboard UI rather than Prometheus scraping.
3. Ad-hoc Map-based modules (rate limit, webhooks — now also mirrored per
   §11.1; persistence-recovery's `src/core/persistenceRecovery/metrics.js`
   remains internal-only, lower value to migrate since the DLQ subsystem
   already has 7 first-class `qodiqa_prq_dlq_*` Prometheus metrics covering
   its operationally significant signals).

These were **not** merged into a single system for this task. Merging (1)
and (2) would require substantial changes to the dashboard subsystem for no
operational benefit — the dashboard already has its own aggregation
lifecycle and is not a Prometheus consumer. This is documented here as an
intentional layering, not an oversight, consistent with "avoid introducing
duplicate implementations" being interpreted as *no new duplicate systems*,
not *forced convergence of pre-existing, independently justified systems*.

### 11.3 Severity/type definitions exist in two places

`src/alerting/constants.js` defines `ALERT_TYPE`/subtypes and `SEVERITY`;
`src/alerting/engine/SeverityModel.js` defines the operational response
model per severity. These are complementary (constants = vocabulary,
SeverityModel = behavior), not duplicative — `SeverityModel.js` imports its
`SEVERITY` values from `constants.js`. No conflicting duplication was found;
this is called out simply so a future contributor does not assume they need
to reconcile two independent definitions.

### 11.4 Type mismatch: execution integrity representation

`qodiqa_execution_integrity_full` is a numeric Prometheus gauge (1/0), while
`GET /diagnostics`'s `executionIntegrity` field is a string (`'FULL'` /
`'DEGRADED'`). Both represent the same underlying fact (all critical stores
ready) computed independently in `metrics.js`/`metricsMiddleware.js` and
`diagnostics.js` respectively. This is a pre-existing, cosmetic
representation difference (gauge vs. JSON string) rather than a functional
bug — changing either shape risks breaking existing Prometheus queries or
`/diagnostics` consumers, so no code change was made; operators should be
aware both signals mean the same thing when correlating a Grafana panel
against a `/diagnostics` call.

### 11.5 Gaps intentionally left undocumented as metrics

- CPU/memory/disk: expected to come from infrastructure-layer exporters
  (node_exporter, cAdvisor, cloud metrics), not the application itself.
- Audit-chain and policy-store validation status: validated via
  `scripts/dr/validate.js`'s deterministic exit codes and CI scheduling
  (see [Backup → Restore Validation](backup-restore-validation.md)) rather
  than a scraped gauge. (Backup and DR job status *is* exported, as
  textfile-collector gauges — see [§3.6](#36-reliability).)
- HSM/KMS failures: superseded — they now have dedicated metrics
  (`qodiqa_signing_failures_total`, `qodiqa_signing_health_state`; see [§3.3](#33-cryptography)).

---

### 11.6 Anchoring and backup signals

| Metric | Type | Labels | Source |
|---|---|---|---|
| `qodiqa_audit_anchor_events_total` | Counter | `outcome` = `anchored` \| `witness_refused` \| `witness_failed` \| `export_failed` \| `transparency_anchor_failed` | `src/core/audit/checkpoint/checkpointWriter.js` (one increment per anchor publication outcome; `transparency_anchor_failed` = the signed checkpoint could not be registered in the transparency log, alert **QodiqaCheckpointTransparencyAnchorFailed**) |
| `qodiqa_pg_backup_success`, `qodiqa_pg_backup_last_run_timestamp_seconds`, `qodiqa_pg_backup_size_bytes` | Gauge (textfile collector) | `mode`, `tier` | `scripts/pg-backup.sh` (`QODIQA_BACKUP_METRICS_FILE`) |

Alert rules shipped in `deploy/kubernetes/overlays/examples/monitoring/prometheusrule.yaml` (gateway metrics): **QodiqaAnchorWitnessRefused** (critical: a witness saw a rollback or equivocation attempt), **QodiqaAnchorWitnessFailed** (warning), **QodiqaAnchorExportFailed** (critical); and in `backup-prometheusrule.yaml` (textfile-collector metrics, group `qodiqa.backup`): **QodiqaBackupFailed** (critical), **QodiqaBackupStale** (a tier has not run within its schedule: daily 26 h, weekly 8 d, monthly 32 d; more backup, WAL-archive and audit-log-backup rules in §11.8), **QodiqaBackupMetricsAbsent** (the job never ran or its metrics are not collected). Not exercised against a real Prometheus/Alertmanager here: the rule file is YAML-validated and `deploy:validate` passes.

### 11.7 Audit mirror backlog bound

The PostgreSQL audit mirror is written by an in-process FIFO (`qodiqa_audit_mirror_writer_depth`). A database that is slow but still up used to let that backlog, and the heap, grow without limit (58,756 entries behind; post-GC heap 182 → 623 MB over 30 segments on a slow container database). The backlog is now bounded. When it reaches `QODIQA_AUDIT_MIRROR_MAX_DEPTH` (default 20,000; minimum 100):
- admission refuses new `/sign` and `/ai/chat` requests up front with 503 `SERVER_OVERLOADED`. Nothing is written, no provider is called and the nonce is not consumed. The refusal is counted as `qodiqa_admission_rejected_total{cause="audit_backlog"}`;
- `GET /ready` reports `auditBacklog: false`.

Both clear once the backlog has drained to half the limit. The engage and release transitions are logged as `AUDIT_MIRROR_BACKPRESSURE_ENGAGED` and `AUDIT_MIRROR_BACKPRESSURE_RELEASED`. The authoritative file chain is unaffected. A PostgreSQL that is fully down is still handled by the persistence recovery queue, not by this bound.

Alerts (`prometheusrule.yaml`, group `qodiqa.mirror`):
- **QodiqaAuditMirrorBacklogHigh** (warning): depth above 5,000 for 5 minutes;
- **QodiqaAuditBacklogShedding** (critical): any `audit_backlog` refusal.

### 11.8 Shipped Prometheus alerts

Source: (audit) and (fix).
Every rule in `deploy/kubernetes/overlays/examples/monitoring/prometheusrule.yaml` (gateway) and
`backup-prometheusrule.yaml` (textfile collector) now carries `severity`, `summary` and a `runbook_url` that resolves to a
repository document and heading; runbook sections that did not exist anywhere are in [Alert Runbooks](alert-runbooks.md).
Guarded by tests: every metric `metrics.js` exports is served by `/metrics` (`metricsRegistryCompleteness.test.js` MR-01,
and SD-06 now checks the served exposition, not module exports); every metric a gateway rule references is served (MR-03,
SD-06); every rule is structurally complete and its runbook link resolves (`prometheusRuleStructure.test.js`).

**First-event blind spot.** A labelled counter appears on its first increment already at 1, and `increase()` never sees
a series' first sample. Closed label sets that a rule matches on are seeded at 0 in `metrics.js`
(`admission_rejected_total`, `audit_anchor_events_total`, `audit_fail_closed_rejections_total`,
`transparency_fail_closed_rejections_total`, `transparency_enforcement_failures_total`, `audit_crosscheck_failure_total`,
`queue_backlog_alerts_total`, `security_events_total`, `ops_auth_failures_total`, `mfa_events_total`,
`audit_mirror_count_drift_total`). Open-ended label sets, and events that can happen at boot before the first scrape,
use `(increase(X[w]) > 0) or (X > 0 unless X offset w)`. **Unset gauges read 0**, which for some gauges means unsafe or
unavailable; those rules are guarded (labelled-series matcher, last-check timestamp > 0, or process uptime).

| Group | Alert | Severity | Signal |
|---|---|---|---|
| evidence | QodiqaAuditFailClosedRejections, QodiqaAuditAppendFailed | critical | audit append fail-closed / failing |
| evidence | QodiqaAuditDiskFull | critical | `qodiqa_audit_disk_full_total` — an append failed on ENOSPC |
| evidence | QodiqaCheckpointTransparencyAnchorFailed | warning | `qodiqa_audit_anchor_events_total{outcome="transparency_anchor_failed"}` |
| evidence | QodiqaHigh5xxRate | warning | `qodiqa_http_responses_total{status_class="5xx"}` above 5% of a route family's responses for 10 min |
| evidence | QodiqaAuditWalFsyncSlow | warning | `qodiqa_audit_wal_fsync_duration_seconds` p99 > 0.5 s, 10 min |
| evidence | QodiqaTransparencyFailClosed, QodiqaTransparencyEnforcementFailures | critical | transparency append failure (ALLOW refusal / any stage BLOCK, ALLOW, STREAM) |
| evidence | QodiqaTransparencyGapUnrecoverable (critical), QodiqaGapScannerStale, QodiqaTransparencyRootErrors, QodiqaTransparencyUnrootedSpan (warning) | | transparency pipeline |
| evidence | QodiqaAuditChainVerifierFailure (critical), QodiqaAuditChainVerifierLag (warning) | | live chain verifier |
| evidence | QodiqaChecksumAnchorMismatch (critical), QodiqaChecksumAnchorPgWriteFailing (warning) | | checksum anchor |
| evidence | QodiqaAnchorWitnessRefused, QodiqaAnchorExportFailed (critical), QodiqaAnchorWitnessFailed, QodiqaCheckpointTickFailed (warning) | | external anchoring |
| evidence | QodiqaEvidenceChainPersistFailures | warning | evidence chain |
| evidence | QodiqaTransparencyPersistFailures | warning | `increase(qodiqa_transparency_persist_failures_total[15m]) > 0` — transparency entries/roots failing to persist |
| mirror | QodiqaMirrorCrosscheckDivergence, QodiqaMirrorCountDrift (critical), QodiqaMirrorCrosscheckFailed, QodiqaAuditPgHydrationFailed, QodiqaAuditPgSyncLag (warning) | | PG audit mirror |
| mirror | QodiqaAuditMirrorBacklogHigh (warning), QodiqaAuditBacklogShedding (critical) | | mirror backlog (§11.7) |
| dependencies | QodiqaReadinessDependencyFailures, QodiqaReadinessComponentDown | warning | readiness (consentCache excluded; failures in the first 10 min of uptime excluded from the counter rule) |
| dependencies | QodiqaRedisStoreDown, QodiqaExecutionIntegrityDegraded, QodiqaRedisPersistenceUnsafe (critical), QodiqaRedisCommandFailures (warning) | | Redis |
| dependencies | QodiqaRedisConnectionDegraded | warning | `qodiqa_redis_connection_state_code{purpose!=""} < 3` for 5 min — a managed Redis client not HEALTHY |
| dependencies | QodiqaPrqJournalWriteFailed | critical | `(increase(qodiqa_prq_journal_write_failed_total[15m]) > 0) or (qodiqa_prq_journal_write_failed_total > 0 unless qodiqa_prq_journal_write_failed_total offset 15m)` — a recovery-queue operation lost (PostgreSQL and the local journal both refused it) |
| dependencies | QodiqaPgCircuitOpen (critical), QodiqaPgPoolSaturated, QodiqaPgAcquireFailures (warning) | | PostgreSQL pool / circuit |
| dependencies | QodiqaQueueBacklog, QodiqaPrqOldestPending (warning), QodiqaPrqDlqNonEmpty (info), QodiqaPrqPersistFailed (critical) | | recovery queue |
| dependencies | QodiqaAdmissionRejecting, QodiqaProviderFailures, QodiqaRetentionPrivilegeCheckFailed | warning | saturation, provider, retention role |
| security | QodiqaReplaySpike (warning), QodiqaNonceViolation (critical) | | replay / nonce |
| security | QodiqaMfaLockouts, QodiqaOpsAuthFailureBurst, QodiqaRbacDenialBurst, QodiqaAuthLockoutStorageFailures | warning | operator auth |
| security | QodiqaPubsubSignatureRejects | critical | `(increase(qodiqa_pubsub_signature_rejects_total[15m]) > 0) or (qodiqa_pubsub_signature_rejects_total > 0 unless qodiqa_pubsub_signature_rejects_total offset 15m)` — revocation / org-status messages rejected for a missing or invalid MAC |
| runtime | QodiqaEventLoopUnhealthy (critical), QodiqaEventLoopDegraded (warning) | | event loop |
| runtime | QodiqaBackgroundTaskFailing | warning | background tasks |
| runtime | QodiqaKeyRotationOverdue, QodiqaKeyRotationSchedulerFailed (warning), QodiqaKeyExpiringSoon (info), QodiqaSigningProviderUnavailable (critical) | | keys / signing |
| scrape | QodiqaScrapeDown, QodiqaMetricsAbsent | critical | scrape health (`up`, `absent`) — without these every other alert can be silently blind |
| backup | QodiqaBackupFailed, QodiqaBackupVerifyFailed (critical), QodiqaBackupStale (per tier: daily 26 h, weekly 8 d, monthly 32 d), QodiqaBackupVerifyStale (26 h), QodiqaBackupMetricsAbsent (warning) | | `pg-backup.sh` textfile |
| wal-archive | QodiqaWalArchiveVerifyFailed (critical), QodiqaWalArchiveMetricsStale (warning, 30 min) | | `pg-wal-archive.sh` textfile |
| audit-log-backup | QodiqaAuditLogBackupFailed (critical), QodiqaAuditLogBackupStale (warning, 30 min) | | `backup-audit-log.sh` textfile (systemd only; silent in Kubernetes) |
| dr | QodiqaDrBackupFailed, QodiqaDrBackupVerifyFailed, QodiqaDrRestoreValidationFailed (critical), QodiqaDrBackupStale (warning) | | `scripts/dr/*` textfile |

**New metrics.** All counters unless noted; every one is written by a single best-effort, try/catch-wrapped
call and never on a decision path.

| Metric | Labels | Written at |
|---|---|---|
| `qodiqa_provider_failures_total` | `provider` (token-shaped, else `other`), `code` (UPPER_SNAKE, else `OTHER`) | `src/api/routes/aiChat.js` provider catch (non-cancellation) and `src/streaming/streamEnforcer.js` `STREAM_PROVIDER_ERROR` (streaming; client disconnect / stream timeout excluded) |
| `qodiqa_rbac_denials_total` | `action` (permission constant), `reason` (`RBAC_NOT_RESOLVED`, `ENGINE_ERROR`, `INSUFFICIENT_ROLE`) | `src/middleware/rbac.js` (`RBAC_DENY`) |
| `qodiqa_ops_auth_failures_total` | `reason` = `missing_credentials` \| `invalid_token` | `src/middleware/opsAuth.js` |
| `qodiqa_mfa_events_total` | `outcome` = `failed` \| `locked` \| `step_up_denied` \| `step_up_error` | `src/core/rbac/mfa.js`, `src/middleware/mfaStepUp.js` |
| `qodiqa_audit_mirror_count_drift_total` | `reason` = `MISMATCH` \| `COUNTER_MISSING` | `src/core/audit/mirrorCountReconciler.js` (`AUDIT_MIRROR_COUNT_DRIFT`) |
| `qodiqa_audit_pg_lag_entries` (gauge) | — | `src/core/audit/pgLagMonitor.js` (every successful lag check; 0 in sync) |

Also: `REPLAY_STATE_UNPROVABLE` now maps to `qodiqa_security_events_total{event="nonce_violation"}` (it was unmapped),
and the seven metrics that were exported but never served (`qodiqa_admission_rejected_total`, `_inflight`, `_queued`,
`qodiqa_provider_execution_cancelled_total`, `qodiqa_transparency_signer_{signatures,failures,key_rotations}_total`)
are now in the served registry.

**Unused metrics (registered, never written — they always read 0; kept, not deleted, because removing them is an owner
decision).** `qodiqa_provenance_diff_failures_total`, `qodiqa_transparency_gap_active`, `qodiqa_org_requests_total`,
`qodiqa_org_blocks_total`, `qodiqa_org_active_sessions`, `qodiqa_logship_reconnects_total`,
`qodiqa_redis_connection_uptime_seconds`, `qodiqa_redis_current_master_info`, `qodiqa_redis_latency_ms`,
`qodiqa_redis_queue_recovery_total`. `qodiqa_audit_chain_verifier_repair_attempts` is always 0 by design (non-repair policy).
Do not build dashboards or alerts on any of them. `qodiqa_transparency_signer_{signatures,failures,key_rotations}_total`
are now WRITTEN (the signer mirrors its private counters to them) and may be used. (`qodiqa_build_info`, `qodiqa_process_uptime_seconds`
and `qodiqa_active_requests` are set inside `collect()` on every scrape — they were never unused.)

**Known limits.**
- `qodiqa_redis_connection_state_code{purpose}` follows every managed-client state transition in single, sentinel
  and cluster mode: 0 DISCONNECTED (constructed, never connected), 1 DEGRADED (an error, or a command-deadline miss
  — this includes silent partitions), 2 RECOVERING (terminal disconnect, stall teardown or Sentinel master switch;
  reconnect loop running), 3 HEALTHY (PING-verified ready). Before any managed client exists the gauge is served as an
  unlabelled `0`; match on `{purpose!=""}`. An intentional `disconnect()` does not change it. Alert:
  `QodiqaRedisConnectionDegraded`.
- `qodiqa_auth_lockout_active` is a per-process inc/dec delta over Redis-held state, not a count; it can drift or go
  negative across instances. Do not alert on it.
- Readiness metrics update only when `GET /ready` is probed.
- Shutdown/drain failures (`SHUTDOWN_TIMEOUT`, `SHUTDOWN_AUDIT_FLUSH_FAILED`, `SHUTDOWN_ERROR`) exist only as log events
  (the process is exiting): alert on them in the log pipeline.
- No promtool was available offline: rule syntax is checked by YAML parsing and structural tests, not by
  `promtool check rules` / `promtool test rules` (recommended before production).

## 12. Exit Criteria

This unified operational model is considered complete when:

- [x] All pre-existing metrics remain functional and unchanged in name/shape.
- [x] `/metrics`, `/health`, `/ready`, `/diagnostics` all continue to operate
      correctly with no duplicate metric registration.
- [x] The two audit-identified metric gaps (rate limiting, webhook delivery)
      are closed additively, without removing the internal APIs they mirror.
- [x] A single document ties metrics, alerts, severities, and runbooks
      together with consistent naming and no contradictory definitions.
- [x] The complete test suite passes with zero regressions (see final
      validation report in the Task #11 completion summary).

---

*Cross-references: [Alerting & Notification Framework](alerting.md) | [Operations README](README.md) | [Incident Response](incident-response.md) | [Disaster Recovery](disaster-recovery.md) | [Backup → Restore Validation](backup-restore-validation.md) | [Redis Failure Runbook](redis-failure.md) | [PostgreSQL Failure Runbook](postgresql-failure.md) | [Key Compromise Runbook](key-compromise-runbook.md) | [Transparency Recovery](transparency-recovery.md) | Operational Validation Guide*
