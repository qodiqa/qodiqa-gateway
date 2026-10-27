# QODIQA Alerting & Notification Framework

**Version:** 1.0.0
**Status:** Implemented

> This document is the detailed reference for detection, correlation, and
> notification internals. For the unified operational model tying these
> alerts together with Prometheus metrics, severity SLAs, and a named alert
> catalog, see [docs/operations/metrics-and-alerting.md](metrics-and-alerting.md).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        QODIQA PLATFORM EVENT BUS                            │
│                   (services/logger.js → eventBus.on('log'))                 │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │  Real-time structured log records
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DETECTION ENGINE                                    │
│                  (src/alerting/detection/DetectionEngine.js)                 │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────────────┐ │
│  │  ReplayDetector  │  │SignatureDetector  │  │    PolicyDetector         │ │
│  │  - Nonce reuse   │  │- Invalid sig      │  │- Invariant violations     │ │
│  │  - Cross-tenant  │  │- Revoked keys     │  │- Policy load failure      │ │
│  │  - Rate burst    │  │- Expired keys     │  │- Drift detection          │ │
│  │  - Binding fail  │  │- Unknown keys     │  │- Fail-open detection      │ │
│  └──────────────────┘  └──────────────────┘  └───────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  AnomalyDetector (statistical — sliding window, per-key, per-tenant) │   │
│  │  OperationalDetector (infrastructure degradation, governance)        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │  Alert specifications
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ALERT ENGINE                                       │
│                   (src/alerting/engine/AlertEngine.js)                       │
│                                                                              │
│  1. Suppression check (qodiqa_suppression_rules)                            │
│  2. Risk score computation (RiskScorer.js — 0–100 composite score)          │
│  3. Severity derivation (score → INFO/LOW/MEDIUM/HIGH/CRITICAL)             │
│  4. Persistence (AlertStore → PostgreSQL + memory fallback)                 │
│  5. Alert lifecycle events (alertBus.emit)                                   │
└────────────┬──────────────────────────────┬────────────────────────────────┘
             │                              │
             ▼                              ▼
┌────────────────────────┐    ┌─────────────────────────────────────────────┐
│  CORRELATION ENGINE    │    │            NOTIFICATION SERVICE              │
│  (CorrelationEngine.js)│    │         (NotificationService.js)             │
│                        │    │                                              │
│  Correlation keys:     │    │  Channels (based on severity):              │
│  - requestId           │    │  ┌──────────┬──────────┬─────────────────┐  │
│  - tenantId + window   │    │  │ Webhook  │  Slack   │  MS Teams       │  │
│  - alertType + window  │    │  ├──────────┼──────────┼─────────────────┤  │
│  - publicKeyId         │    │  │   SIEM   │  Email   │  PagerDuty      │  │
│                        │    │  │  (CEF)   │  (SMTP/  │  (Events v2)    │  │
│  → Creates Incidents   │    │  │          │  HTTP)   │                 │  │
│    in PostgreSQL        │    │  ├──────────┴──────────┴─────────────────┤  │
└────────────────────────┘    │  │ SMS (Twilio-compatible)                │  │
                              │  └───────────────────────────────────────┘  │
                              │                                              │
                              │  Features: retry, rate limit, HMAC signing  │
                              └─────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ESCALATION SERVICE                                   │
│                   (src/alerting/escalation/EscalationService.js)             │
│                                                                              │
│  INFO  → L0: Log only                                                       │
│  LOW   → L1: Notify operator (4hr ack window)                               │
│  MEDIUM → L1→L2: Operator → Security team (2hr)                             │
│  HIGH   → L2→L3: Security → Compliance + Admin (30min)                      │
│  CRITICAL → L3→L4: All hands → CISO (15min)                                 │
│                                                                              │
│  Timer scan: every 30s | Rehydrated from DB on restart                      │
└─────────────────────────────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ALERT STORAGE                                       │
│                    (PostgreSQL — migration 006)                              │
│                                                                              │
│  qodiqa_alerts              — All alerts with full evidence payload          │
│  qodiqa_alert_history       — Immutable state transition audit trail         │
│  qodiqa_incidents           — Correlated alert groups                        │
│  qodiqa_notification_deliveries — Per-channel delivery tracking             │
│  qodiqa_escalation_records  — Escalation audit trail                         │
│  qodiqa_suppression_rules   — Active suppression rules                       │
│  qodiqa_anomaly_baselines   — Statistical baselines                          │
│  qodiqa_alert_stats         — Pre-aggregated hourly statistics               │
└─────────────────────────────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ALERT API                                          │
│               GET  /alerts                   — List alerts                   │
│               POST /alerts                   — Create alert (admin)          │
│               GET  /alerts/stats             — Aggregate stats               │
│               GET  /alerts/stream            — SSE real-time stream          │
│               GET  /alerts/:id               — Alert details                 │
│               POST /alerts/:id/acknowledge   — Acknowledge                   │
│               POST /alerts/:id/resolve       — Resolve                       │
│               POST /alerts/:id/suppress      — Suppress                      │
│               POST /alerts/:id/false-positive — Mark FP                      │
│               GET  /alerts/:id/history       — Audit history                 │
│               GET  /alerts/health            — Channel health check          │
│               POST /alerts/test/:channel     — Test notification             │
│               GET  /alerts/counters          — Live anomaly counters         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 1 — Component Responsibilities

| Component | File | Responsibility |
|-----------|------|----------------|
| DetectionEngine | `detection/DetectionEngine.js` | Subscribes to eventBus; routes events through detector pipeline; applies deduplication |
| ReplayDetector | `detection/ReplayDetector.js` | Detects nonce reuse, cross-tenant replay, expired artifacts, binding mismatches |
| SignatureDetector | `detection/SignatureDetector.js` | Detects invalid/revoked/expired/unknown key usage, corrupted signatures |
| PolicyDetector | `detection/PolicyDetector.js` | Detects invariant violations, policy load failures, drift, fail-open events |
| AnomalyDetector | `detection/AnomalyDetector.js` | Statistical volume spike, block rate, per-tenant, per-key anomalies |
| OperationalDetector | `detection/OperationalDetector.js` | Redis (incl. HA mode) degradation, audit chain corruption, RBAC violations, signing/KMS provider failures |
| AlertEngine | `engine/AlertEngine.js` | Alert lifecycle: create, acknowledge, resolve, suppress; risk scoring |
| RiskScorer | `engine/RiskScorer.js` | Composite 0–100 risk score from severity + subtype + context amplifiers |
| SeverityModel | `engine/SeverityModel.js` | Severity definitions: SLA windows, escalation paths, notification channels |
| CorrelationEngine | `correlation/CorrelationEngine.js` | Groups related alerts into incidents using time-windowed correlation keys |
| NotificationService | `notification/NotificationService.js` | Routes alert to all configured channels; tracks delivery |
| WebhookChannel | `notification/channels/WebhookChannel.js` | HTTPS POST with HMAC signing; configurable endpoint |
| SlackChannel | `notification/channels/SlackChannel.js` | Slack Block Kit via incoming webhook |
| TeamsChannel | `notification/channels/TeamsChannel.js` | MS Teams Adaptive Cards via webhook connector |
| SIEMChannel | `notification/channels/SIEMChannel.js` | CEF format via Syslog UDP/TCP or HTTP (Splunk HEC) |
| EmailChannel | `notification/channels/EmailChannel.js` | SendGrid / Mailgun / SMTP (no external dependencies for SMTP) |
| PagerDutyChannel | `notification/channels/PagerDutyChannel.js` | PagerDuty Events API v2 |
| SMSChannel | `notification/channels/SMSChannel.js` | Twilio REST API or generic webhook |
| EscalationService | `escalation/EscalationService.js` | Timer-based escalation with rehydration |
| AlertStore | `storage/AlertStore.js` | PostgreSQL persistence + in-memory fallback |
| Alert API | `api/alertRoutes.js` | REST API for alert management |
| WindowedCounter | `anomaly/WindowedCounter.js` | In-memory sliding-window event counter for anomaly detection |

---

## Part 2 — Replay Attack Detection Rules

| Event / Pattern | Subtype | Severity | Confidence | Notes |
|-----------------|---------|----------|-----------|-------|
| `NONCE_V2_REPLAY_DETECTED` | NONCE_REUSE | HIGH | 99% | Atomic Redis check |
| `ANOMALY_THRESHOLD_EXCEEDED` | ANOMALY_THRESHOLD | HIGH | 85% | Per-key burst |
| `INVALID_BINDING` / `REQUEST_BINDING_MISMATCH` | REQUEST_BINDING_MISMATCH | HIGH | 95% | Hash mismatch after signing |
| GATEWAY_BLOCK reason=`REPLAY*` | NONCE_REUSE | HIGH | 90% | Secondary from block log |
| GATEWAY_BLOCK reason=`EXPIRED*` | EXPIRED_ARTIFACT | MEDIUM | 88% | Clock skew or old replay |

---

## Part 3 — Signature Failure Detection Rules

| Event / Pattern | Subtype | Severity | Confidence |
|-----------------|---------|----------|-----------|
| `TENANT_KEY_EXPIRED_ACTIVE` | EXPIRED_KEY | HIGH | 100% |
| `MULTIPLE_ACTIVE_KEYS_DETECTED` | MULTIPLE_ACTIVE_KEYS | MEDIUM | 100% |
| `TENANT_KEY_PROVISIONING_FAILED` | KEY_MISMATCH | CRITICAL | 100% |
| GATEWAY_BLOCK reason=`KEY_REVOKED` | REVOKED_KEY | HIGH | 98% |
| GATEWAY_BLOCK reason=`SIGNATURE_INVALID` | INVALID_SIGNATURE | HIGH | 92% |
| GATEWAY_BLOCK reason=`UNKNOWN_KEY` | UNKNOWN_KEY | HIGH | 90% |
| GATEWAY_BLOCK reason=`ENVELOPE*` | ENVELOPE_BINDING_FAILURE | HIGH | 90% |

---

## Part 4 — Policy Failure Detection Rules

| Event / Pattern | Subtype | Severity | Confidence |
|-----------------|---------|----------|-----------|
| `EXECUTION_INVARIANT_VIOLATED` | INVARIANT_VIOLATED | CRITICAL | 100% |
| `POLICY_LOAD_FAILED` | LOAD_FAILURE | CRITICAL | 100% |
| `POLICY_RELOAD_FAILED` | LOAD_FAILURE | HIGH | 100% |
| `POLICY_DRIFT_DETECTED` | DRIFT_DETECTED | HIGH | 95% |
| `POLICY_RATE_LIMIT_EXCEEDED` | RATE_LIMIT_EXCEEDED | MEDIUM | 100% |
| `POLICY_RATE_LIMIT_DEGRADED` | ENFORCEMENT_FAILURE | HIGH | 100% |
| GATEWAY_BLOCK reason=`NO_EXPLICIT_ALLOW` | EVALUATION_FAILURE | HIGH | 90% |
| GATEWAY_BLOCK reason=`BYPASS*` | BYPASS_ATTEMPT | CRITICAL | 85% |

---

## Part 5 — Anomaly Detection

**Algorithm:** Welford's method (incremental mean/stddev via sliding windows)

| Metric | Window | Default Threshold |
|--------|--------|------------------|
| Global request volume | 1 hour / 1-min buckets | 3σ above mean |
| Block rate | 1 hour | > 50% of requests |
| Error rate | 1 hour | > 20% of requests |
| Per-tenant volume | 1 hour | 4σ above tenant mean |
| Per-key usage | 1 hour | 3σ above key mean |
| RBAC denial rate | 1 hour | 3σ above baseline |

Environment overrides: `ANOMALY_SIGMA_THRESHOLD`, `ANOMALY_BLOCK_RATE_THRESHOLD`, `ANOMALY_WINDOW_MS`

---

## Audit Chain Integrity Alerts

Two `OPERATIONAL` subtypes now cover the execution audit chain (`src/alerting/detection/OperationalDetector.js`), driven by the live audit chain verifier (`src/core/audit/verifier/`, Decision Update and `docs/operations/audit-chain-integrity-verification.md`):

| Event | Subtype | Severity | Confidence | Meaning |
|---|---|---|---|---|
| `AUDIT_CHAIN_CORRUPTED` | `AUDIT_CHAIN_CORRUPTED` | CRITICAL | 100 | Hash/prevHash break, duplicate artifact ID or PG `seq`, orphan record, invalid/duplicate genesis, or file↔PG mirror divergence. Likely tampering — "DO NOT allow further writes until the chain is validated." Pre-existing rule; the live verifier now also feeds it continuously, not just at startup or on-demand. |
| `AUDIT_CHAIN_STRUCTURAL_ANOMALY` | `AUDIT_CHAIN_STRUCTURAL_ANOMALY` | MEDIUM | 70 | Currently only a bare PostgreSQL `seq` gap — `audit_chain.seq` is `BIGSERIAL` with no uniqueness constraint, and `nextval()` is non-transactional, so a rolled-back insert routinely burns a sequence value. Investigate before escalating; does not by itself indicate tampering, and does not block further writes. |

Both route through the same `emit()` → `DetectionEngine` → `AlertEngine` pipeline as every other alert in this document — the verifier never calls the alerting engine directly. See `src/core/audit/verifier/diagnostics.js` for the full violation-reason-to-severity mapping.

---

## Complete Alert Coverage

Five new `OPERATIONAL` rules (`src/alerting/detection/OperationalDetector.js`), closing gaps where a periodic monitor or a code path already existed but had no alerting hook:

| Event | Subtype | Severity | Source |
|---|---|---|---|
| `REQUEST_LATENCY_SLA_BREACH` | `LATENCY_SLA_BREACH` | HIGH | `src/observability/latencySlaMonitor.js` — mean `requestDurationMs` (label `decision=EXECUTE`) crosses `QODIQA_SLA_LATENCY_MS` (default 2000ms) |
| `REQUEST_LATENCY_P99_BREACH` | `LATENCY_P99_BREACH` | HIGH | Same monitor — estimated p99 crosses `QODIQA_P99_LATENCY_MS` (default 5000ms). Independent state from the SLA rule above — a long tail can breach without the mean doing so. |
| `AUDIT_DISK_FULL` | `AUDIT_DISK_FULL` | CRITICAL | `appendMandatory()` (`src/core/audit/audit-log.js`) — ENOSPC specifically, on retry-budget exhaustion. Distinct from the existing `auditAppendFailedTotal` counter, which buckets every retryable failure type together. |
| `KEY_EXPIRING_SOON` | `KEY_EXPIRY_APPROACHING` | LOW | `services/artifact/keyExpiryMonitor.js` (new periodic re-check, default every 6h) and `keyManager.js`'s existing startup check — same event name, reused taxonomy. Advance warning, distinct from the already-expired `KEY_EXPIRED`/`TENANT_KEY_EXPIRED_ACTIVE` rules (Part 3). |
| `KEY_ROTATION_OVERDUE` | `KEY_ROTATION_OVERDUE` | MEDIUM | Same monitor/startup check — a key past its rotation-due deadline; may indicate the rotation scheduler is disabled or failing. |
| `PG_CIRCUIT_BREAKER_STATE` (only `to === 'OPEN'`) | `PG_POOL_EXHAUSTED` | CRITICAL | `src/infra/postgres/pgCircuitBreaker.js` — this event already existed but was not wired to alerting. The rule uses a `matches(event)` predicate (new, optional, additive capability on `OperationalDetector.analyze()`) so only the OPEN transition alerts — `CLOSED`/`HALF_OPEN` are recovery signals, not incidents. |

Environment overrides: `QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS`, `QODIQA_SLA_LATENCY_MS`, `QODIQA_P99_LATENCY_MS`, `QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS`. All five reuse the existing dedup/suppression window (Part 7) — no new correlation logic was added.

---

## Part 6 — Alert Severity Model

| Level | Risk Score | Ack Window | Channels | Response |
|-------|-----------|-----------|---------|---------|
| INFO | 0–19 | None | None (stored only) | Daily review |
| LOW | 20–39 | 4 hours | Webhook, SIEM | Investigate in business hours |
| MEDIUM | 40–59 | 2 hours | Slack, Webhook, SIEM | Notify on-call, 2hr investigation |
| HIGH | 60–79 | 30 minutes | Slack, Teams, PagerDuty, Webhook, SIEM, Email | Page immediately, incident response |
| CRITICAL | 80–100 | 15 minutes | All channels incl. SMS | All-hands, CISO notification |

**Risk Score Formula:**
```
score = BASE[severity]
      + SUBTYPE_AMPLIFIER[subtype]          (optional, 5–20 pts)
      + Σ CONTEXT_BONUS[flag]               (optional, 5–15 pts each)
      - CONFIDENCE_DISCOUNT                 ((1 - confidence/100) × 20)
score = clamp(score, 0, 100)
```

---

## Part 7 — Alert Correlation

**Correlation window:** 15 minutes
**Minimum alerts for incident:** 2

Correlation keys (evaluated in order):
1. `req:{requestId}` — Same request (strongest signal)
2. `tenant:{tenantId}:{15min-bucket}` — Same tenant, same window
3. `type:{alertType}:{15min-bucket}` — Same type cluster
4. `key:{publicKeyId}:{15min-bucket}` — Same key compromise

**Incident title patterns:**
- Multi-type: `[CRITICAL] Multi-vector security incident: REPLAY_ATTACK + SIGNATURE_FAILURE + POLICY_FAILURE`
- Single-type: `[HIGH] Replay attack campaign — tenant alpha`

---

## Part 8 — Notification Channels

### Webhook
- HTTPS POST with JSON payload
- HMAC-SHA256 signature: `X-QODIQA-Signature: sha256={hex}`
- Retry: 3 attempts with exponential backoff + ±25% jitter
- Rate limit: 120/minute

### Slack
- Block Kit attachments via Incoming Webhooks
- Color-coded by severity (gray/blue/amber/red/purple)
- Fields: type, subtype, risk score, tenant, request ID, key ID

### MS Teams
- Adaptive Cards v1.4 via webhook connector
- Fact sets for all alert metadata
- Action button: "View in QODIQA Console"

### SIEM (CEF)
- Format: `CEF:0|QODIQA|QODIQA Platform|1.0.0|{type}_{subtype}|{title}|{cef_sev}|{ext}`
- Delivery: UDP/TCP Syslog OR HTTP (Splunk HEC)
- Supports: Splunk, QRadar, ArcSight, Elastic SIEM, Chronicle

### Email
- Providers: SendGrid, Mailgun, or direct SMTP (built-in client, no deps)
- HTML + text multipart
- Severity-coded subject prefix
- Full metadata table in body

### PagerDuty
- Events API v2
- `dedup_key = alert.id` (enables acknowledge/resolve sync)
- Severity mapping: INFO/LOW→info, MEDIUM→warning, HIGH→error, CRITICAL→critical

### SMS
- Twilio REST API or configurable webhook
- 160-char limit enforced
- Rate limit: 10/minute (conservative)

---

## Part 9 — Escalation Workflows

```
CRITICAL alert created
  ├─ Immediate: Notify L3 roles (admin, compliance, operator)
  │            Channels: All (Slack, Teams, PagerDuty, Email, SMS, Webhook, SIEM)
  │
  ├─ T+15min (if not ACK'd):
  │    → Escalate to L3
  │    → Re-notify: admin, compliance, operator
  │    → Record in qodiqa_escalation_records
  │
  ├─ T+30min (if not ACK'd):
  │    → Escalate to L4
  │    → Re-notify: admin
  │    → reason: CRITICAL_UNACKNOWLEDGED
  │
  └─ On ACK: Cancel all timers, record acknowledger

HIGH alert created
  ├─ Immediate: Notify L2 roles
  ├─ T+30min → L2 (ACK_TIMEOUT)
  └─ T+60min → L3 (SUSTAINED_UNACKNOWLEDGED)

MEDIUM: T+2hr → L2 (ACK_TIMEOUT)
LOW:    T+4hr → L1 (ACK_TIMEOUT)
INFO:   No escalation — logged only
```

---

## Part 10 — Alert Storage Schema

See: `src/infra/postgres/migrations/006_alerting_schema.sql`

**Primary tables:**
- `qodiqa_alerts` — Alert records with JSONB evidence + context
- `qodiqa_alert_history` — Immutable audit trail (BIGSERIAL, append-only)
- `qodiqa_incidents` — Correlated incident groups
- `qodiqa_notification_deliveries` — Per-channel delivery tracking with retry
- `qodiqa_escalation_records` — Full escalation audit trail
- `qodiqa_suppression_rules` — Time-limited suppression rules
- `qodiqa_anomaly_baselines` — Statistical baselines (self-adapting)
- `qodiqa_alert_stats` — Pre-aggregated hourly stats for dashboards

**Retention:**
- INFO: 30 days | LOW: 90 days | MEDIUM: 180 days | HIGH: 365 days | CRITICAL: 730 days

---

## Part 11 — Alert Management API

### `GET /alerts`
Query params: `status`, `severity`, `type`, `tenantId`, `requestId`, `artifactId`, `incidentId`, `from`, `to`, `page`, `pageSize`, `sort`

### `POST /alerts`
Body: `{ type, subtype, severity, title, description?, tags?, evidence?, context?, tenantId?, requestId? }`

### `GET /alerts/stats`
Returns aggregate counts by severity, type, and status with mean MTTA/MTTR.

### `GET /alerts/stream`
Server-Sent Events stream. Events: `alert.created`, `alert.acknowledged`, `alert.resolved`

### `POST /alerts/:id/acknowledge`
Body: `{ actor, note? }` → transitions OPEN/INVESTIGATING → ACKNOWLEDGED

### `POST /alerts/:id/resolve`
Body: `{ actor, note? }` → transitions any non-closed status → RESOLVED

### `GET /alerts/:id/history`
Returns immutable audit trail of all state transitions for an alert.

### `GET /alerts/health`
Returns health status of all configured notification channels.

### `POST /alerts/test/:channel`
Sends a test notification to verify channel configuration.

---

## Part 12 — Dashboard Integration

The alerting framework publishes to the existing QODIQA SSE dashboard via:
```
eventBus.emit('alert', { channel: 'alert.created', alert: {...} })
```

Dashboard consumers can subscribe to `/alerts/stream` for:
- `alert.created` — New alert
- `alert.acknowledged` — Alert acknowledged
- `alert.resolved` — Alert resolved
- `alert.suppressed` — Alert suppressed
- `alert.false_positive` — Marked as false positive

`GET /alerts/counters` provides live anomaly counter snapshot.

---

## Part 13 — Security Analysis & Mitigations

| Attack | Mitigation |
|--------|-----------|
| **Alert suppression** | Suppression rules require explicit creation; all suppressions audited; fail-open on suppression check failure |
| **Notification bypass** | Multiple channels dispatched concurrently; delivery failures logged; SIEM integration provides out-of-band visibility |
| **Alert flooding / DoS** | In-memory deduplication window (60s); per-channel rate limiting (token bucket); GATEWAY_ALLOW excluded from detection |
| **SIEM poisoning** | CEF values escaped; payload bounded (1000 char description); source field fixed as 'qodiqa' |
| **False positive generation** | Confidence scoring discounts low-confidence detections; false positive marking with actor audit; suppression rules for known-benign patterns |
| **False negative generation** | Detection runs on every event (not sampled); fail-closed on detection errors; multiple independent detectors |
| **Escalation manipulation** | Escalation records are immutable PostgreSQL inserts; level can only increase; acknowledgement tracked per actor |
| **Webhook MITM** | HMAC-SHA256 signing on all webhook payloads; HTTPS enforced |

---

## Part 14 — Environment Configuration

**(Enterprise Audit)**: every notification channel below ships
**disabled by default** — with zero of these variables set, QODIQA still
detects every CRITICAL failure, but nobody is notified (visible only via
`GET /alerts` / `GET /alerts/stream`). This is intentional secure-by-default
behavior, not a bug — but it means production deployments MUST explicitly
configure at least one channel. See
[deploy/env/production.env.example](../../deploy/env/production.env.example)'s "NOTIFICATION
CHANNELS" section for the full, copy-pasteable reference with
placeholders and per-variable docs, and
[docs/operations/notification-setup.md](notification-setup.md)
for the operator runbook (testing procedures, troubleshooting, recommended
production configuration). The list below is a quick-reference summary,
not the canonical source.

```bash
# Detection
ALERT_DEDUP_WINDOW_MS=60000          # Alert deduplication window (1 min)
ANOMALY_SIGMA_THRESHOLD=3.0          # N-sigma for anomaly detection
ANOMALY_BLOCK_RATE_THRESHOLD=0.50    # Block rate anomaly threshold
ANOMALY_WINDOW_MS=3600000            # Sliding window duration (1 hr)

# Notification channels — see deploy/env/production.env.example for full docs
ALERT_WEBHOOK_URL=https://...        # Default webhook endpoint
ALERT_WEBHOOK_SECRET=...             # HMAC signing secret
ALERT_SLACK_WEBHOOK_URL=https://...  # Slack incoming webhook
ALERT_TEAMS_WEBHOOK_URL=https://...  # MS Teams webhook
ALERT_SIEM_URL=https://...           # SIEM HEC endpoint
ALERT_SIEM_TOKEN=...                 # SIEM auth token
ALERT_SIEM_SYSLOG_HOST=...          # Syslog receiver host
ALERT_EMAIL_PROVIDER=sendgrid        # Email provider
ALERT_EMAIL_FROM=security@...        # Sender address
ALERT_EMAIL_TO=soc@...              # Default recipient
ALERT_EMAIL_SENDGRID_API_KEY=...    # SendGrid API key
ALERT_PAGERDUTY_ROUTING_KEY=...     # PagerDuty integration key
ALERT_SMS_TWILIO_ACCOUNT_SID=...    # Twilio SID
ALERT_SMS_TWILIO_AUTH_TOKEN=...     # Twilio auth token
ALERT_SMS_FROM=+1...                 # Sender number
ALERT_SMS_TO=+1...                   # Default recipient

# Disable channels explicitly
ALERT_SMS_ENABLED=false
ALERT_EMAIL_ENABLED=false

# Startup posture (MON-3) — fail closed instead of warning when zero
# channels are configured. Recommended for compliance-sensitive deployments.
QODIQA_REQUIRE_NOTIFICATION_CHANNEL=false
```

`ALERT_WEBHOOK_URL` is intentionally shared across three independent
producers: this framework's `WebhookChannel`, `scripts/dr/alert.js`
(backup/DR job failures), and `src/runtime/earlyCriticalNotify.js` (the
multi-instance HA guard's best-effort notify — see Part 15).

---

## Part 15 — Migration & Deployment

1. **Database migration**: `QODIQA_PG_AUTO_MIGRATE=true` on restart, or run `node src/infra/postgres/migrate.js` to apply `006_alerting_schema.sql`

2. **Environment variables**: Configure at minimum `ALERT_SLACK_WEBHOOK_URL` or `ALERT_WEBHOOK_URL` for notifications; `ALERT_PAGERDUTY_ROUTING_KEY` for on-call. Example: `ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/xxxxxxxx` is sufficient on its own — see Part 14 and `deploy/env/production.env.example` for the full set.

3. **Startup**: Framework initializes automatically when `server.js` starts — no manual invocation required. A separate startup check logs `NOTIFICATION_CHANNELS_READY` (INFO) if any channel is configured, `NO_NOTIFICATION_CHANNEL_CONFIGURED` (WARN) if none is and `QODIQA_REQUIRE_NOTIFICATION_CHANNEL` is unset, or exits with `NOTIFICATION_CHANNEL_REQUIRED_BUT_MISSING` (FATAL) if none is configured and `QODIQA_REQUIRE_NOTIFICATION_CHANNEL=true`.

4. **Validation**: `GET /alerts/health` confirms all configured channels are reachable; `POST /alerts/test/SLACK` sends test message

5. **Monitoring**: `GET /alerts/stats` for 24hr aggregate; `GET /alerts/counters` for live metrics; `GET /alerts/stream` for SSE console; `GET /metrics` for Prometheus counters `qodiqa_alert_notification_sent_total` / `_failed_total` / `_retries_total` / `_rate_limited_total`, each labeled by `channel`

6. **The one path outside this framework**: `src/core/audit/multiInstanceGuard.js`'s multi-instance HA startup guard calls `process.exit(1)` before this framework initializes, so it cannot route through `NotificationService`. It fires a separate, best-effort, non-blocking notification via `src/runtime/earlyCriticalNotify.js` (posts directly to `ALERT_WEBHOOK_URL`) immediately before exiting — deliberately not awaited, since the guard's exit must remain synchronous and immediate to preserve its fail-closed guarantee (see that module's header comment). The synchronous stderr `FATAL` diagnostic (`rawStderrDiagnostic.js`) remains the authoritative signal for this path.

---

## Testing

```bash
# Run unit test suite (79 tests)
npx jest src/alerting/alerting.test.js

# Integration smoke test
node -e "
const f = require('./src/alerting');
f.initialize().then(() => {
  const { eventBus } = require('./services/logger');
  eventBus.emit('log', {
    ts: new Date().toISOString(), level: 'WARN',
    event: 'NONCE_V2_REPLAY_DETECTED',
    requestId: require('crypto').randomUUID(),
    tenantId: 'test', publicKeyId: 'test:key_v1',
  });
  setTimeout(() => process.exit(0), 500);
});
"
```
