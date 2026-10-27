# QODIQA Operations —

**Production Operations & Readiness Documentation**

| Field | Value |
|-------|-------|
| Phase | 48 — Operations & Production Readiness |
| Version | 1.0.0 |
| Owner | Platform Engineering / SRE |
| Last Updated | 2026-07-03 |

---

## Purpose

This directory contains complete operational documentation for QODIQA — a deterministic AI authorization and enforcement platform. Every runbook here is implementation-aware, validated against the actual QODIQA architecture, and sufficient to operate the platform without tribal knowledge.

**A new engineering team must be able to operate the platform using only these documents.**

---

## Quick Reference

### I need to...

| Task | Document |
|------|---------|
| Start QODIQA for the first time | [Startup Runbook](startup-runbook.md) |
| Shut down QODIQA gracefully | [Shutdown Runbook](shutdown-runbook.md) |
| Deploy a new version | [Deployment Runbook](deployment-runbook.md) |
| Roll back a failed deployment | [Rollback Runbook](rollback-runbook.md) |
| Upgrade Redis / PostgreSQL / K8s | [Upgrade Runbook](upgrade-runbook.md) |
| Back up the system | [Backup Runbook](backup-runbook.md) |
| Restore from backup | [Restore Runbook](restore-runbook.md) |
| Recover from a regional outage | [Disaster Recovery](disaster-recovery.md) |
| Respond to a key compromise | [Key Compromise Runbook](key-compromise-runbook.md) |
| Renew or rotate TLS certificates | [Certificate Expiration Runbook](certificate-expiration.md) |
| Recover the transparency log | [Transparency Recovery](transparency-recovery.md) |
| Recover from Redis failure | [Redis Failure Runbook](redis-failure.md) |
| Recover from PostgreSQL failure | [PostgreSQL Failure Runbook](postgresql-failure.md) |
| Manage a production incident | [Incident Response Guide](incident-response.md) |
| Validate operational procedures | Operational Validation Guide |
| Understand the unified metrics/alerting model | [Metrics & Alerting](metrics-and-alerting.md) |
| Measure a real RTO during a DR drill | DR RTO Measurement |
| Configure/test notification channels (Slack, PagerDuty, etc.) | [Notification Setup](notification-setup.md) |
| Create/alter/drop a PostgreSQL role or its attributes | [Database Role Management](database-role-management.md) |

---

## Runbook Index

### Core Lifecycle

| # | Document | Description |
|---|---------|-------------|
| 48.1 | [Startup Runbook](startup-runbook.md) | Complete startup procedure including prerequisites, validation, health checks, and startup checklist |
| 48.2 | [Shutdown Runbook](shutdown-runbook.md) | Graceful shutdown, connection draining, flush sequence, and forced shutdown procedure |
| 48.3 | [Deployment Runbook](deployment-runbook.md) | Rolling, blue/green, and canary deployment strategies with smoke tests and rollback triggers |
| 48.4 | [Rollback Runbook](rollback-runbook.md) | Application, database, schema, configuration, certificate, and key rollback procedures |
| 48.5 | [Upgrade Runbook](upgrade-runbook.md) | Application, Redis, PostgreSQL, Kubernetes, and Docker image upgrade procedures |

### Data Management

| # | Document | Description |
|---|---------|-------------|
| 48.6 | [Backup Runbook](backup-runbook.md) | Database, audit chain, transparency log, key store, configuration, and certificate backup |
| 48.7 | [Restore Runbook](restore-runbook.md) | Full and partial restore, database restore, audit restore, consistency verification |
| 48.19 | [Database Role Management](database-role-management.md) | Migrations-only policy for PostgreSQL role attributes, the documented bootstrap exception, and password-rotation handling |

### Disaster and Security

| # | Document | Description |
|---|---------|-------------|
| 48.8 | [Disaster Recovery](disaster-recovery.md) | RTO/RPO targets, regional outage, infrastructure loss, key/cert compromise, network partition |
| 48.9 | [Key Compromise Runbook](key-compromise-runbook.md) | Detection, containment, revocation, rotation, forensics, customer notification |
| 48.10 | [Certificate Expiration Runbook](certificate-expiration.md) | Renewal, rotation, monitoring, emergency replacement |
| 48.11 | [Transparency Recovery](transparency-recovery.md) | Corruption detection, missing entries, integrity verification, rebuild procedures |

### Component Failures

| # | Document | Description |
|---|---------|-------------|
| 48.12 | [Redis Failure Runbook](redis-failure.md) | Detection, fail-closed behaviour, node failure, connection exhaustion, latency, recovery |
| 48.13 | [PostgreSQL Failure Runbook](postgresql-failure.md) | Detection, disk full, corruption, slow queries, deadlocks, recovery (consent and readiness depend on it; the audit file chain does not) |

### Incident and Validation

| # | Document | Description |
|---|---------|-------------|
| 48.14 | [Incident Response Guide](incident-response.md) | Severity definitions, classification, communication, triage, containment, postmortem, forensics |
| 48.15 | Operational Validation Guide | Exercise procedures for every operational runbook with success criteria and evidence collection |
| 48.16 | [Metrics & Alerting](metrics-and-alerting.md) | Unified operational model — metrics taxonomy, naming conventions, alert catalog, severity/SLA model, dashboard and Alertmanager integration |
| 48.17 | DR RTO Measurement | `scripts/dr/rtoHarness.js` — turns the RTO validation checklist into a real, timestamped drill measurement |
| 48.18 | [Notification Setup](notification-setup.md) | Notification channel configuration, testing, troubleshooting, and architecture |

---

## Architecture Context

QODIQA is a Node.js/Express application with:

| Component | Technology | Critical? | Notes |
|-----------|-----------|-----------|-------|
| Application | Node.js 22 or later, Express 4 | Yes | Entry: `node start.js` |
| Signing | Ed25519 (in-process) | Yes | Keys in encrypted `keys.json` |
| Replay protection | Redis (nonce store) | Yes | Fail-closed; AOF required |
| Audit chain | NDJSON file (authoritative) + PG replica | Yes (file) | Single-writer constraint |
| Transparency log | PostgreSQL | High | Append-only, Merkle tree |
| Policy engine | In-memory set derived from the control plane (PostgreSQL in production); `policies.json` is import-only | Yes | Re-read from the control plane on change or SIGHUP |
| Consent cache | Redis | Medium | Falls through to PG on miss |
| HSM/KMS | Pluggable (local, Vault, AWS KMS, etc.) | Yes | KEK for key store decryption |

**Critical invariants:**
- Redis must be available for enforcement (fail-closed).
- PostgreSQL is mandatory in production and is on the critical path: consent verification (`REQUIRE_CONSENT`) fails closed without it, `/ready` answers 503 while it is down, and production refuses to boot without it. The audit file chain remains authoritative; the PostgreSQL mirror is recovered through the recovery queue.
- Audit chain is single-writer (multi-instance guard enforced in code).
- STRICT_REPLAY_PROTECTION=true requires Redis AOF to be enabled before QODIQA starts.

---

## Service Endpoints

| Endpoint | Purpose | Critical |
|----------|---------|---------|
| `GET /health` | Liveness (no dependency checks) | Yes |
| `GET /ready` | Readiness (checks the Redis stores, PostgreSQL, the revocation subscriber, admission, audit and transparency health) | Yes |
| `GET /metrics` | Prometheus metrics | Yes |
| `POST /ai/chat` | Enforcement gateway | Yes |
| `POST /sign` | Artifact signing | Yes |
| `POST /verify/v2` | Artifact verification | Yes |
| `GET /public-key` | Active public key | Yes |
| `GET /.well-known/qodiqa/keys` | JWKS endpoint | Yes |

---

## Key Operational Metrics

| Metric | Healthy Value | Alert Threshold |
|--------|--------------|----------------|
| `qodiqa_execution_integrity_full{}` | 1 | < 1 for > 60s → P1 |
| `qodiqa_redis_store_up{store="nonce"}` | 1 | 0 for > 30s → P1 |
| `qodiqa_redis_store_up{store="anomaly"}` | 1 | 0 for > 30s → P2 |
| `qodiqa_redis_store_up{store="rate_limit"}` | 1 | 0 for > 30s → P2 |
| `qodiqa_requests_total` | Monotonically increasing | Sudden stop → P1 |
| `qodiqa_blocks_total` | Within policy baseline | Spike > 10% → P2 |

---

## Recovery Time Objectives

| Scenario | RTO | RPO | Runbook |
|----------|-----|-----|---------|
| Redis failure | 2–5 min (auto-recovery); automatic, no cap in Sentinel/Cluster mode | 0 | [Redis Failure](redis-failure.md) |
| PostgreSQL failure | 0 (enforcement unaffected) | 5 minutes | [PostgreSQL Failure](postgresql-failure.md) |
| Application rollback | < 3 min | 0 | [Rollback](rollback-runbook.md) |
| Key compromise | < 1 hour | 0 | [Key Compromise](key-compromise-runbook.md) |
| Regional DR failover | < 4 hours* | 5 minutes | [Disaster Recovery](disaster-recovery.md) |
| Certificate expiry | < 10 min (pre-planned) | 0 | [Certificate Expiration](certificate-expiration.md) |

\* Step-budget estimate, not yet measured against a live drill — see DR RTO Measurement.

---

## Related Documentation

| Topic | Location |
|-------|---------|
| Architecture | [docs/architecture/overview.md](../architecture/overview.md) |
| Enforcement flow | [docs/architecture/enforcement-flow.md](../architecture/enforcement-flow.md) |
| Key management | [docs/security/key-management.md](../security/key-management.md) |
| Secrets management | [docs/security/secrets-management.md](../security/secrets-management.md) |
| Redis deployment | [docs/deployment/redis.md](../deployment/redis.md) |
| Production deployment | [docs/deployment/production.md](../deployment/production.md) |
| Troubleshooting | [docs/operations/troubleshooting.md](troubleshooting.md) |
| Security guide | [docs/security/SECURITY_GUIDE.md](../security/SECURITY_GUIDE.md) |
| Threat model | [docs/security/THREAT_MODEL.md](../security/THREAT_MODEL.md) |
| Reliability guide | [docs/architecture/RELIABILITY_GUIDE.md](../architecture/RELIABILITY_GUIDE.md) |
| Audit chain ADR | docs/protocol/AUDIT-SCHEMA-V8.md |
| Alerting framework | [docs/operations/alerting.md](alerting.md) |
| Metrics & alerting (unified model) | [metrics-and-alerting.md](metrics-and-alerting.md) |
| Redis TLS | [docs/deployment/redis-tls.md](../deployment/redis-tls.md) |
| Kubernetes probes | [docs/deployment/kubernetes-probes.md](../deployment/kubernetes-probes.md) |
| Production checklist | [docs/deployment/production-checklist.md](../deployment/production-checklist.md) |
