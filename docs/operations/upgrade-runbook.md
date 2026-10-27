# QODIQA Upgrade Runbook

**Operations & Production Readiness**

| Field | Value |
|-------|-------|
| Document | Upgrade Runbook |
| Version | 1.0.0 |
| Owner | Platform Engineering |
| Audience | SRE, Platform Engineer, Release Engineer |
| Classification | Internal — Operational |
| Last Updated | 2026-07-03 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Upgrade Order](#2-upgrade-order)
3. [Application Upgrade](#3-application-upgrade)
4. [Database Schema Upgrade](#4-database-schema-upgrade)
5. [Dependency Upgrade](#5-dependency-upgrade)
6. [Redis Upgrade](#6-redis-upgrade)
7. [PostgreSQL Upgrade](#7-postgresql-upgrade)
8. [Kubernetes Upgrade](#8-kubernetes-upgrade)
9. [Docker Image Upgrade](#9-docker-image-upgrade)
10. [Configuration Upgrade](#10-configuration-upgrade)
11. [Compatibility Verification](#11-compatibility-verification)
12. [Downtime Expectations](#12-downtime-expectations)
13. [Rollback Triggers](#13-rollback-triggers)
14. [Upgrade Verification](#14-upgrade-verification)

---

## 1. Overview

Upgrades differ from deployments in scope: they involve changes to infrastructure components (Redis, PostgreSQL, Kubernetes, Node.js), not just the QODIQA application image. Infrastructure upgrades require more careful sequencing and have longer rollback windows.

**Golden rule:** Every infrastructure upgrade must be tested in a staging environment that mirrors production before being applied to production.

---

## 2. Upgrade Order

When multiple components are being upgraded simultaneously, follow this order to preserve dependency compatibility:

```
1. PostgreSQL (database layer — most stable, upgrade first)
      ↓
2. Redis (cache/replay layer)
      ↓
3. Docker base images (runtime container)
      ↓
4. Node.js version (application runtime)
      ↓
5. npm dependencies (application libraries)
      ↓
6. QODIQA application (schema migrations + code)
      ↓
7. Kubernetes manifests (orchestration layer — last)
```

**Never upgrade QODIQA and PostgreSQL in the same change window.** If a schema migration introduces incompatibility with the PostgreSQL version, diagnosing the cause is impossible if both changed simultaneously.

---

## 3. Application Upgrade

Application upgrades are performed via the [Deployment Runbook](deployment-runbook.md). This section covers upgrade-specific concerns beyond standard deployment.

### 3.1 Breaking Change Identification

Before each upgrade, review the changelog for breaking changes:

```bash
# Compare package.json between versions
git diff v1.1.0..v1.1.0 -- package.json

# Review migration file additions
git diff v1.1.0..v1.1.0 -- src/infra/postgres/migrations/

# Review environment variable changes
git diff v1.1.0..v1.1.0 -- deploy/env/production.env.example
```

### 3.2 API Compatibility

QODIQA's enforcement API (`POST /ai/chat`, `POST /sign`, `POST /verify/v2`) must maintain backward compatibility across minor versions. Breaking changes are only permitted in major version bumps.

Before upgrading, verify client SDK compatibility. Only the maintained SDKs
are part of the supported upgrade path:

```bash
# Check SDK version compatibility
cat sdk/javascript/package.json | jq .version
cat sdk/python/pyproject.toml | grep version
```

### 3.3 Schema Migration Compatibility

New schema migrations must be backward-compatible with the previous application version. This ensures:
- The database can be migrated before the application is updated.
- If a rollback is needed, the previous application version runs against the new schema.

Test backward compatibility:

```bash
# Run migrations in staging — with the migration runner, never `psql -f` (a raw psql run bypasses migrate.js's checksum
# record, advisory lock and lock_timeout). Point PG*/QODIQA_PG_* at STAGING explicitly (never a default
# localhost:5432, which on a workstation is usually a live cluster); the migration password comes from
# QODIQA_PG_MIG_PASSWORD in the environment, never argv. qodiqa_test is needed when a pending migration creates or
# alters a role (docs/operations/database-role-management.md).
QODIQA_PG_MIG_USER=qodiqa_test node src/infra/postgres/migrate.js --dry-run
QODIQA_PG_MIG_USER=qodiqa_test node src/infra/postgres/migrate.js

# Start the previous application version against the new schema in staging
docker run --rm \
  --env-file staging.env \
  qodiqa:1.0.0 \
  node -e "require('./start.js')"
# Verify no startup errors related to schema
```

---

### 3.4 Seal the key stores before upgrading to a version that requires it (OA-RC-2)

From the release that carries OA-RC-2 a **production** gateway refuses an unsealed key file
(`QODIQA_KEYSTORE_REQUIRE_SEALED` defaults to `true` when `NODE_ENV=production`). Key files created by a release with record
sealing are already sealed; a file created before it must be sealed once, offline, before the upgraded gateway starts:

```bash
# 1. stop the gateway (no other process may write the key files), with the deployment's env loaded
#    (QODIQA_KEY_ENCRYPTION_KEY, QODIQA_KEYS_PATH, QODIQA_TRANSPARENCY_KEYS_PATH, QODIQA_CHECKPOINT_KEYS_PATH)
# 2. report: path, sha256, sealed?, key ids and public-key fingerprints per store — compare the fingerprints with the
#    published /.well-known/qodiqa/keys, /transparency-keys and /checkpoint-keys BEFORE sealing (sealing makes the file
#    on disk authoritative)
node scripts/keys/seal-keystore.js
# 3. seal (a wrong KEK fails and writes nothing), verified in a separate process with sealing required
node scripts/keys/seal-keystore.js --seal --confirm-gateway-stopped
# 4. start the upgraded gateway
```

`SEAL_OK` is required. `QODIQA_KEYSTORE_REQUIRE_SEALED=false` restores trust-on-first-use sealing in production; it boots
with a `BOOT_CONFIG_WARNING` and is not a supported steady state.

## 4. Database Schema Upgrade

### 4.1 Pre-Upgrade Preparation

```bash
# 1. Full backup before any schema change — encrypted + sealed, as the backup role qodiqa_backup, PG* target and
#    PGPASSFILE (never a password in a URL or on the command line)
./scripts/pg-backup.sh full && ./scripts/pg-backup.sh verify   # expect BACKUP_SEAL_OK, BACKUP_VERIFY_OK

# 2. Estimate migration duration on large tables
# For ALTER TABLE on tables with millions of rows, this can be minutes
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "
  SELECT relname, n_live_tup
  FROM pg_stat_user_tables
  WHERE relname IN ('audit_chain','transparency_log_entries','platform_audit_events')
  ORDER BY n_live_tup DESC;
"

# 3. Check for table locks that could block migration
psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -c "
  SELECT pid, usename, query, state, wait_event_type, wait_event
  FROM pg_stat_activity
  WHERE state != 'idle'
  AND datname = 'qodiqa';
"
```

### 4.2 Zero-Downtime Migration Principles

| Operation | Zero-Downtime? | Approach |
|-----------|---------------|----------|
| `CREATE TABLE` | Yes | Standard DDL |
| `CREATE INDEX CONCURRENTLY` | Yes | Use CONCURRENTLY keyword |
| `ALTER TABLE ADD COLUMN` (nullable) | Yes | Standard DDL |
| `ALTER TABLE ADD COLUMN NOT NULL` (without default) | No — needs backfill | Add nullable, backfill, add constraint |
| `ALTER TABLE DROP COLUMN` | No — irreversible | Coordinate with app deploy |
| `DROP TABLE` | No — irreversible | Archive first |
| `ALTER TABLE ALTER COLUMN TYPE` | No | Column rename + backfill pattern |

### 4.3 Applying Migrations

> ** Corrected.** This section previously said migrations run automatically at
> startup and showed `psql -f <migration>.sql` plus a `migration_name` query. Single-node startup never runs
> migrations (`QODIQA_PG_AUTO_MIGRATE` is consulted only in distributed mode, which production refuses —
> `src/core/audit/multiInstanceGuard.js`, `src/infra/config/bootValidator.js`); a raw `psql -f` bypasses `migrate.js`'s
> checksum record, advisory lock and `lock_timeout`; and `qodiqa_migrations` has no `migration_name` column
> (`version, name, checksum, applied_at, applied_by`).

Migrations are **not** applied at startup in the supported (single-node) production topology. Apply them with the
runner only, after a verified backup and with no writer. Name the target explicitly with `QODIQA_PG_HOST` /
`QODIQA_PG_PORT` / `QODIQA_PG_DATABASE` (`migrate.js` otherwise defaults to `localhost:5432`, usually some other, live
cluster on an operator workstation) and supply the password as `QODIQA_PG_MIG_PASSWORD` in the environment, never on
the command line:

```bash
QODIQA_PG_MIG_USER=qodiqa_test QODIQA_PG_MIG_LOCK_TIMEOUT_MS=5000 node src/infra/postgres/migrate.js --dry-run
QODIQA_PG_MIG_USER=qodiqa_test QODIQA_PG_MIG_LOCK_TIMEOUT_MS=5000 node src/infra/postgres/migrate.js
node src/infra/postgres/migrate.js --status
```

Use `qodiqa_test` (or another CREATEROLE identity) whenever a pending migration creates or alters a role
(002, 018, 038, 060, 065, 067). Never apply a migration file with `psql -f`. For LIVE, follow
 (approval required).

---

## 5. Dependency Upgrade

### 5.1 npm Dependency Upgrade Process

```bash
# 1. Check for available updates
npm outdated

# 2. Check for security vulnerabilities in current deps
npm audit

# 3. For minor/patch updates (generally safe):
npm update --save

# 4. For major version updates (breaking changes possible):
# Update individual packages; do not use npm update for majors
npm install <package>@<new-version> --save

# 5. Run the full test suite
npm test

# 6. Run security tests
npm test -- --testPathPatterns=phase46   # Jest 30 flag is --testPathPatterns (plural)

# 7. Verify supply chain integrity
node scripts/verify-supply-chain.js

# 8. Update lock file and commit
npm ci  # Verify clean install from updated lock
git add package.json package-lock.json
git commit -m "chore: update dependencies to <date>"
```

### 5.2 Node.js Runtime Upgrade

QODIQA requires Node.js 22 or later (the current baseline, pinned via `ARG NODE_VERSION=22` in the Dockerfile and `engines.node` in `package.json`). When upgrading to a newer Node.js major version:

```bash
# Check current version compatibility
node --version

# Build the new Docker image with an updated Node.js base
# In Dockerfile, update:
# ARG NODE_VERSION=22 → ARG NODE_VERSION=<new LTS major>

# Rebuild and test
docker build -t qodiqa:1.1.0-node<new-major> .
docker run --rm qodiqa:1.1.0-node<new-major> node --version

# Run full test suite in the new container
docker run --rm --env-file test.env qodiqa:1.1.0-node<new-major> npm test
```

**Node.js LTS support policy:**
- Only upgrade to LTS (even-numbered major) releases.
- Never run QODIQA on an End-of-Life Node.js version.
- Check current LTS status at: https://nodejs.org/en/about/previous-releases

---

## 6. Redis Upgrade

### 6.1 Redis Version Compatibility

QODIQA uses Redis 7.x. The minimum required version is Redis 6.0 (for `SET NX PX` atomic replay protection). Redis 7.x is strongly recommended for improved Lua scripting performance (used in rate limiting).

| Redis Version | QODIQA Compatible | Notes |
|--------------|------------------|-------|
| 5.x | No | Missing `SET NX PX` atomic semantics |
| 6.x | Yes | Minimum supported |
| 7.x | Yes (recommended) | Improved Lua performance |
| 8.x | Verify | Test in staging before production upgrade |

### 6.2 Redis Upgrade Procedure

**Redis upgrade requires QODIQA to be stopped during the upgrade window to prevent replay-protection nonce loss.**

Credentials: `REDIS_URL` must carry **no password** (the shipped ConfigMap's `rediss://redis-service…:6380` has none;
the password is `REDIS_PASSWORD`). Export it for redis-cli as `REDISCLI_AUTH` from your secret store (and pass
`--user "$REDIS_USERNAME"` when an ACL user is configured) — never `-a <password>` or a password inside the URL, both
of which land in argv and shell history.

```bash
# 1. Assess current Redis data
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" INFO keyspace
# Note: most nonce keys have short TTLs (milliseconds to minutes)
# Rate limit keys persist longer but are stateless (lost rate limit state is not a security issue)

# 2. Save an AOF snapshot
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" BGSAVE
# Wait for background save to complete
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" LASTSAVE

# 3. Stop QODIQA gracefully
kubectl scale statefulset/qodiqa --replicas=0 -n qodiqa

# 4. Update Redis image in docker-compose.prod.yml or Helm chart
# redis:7-alpine → redis:7.2-alpine (or target version)

# 5. Restart Redis with new image
docker-compose -f deploy/docker/docker-compose.prod.yml up -d redis

# 6. Wait for Redis readiness
until redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" PING 2>/dev/null | grep -q PONG; do
  echo "Waiting for Redis..."
  sleep 2
done

# 7. Verify Redis version
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" INFO server | grep redis_version

# 8. Verify AOF is enabled
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" CONFIG GET appendonly

# 9. Start QODIQA
kubectl scale statefulset/qodiqa --replicas=1 -n qodiqa   # 1 is the only supported count
kubectl rollout status statefulset/qodiqa -n qodiqa --timeout=120s
```

### 6.3 Redis Downtime Window

A Redis upgrade requires QODIQA downtime equal to:
- Time to stop QODIQA gracefully: ≤ 30 seconds
- Redis restart time: 5–30 seconds
- QODIQA startup time: ≤ 60 seconds

**Total expected downtime: 90–120 seconds**

Schedule during a maintenance window. Notify clients via the incident communication channel at least 24 hours in advance.

---

## 7. PostgreSQL Upgrade

### 7.1 PostgreSQL Version Compatibility

Supported: **PostgreSQL 15–18** (see [docs/guides/installation.md](../guides/installation.md) and
[docs/deployment/production.md](../deployment/production.md): the CI workflows run on `postgres:15-alpine` and
`postgres:17-alpine`, the production-profile check passes on 15, 16 and 17, and 18.6 runs the full gate set).

| PostgreSQL Version | QODIQA Compatible | Notes |
|-------------------|------------------|-------|
| 13.x, 14.x | No | Below the supported range — not tested |
| 15.x | Yes | Supported (CI `backup-restore` workflow) |
| 16.x | Yes | Supported |
| 17.x | Yes | Supported (most CI workflows) |
| 18.x | Yes | Supported (full gate set on 18.6) |

### 7.2 Major Version Upgrade (e.g., 15 → 16)

Major PostgreSQL upgrades require `pg_upgrade` and a full backup. These are high-risk operations.

```bash
# 1. Full database backup — MANDATORY
#    Encrypted + sealed, as qodiqa_backup, PG* target + PGPASSFILE (never a password in a URL or argv).
#    The pg_dump client must be the server's major version or newer: an older client refuses a newer server and the
#    backup fails — check the backup image's client before and after the server upgrade.
./scripts/pg-backup.sh full && ./scripts/pg-backup.sh verify   # expect BACKUP_SEAL_OK, BACKUP_VERIFY_OK

# 2. Stop all QODIQA instances
kubectl scale statefulset/qodiqa --replicas=0 -n qodiqa

# 3. Perform pg_upgrade (or use pg_dumpall + restore for managed databases)
# For managed databases (RDS, Cloud SQL, AlloyDB): use the platform's upgrade wizard
# Document the upgrade procedure for your specific managed PG provider

# For self-managed PostgreSQL:
pg_upgrade \
  -b /usr/lib/postgresql/15/bin \
  -B /usr/lib/postgresql/16/bin \
  -d /var/lib/postgresql/15/main \
  -D /var/lib/postgresql/16/main \
  --link  # Use hardlinks to avoid copying data

# 4. Start PostgreSQL 16
systemctl start postgresql@16-main

# 5. Verify database integrity
psql -d qodiqa -c "\l"
psql -d qodiqa -c "SELECT COUNT(*) FROM audit_chain;"

# 6. Run VACUUM ANALYZE (important after pg_upgrade)
psql -d qodiqa -c "VACUUM ANALYZE;"

# 7. Update connection strings if port or host changed
# Update QODIQA_PG_URL / QODIQA_PG_HOST in secrets

# 8. Restart QODIQA
kubectl scale statefulset/qodiqa --replicas=1 -n qodiqa   # 1 is the only supported count
kubectl rollout status statefulset/qodiqa -n qodiqa --timeout=120s
```

### 7.3 Minor Version Upgrade (e.g., 15.4 → 15.8)

Minor version upgrades are typically applied in-place and do not require downtime:

```bash
# For managed databases: apply via platform console (RDS, Cloud SQL)
# For self-managed:
apt-get update && apt-get install --only-upgrade postgresql-15

# Restart PostgreSQL to apply the new minor version
systemctl restart postgresql@15-main

# Verify version
psql -d qodiqa -c "SHOW server_version;"

# QODIQA does not need to restart for a PostgreSQL minor version upgrade
# if the connection pool reconnects automatically on disconnect
```

---

## 8. Kubernetes Upgrade

### 8.1 Control Plane Upgrade

Kubernetes control plane upgrades are managed by your cloud provider (EKS, GKE, AKS) or the `kubeadm upgrade` tool for self-managed clusters.

Before upgrading the control plane:

```bash
# Check QODIQA manifest compatibility with target K8s version
kubectl api-versions | grep -E 'apps/v1|networking.k8s.io|policy'

# Verify API deprecations in target version
# Reference: https://kubernetes.io/docs/reference/using-api/deprecation-guide/

# Document current resource versions
kubectl get all -n qodiqa -o yaml > /opt/qodiqa/backups/k8s-resources-$(date +%Y%m%d).yaml
```

### 8.2 Node Pool Upgrade

```bash
# For managed K8s (EKS/GKE/AKS): use the platform's node upgrade mechanism

# For self-managed K8s:
# Cordon the node to prevent new pod scheduling
kubectl cordon <node-name>

# Drain the node. If it runs qodiqa-0 (the only QODIQA pod — single-node StatefulSet, replicas 1), QODIQA is DOWN
# from eviction (graceful, terminationGracePeriodSeconds: 60) until qodiqa-0 is ready again, on this or another node
# where its audit-log PVC can attach. Schedule that node in a maintenance window.
kubectl drain <node-name> \
  --ignore-daemonsets \
  --delete-emptydir-data \
  --grace-period=60

# Upgrade the node (OS + Kubelet)
# ... platform-specific upgrade steps ...

# Uncordon the node after upgrade
kubectl uncordon <node-name>

# Verify qodiqa-0 is Running and Ready again
kubectl get pods -n qodiqa -o wide
```

### 8.3 QODIQA Manifest Compatibility

After a Kubernetes upgrade, verify that QODIQA's manifests remain valid:

```bash
kubectl apply --dry-run=server -k deploy/kubernetes/overlays/single-node/ -n qodiqa
# Expected: All resources validate without errors. The single-node overlay is the only production topology.
# The distributed overlay can be dry-run the same way for a NON-PRODUCTION environment only: the production boot
# validator refuses the distributed mode until its audit chain has signed checkpoints and anchors (
# src/infra/config/bootValidator.js). See deploy/kubernetes/kustomization.yaml's header comment for why there is no
# single combined entry point.
```

---

## 9. Docker Image Upgrade

### 9.1 Base Image Update

QODIQA uses `node:${NODE_VERSION}-alpine${ALPINE_VERSION}` as its base image, pinned via Dockerfile build args (currently `NODE_VERSION=22`, the current Node.js LTS line). Alpine security patches are released frequently.

```bash
# Build with updated base image (no cache)
docker build --no-cache \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  -t qodiqa:1.0.0-patched-$(date +%Y%m%d) \
  .

# Scan the new image for vulnerabilities
docker scout cves qodiqa:1.0.0-patched-$(date +%Y%m%d)
# Or: trivy image qodiqa:1.0.0-patched-$(date +%Y%m%d)

# Verify the image runs correctly
docker run --rm \
  --env-file test.env \
  qodiqa:1.0.0-patched-$(date +%Y%m%d) \
  node -e "console.log('Image OK')"
```

### 9.2 Image Security Scanning Policy

| Severity | Action |
|----------|--------|
| CRITICAL | Block deployment; patch immediately or pin to previous base image |
| HIGH | Patch within 72 hours |
| MEDIUM | Patch within 2 weeks |
| LOW | Include in next planned maintenance |

---

## 10. Configuration Upgrade

### 10.1 New Environment Variables

When a new QODIQA version introduces required environment variables:

```bash
# Check for new variables in deploy/env/production.env.example
git diff v1.1.0..v1.1.0 -- deploy/env/production.env.example | grep '^+[A-Z]'
```

For each new required variable:
1. Determine the value for production.
2. Store in the secrets management system (Vault, Kubernetes Secrets, AWS Secrets Manager).
3. Update the deployment manifests (ConfigMap or Secret).
4. Deploy QODIQA — it will fail fast on startup if a required variable is missing.

### 10.2 Deprecated Variable Migration

```bash
# Check for deprecated variables to remove
git diff v1.1.0..v1.1.0 -- deploy/env/production.env.example | grep '^-[A-Z]'

# Example: QODIQA_OPS_TOKEN is deprecated in favour of RBAC
# Migration: create per-operator RBAC keys, then remove QODIQA_OPS_TOKEN
```

---

## 11. Compatibility Verification

### 11.1 Pre-Upgrade Compatibility Matrix

Document the compatibility matrix before each upgrade:

| Component | Current Version | Target Version | Compatibility Verified | Notes |
|-----------|---------------|---------------|----------------------|-------|
| QODIQA | 1.0.0 | 1.1.0 | Staging: PASS | — |
| Node.js | 20.x | 22.x | Staging: PASS | LTS |
| PostgreSQL | 15.4 | 15.8 | Staging: PASS | Minor version only |
| Redis | 7.0.15 | 7.2.4 | Staging: PASS | Minor version |
| Kubernetes | 1.29.x | 1.30.x | Dry-run: PASS | API compat verified |

### 11.2 API Backward Compatibility Test

```bash
# Run the maintained SDK test suites (contract/conformance tests; there is no separate "integration" directory in
# either SDK — sdk/javascript/tests, sdk/python/tests)
(cd sdk/javascript && npm test)
(cd sdk/python && python -m pytest test/)
```

---

## 12. Downtime Expectations

| Upgrade Type | Expected Downtime | Strategy |
|-------------|------------------|---------|
| QODIQA application (K8s rolling) | Brief full outage (pod replaced in place; startup window up to 120 s) | Rolling replacement of the single StatefulSet pod (`maxUnavailable: 1`, no surge) |
| QODIQA application (Docker) | 30–60 seconds | Stop/start |
| Redis minor version | 90–120 seconds | Restart |
| Redis major version | 5–15 minutes | Stop, upgrade, start |
| PostgreSQL minor version | Near-zero | In-place restart |
| PostgreSQL major version | 30–60 minutes | pg_upgrade |
| Kubernetes control plane | Zero (if configured for HA) | Provider-managed |
| Kubernetes node upgrade | Zero for nodes not running `qodiqa-0`; a brief full outage when the node running `qodiqa-0` is drained | Rolling node drain |
| Node.js base image | Brief full outage (new image = pod replacement) | Rolling replacement of the single pod |
| npm dependencies | Brief full outage (new image = pod replacement) | Rolling replacement of the single pod |

---

## 13. Rollback Triggers

Abort the upgrade and invoke the [Rollback Runbook](rollback-runbook.md) if:

| Condition | Rollback Scope |
|-----------|---------------|
| Smoke test fails after upgrade | Application |
| PostgreSQL migration fails | Database + Application |
| Redis AOF not re-enabled after upgrade | Redis configuration |
| K8s manifest API version no longer supported | Kubernetes manifests |
| `qodiqa_execution_integrity_full{}` = 0 after upgrade | Application + dependencies |
| New Node.js version breaks a native addon | Application |
| Certificate TLS negotiation fails after upgrade | Certificate |

---

## 14. Upgrade Verification

After every upgrade, run the full post-deployment validation from the Deployment Runbook (Section 10) plus:

```bash
# Verify all component versions post-upgrade
echo "=== Component Version Report ==="
echo "QODIQA: $(curl -sf http://localhost:3000/health | jq -r .version 2>/dev/null || echo 'check logs')"
echo "Node.js: $(node --version)"
echo "Redis: $(redis-cli --tls --cacert $REDIS_TLS_CA --cert $REDIS_TLS_CERT --key $REDIS_TLS_KEY -u $REDIS_URL INFO server | grep redis_version)"
echo "PostgreSQL: $(psql -d "${QODIQA_PG_DATABASE:-qodiqa}" -t -c 'SHOW server_version;' | tr -d ' ')"   # PG* target + PGPASSFILE
echo "Kubernetes: $(kubectl version --short 2>/dev/null | grep Server)"
echo "================================"
```

Record this version report in the maintenance log for every production upgrade.

---

*Cross-references: [Deployment Runbook](deployment-runbook.md) | [Rollback Runbook](rollback-runbook.md) | [Redis Failure Runbook](redis-failure.md) | [PostgreSQL Failure Runbook](postgresql-failure.md) | [Backup Runbook](backup-runbook.md)*
