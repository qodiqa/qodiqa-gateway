# QODIQA Startup Runbook

**Operations & Production Readiness**

| Field | Value |
|-------|-------|
| Document | Startup Runbook |
| Version | 1.0.0 |
| Owner | Platform Engineering |
| Audience | SRE, Platform Engineer, On-Call |
| Classification | Internal — Operational |
| Last Updated | 2026-07-03 |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Dependency Verification](#3-dependency-verification)
4. [Environment Validation](#4-environment-validation)
5. [Secrets Validation](#5-secrets-validation)
6. [Certificate Validation](#6-certificate-validation)
7. [Database Readiness](#7-database-readiness)
8. [Redis Readiness](#8-redis-readiness)
9. [HSM Readiness](#9-hsm-readiness)
10. [Migration Execution](#10-migration-execution)
11. [Startup Order](#11-startup-order)
12. [Health Verification](#12-health-verification)
13. [Post-Start Validation](#13-post-start-validation)
14. [Rollback Conditions](#14-rollback-conditions)
15. [Expected Logs](#15-expected-logs)
16. [Expected Metrics](#16-expected-metrics)
17. [Failure Cases and Recovery](#17-failure-cases-and-recovery)
18. [Startup Checklist](#18-startup-checklist)

---

## 1. Overview

QODIQA starts via `node start.js`, which initialises the KMS provider and loads the Ed25519 key store **before** Express routes are registered. Startup is fail-fast: any unrecoverable condition causes the process to exit with a non-zero code and a structured error message. The system enforces ordered startup to prevent serving traffic before every integrity guarantee is in place.

```mermaid
flowchart TD
    A[node start.js] --> B[Load environment variables]
    B --> C[Initialise KMS / KEK provider]
    C --> D[Decrypt Ed25519 key store]
    D --> E[Connect Redis — all stores]
    E --> F[Validate Redis AOF if STRICT_REPLAY_PROTECTION=true]
    F --> G[Connect PostgreSQL]
    G --> H[Run pending migrations]
    H --> I[Load policy file]
    I --> J[Register Express routes]
    J --> K[Bind HTTP listener on PORT]
    K --> L[/health returns 200]
    L --> M[/ready returns 200]
```

**Startup failure is always preferable to serving with degraded integrity guarantees.**

---

## 2. Prerequisites

### 2.1 Operator Checklist

Before initiating startup, the operator must confirm the following are in place.

| Requirement | Verification Command | Expected Result |
|-------------|---------------------|-----------------|
| Node.js 22 or later | `node --version` | `v22.x.x` or higher |
| npm ≥ 9.0.0 | `npm --version` | `9.x.x` or higher |
| Dependencies installed | `node -e "require('./package.json').dependencies && console.log('OK')"` | `OK` |
| `node_modules` present and intact | `npm ci --dry-run 2>&1 \| tail -1` | No integrity errors |
| `start.js` present | `test -f start.js && echo OK` | `OK` |
| `server.js` present | `test -f server.js && echo OK` | `OK` |
| Production env file configured | `test -f .env \|\| test -f /etc/qodiqa/env && echo OK` | `OK` |

### 2.2 System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 250m (0.25 core) | 1 core |
| Memory | 256 MiB | 512 MiB |
| Disk (data volume) | 1 GiB | 10 GiB |
| Disk (log volume) | 1 GiB | 20 GiB |
| Open file descriptors | 1024 | 4096 |
| Network connectivity | Redis, PostgreSQL reachable | — |

### 2.3 Required Files and Volumes

| Path | Purpose | Must Exist Before Start |
|------|---------|------------------------|
| `$QODIQA_KEYS_PATH` (default `/opt/qodiqa/data/keys.json`) | Encrypted Ed25519 key store | Yes (created on first init) |
| `$QODIQA_AUDIT_LOG` (default `/opt/qodiqa/logs/audit.log`) | Audit chain file | Parent directory must exist |
| `$POLICY_FILE` (default `/opt/qodiqa/config/policies.json`) | Active policy set | Yes |
| `$QODIQA_AUDIT_LOG.wal` | Write-ahead log for crash safety | Created automatically |
| `$QODIQA_AUDIT_LOG.sum` | Audit chain checksum file | Created automatically if missing |

---

## 3. Dependency Verification

### 3.1 Node Module Integrity

```bash
# Verify all production dependencies are installed and match lock file
npm ci --omit=dev 2>&1
echo "Exit code: $?"
# Expected: exit 0
```

### 3.2 Supply Chain Verification

```bash
# Verify dependency hashes against known-good manifest
node scripts/verify-supply-chain.js
# Expected: "Supply chain verification passed"
```

```bash
# Verify lock file has not been tampered with
node scripts/verify-deps.js
# Expected: exit 0 with no integrity warnings
```

### 3.3 npm Audit

```bash
npm audit --audit-level=high --omit=dev
# Expected: zero high-severity or critical vulnerabilities
# Action on failure: DO NOT start; escalate to security team
```

---

## 4. Environment Validation

### 4.1 Required Environment Variables

Load the environment file before validation:

```bash
# Docker deployments: variables are injected by container runtime
# Bare-metal / VM: source the env file
source /etc/qodiqa/env
```

Validate each required variable is set and non-empty:

```bash
validate_env() {
  local var=$1
  local value="${!var}"
  if [[ -z "$value" ]]; then
    echo "FATAL: Required variable $var is not set" >&2
    exit 1
  fi
  echo "OK: $var is set"
}

validate_env NODE_ENV
validate_env PORT
validate_env QODIQA_KEY_ENCRYPTION_KEY
validate_env OPENAI_API_KEY
validate_env QODIQA_CLIENT_ID
validate_env REDIS_URL
```

There is no `QODIQA_SIGN_TOKEN` startup check — removed the shared sign secret; `server/startup.js` has no `SIGN_TOKEN_NOT_CONFIGURED` FATAL check. Instead, confirm at least one signing identity is provisioned (`node scripts/provision-signing-identity.js ...` — see docs/guides/quickstart.md#provision-a-signing-identity).

### 4.2 Environment Value Constraints

| Variable | Constraint | Validation Command |
|----------|------------|-------------------|
| `NODE_ENV` | Must be `production` | `[[ "$NODE_ENV" == "production" ]] && echo OK` |
| `QODIQA_KEY_ENCRYPTION_KEY` | Exactly 64 hex characters (256-bit) | `echo -n "$QODIQA_KEY_ENCRYPTION_KEY" \| grep -qP '^[0-9a-fA-F]{64}$' && echo OK` |
| `QODIQA_CLIENT_ID` | 1–64 chars, `[A-Za-z0-9_-]` only | `echo "$QODIQA_CLIENT_ID" \| grep -qP '^[A-Za-z0-9_-]{1,64}$' && echo OK` |
| `PORT` | Integer 1–65535 | `[[ "$PORT" =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] && echo OK` |
| `REDIS_URL` | `redis://` or `rediss://` prefix | `echo "$REDIS_URL" \| grep -qP '^rediss?://' && echo OK` |
| `STRICT_REPLAY_PROTECTION` | Should be `true` in production | `[[ "$STRICT_REPLAY_PROTECTION" == "true" ]] && echo OK` |
| `QODIQA_RBAC_ENABLED` | Deprecated and ignored; remove it from the environment | none |

### 4.3 Dangerous Configuration Check

```bash
# These settings must NEVER be enabled in production
if [[ "$REDIS_TLS_REJECT_UNAUTHORIZED" == "false" ]]; then
  echo "FATAL: REDIS_TLS_REJECT_UNAUTHORIZED=false in production is prohibited" >&2
  exit 1
fi

if [[ "$NODE_ENV" != "production" ]]; then
  echo "FATAL: NODE_ENV must be 'production'" >&2
  exit 1
fi
```

---

## 5. Secrets Validation

### 5.1 Key Encryption Key (KEK) Validation

The KEK must be a 256-bit (64 hex character) value. Verify format without logging the value:

```bash
KEK_LEN=$(echo -n "$QODIQA_KEY_ENCRYPTION_KEY" | wc -c)
if [[ "$KEK_LEN" -ne 64 ]]; then
  echo "FATAL: QODIQA_KEY_ENCRYPTION_KEY must be exactly 64 hex characters; got $KEK_LEN" >&2
  exit 1
fi
echo "KEK length: OK (64 chars)"
```

### 5.2 Key Store Decryptability

The key store file is decrypted during `start.js` initialisation using AES-256-GCM. If decryption fails (wrong KEK, tampered ciphertext), startup aborts.

Pre-flight check (do not log decrypted content):

```bash
# Verify the key store file exists and is valid JSON
test -f "$QODIQA_KEYS_PATH" && \
  node -e "JSON.parse(require('fs').readFileSync('$QODIQA_KEYS_PATH','utf8')); console.log('Key store JSON: OK')"
```

If the key store file does not exist (first-time deployment), QODIQA will create it during startup. Ensure the data volume is writable.

### 5.3 Signing Identity Verification

: there is no `QODIQA_SIGN_TOKEN` to entropy-check — each caller authenticates
with its own individually-issued `sk_...` signing API key
(`src/core/signing/signingIdentityStore.js`), always generated server-side via
`crypto.randomBytes(32)` (line ~94), never user-supplied. Confirm at least one
signing identity exists in the store instead:

```bash
node -e "console.log(require('./src/core/signing/signingIdentityStore').listSigningIdentities().length)"
```

### 5.4 Ops Token Check

```bash
# QODIQA_OPS_TOKEN is deprecated; ensure migration to RBAC keys is complete
if [[ -n "$QODIQA_OPS_TOKEN" ]]; then
  echo "WARNING: QODIQA_OPS_TOKEN is deprecated. Migrate to per-operator RBAC keys."
fi
```

---

## 6. Certificate Validation

### 6.1 Redis TLS Certificates

```bash
REDIS_CA_PATH="$REDIS_TLS_CA"
REDIS_CERT_PATH="$REDIS_TLS_CERT"
REDIS_KEY_PATH="$REDIS_TLS_KEY"

# Verify files exist
for f in "$REDIS_CA_PATH" "$REDIS_CERT_PATH" "$REDIS_KEY_PATH"; do
  [[ -f "$f" ]] || { echo "FATAL: Missing TLS file: $f" >&2; exit 1; }
done

# Verify certificate is not expired (must have > 30 days remaining)
EXPIRY=$(openssl x509 -enddate -noout -in "$REDIS_CERT_PATH" | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_REMAINING=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
echo "Redis client cert expires in $DAYS_REMAINING days"
if [[ $DAYS_REMAINING -lt 30 ]]; then
  echo "WARNING: Redis TLS certificate expires in $DAYS_REMAINING days — schedule renewal"
fi

# Verify the certificate matches the key
CERT_MODULUS=$(openssl x509 -noout -modulus -in "$REDIS_CERT_PATH" | md5sum)
KEY_MODULUS=$(openssl pkey -noout -modulus -in "$REDIS_KEY_PATH" | md5sum)
[[ "$CERT_MODULUS" == "$KEY_MODULUS" ]] || { echo "FATAL: Redis cert/key mismatch" >&2; exit 1; }
echo "Redis cert/key match: OK"
```

### 6.2 PostgreSQL TLS Certificates

```bash
if [[ "$QODIQA_PG_SSL" == "true" ]]; then
  for f in "$QODIQA_PG_SSL_CA" "$QODIQA_PG_SSL_CERT" "$QODIQA_PG_SSL_KEY"; do
    [[ -f "$f" ]] || { echo "FATAL: Missing PG TLS file: $f" >&2; exit 1; }
  done
  EXPIRY=$(openssl x509 -enddate -noout -in "$QODIQA_PG_SSL_CERT" | cut -d= -f2)
  EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
  DAYS_REMAINING=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
  echo "PostgreSQL client cert expires in $DAYS_REMAINING days"
  [[ $DAYS_REMAINING -lt 30 ]] && echo "WARNING: PG TLS certificate expires soon — schedule renewal"
fi
```

---

## 7. Database Readiness

### 7.1 PostgreSQL Connectivity Test

```bash
# Test basic connectivity — exits 0 if reachable
psql "$QODIQA_PG_URL" -c "SELECT 1;" -t 2>&1
if [[ $? -ne 0 ]]; then
  echo "FATAL: Cannot connect to PostgreSQL at $QODIQA_PG_HOST:$QODIQA_PG_PORT" >&2
  exit 1
fi
echo "PostgreSQL connectivity: OK"
```

### 7.2 Role Verification

```bash
# Verify qodiqa_app role exists and has correct privileges
psql "$QODIQA_PG_URL" -c "
  SELECT rolname, rolcanlogin
  FROM pg_roles
  WHERE rolname IN ('qodiqa_app', 'qodiqa_read')
  ORDER BY rolname;
" -t
```

Expected output (after / `role-credentials.js --harden-unused`, an unused `qodiqa_read` is `NOLOGIN`; also run
`node scripts/db/role-credentials.js --check`, which must exit 0):
```
 qodiqa_app  | t
 qodiqa_read | f
```

### 7.3 Migration Table Existence

```bash
psql "$QODIQA_PG_URL" -c "
  SELECT COUNT(*) FROM information_schema.tables
  WHERE table_name = 'qodiqa_migrations';
" -t
# Expected: 1
```

### 7.4 Database Disk Space

```bash
psql "$QODIQA_PG_URL" -c "
  SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size;
"
# Verify available disk space on the PG volume exceeds 3× the current DB size
```

### 7.5 Row-Level Security Verification

```bash
psql "$QODIQA_PG_URL" -c "
  SELECT tablename, rowsecurity
  FROM pg_tables
  WHERE schemaname = 'public'
  AND tablename IN ('audit_chain','transparency_log_entries','signing_keys')
  ORDER BY tablename;
"
# Expected: rowsecurity = 't' for all three tables
```

---

## 8. Redis Readiness

### 8.1 Connectivity Test

```bash
# Verify Redis is reachable and authenticated
redis-cli \
  --tls \
  --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" \
  --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" \
  PING
# Expected: PONG
```

### 8.2 AOF Persistence Verification

This check is **mandatory** when `STRICT_REPLAY_PROTECTION=true`. QODIQA refuses to start if AOF is not enabled; this check surfaces the failure before launch.

```bash
AOF_STATUS=$(redis-cli \
  --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" \
  CONFIG GET appendonly | tail -1)

if [[ "$AOF_STATUS" != "yes" ]]; then
  echo "FATAL: Redis AOF is not enabled. STRICT_REPLAY_PROTECTION requires appendonly=yes" >&2
  echo "Set 'appendonly yes' and 'appendfsync everysec' in redis.conf and restart Redis" >&2
  exit 1
fi
echo "Redis AOF: OK (appendonly=yes)"
```

### 8.3 Redis Memory Headroom

```bash
MAXMEM=$(redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" CONFIG GET maxmemory | tail -1)

USEDMEM=$(redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" INFO memory | grep used_memory: | awk -F: '{print $2}' | tr -d '\r')

echo "Redis used memory: $USEDMEM bytes"
echo "Redis max memory: ${MAXMEM:-unlimited}"

# If maxmemory is set, verify at least 20% headroom remains
if [[ -n "$MAXMEM" && "$MAXMEM" -gt 0 ]]; then
  PCT=$(( USEDMEM * 100 / MAXMEM ))
  [[ $PCT -gt 80 ]] && echo "WARNING: Redis memory utilisation at $PCT% — monitor closely"
fi
```

### 8.4 Nonce Store Isolation Test

```bash
# Verify QODIQA's nonce key prefix is accessible and writeable
TEST_KEY="qodiqa:req:v2:startup-preflight-$(date +%s)"
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" \
  SET "$TEST_KEY" "1" PX 5000 NX
redis-cli --tls --cacert "$REDIS_TLS_CA" \
  --cert "$REDIS_TLS_CERT" --key "$REDIS_TLS_KEY" \
  -u "$REDIS_URL" \
  DEL "$TEST_KEY"
echo "Redis nonce store write/delete: OK"
```

---

## 9. HSM Readiness

HSM checks depend on the configured `QODIQA_KMS_PROVIDER` and `QODIQA_HSM_PROVIDER`.

### 9.1 Local KEK Provider

```bash
if [[ "$QODIQA_KMS_PROVIDER" == "local" ]]; then
  # Local mode uses QODIQA_KEY_ENCRYPTION_KEY env var — already validated in Section 5
  echo "KMS provider: local — no external HSM connectivity required"
fi
```

### 9.2 HashiCorp Vault Provider

```bash
if [[ "$QODIQA_KMS_PROVIDER" =~ ^vault ]]; then
  # Test Vault connectivity
  curl -sf --max-time 5 \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/sys/health" > /dev/null
  echo "Vault connectivity: OK"

  # Verify the KEK secret path exists
  curl -sf --max-time 5 \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/$VAULT_KEK_PATH" > /dev/null
  echo "Vault KEK path accessible: OK"
fi
```

### 9.3 AWS KMS Provider

```bash
if [[ "$QODIQA_KMS_PROVIDER" == "aws-kms" ]]; then
  aws kms describe-key \
    --key-id "$AWS_KMS_KEY_ID" \
    --region "$AWS_REGION" \
    --query 'KeyMetadata.{State:KeyState,Enabled:Enabled}' \
    --output json
  # Expected: {"State":"Enabled","Enabled":true}
fi
```

### 9.4 PKCS#11 / Hardware HSM

```bash
if [[ "$QODIQA_HSM_PROVIDER" == "pkcs11" ]]; then
  # Verify the PKCS#11 module is loadable
  pkcs11-tool --module "$PKCS11_MODULE" --list-slots 2>&1 | head -5
  # Expected: slot listings without error
fi
```

---

## 10. Migration Execution

> ** Corrected.** This section previously said QODIQA runs migrations automatically at
> startup (001–021), took a plaintext `pg_dump --no-acl --no-owner` backup, queried a non-existent `migration_name`
> column and described startup migration log lines. None of that matches the current system; git history keeps the
> original.

Migrations are applied by the operator with `node src/infra/postgres/migrate.js` (001–078 at the time of writing);
the single-node production boot does not apply them (`QODIQA_PG_AUTO_MIGRATE` is consulted only in distributed mode,
which production refuses). The runner records each file's checksum in `qodiqa_migrations`
(`version, name, checksum, applied_at, applied_by`), holds an advisory lock and applies a per-migration `lock_timeout`.

### 10.1 Pre-Migration Backup

**Always take an encrypted, sealed backup before running migrations in production:**

```bash
./scripts/pg-backup.sh full && ./scripts/pg-backup.sh verify
# Expect BACKUP_ENCRYPTED, BACKUP_SEAL_OK, BACKUP_VERIFY_OK (owners and ACLs are kept in the dump)
```

### 10.2 Check Pending Migrations

```bash
node src/infra/postgres/migrate.js --status
node src/infra/postgres/migrate.js --dry-run    # what would run
```

### 10.3 Applying Migrations

With no writer running and after 10.1:

```bash
QODIQA_PG_MIG_USER=qodiqa_test QODIQA_PG_MIG_LOCK_TIMEOUT_MS=5000 node src/infra/postgres/migrate.js
node src/infra/postgres/migrate.js --status
```

Use `qodiqa_test` (or another CREATEROLE identity) whenever a pending migration creates or alters a role
(002, 018, 038, 060, 065, 067). Never apply a migration file with `psql -f`. For LIVE, follow
 (approval required).

### 10.4 Migration Failure Response

A failed migration is rolled back in its own transaction and the runner exits non-zero; the next run resumes from it.

**Action:**
1. Do not start QODIQA against a partially migrated database until the root cause is identified.
2. Fix the cause (lock timeout, privilege, disk space, connection) and re-run `migrate.js`, or restore the
   pre-migration backup into a new database (`restore-runbook.md` §5).
3. Never edit or delete `qodiqa_migrations` rows.

---

## 11. Startup Order

### 11.1 Correct Service Startup Sequence

Start services in this precise order. Out-of-order startup causes QODIQA to fail during dependency health checks.

```
1. PostgreSQL
      ↓
2. Redis
      ↓
3. QODIQA (node start.js)
```

### 11.2 Docker Compose Startup

```bash
cd /opt/qodiqa

# Start infrastructure services first
docker-compose -f deploy/docker/docker-compose.prod.yml up -d redis

# Wait for Redis to be healthy
until docker-compose -f deploy/docker/docker-compose.prod.yml \
  exec redis redis-cli --tls \
  --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key \
  -p 6380 PING 2>/dev/null | grep -q PONG; do
  echo "Waiting for Redis..."
  sleep 2
done
echo "Redis: READY"

# Start QODIQA
docker-compose -f deploy/docker/docker-compose.prod.yml up -d qodiqa

echo "QODIQA: starting..."
```

### 11.3 Kubernetes Startup

The Kubernetes Deployment includes an `initContainer` (`wait-for-redis`) that gates QODIQA startup on Redis availability. PostgreSQL must be available before Kubernetes pod scheduling completes, or the migration step will abort.

```bash
# Apply all manifests (pick the topology this environment runs — see
# deploy/kubernetes/kustomization.yaml's header comment for why there is no
# longer a single combined entry point)
kubectl apply -k deploy/kubernetes/overlays/distributed/
# — or —
kubectl apply -k deploy/kubernetes/overlays/single-node/

# Monitor pod startup
kubectl rollout status deployment/qodiqa -n qodiqa --timeout=120s   # distributed
# — or —
kubectl rollout status statefulset/qodiqa -n qodiqa --timeout=120s # single-node

# Verify pods are running
kubectl get pods -n qodiqa -l app=qodiqa
```

### 11.4 Bare-Metal / systemd Startup

```bash
# Ensure PostgreSQL is active
systemctl is-active postgresql || { echo "FATAL: PostgreSQL not running"; exit 1; }

# Ensure Redis is active
systemctl is-active redis || { echo "FATAL: Redis not running"; exit 1; }

# Start QODIQA
systemctl start qodiqa

# Monitor journal
journalctl -u qodiqa -f --since now
```

---

## 12. Health Verification

### 12.1 Liveness Endpoint

```bash
curl -sf http://localhost:3000/health
```

**Expected response:**
```json
{"status":"ok","uptime":12.3}
```

The `/health` endpoint returns `200 OK` as soon as the HTTP listener is bound. It does **not** check dependencies.

### 12.2 Readiness Endpoint

```bash
curl -sf http://localhost:3000/ready
```

**Expected response:**
```json
{"status":"ready"}
```

The `/ready` endpoint returns `503 Service Unavailable` if:
- Redis is unavailable (any of the five Redis stores is disconnected)
- The process is in graceful shutdown state

Poll readiness until it returns `200`:

```bash
MAX_WAIT=60
ELAPSED=0
until curl -sf http://localhost:3000/ready > /dev/null 2>&1; do
  echo "Waiting for readiness... ($ELAPSED/$MAX_WAIT s)"
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  [[ $ELAPSED -ge $MAX_WAIT ]] && { echo "FATAL: Readiness timeout"; exit 1; }
done
echo "QODIQA is READY"
```

### 12.3 Metrics Endpoint

```bash
# /metrics is ops-authenticated (src/app.js:179): OPS_AUTH_HEADER_FILE is a 0600 file holding one line
# "Authorization: Bearer <operator API key>" (curl -H @file keeps the key out of argv; docs/operations/deployment-runbook.md §8).
curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep qodiqa_execution_integrity_full
```

**Expected:**
```
qodiqa_execution_integrity_full{} 1
```

A value of `0` means one or more Redis stores is unavailable — enforcement is fail-closed in this state.

---

## 13. Post-Start Validation

### 13.1 Public Key Availability

```bash
curl -sf http://localhost:3000/public-key | jq .
```

Expected: JSON with `keyId`, `publicKey` (Ed25519 public key in base64), `algorithm: "Ed25519"`.

```bash
curl -sf http://localhost:3000/.well-known/qodiqa/keys | jq '.keys | length'
# Expected: ≥ 1
```

### 13.2 Policy File Loaded

```bash
curl -sf http://localhost:3000/policy/status 2>/dev/null || \
  curl -sf -H "Authorization: Bearer $QODIQA_OPS_TOKEN" http://localhost:3000/policy/status
# Expected: active policy count ≥ 1
```

Verify the policy file path in startup logs:

```
{"level":"info","msg":"Policy file loaded","path":"/opt/qodiqa/config/policies.json","policyCount":N}
```

### 13.3 Audit Chain Integrity

On startup, QODIQA replays the existing audit log to rebuild in-memory indexes and verify chain continuity. If the chain is broken, startup aborts.

Verify audit chain status in logs:

```
{"level":"info","msg":"Audit chain loaded","entryCount":N,"tailHash":"..."}
```

If the audit log is missing or empty, a genesis entry is created automatically:

```
{"level":"info","msg":"Audit chain initialised with genesis entry","hash":"..."}
```

### 13.4 Replay Protection Active

```bash
curl -sf -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep qodiqa_redis_store_up
```

Expected:
```
qodiqa_redis_store_up{store="nonce"} 1
qodiqa_redis_store_up{store="anomaly"} 1
qodiqa_redis_store_up{store="rate_limit"} 1
```

All three must be `1`. Any `0` value means that store is disconnected.

### 13.5 Smoke Test — Enforcement Endpoint

$QODIQA_SIGNING_KEY is not a shared secret — there is no QODIQA_SIGN_TOKEN. It is the
sk_... key from a provisioned signing identity (see
docs/guides/quickstart.md#provision-a-signing-identity or scripts/provision-signing-identity.js).
/ai/chat takes a signed artifact via the x-qodiqa-artifact header, not a bearer
token, and its body is {"prompt": ...} — src/api/routes/aiChat.js:291.

```bash
# Verify the enforcement endpoint is accepting requests
REQUEST_OBJ='{"method":"POST","path":"/ai/chat","body":{"prompt":"Hello"}}'
SIGN_BODY="{\"request\":$REQUEST_OBJ}"
SIGNED=$(curl -sf \
  -X POST http://localhost:3000/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $QODIQA_SIGNING_KEY" \
  -d "$SIGN_BODY")
ARTIFACT_B64=$(node -e "
  const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  process.stdout.write(Buffer.from(JSON.stringify(d.artifact)).toString('base64'));
" <<< "$SIGNED")

curl -sf \
  -X POST http://localhost:3000/ai/chat \
  -H "Content-Type: application/json" \
  -H "x-qodiqa-artifact: $ARTIFACT_B64" \
  -d '{"prompt":"Hello"}' \
  | jq '.decision'
# Expected: "EXECUTE" or "BLOCK" — any structured response confirms enforcement is active
```

### 13.6 Transparency Log Status

```bash
curl -sf http://localhost:3000/transparency/status 2>/dev/null | jq '.'
# Expected: {"status":"active","entryCount":N,"latestRootSeq":N}
```

---

## 14. Rollback Conditions

Abort startup and invoke the rollback procedure if any of the following are observed:

| Condition | Severity | Action |
|-----------|----------|--------|
| `QODIQA_KEY_ENCRYPTION_KEY` does not decrypt the key store | CRITICAL | Stop immediately; do not start |
| Redis AOF is disabled with `STRICT_REPLAY_PROTECTION=true` | CRITICAL | Fix Redis config; restart Redis; retry |
| Consent revocation subscriber cannot connect/subscribe within `REVOCATION_SUBSCRIBER_STARTUP_TIMEOUT_MS` (default 10s) — `REVOCATION_SUBSCRIBER_STARTUP_FAILED`, process calls `process.exit(1)` | CRITICAL | Fix Redis reachability/ACL (verify `SUBSCRIBE` is permitted for the QODIQA Redis user); retry. This is a hard, non-retried startup stop by design — see [Redis Failure Runbook §12.2](redis-failure.md#122-revocation-subscriber--the-control-that-actually-matters) |
| PostgreSQL migration fails | CRITICAL | Restore pre-migration backup; fix cause; retry |
| Audit chain hash mismatch detected on startup replay | CRITICAL | Invoke transparency recovery runbook |
| Policy file missing or unparseable | HIGH | Restore policy from backup; retry |
| `/ready` does not return 200 within 60 seconds | HIGH | Investigate Redis/PG connectivity; rollback if unresolvable |
| Any Redis store in disconnected state after 30 seconds | HIGH | Fix Redis connectivity; retry |
| Node.js process exits within 30 seconds of start | HIGH | Check exit logs; fix cause; retry |
| HSM connectivity failure | HIGH | Fix HSM credentials/connectivity; retry |
| `qodiqa_execution_integrity_full{}` metric is 0 at startup | MEDIUM | Investigate Redis stores; do not route production traffic |

---

## 15. Expected Logs

All startup logs are structured JSON written to stdout. The following sequence is expected on a clean startup.

```json
{"level":"info","msg":"QODIQA startup initiated","version":"1.0.0","node":"v22.x.x","ts":"..."}
{"level":"info","msg":"Loading KMS provider","provider":"local","ts":"..."}
{"level":"info","msg":"KEK loaded successfully","keyLength":256,"ts":"..."}
{"level":"info","msg":"Key store loaded","keyCount":1,"activeKeyId":"key-...","ts":"..."}
{"level":"info","msg":"Redis client connecting","store":"nonce","url":"rediss://...","ts":"..."}
{"level":"info","msg":"Redis client connecting","store":"anomaly","url":"rediss://...","ts":"..."}
{"level":"info","msg":"Redis client connecting","store":"rate_limit","url":"rediss://...","ts":"..."}
{"level":"info","msg":"Redis client connecting","store":"consent","url":"rediss://...","ts":"..."}
{"level":"info","msg":"Redis client connecting","store":"persistence_recovery","url":"rediss://...","ts":"..."}
{"level":"info","msg":"Redis AOF verified","appendonly":"yes","appendfsync":"everysec","ts":"..."}
{"level":"info","msg":"PostgreSQL pool initialised","host":"...","database":"qodiqa","poolMax":10,"ts":"..."}
{"level":"info","msg":"All migrations complete","schemaVersion":"021","ts":"..."}
{"level":"info","msg":"Audit chain loaded","entryCount":N,"tailHash":"...","ts":"..."}
{"level":"info","msg":"Policy file loaded","path":"...","policyCount":N,"ts":"..."}
{"level":"info","msg":"Transparency log active","entryCount":N,"ts":"..."}
{"event":"REVOCATION_SUBSCRIBER_READY","level":"INFO","ts":"..."}
{"event":"REVOCATION_SUBSCRIBER_STARTUP_OK","level":"INFO","channel":"qodiqa:consent:revocation","ts":"..."}
{"level":"info","msg":"HTTP server listening","port":3000,"ts":"..."}
{"level":"info","msg":"QODIQA ready to serve","ts":"..."}
```

The revocation subscriber is started synchronously during boot, before the
HTTP server begins listening — if `REVOCATION_SUBSCRIBER_STARTUP_OK` does
not appear, the process has already exited (`REVOCATION_SUBSCRIBER_STARTUP_FAILED`,
FATAL) and `"HTTP server listening"` never fires. See
[Redis Failure Runbook §12.2](redis-failure.md#122-revocation-subscriber--the-control-that-actually-matters).

Any deviation from this sequence — or the appearance of `"level":"error"` or `"level":"fatal"` — requires immediate investigation before routing traffic.

---

## 16. Expected Metrics

After successful startup, the following metric values are expected at `/metrics`:

| Metric | Expected Value | Notes |
|--------|---------------|-------|
| `qodiqa_execution_integrity_full{}` | `1` | All Redis stores connected |
| `qodiqa_redis_store_up{store="nonce"}` | `1` | Nonce store active |
| `qodiqa_redis_store_up{store="anomaly"}` | `1` | Anomaly store active |
| `qodiqa_redis_store_up{store="rate_limit"}` | `1` | Rate limit store active |
| `qodiqa_requests_total` | `0` | No requests served yet |
| `qodiqa_blocks_total` | `0` | No blocks yet |

---

## 17. Failure Cases and Recovery

### 17.1 KEK Decryption Failure

**Symptom:** Startup log contains:
```
{"level":"fatal","msg":"Failed to decrypt key store","error":"AES-GCM authentication failed","ts":"..."}
```

**Cause:** `QODIQA_KEY_ENCRYPTION_KEY` does not match the key used to encrypt `keys.json`.

**Recovery:**
1. Verify `QODIQA_KEY_ENCRYPTION_KEY` is set to the correct 64-character hex value.
2. If the KEK was rotated, ensure the new KEK was used to re-encrypt `keys.json` before deployment.
3. If the KEK is lost and no backup exists, invoke the Key Compromise Runbook (Section 48.9).

### 17.2 Redis Connection Refused

**Symptom:**
```
{"level":"error","msg":"Redis connection failed","store":"nonce","error":"ECONNREFUSED","ts":"..."}
```

**Recovery:**
1. Verify Redis is running: `systemctl status redis` or `docker ps | grep redis`.
2. Verify `REDIS_URL` matches the actual Redis address and port.
3. Verify TLS certificates are valid and paths are correct.
4. Test connectivity: `redis-cli --tls ... PING`.
5. Start Redis if stopped, then retry QODIQA startup.

### 17.3 PostgreSQL Connection Failure

**Symptom:**
```
{"level":"error","msg":"PostgreSQL connection failed","error":"ECONNREFUSED 5432","ts":"..."}
```

**Recovery:**
1. Verify PostgreSQL is running.
2. Verify `QODIQA_PG_URL` or individual `QODIQA_PG_*` variables are correct.
3. Verify `qodiqa_app` role credentials are correct.
4. Test with `psql "$QODIQA_PG_URL" -c "SELECT 1;"`.
5. Resolve connectivity; retry startup.

**Note:** If `QODIQA_PG_ENABLED=false`, PostgreSQL connection failure is non-fatal (audit chain operates file-only). In production, `QODIQA_PG_ENABLED=true` is required.

### 17.4 Audit Chain Corruption

**Symptom:**
```
{"level":"fatal","msg":"Audit chain integrity check failed","error":"Hash mismatch at entry 1234","ts":"..."}
```

**Recovery:**
1. Do not start the process.
2. Preserve the corrupted files (`audit.log`, `audit.log.wal`, `audit.log.sum`) for forensic analysis.
3. Invoke the Transparency Recovery Runbook (Section 48.11).

### 17.5 Policy File Missing

**Symptom:**
```
{"level":"error","msg":"Policy file not found","path":"/opt/qodiqa/config/policies.json","ts":"..."}
```

**Recovery:**
1. Restore `policies.json` from backup or Kubernetes ConfigMap.
2. Verify `POLICY_FILE` env var points to the correct path.
3. Retry startup.

---

## 18. Startup Checklist

Use this checklist for every production startup. Mark each item before proceeding to the next.

```
STARTUP CHECKLIST — QODIQA v1.0.0
Date: __________  Operator: __________  Environment: __________

PRE-STARTUP
[ ] Node.js version 22 or later confirmed
[ ] npm dependencies installed and supply chain verified
[ ] npm audit: zero high/critical vulnerabilities
[ ] All required environment variables set and validated
[ ] QODIQA_KEY_ENCRYPTION_KEY: 64 hex chars, confirmed correct KEK
[ ] At least one signing identity is provisioned (there is no `QODIQA_SIGN_TOKEN` shared secret — see `docs/configuration/reference.md`)
[ ] QODIQA_CLIENT_ID: valid format
[ ] NODE_ENV=production
[ ] STRICT_REPLAY_PROTECTION=true
[ ] REDIS_TLS_REJECT_UNAUTHORIZED is NOT set to false

DEPENDENCY CHECKS
[ ] Redis connectivity: PING → PONG
[ ] Redis AOF enabled (appendonly=yes)
[ ] Redis memory headroom > 20%
[ ] PostgreSQL connectivity: SELECT 1 → success
[ ] PostgreSQL roles qodiqa_app and qodiqa_read exist
[ ] Row-level security enabled on audit_chain, transparency_log_entries, signing_keys
[ ] HSM/KMS provider accessible (if not local)

CERTIFICATE CHECKS
[ ] Redis TLS cert valid (> 30 days remaining)
[ ] Redis cert/key pair match verified
[ ] PostgreSQL TLS cert valid (if QODIQA_PG_SSL=true)

PRE-MIGRATION
[ ] Pre-migration database backup completed and verified: __________
[ ] Pending migrations identified and reviewed

STARTUP
[ ] Services started in correct order: PostgreSQL → Redis → QODIQA
[ ] Process started: node start.js
[ ] Startup logs reviewed — no errors or fatals

POST-STARTUP VERIFICATION
[ ] GET /health → 200 {"status":"ok"}
[ ] GET /ready → 200 {"status":"ready"}
[ ] GET /metrics → qodiqa_execution_integrity_full{} = 1
[ ] GET /metrics → all qodiqa_redis_store_up = 1
[ ] GET /public-key → valid key returned
[ ] GET /.well-known/qodiqa/keys → ≥ 1 key
[ ] Audit chain loaded successfully (entry count in logs)
[ ] Policy file loaded (policy count in logs)
[ ] Transparency log active (status endpoint)
[ ] Smoke test enforcement request returns structured decision

SIGN-OFF
Operator signature: __________  Time: __________
```

---

*Cross-references: [Shutdown Runbook](shutdown-runbook.md) | [Deployment Runbook](deployment-runbook.md) | [Redis Failure Runbook](redis-failure.md) | [PostgreSQL Failure Runbook](postgresql-failure.md) | [Key Compromise Runbook](key-compromise-runbook.md) | [Transparency Recovery](transparency-recovery.md)*
