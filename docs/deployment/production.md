# PRODUCTION DEPLOYMENT

This document covers deploying QODIQA in production: infrastructure requirements, environment configuration, deployment topologies, and the startup validation sequence.

---

## System overview

QODIQA is a Node.js/Express gateway that enforces cryptographic authorization before every AI provider call. Every request to `POST /ai/chat` traverses a five-step enforcement pipeline:

1. **validateArtifact** — Ed25519 signature verification; schema, expiry, clock-skew (≤60 s), key resolution
2. **verifyRequestBinding** — SHA-256 of method + path + body compared against artifact payload; reason code `REQUEST_MISMATCH` on failure
3. **registerNonce** — Redis `SET NX PX`; returns `REPLAY_DETECTED` on collision
4. **checkAnomaly** — Redis sorted-set sliding windows; per-key max 100/min, global max 5000/min
5. **enforcePolicy** — structured policy engine (REQUIRE_CONSENT, BLOCK_IP, TIME_WINDOW, RATE_LIMIT)

All five steps are fail-closed: any Redis unavailability in these steps (nonce / anomaly stores) blocks execution. The exception is HTTP rate limiting: traffic buckets configured `failMode: 'degrade'` (e.g. `ai_chat_ip`, `ai_chat_identity`, `verify_public`, `public_verify` — `src/core/rateLimit/config.js`) fall back to a per-process limiter with a CRITICAL alert when Redis is unavailable.

---

## Runtime requirements

| Requirement | Notes |
|---|---|
| Node.js 22 or later | LTS; matches `node:22-slim` container base image (`Dockerfile`) |
| Redis | Sorted sets and Lua scripting required; ACL authentication requires Redis 6+ |
| PostgreSQL | **Mandatory with `NODE_ENV=production`** — boot exits with `EVIDENCE_DURABILITY_VIOLATION` if PostgreSQL is disabled or the evidence stores are not ready (`server/startup.js`); also backs consent, the control plane and v7 identity pseudonymization |
| At least one AI provider credential | See [Provider architecture](../../README.md) — `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, or `LOCAL_BASE_URL` |
| Persistent volume | Key store (`keys.json`) and audit log must survive pod restarts |

---

### PostgreSQL versions exercised

| Version | Where it is exercised |
|---|---|
| 18.6 | The full local gate set (unit/component/acceptance/real-server suites) on the development machine |
| 17 (`postgres:17-alpine`) | CI test jobs; Kubernetes init/wait containers; `scripts/ci/container-boot-gate.js` (TLS, production profile) |
| 16 (`postgres:16-alpine`) | `deploy/docker/docker-compose.prod.yml` |
| 15 (`postgres:15-alpine`) | The backup/restore CI job's `dr-postgres` |

**Supported: 15–18** — the container boot gate passes on `postgres:15-alpine`, `postgres:16-alpine` and `postgres:17-alpine`; 18.6 runs the full gate set. Run the container
boot gate against your exact server version before an upgrade (`--pg-image postgres:<ver>-alpine`).

## Required environment variables

Three fixed variables plus at least one AI provider credential must be set. The server will
not start without them (the boot validator exits with one `FATAL BOOT_VALIDATION_FATAL` event listing every
violation, including "no valid AI provider is configured" — `src/infra/config/bootValidator.js`; the separate
`NO_PROVIDER_CONFIGURED` event was removed).

| Variable | Purpose | Format |
|---|---|---|
| `QODIQA_KEY_ENCRYPTION_KEY` | AES-256-GCM key for the Ed25519 signing key store | Exactly 64 hexadecimal characters |
$1| `QODIQA_EXECUTION_INVARIANT_SECRET` | HMAC key that binds the execution invariant | Exactly 64 hexadecimal characters, different from the key-encryption key |

There is no `QODIQA_SIGN_TOKEN` variable — removed the shared sign secret. `POST /sign` authenticates via `Authorization: Bearer <sk_...>`, a per-identity signing API key provisioned with `node scripts/provision-signing-identity.js ...` (see `docs/security/secrets-management.md` and `docs/guides/quickstart.md#provision-a-signing-identity`).
| One of: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL` | Enables the corresponding AI provider | Valid provider API key (placeholder or wrongly-formatted values for every keyed provider — `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY` — are fatal at startup in production; invalid `LLAMA_BASE_URL`/`LOCAL_BASE_URL` likewise — see `docs/security/secrets-management.md`) or, for `llama`/`local`, a reachable base URL |

Generate values:
```bash
# KEK (key encryption key)
openssl rand -hex 32
```
(There is no sign token to generate — see above; signing identities are provisioned with `scripts/provision-signing-identity.js`.)

---

## Full environment variable reference

### Redis

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `REDIS_URL` | No | `redis://localhost:6379` | Connection string; use `rediss://` for TLS |
| `REDIS_USERNAME` | No | — | ACL username |
| `REDIS_PASSWORD` | No | — | ACL password; minimum 16 characters |
| `REDIS_TLS` | No | `false` | Enable TLS regardless of URL scheme |
| `REDIS_TLS_CA` | No | — | Path to CA certificate for server verification |
| `REDIS_TLS_CERT` | No | — | Path to client certificate (mTLS); must be paired with `REDIS_TLS_KEY` |
| `REDIS_TLS_KEY` | No | — | Path to client private key (mTLS); must be paired with `REDIS_TLS_CERT` |
| `REDIS_TLS_REJECT_UNAUTHORIZED` | No | enabled | Set to `false` to disable cert verification; rejected in production |
| `REDIS_CONNECT_TIMEOUT_MS` | No | `5000` | Milliseconds to wait for Redis at startup |

### Replay protection

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `STRICT_REPLAY_PROTECTION` | No | `true` | Refuse startup if Redis AOF persistence is not durable; set `false` only in dev environments without durable Redis |

### Server

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `NODE_ENV` | No | — | Set to `production` to enable fatal-exit on validation failures |
| `PORT` | No | `3000` | HTTP listen port (1–65535) |
| `MAX_BODY_BYTES` | No | `65536` | Global request body size limit in bytes |
| `TRUSTED_PROXY` | No | `loopback` | Proxies whose `X-Forwarded-For` is honoured (see **Proxy trust** below). The shipped Kubernetes base trusts loopback only |
| `TRUSTED_PROXY_REAL_IP` | No | unset | `true` only if your trusted proxy sets `X-Real-IP` itself; otherwise the header is ignored |
| `SHUTDOWN_TIMEOUT_MS` | No | `30000` | Milliseconds before forced exit(1) during shutdown |
| `AI_CHAT_TIMEOUT_MS` | No | `30000` | Full `/ai/chat` pipeline timeout |
| `OPENAI_TIMEOUT_MS`, `ANTHROPIC_TIMEOUT_MS`, `GEMINI_TIMEOUT_MS`, `MISTRAL_TIMEOUT_MS`, `LLAMA_TIMEOUT_MS`, `LOCAL_TIMEOUT_MS` | No | `30000` each | Per-provider outbound API call timeout — see `docs/configuration/reference.md#5-ai-provider-keys` |
| `VERIFY_TIMEOUT_MS` | No | `5000` | `/verify/v2` policy evaluation timeout |
| `AUDIT_TIMEOUT_MS` | No | `10000` | `/audit` endpoint timeout |

### File paths

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `QODIQA_KEYS_PATH` | No | `data/keys.json` | Path to the encrypted signing key store |
| `QODIQA_AUDIT_LOG` | No | `audit.log` | Path to the hash-chained audit log |
| `POLICY_FILE` | **Yes, in production** | none in production; `policies.json` outside it | Path to the policy configuration file — see `docs/configuration/reference.md` §13. There is no safe production default: the repository-root `policies.json` is a demo fixture. Copy `deploy/env/production.policies.example` to your own path and set this variable before deploying. |

### Verification limits

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `VERIFY_MAX_ARTIFACT_BYTES` | No | `8192` | Maximum artifact header size |
| `VERIFY_MAX_REQUEST_BYTES` | No | `4096` | Maximum `/verify/v2` body size |
| `VERIFY_MAX_OBJECT_DEPTH` | No | `12` | Maximum object nesting depth |
| `VERIFY_V2_RATE_LIMIT_MAX` | No | `60` | Maximum requests per window to `/verify/v2` |
| `VERIFY_V2_RATE_LIMIT_WINDOW_MS` | No | `60000` | Rate limit window duration in milliseconds |

---

## Proxy trust

The gateway keys brute-force lockout, rate limits and the ops IP allowlist on the client address. It takes that address from `X-Forwarded-For` only when the connecting peer is listed in `TRUSTED_PROXY`.

- **Shipped default (Kubernetes base): `loopback`.** No proxy is trusted. Every request appears to come from the ingress pod's address. That is coarse (one bucket per ingress pod), but nothing can forge it.
- **To see real client addresses,** set `TRUSTED_PROXY` to your ingress controller's pod CIDR or addresses in an overlay patch you own. Make sure the proxy strips any client-supplied `X-Forwarded-*` headers.
- **Whole private ranges** (`uniquelocal`, `10.0.0.0/8`, …) are fatal in production unless `QODIQA_TRUSTED_PROXY_BROAD_ACK=true` is set. Set that acknowledgement only after verifying that your CNI enforces `networkpolicy.yaml`, so that nothing but the ingress controller can reach the gateway. It is deliberately not shipped pre-set.

## Startup validation sequence

Before accepting traffic, the server runs these validations in order. Any failure at a fatal-exit step calls `process.exit(1)`.

| Phase | Description | On failure |
|---|---|---|
| Boot validation | `src/infra/config/bootValidator.js` checks `QODIQA_KEY_ENCRYPTION_KEY`, `QODIQA_CLIENT_ID`, at least one of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL`, and the production rules (`docs/configuration/boot-rules.md`) and reports every violation in one `FATAL BOOT_VALIDATION_FATAL` event (the separate `NO_PROVIDER_CONFIGURED` event was removed) — there is no `QODIQA_SIGN_TOKEN` check | Fatal (immediate exit) |
| Env validation | All numeric, boolean, path, and URL env vars validated | Fatal in production |
| Secret validation | Detects placeholder/weak values for `QODIQA_KEY_ENCRYPTION_KEY`, `QODIQA_CLIENT_ID`, and every keyed provider credential (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`; `bootValidator.js` rule `providers`) — see `docs/security/secrets-management.md`. Per-identity signing keys are not weak-checked here — always server-generated via `crypto.randomBytes(32)`, never user-supplied | Fatal in production |
| KEK validation | `QODIQA_KEY_ENCRYPTION_KEY` must be 32-byte Buffer after hex decode | Fatal (throws) |
| Key store validation | At least one active key per client; no structural violations; no expired active keys | Fatal (throws) |
| Key expiry warning | Keys within 30 days of expiry emit `KEY_EXPIRING_SOON` | Warn only |
| Policy load | `policies.json` parsed, validated; must include at least one enabled `REQUIRE_CONSENT` policy | Fatal (throws) |
| Startup diagnostics | Clock, environment, and key store state emitted | Informational |
| Redis initialization | All three stores connect concurrently; namespace probes run | Degraded if any fail |
| Persistence check | Redis AOF state checked via nonce store client | Warn; fatal if `STRICT_REPLAY_PROTECTION=true` |
| HTTP listen | `app.listen(PORT, QODIQA_BIND_HOST || '0.0.0.0')` → `setReady(_allReady)` | — |

`setReady(_allReady)` is called after `app.listen` resolves, where `_allReady` is true only when all three Redis stores (nonce, anomaly, rate limit) initialized successfully. `/ready` returns 503 while readiness is false. The load balancer must not route traffic until `/ready` returns 200.

---

## Deployment topologies

### Single-node (the only production topology)

One QODIQA instance, one Redis instance, persistent volume on the host — plus PostgreSQL, which is mandatory whenever `NODE_ENV=production` (`EVIDENCE_DURABILITY_VIOLATION` otherwise); the diagram below omits it.

```
client → QODIQA (port 3000) → Redis (port 6379)
                ↓
        /opt/qodiqa/data/keys.json
        /opt/qodiqa/logs/audit.log
```

### Docker Compose

The production Docker Compose configuration is at `deploy/docker/docker-compose.prod.yml`. It includes:

- **Redis** (`redis:7.4.11-alpine`, digest-pinned): TLS on port 6380 (`--tls-port 6380 --port 0`), mTLS client authentication (`--tls-auth-clients yes`), AOF persistence (`--appendonly yes --appendfsync everysec`), password authentication. The Redis port is **not published to the host** — internal network only.
- **QODIQA**: `read_only: true`, `user: "1000:1000"`, `cap_drop: ALL`, `no-new-privileges: true`, `/tmp` as tmpfs. Port bound to `127.0.0.1:3000:3000` — place a TLS-terminating reverse proxy in front. `stop_grace_period: 60s` to accommodate the 30 s shutdown drain.
- **PostgreSQL** (`postgres:16.15-alpine`, digest-pinned): TLS with an operator-provided server certificate (`tls/postgres/`), port **not published to the host**. Caution: the container's bootstrap superuser is `POSTGRES_USER: "${QODIQA_PG_USER}"` — the same variable the gateway connects with — so as shipped the request-serving role is the cluster superuser (RLS and the GRANT model are not enforced against it). Until the compose file separates the two identities, do not treat this file's PostgreSQL as representative of the least-privilege role model (`docs/operations/database-role-management.md`).
- **Volumes**: `qodiqa-data` (key store), `qodiqa-logs` (audit log), `qodiqa-anchors` (anchor export + local witness log; copy `anchors.jsonl` off-host), `redis-data` (AOF), `postgres-data` — all must be backed by durable storage.
- **Network**: isolated `backend` bridge with `internal: true`.

Usage:
```bash
# 1. Copy and fill in real secret values
cp deploy/env/production.env.example .env.prod
# edit .env.prod

# 2. Generate TLS certificates (see docs/deployment/redis-tls.md)
# Place ca.crt, client.crt, client.key, server.crt, server.key in ./tls/

# 3. Start
docker compose -f deploy/docker/docker-compose.prod.yml --env-file .env.prod up -d
```

### Kubernetes

The reference manifests are in `deploy/kubernetes/`, split into a shared
Kustomize base plus two independently deployable topology overlays (see `deploy/kubernetes/kustomization.yaml`'s header comment for the
dual-topology defect this split fixes):

```
deploy/kubernetes/
  base/                  — namespace, secrets, shared ConfigMap, keystore PVC,
                           shared NetworkPolicy, backup CronJobs
  overlays/
    single-node/         — StatefulSet, per-pod exclusive audit-log volume
                           (default; docs/deployment/topology.md Topology C/D)
    distributed/         — Deployment, QODIQA_DEPLOYMENT_MODE=distributed
                           (resolves PostgreSQL enablement,
                           audit-chain ordering authority, and migration
                           verification automatically; SCAL-11's original
                           mechanism), plus the PostgreSQL egress
                           NetworkPolicy that topology requires
```

There is no top-level entry point that deploys "the app" — pick exactly one
overlay per namespace/cluster. `kubectl apply -k deploy/kubernetes/` (without
an overlay path) is intentionally not a valid Kustomization and fails fast.

**Choosing a topology**: single-node is the default and simplest option (see
docs/deployment/topology.md). Choose distributed only if you need audit-append ordering
that is consistent across an arbitrary number of freely-scaling replicas
backed by PostgreSQL —
"Decision Update" sections for the full trade-off analysis, and
`overlays/distributed/deployment.yaml`'s header comment for the PostgreSQL
migration 026 / `checkDistributedPreconditions` prerequisites. Production
deployments use the single-node overlay. `QODIQA_DEPLOYMENT_MODE=distributed`
(and the legacy `QODIQA_AUDIT_ORDERING_MODE=distributed`) is **refused at
production boot** until adds distributed checkpoints and anchors (
`src/infra/config/bootValidator.js`); the distributed overlay is
for non-production evaluation.

**Pod security context** (both overlays):
- `runAsNonRoot: true`, `runAsUser: 1000`, `runAsGroup: 1000`, `fsGroup: 1000`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `seccompProfile.type: RuntimeDefault`
- `automountServiceAccountToken: false`

**Rollout strategy:**
- single-node (StatefulSet): `replicas: 1` — a correctness bound, not a capacity setting (more than one single-node replica is refused at boot by `assertNoIllegalTopology()`), `RollingUpdate` with `maxUnavailable: 1` (no `maxSurge` equivalent for StatefulSets — a rollout is a brief full outage; no HA in this topology)
- distributed (Deployment, **non-production only — refused with `NODE_ENV=production` until**): `replicas: 3`, `RollingUpdate` with `maxUnavailable: 0` and `maxSurge: 1`

**Probes** (both overlays):
- `startupProbe`: `GET /health`, period 5 s, failureThreshold 24 (120 s maximum startup window)
- `livenessProbe`: `GET /health`, period 15 s, failureThreshold 3 (restart after 45 s)
- `readinessProbe`: `GET /ready`, period 5 s, failureThreshold 3 (removed from LB after 15 s)

**Resources** (single-node, enforced by `scripts/deploy/validate-manifests.js`):
- Requests: 1000m CPU / 2304Mi memory
- Limits: 4000m CPU / 3 Gi memory

**Graceful shutdown:**
- `terminationGracePeriodSeconds: 60` — must exceed `SHUTDOWN_TIMEOUT_MS / 1000 + 15 s`

**Persistent volumes:**
- `qodiqa-keystore` → `/opt/qodiqa/data` (key store; `base/pvc.yaml`, shared by both overlays)
- `auditlog-qodiqa-<ordinal>` → `/opt/qodiqa/logs` (audit log; single-node overlay only, one exclusive PVC per pod via `volumeClaimTemplates` — the distributed overlay has no audit-log volume at all, PostgreSQL is authoritative there)

**Secrets injection** (via `secretKeyRef`, from `base/secret.yaml`): `QODIQA_KEY_ENCRYPTION_KEY`, `OPENAI_API_KEY`, `QODIQA_CLIENT_ID`, `REDIS_PASSWORD`, plus `QODIQA_PG_PASSWORD`, in both overlays (PostgreSQL is mandatory in production). Per-identity signing keys are provisioned separately (`scripts/provision-signing-identity.js`), not injected via this Secret. The reference manifests wire up the `openai` provider only — substitute the appropriate credential (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, or `LOCAL_BASE_URL`) if deploying with a different provider.

**Network policy**: `base/networkpolicy.yaml` starts every pod in the namespace at default-deny and adds back ingress from the ingress namespace and egress to Redis/OpenAI/DNS for the gateway, plus PostgreSQL/DNS/HTTPS-only egress for the backup CronJobs. **Each overlay** additionally applies its own `networkpolicy-postgres.yaml` (`overlays/single-node/` and `overlays/distributed/`), granting the gateway egress to PostgreSQL on port 5432 — PostgreSQL is mandatory in production, so the production single-node overlay needs it too. See that file's header comment if your PostgreSQL is external/managed rather than an in-cluster Service (replace the `podSelector` with an `ipBlock` for the database CIDR, never `0.0.0.0/0`).

**Local manifest validation**: `kubectl kustomize` (bundled with Docker Desktop, `v1.36.1`/kustomize `v5.8.1`) renders `base/`, `overlays/single-node/`, and `overlays/distributed/` cleanly (18/23/22 resources respectively); the root `deploy/kubernetes/kustomization.yaml` still fails to build as intended. A structural sanity pass (required fields, known kinds, no duplicate `(kind, namespace, name)` identities, single-node has no `Deployment`, distributed has no `StatefulSet`) passed on all three. `kubeconform` itself could not be installed locally without downloading an unverified external binary (no npm/pip package exists for it) and `kubectl apply --dry-run` requires a reachable API server in this kubectl version (none available — Docker Desktop is down, see the standing blocker) — so full OpenAPI/admission-level schema validation (`kubeconform -strict` / `kubectl apply --dry-run=server`, as `.github/workflows/k8s-manifests.yml` runs against a real `kind` cluster in CI) was not reproduced locally; this is a disclosed gap, not a claimed pass. One genuine, pre-existing defect this pass DID catch and fix: `base/secret.yaml`'s (and the two `overlays/examples/*/secret.yaml` templates') placeholder values were literal `<ANGLE_BRACKET>` tokens under a `data:` field, which is not valid base64 and would fail admission — replaced with real base64 encodings of clearly-labeled `REPLACE_WITH_REAL_..._BEFORE_DEPLOY` marker strings, so the manifests are schema-valid as shipped while still failing obviously at application boot if used unedited (the "you must replace this" intent is preserved, only the YAML's own validity changed). See for the full evidence.

Deploy (pick one):
```bash
# Single-node (default)
kubectl apply -k deploy/kubernetes/overlays/single-node/
kubectl rollout status statefulset/qodiqa -n qodiqa

# Distributed (non-production evaluation only — refused with NODE_ENV=production until)
kubectl apply -k deploy/kubernetes/overlays/distributed/
kubectl rollout status deployment/qodiqa -n qodiqa
```

### Multiple instances (not supported in production)

> With `NODE_ENV=production` more than one instance is refused: single-node with
> PostgreSQL is limited to one replica (`assertNoIllegalTopology()`), and distributed mode is refused
>. The constraints below apply to non-production evaluation only.

Multiple QODIQA pods sharing a single Redis cluster. Required constraints:

1. **All pods must connect to the same Redis.** Separate Redis instances per pod break nonce deduplication — replay attacks succeed against any pod that has not seen a given request ID.
2. **Each pod must write to its own audit log path.** Two instances writing the same file produces a broken hash chain. Set `QODIQA_AUDIT_LOG` per pod.
3. **All pods must share the same `QODIQA_CLIENT_ID` and key store.** Key resolution is by client ID — mismatched IDs break artifact verification.
4. **Key rotation reaches every pod via the rotation scheduler's periodic `keys.json` reload** (`QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS`, default 300000 ms = 5 min; `services/artifact/rotationScheduler.js`) — no rolling restart is needed unless reload is disabled (`QODIQA_KEY_RELOAD_ENABLED=false`; disabling automatic *rotation* never disables reload). SIGHUP does not reload the key store (it re-reads the enforced policy set from the control plane).

---

## Deployment procedure

### Key provisioning (required before first start)

QODIQA will not start if no active signing key exists for `QODIQA_CLIENT_ID`. The server exits at startup with `KEYSTORE_EMPTY` if the key store is empty.

Provision the initial key before starting the server for the first time:

```bash
# With required env vars set (QODIQA_KEY_ENCRYPTION_KEY, QODIQA_CLIENT_ID,
# QODIQA_KEYS_PATH):
node -e "require('./services/artifact/keyManager').rotate(process.env.QODIQA_CLIENT_ID)"
```

This calls `rotateKey()`, which detects the empty store and provisions the first key (`key_v1`). Emits `KEY_CREATED` and writes the encrypted key store to `QODIQA_KEYS_PATH`. On subsequent server starts, `KEYSTORE_LOADED` and `KEY_MANAGER_READY` are emitted to confirm the key store loaded successfully.

### First-time deployment

1. Generate required secrets:
   ```bash
   openssl rand -hex 32   # KEK
   ```
   (No sign token — removed by ; provision signing identities with `scripts/provision-signing-identity.js`.)
2. Provision a Redis instance with AOF persistence (`appendonly yes`, `appendfsync everysec`).
3. Create the key store directory with correct permissions:
   ```bash
   install -d -m 700 -o qodiqa /opt/qodiqa/data
   ```
4. Provision the initial Ed25519 key pair (see **Key provisioning** above). Confirm `KEY_CREATED` is emitted and `QODIQA_KEYS_PATH` is written.
4a. **PostgreSQL schema** — provision PostgreSQL 15–18 and run the migration runner (production does not migrate at
    startup): `QODIQA_PG_MIG_USER=qodiqa_test node src/infra/postgres/migrate.js` (a CREATEROLE identity is required
    for the role migrations 002/018/038/060/065/067); confirm `node src/infra/postgres/migrate.js --status` shows all
    migrations of the chain applied. Production refuses to boot without PostgreSQL
    (`EVIDENCE_DURABILITY_VIOLATION`).
4b. **Role credentials** — rotate every migration-created role (`node scripts/db/role-credentials.js --rotate <role>
    --password-env <VAR> --confirm`, or `--harden-unused --confirm` for roles the deployment does not use) and confirm
    `node scripts/db/role-credentials.js --check` exits 0; production refuses to boot while any role accepts its
    published placeholder (`PG_ROLE_PLACEHOLDER_CREDENTIAL`, `docs/operations/database-role-management.md`).
4c. **Witness and anchor export** — provision the witness and `QODIQA_ANCHOR_EXPORT_PATH`
    (`docs/security/audit-anchoring.md`); production refuses to boot without them (`bootValidator.js` rule
    `audit.anchoring`).
4d. **Backup keys** — provide distinct `backup-encryption-key` and `backup-hmac-key` secrets.
5. Import the initial policy set into the control plane (it must include at least one enabled `REQUIRE_CONSENT`
   policy); `policies.json` / `POLICY_FILE` is import-only (`docs/operations/control-plane.md`).

6. Start the server. Confirm `KEYSTORE_LOADED` and `KEY_MANAGER_READY` in logs, then `GATEWAY_START`.
7. Verify readiness: `curl http://localhost:3000/ready` — expect `{"ready":true,...}`.
8. Test the enforcement pipeline: a request without an artifact must return `{"decision":"BLOCK","reason":"MISSING_ARTIFACT"}` — HTTP `200` in the default `QODIQA_BLOCK_HTTP_MODE=decision`, HTTP `400` with `QODIQA_BLOCK_HTTP_MODE=status` (`src/api/blockHttpStatus.js`).

### Rolling update (Kubernetes)

```bash
# Distributed overlay (Deployment, NON-PRODUCTION — refused at production boot until) — maxUnavailable: 0
kubectl set image deployment/qodiqa qodiqa=YOUR_REGISTRY/qodiqa:NEW_VERSION -n qodiqa
kubectl rollout status deployment/qodiqa -n qodiqa

# Single-node overlay (StatefulSet) — replicas: 1, so the rollout is a brief full outage
kubectl set image statefulset/qodiqa qodiqa=YOUR_REGISTRY/qodiqa:NEW_VERSION -n qodiqa
kubectl rollout status statefulset/qodiqa -n qodiqa
```

### Policy update (no restart required)

Change policy through the policy API (governance workflow — see `docs/guides/policy-governance.md` §14). The enforced set lives in the control plane (PostgreSQL in production; `src/core/policy/store.js`) and a published change is enforced on every replica within the control plane's pull bound. `POLICY_FILE` / `policies.json` is **import-only** since it is read only to seed an empty store, so editing the ConfigMap's `policies.json` and sending SIGHUP changes nothing. SIGHUP only re-reads the enforced set from the control plane (`server/startup.js`, `POLICIES_RELOADED` with `source: control-plane`); a failure emits `POLICY_RELOAD_FAILED` and keeps the previous set.

### Key rotation (no restart required)

See `docs/security/key-management.md` and `docs/security/secrets-management.md` for the full key rotation procedure. Every instance re-reads `keys.json` on the rotation scheduler's reload cadence (`QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS`, default 5 min); a rolling restart is only needed when reload is disabled (`QODIQA_KEY_RELOAD_ENABLED=false`). SIGHUP does not reload the key store.

---

## Provider model allowlist policy

The `local` and `llama` provider adapters accept **any non-empty model name** —
there is no allowlist for either, deliberately (see `docs/guides/providers.md`'s
"Model allowlist" row for both providers). This is a approved decision, not
an oversight: deployment-specific model names (e.g. a fine-tuned model tag,
an internal Ollama alias) cannot be predicted or enumerated in advance, so a
static allowlist would either be perpetually out of date or would need to be
kept open anyway. Operators who need to restrict which models a tenant can
invoke must do so at the **policy layer** (`policies.json` / the policy
engine), not via provider configuration — `PROVIDER_ALLOWED_MODELS_EXTRA_LOCAL`
/ `_LLAMA` are documented no-ops for this reason. The only shape check
applied to any model name is a length cap
(`src/validation/schemas/aiChat.schema.js`'s `MAX_MODEL_LENGTH`), unchanged
by this decision. `openai`/`anthropic`/`mistral`/`gemini` are unaffected —
their model allowlists are unrelated and remain as documented in
`docs/guides/providers.md`.

---

## Production validation checklist

Run after every deployment:

- [ ] `GET /ready` returns `{"ready":true,"components":{"nonceStore":true,"anomalyStore":true,"rateLimitStore":true}}`
- [ ] `GET /health` returns `{"status":"ok","uptime":<seconds>}`
- [ ] `GET /public-key` returns a valid base64 public key
- [ ] `GET /.well-known/qodiqa/keys` returns a list of public keys
- [ ] `POST /ai/chat` without artifact returns `{"decision":"BLOCK","reason":"MISSING_ARTIFACT"}` (HTTP 200 in the default `decision` mode; 400 with `QODIQA_BLOCK_HTTP_MODE=status`)
- [ ] Logs show `GATEWAY_START` with `executionIntegrity: "FULL"`
- [ ] Logs show `SECRET_VALIDATION_OK` and `ENV_VALIDATION_OK`
- [ ] Logs show `REDIS_PERSISTENCE_VALIDATED` (if `STRICT_REPLAY_PROTECTION=true`)
- [ ] `GET /metrics` returns Prometheus metrics including `qodiqa_execution_integrity_full{} 1`
- [ ] Audit log path exists and is writable by the QODIQA process user
- [ ] Key store path exists, is writable, and has correct permissions (mode 600, directory mode 700)

---

## Filesystem permissions

| Path | Mode | Purpose |
|---|---|---|
| `QODIQA_KEYS_PATH` directory | `700` | Key store parent directory |
| `QODIQA_KEYS_PATH` file | `600` | Encrypted Ed25519 key pairs |
| `QODIQA_AUDIT_LOG` directory | `700` | Audit log parent directory |
| `QODIQA_AUDIT_LOG` file | `600` | Hash-chained audit log |
| `REDIS_TLS_KEY` | `400` | Redis client private key |
| `REDIS_TLS_CA`, `REDIS_TLS_CERT` | `440` | Redis TLS certificates |

All paths must be owned by the QODIQA process user (UID 1000 in the reference Kubernetes manifest).
