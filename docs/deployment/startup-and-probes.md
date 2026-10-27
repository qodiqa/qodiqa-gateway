# Startup Sequence and Health Probes

This document describes QODIQA's startup sequence, dependency requirements,
health and readiness probe contracts, and graceful shutdown behavior.  Use it
to configure container orchestration probes, load balancer health checks, and
deployment readiness gates.

---

## Startup sequence

QODIQA performs a deterministic, ordered startup sequence before accepting
any enforcement traffic.  The sequence has eight phases.

### Environment, provider, and secret validation

Runs before any I/O, in this order (`server.js`):

1. `dotenv` loads `.env` if present (development only; production uses injected env vars).
2. `checkSingleInstance()` guards against multiple concurrent instances writing the audit chain; exits with code 1 if a second instance/cluster worker is detected.
3. `hasAnyProvider()` (`services/providers/config.js`) checks that at least one AI provider is enabled — i.e. at least one of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL` is set. If none are set, emits `NO_PROVIDER_CONFIGURED` at FATAL and exits with code 1. On success, emits `PROVIDERS_CONFIGURED` at INFO with the list of enabled provider names.
4. Required secrets are checked for presence, one at a time: `QODIQA_KEY_ENCRYPTION_KEY`, `QODIQA_CLIENT_ID`. Any missing variable emits its own `FATAL` event (`KEY_ENCRYPTION_KEY_NOT_CONFIGURED`, `CLIENT_ID_NOT_CONFIGURED`) and exits with code 1. There is no presence check for `QODIQA_EXECUTION_INVARIANT_SECRET` or for a signing identity — both are required in practice but neither gates startup; see "Dependency requirements" below.
5. `runEnvValidation()` validates all optional numeric, boolean, and URL env vars.
   Emits `ENV_VALIDATION_OK` or `ENV_VALIDATION_FATAL`.
6. `runSecretValidation()` checks for placeholder or weak secret values when set (`QODIQA_KEY_ENCRYPTION_KEY`, `QODIQA_EXECUTION_INVARIANT_SECRET`, `QODIQA_CLIENT_ID`, `QODIQA_OPS_TOKEN`, and — OpenAI-specific only — `OPENAI_API_KEY`; see `docs/security/secrets-management.md`).
   Emits `SECRET_VALIDATION_OK` or `SECRET_VALIDATION_FATAL`.

**Expected log events:**
```
PROVIDERS_CONFIGURED
ENV_VALIDATION_OK
SECRET_VALIDATION_OK
```

**Failure behavior:** `process.exit(1)` — container restarts.

### Key manager validation

5. `keyManager.validateStartup()` loads and decrypts the key store using the KEK.
   Validates that at least one active signing key exists.
   Emits `KEY_MANAGER_READY`.

**Expected log events:**
```
KEY_MANAGER_READY  { activeKeys: N, encryptionAlgorithm: "aes-256-gcm" }
```

**Failure behavior:** `process.exit(1)` — container restarts.

### Policy loading

6. `loadPolicies()` reads and validates the policy file. In production
   (`NODE_ENV=production`), `POLICY_FILE` must be set explicitly —
   see `docs/configuration/reference.md` §13 — startup fails closed with
   `FATAL POLICY_FILE_REQUIRED` otherwise. Outside production, `POLICY_FILE`
   defaults to the repository's own `policies.json` (a demo/dev fixture),
   unchanged developer convenience. Emits `POLICIES_LOADED`.

**Expected log events:**
```
POLICIES_LOADED  { count: N, ids: [...] }
```

**Failure behavior:** `process.exit(1)` — container restarts.

### Express app initialization

7. Express app is constructed.  Routes, middleware, and probe endpoints are registered.
   The app is ready to bind but not yet listening.

No log events at this phase.  If a route module throws at require time, the
process exits with an uncaught exception.

### Startup diagnostics

8. `emitStartupDiagnostics()` emits `STARTUP_DIAGNOSTICS` — a snapshot of the
   environment at launch time (Node version, Redis URL redacted, probe states).
9. `emitClockDiagnostics()` emits `CLOCK_DIAGNOSTICS` — system clock state.

**Expected log events:**
```
STARTUP_DIAGNOSTICS
CLOCK_DIAGNOSTICS
```

### Redis security summary

10. Redis TLS and auth configuration is read from env vars and summarized.
    Emits `REDIS_AUTH_CONFIGURED` or `REDIS_AUTH_MISSING`.
    Emits `REDIS_TLS_ENABLED` or `REDIS_TLS_DISABLED`.

**Expected log events (production):**
```
REDIS_AUTH_CONFIGURED
REDIS_TLS_ENABLED  { tlsVerified: true }
```

### Redis store initialization

11. All three Redis stores initialize concurrently (`Promise.allSettled`):
    - Nonce store (replay protection)
    - Anomaly store (burst detection)
    - Rate limit store (policy enforcement)

Each store connects, runs a PING, writes a probe key, reads it back, and deletes
it.  A successful probe emits `*_STORE_READY`.

12. Redis persistence diagnostics run against the live nonce store connection.
    Emits `REDIS_PERSISTENCE_STATUS`.

13. If `STRICT_REPLAY_PROTECTION` is `true` (the default) and persistence is
    unsafe, emits `STRICT_REPLAY_PROTECTION_VIOLATION` and exits with code 1.
    This step only skips the fatal exit if `STRICT_REPLAY_PROTECTION` has been
    explicitly set to `false`.

**Expected log events (all stores healthy):**
```
NONCE_STORE_READY
ANOMALY_STORE_READY       (emitted by anomalyStore)
RATE_LIMIT_STORE_READY    (emitted by rateLimitStore)
REDIS_PERSISTENCE_VALIDATED
REDIS_AUTH_VALIDATED
GATEWAY_RUNTIME_READY     { executionIntegrity: "FULL" }
GATEWAY_STATE_READY
```

**Failure behavior:** stores that fail initialization emit `REDIS_STARTUP_FAILED`.

- **Nonce store (replay protection):** under the default configuration
  (`STRICT_REPLAY_PROTECTION` unset, or anything other than the literal string
  `false`), a failed or unsafe nonce store is fatal — `STRICT_REPLAY_PROTECTION_VIOLATION`
  is emitted and the process calls `process.exit(1)`. The server does **not**
  start in this case. Only when an operator has explicitly set
  `STRICT_REPLAY_PROTECTION=false` does the server continue with the nonce
  store degraded (`executionIntegrity: "DEGRADED"`), blocking all
  replay-guarded execution requests fail-closed until it reconnects.
- **Anomaly store / rate-limit store:** a failure in either of these stores
  alone does not gate startup — the server starts with `executionIntegrity`
  `DEGRADED` and blocks the corresponding execution requests fail-closed
  until the store reconnects, regardless of `STRICT_REPLAY_PROTECTION`.

### HTTP server bind

14. `app.listen(PORT, '0.0.0.0')` binds the HTTP server.
15. Readiness state is set to `true` (or `false` if any store is not ready).
16. `GATEWAY_START` is emitted.
17. Graceful shutdown handlers are registered for `SIGTERM` and `SIGINT`.

**Expected log events:**
```
GATEWAY_START  { port: 3000, executionIntegrity: "FULL", ready: true }
```

**The service is ready to receive traffic only after `GATEWAY_START` is emitted
with `ready: true`.**

---

## Dependency requirements

| Dependency | Required for startup | Fail behavior |
|---|---|---|
| `QODIQA_KEY_ENCRYPTION_KEY` | Yes | `process.exit(1)` |
| At least one of: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL` | Yes (any one) | `process.exit(1)` (`NO_PROVIDER_CONFIGURED`) |
| `QODIQA_CLIENT_ID` | Yes | `process.exit(1)` |
| `data/keys.json` with ≥ 1 active key | Yes | `process.exit(1)` |
| Policy file | Yes | `process.exit(1)` (`POLICY_FILE_REQUIRED` in production if unset; `POLICY_LOAD_FAILED` if the resolved file is missing/invalid) |
| Redis nonce store + AOF persistence | Yes, by default (`STRICT_REPLAY_PROTECTION` defaults to `true`) | `process.exit(1)` (`STRICT_REPLAY_PROTECTION_VIOLATION`) unless `STRICT_REPLAY_PROTECTION=false` is explicitly set |
| Redis anomaly store, rate-limit store | No (degrades enforcement) | Starts in DEGRADED mode; execution requiring that store is blocked |
| `QODIQA_EXECUTION_INVARIANT_SECRET` | No (not startup-gated) | Server starts; `/ai/chat` EXECUTE throws the first time it's reached without it |
| A provisioned signing identity | No (not startup-gated) | Server starts; `POST /sign` returns `401 UNAUTHORIZED` for every caller until one is provisioned — there is no `QODIQA_SIGN_TOKEN` shared secret |

**By default, QODIQA will not start without a reachable, durably-persisted
Redis nonce store.** `STRICT_REPLAY_PROTECTION` is secure by default (`true`
unless the env var is set to the literal string `false`), so a missing or
unsafe nonce store is a hard startup dependency, not a soft one. Only when an
operator explicitly sets `STRICT_REPLAY_PROTECTION=false` does Redis become a
soft dependency for startup (the server starts and blocks affected requests
fail-closed at request time instead). The anomaly and rate-limit stores are
always a soft startup dependency — their failure degrades enforcement without
blocking startup.

---

## Health probe — `/health`

**Purpose:** Liveness.  Answers "is the process alive?"

**Method:** `GET /health`

**Authentication:** None by default — required for Kubernetes/Docker/ECS probe
compatibility. Rate-limited per client IP as defense in depth. Optionally
hardenable via `QODIQA_HEALTH_PROBE_AUTH_REQUIRED` / `QODIQA_HEALTH_REQUIRE_LOOPBACK`
— see `docs/deployment/kubernetes-probes.md` ("Security model") for the full rationale
and configuration.

**Response (always 200 while the process runs):**
```json
{
  "status": "ok",
  "uptime": 42.7
}
```

| Field | Type | Description |
|---|---|---|
| `status` | `"ok"` | Always `"ok"` |
| `uptime` | `number` | Process uptime in seconds (`process.uptime()`) |

**Behavior:**
- Mounted before the request drain middleware — always responds even during shutdown.
- Always returns HTTP 200 while the Node.js process is alive.
- Does NOT check Redis, key store, or any subsystem state.
- A failed `/health` means the process is dead or deadlocked.

**Use as:** Kubernetes `livenessProbe`, Docker `HEALTHCHECK`, ECS `healthCheck`.

---

## Readiness probe — `/ready`

**Purpose:** Readiness.  Answers "is it safe to send enforcement traffic here?"

**Method:** `GET /ready`

**Authentication:** None by default — required for Kubernetes/Docker/ECS probe
compatibility. Same rate limiting and optional hardening as `/health` — see
`docs/deployment/kubernetes-probes.md` ("Security model").

**Response (service ready — HTTP 200):**
```json
{
  "ready": true,
  "components": {
    "nonceStore":        true,
    "anomalyStore":      true,
    "rateLimitStore":    true,
    "persistenceStore":  true,
    "consentSubscriber": true
  }
}
```

**Response (service not ready — HTTP 503):**
```json
{
  "ready": false,
  "components": {
    "nonceStore":        false,
    "anomalyStore":      true,
    "rateLimitStore":    true,
    "persistenceStore":  true,
    "consentSubscriber": true
  }
}
```

| Field | Type | Description |
|---|---|---|
| `ready` | `boolean` | Overall readiness state |
| `components.nonceStore` | `boolean` | Nonce store (replay protection) connected |
| `components.anomalyStore` | `boolean` | Anomaly store connected |
| `components.rateLimitStore` | `boolean` | Rate limit store connected |
| `components.persistenceStore` | `boolean` | PostgreSQL connectivity — reported generically (see "Security model" in `docs/deployment/kubernetes-probes.md`). Always `true` when `QODIQA_PG_ENABLED` is not set — PostgreSQL is only a mandatory dependency when the deployment actually uses it (READY-50). |
| `components.consentSubscriber` | `boolean` | Consent revocation subscriber connected and subscribed. Always a mandatory dependency — a pod that cannot receive revocation events cannot guarantee consent withdrawal is enforced (READY-50). |

**Behavior:**
- Returns HTTP 200 only when `readinessState` is `true` AND every component above is healthy.
- Returns HTTP 503 during startup (before Redis, PostgreSQL where enabled, and the
  consent subscriber are all confirmed), during shutdown, when any Redis store is
  disconnected, when PostgreSQL is enabled but unreachable, or when the consent
  revocation subscriber is disconnected.
- `persistenceStore` and `consentSubscriber` are refreshed reactively / via a bounded
  background probe (never an inline query from the request path — see
  `docs/deployment/kubernetes-probes.md`'s "PostgreSQL readiness (READY-50)" section), so GET
  /ready itself remains O(1) and safe under high probe frequency.
- Mounted before request drain — remains responsive throughout the shutdown sequence so the load balancer can remove the pod promptly.

**Use as:** Kubernetes `readinessProbe`, load balancer health check.

**Do NOT use as a liveness probe** — a degraded dependency will cause the
readiness probe to return 503 but the process is still alive and will recover
when the dependency reconnects (Redis, PostgreSQL, or the consent revocation
subscriber). Using `/ready` as a liveness probe would cause spurious pod
restarts during transient failures that are recoverable without a restart.

---

## Diagnostics endpoint — `/diagnostics`

**Purpose:** Operational visibility.  Not for orchestration probes.

**Method:** `GET /diagnostics`

**Response (always HTTP 200):**
```json
{
  "service":            "qodiqa",
  "version":            "1.0.0",
  "status":             "ready",
  "executionIntegrity": "FULL",
  "uptime":             42.7,
  "pid":                1,
  "nodeVersion":        "v22.0.0",
  "components": {
    "nonceStore":        { "name": "Nonce Store (Replay Protection)",      "ready": true },
    "anomalyStore":      { "name": "Anomaly Store (Burst Detection)",       "ready": true },
    "rateLimitStore":    { "name": "Rate Limit Store (Policy Enforcement)", "ready": true },
    "postgres":          { "name": "PostgreSQL (Persistence)",             "ready": true, "enabled": true },
    "consentSubscriber": { "name": "Consent Revocation Subscriber",        "ready": true }
  },
  "timestamp": "2025-01-01T00:00:00.000Z"
}
```

**Use for:** Operator dashboards, runbook diagnostics, post-incident investigation.
Do not expose `/diagnostics` to the public internet — restrict to internal networks.

---

## Probe configuration recommendations

### Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 10    # Allow startup phases 0–3 to complete
  periodSeconds:       15
  timeoutSeconds:      5
  failureThreshold:    3     # Kill after 3 consecutive failures (~45s)

readinessProbe:
  httpGet:
    path: /ready
    port: 3000
  initialDelaySeconds: 5
  periodSeconds:       5
  timeoutSeconds:      3
  failureThreshold:    3     # Remove from LB after 3 failures (~15s)
  successThreshold:    1

startupProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 0
  periodSeconds:       5
  failureThreshold:    24    # Allow up to 120s for startup (5s × 24)
  timeoutSeconds:      5
```

The `startupProbe` blocks liveness/readiness probes from running until the
process is alive.  This prevents false-positive liveness failures during the
Redis store initialization phase.

### terminationGracePeriodSeconds

```yaml
terminationGracePeriodSeconds: 60
```

Set to at least `SHUTDOWN_TIMEOUT_MS / 1000 + 15` seconds.  With the default
`SHUTDOWN_TIMEOUT_MS=30000`, set `terminationGracePeriodSeconds` to at least 45.
60 seconds is recommended to allow in-flight AI provider requests to complete.

When Kubernetes sends `SIGTERM`:
1. The pod is removed from the Service endpoints (stops receiving new traffic).
2. QODIQA receives `SIGTERM` and begins the ordered shutdown sequence.
3. In-flight requests drain before Redis connections are closed.
4. The process exits with code 0.

---

## Graceful shutdown sequence

On receiving `SIGTERM` or `SIGINT`:

```
SIGTERM / SIGINT received
│
├─ [1] Readiness state → false    (SHUTDOWN_READY_FALSE)
│        /ready returns 503 immediately
│        Load balancer stops routing new requests
│
├─ [2] HTTP server closes          (SHUTDOWN_HTTP_CLOSE_STARTED → SHUTDOWN_HTTP_CLOSED)
│        No new TCP connections accepted
│        Keep-alive connections: new requests receive 503 from drain middleware
│
├─ [3] In-flight requests drain    (SHUTDOWN_DRAIN_STARTED → SHUTDOWN_DRAIN_COMPLETE)
│        Waits for all active requests to complete
│        Force-exit timer running (SHUTDOWN_TIMEOUT_MS)
│
├─ [4] Redis stores disconnect     (REDIS_SHUTDOWN_STARTED → REDIS_SHUTDOWN_COMPLETED)
│        Each store disconnects cleanly
│        Failures are logged but do not abort shutdown
│
├─ [5] Audit writes drained        (SHUTDOWN_AUDIT_FLUSH_STARTED → SHUTDOWN_AUDIT_FLUSH_COMPLETE)
│        Audit log serializes appends through an async FIFO queue; shutdown
│        awaits drainPendingWrites() so no in-flight write is lost
│
└─ [6] Clean exit                  (SHUTDOWN_COMPLETE)
         process.exit(0)
```

**Force exit:** If shutdown takes longer than `SHUTDOWN_TIMEOUT_MS` (default 30s),
a `SHUTDOWN_TIMEOUT` event is emitted and `process.exit(1)` is called.

**Audit safety:** Every audit log write calls `fsyncSync` before returning.
No audit entries can be lost during graceful shutdown.

---

## Restart behavior

| Condition | Exit code | Expected orchestrator action |
|---|---|---|
| Missing required secret | 1 | Restart with back-off — likely a configuration error |
| Invalid env var in production | 1 | Restart with back-off — fix configuration |
| Key store empty or corrupt | 1 | Restart with back-off — requires operator intervention |
| Policy file invalid | 1 | Restart with back-off — fix `policies.json` |
| Nonce store unavailable or Redis persistence unsafe (default config) | 1 | Restart with back-off — fix Redis/AOF; do not set `STRICT_REPLAY_PROTECTION=false` to work around this in production |
| Nonce store unavailable, with `STRICT_REPLAY_PROTECTION=false` explicitly set | 0 (starts degraded) | No restart — traffic blocked fail-closed; recovers on reconnect |
| Anomaly store or rate-limit store unavailable at startup | 0 (starts degraded) | No restart — traffic requiring that store blocked fail-closed; recovers on reconnect |
| SIGTERM (graceful) | 0 | Normal pod termination — no restart |
| SIGKILL or OOM | non-zero | Restart — investigate OOM budget |
| Unhandled exception | non-zero | Restart — investigate logs |

Use `restartPolicy: Always` for deployment pods.  Configure a back-off limit
to prevent rapid crash loops consuming secrets quota or causing Redis connection
storms.

---

## Startup ordering in Kubernetes

QODIQA depends on Redis being reachable before requests are served. Redis
availability is validated during startup. **Under the default
configuration (`STRICT_REPLAY_PROTECTION` unset or anything but `false`), an
unreachable or durability-unsafe nonce store blocks startup outright** —
`process.exit(1)` — rather than letting the pod come up degraded. Only the
anomaly and rate-limit stores are a soft startup dependency in the default
configuration.

**Option 1 (recommended): Use init containers**

```yaml
initContainers:
  - name: wait-for-redis
    image: redis:7-alpine
    command:
      - sh
      - -c
      - |
        until redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" \
          --no-auth-warning -a "$REDIS_PASSWORD" ping 2>/dev/null | grep -q PONG; do
          echo "waiting for Redis..."
          sleep 2
        done
        echo "Redis is ready"
    env:
      - name: REDIS_HOST
        value: redis-service
      - name: REDIS_PORT
        value: "6380"
      - name: REDIS_PASSWORD
        valueFrom:
          secretKeyRef:
            name: qodiqa-secrets
            key: redis-password
```

**Option 2: Explicitly disable strict replay protection and rely on degraded-start behavior**

This option only applies if you explicitly set `STRICT_REPLAY_PROTECTION=false`
in the pod's environment — it is **not** the default and is not recommended
for production, since it weakens replay-protection guarantees. With
`STRICT_REPLAY_PROTECTION=false` set, QODIQA starts even if Redis is
unreachable (in DEGRADED mode) and blocks execution requests until stores
reconnect. Readiness probe returns 503 until all stores are ready, preventing
the load balancer from routing traffic prematurely.

This option requires no init container but means the pod appears in a not-ready
state until Redis is reachable. This is safe — no enforcement traffic reaches a
degraded pod. **Without `STRICT_REPLAY_PROTECTION=false` explicitly set**, an
unreachable Redis nonce store at startup causes the pod to exit and
`CrashLoopBackOff` instead — use Option 1 (init container) to avoid that in
any deployment relying on the default, secure configuration.
