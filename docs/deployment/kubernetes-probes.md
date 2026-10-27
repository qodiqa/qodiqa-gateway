# Kubernetes Probes for QODIQA

QODIQA exposes two HTTP endpoints for Kubernetes probe integration. They serve
distinct purposes and must not be substituted for each other.

---

## Audit chain ordering mode — required for any `replicas` setting

QODIQA's audit chain requires exactly one process to be the writer unless
`QODIQA_AUDIT_ORDERING_MODE=distributed` is set. A Kubernetes pod has no
built-in way to learn its own replica count, so **QODIQA now refuses to start
in the default (single-node) mode when it detects it is running inside
Kubernetes** (`KUBERNETES_SERVICE_HOST` is set), unless you explicitly
acknowledge a single-replica deployment.

> ** Corrected.** This section previously told every Deployment/StatefulSet,
> including `replicas: 1`, to set `QODIQA_DEPLOYMENT_MODE=distributed`. Production refuses distributed mode
>.

For the supported production topology (the `single-node` overlay, StatefulSet `replicas: 1`), set
`QODIQA_K8S_SINGLE_REPLICA=true`, as `deploy/kubernetes/overlays/single-node/statefulset.yaml` does:

```yaml
env:
  - name: QODIQA_K8S_SINGLE_REPLICA
    value: "true"
  # ...plus QODIQA_PG_* connection settings (PostgreSQL is mandatory in production)
```

**Do not set `QODIQA_DEPLOYMENT_MODE=distributed` in production:** the boot validator refuses it until adds
distributed checkpoints and anchors. Distributed mode is for
non-production evaluation only. The rest of this subsection describes that non-production mode.

`QODIQA_DEPLOYMENT_MODE=distributed` is the single authoritative
switch — it resolves PostgreSQL enablement, distributed ordering, migration
verification, and multi-instance safety automatically. No other deployment
variable is required alongside it. See
`src/infra/config/deploymentMode.js` and
.

<details>
<summary>Legacy configuration (still supported, superseded by <code>QODIQA_DEPLOYMENT_MODE</code>)</summary>

```yaml
env:
  - name: QODIQA_AUDIT_ORDERING_MODE
    value: distributed
  - name: QODIQA_PG_ENABLED
    value: "true"
  # ...plus QODIQA_PG_* connection settings
```

`QODIQA_DEPLOYMENT_MODE`, when set, takes precedence over these two
variables — they remain fully functional only when it is left unset.

</details>

PostgreSQL then becomes the shared ordering authority (every append serializes
on a single locked row — see `src/core/audit/distributedOrdering.js` and
), which is correct for any replica
count and requires no pod identity, hostname, or startup-order assumptions.

**Primary (production) path:** a deployment that runs exactly one replica keeps single-node audit storage (the
file chain plus the PostgreSQL mirror, which production requires) and sets `QODIQA_K8S_SINGLE_REPLICA=true` to
acknowledge the single replica — this is what the shipped `single-node` overlay does. Do **not** set this on a
Deployment/StatefulSet with `replicas` > 1 — concurrent pods would append to the audit chain with no shared ordering
authority, corrupting it (and single-node with PostgreSQL refuses more than one replica at boot).

Non-Kubernetes deployments (bare metal, Docker Compose, a single VM) are
unaffected by this check and require no configuration change.

### Replica count and the illegal-topology assertion

If a single-node deployment *also* opts into the optional PostgreSQL
dual-write mirror (`QODIQA_PG_ENABLED=true`) while running more than one
replica, startup now refuses unconditionally
(`AUDIT_CHAIN_ILLEGAL_TOPOLOGY` — see
`src/core/audit/multiInstanceGuard.js`'s `assertNoIllegalTopology()`): each
replica would independently dual-write to the shared PostgreSQL
`audit_chain` table with no shared ordering lock. Set
`QODIQA_REPLICA_COUNT` to your manifest's actual `spec.replicas` value so
this check has accurate data (defaults to `1` — the same
operator-acknowledgment pattern as `QODIQA_K8S_SINGLE_REPLICA` above, and
implied by it when set). This does not fire for the common multi-replica,
no-PG-mirror topology, which is safe by construction.

### Automatic migration

Distributed mode verifies migration 026 (`audit_chain_head`) is applied
before starting, and fails closed with a remediation diagnostic if it is
not. Set `QODIQA_PG_AUTO_MIGRATE=true` to have a missing migration applied
automatically at startup instead (this flag is consulted only in
distributed mode — a single-node boot never migrates, so run
`node src/infra/postgres/migrate.js` there) — but avoid it on a multi-replica overlay where
concurrent pods would each race to apply migrations; apply migration 026 as
an explicit one-time step there instead (see
`deploy/kubernetes/overlays/distributed/kustomization.yaml`).

---

## Endpoints

### `GET /health` — Liveness

Answers: **"Is the QODIQA process alive?"**

- Returns `HTTP 200 { "status": "ok" }` for the entire lifetime of the process.
- No dependency checks — never touches Redis, keys, policies, or external systems.
- Constant O(1) response time.
- Responds during shutdown (mounted before `requestDrain.middleware`).
- If this endpoint stops responding, the process is hung or dead.

### `GET /ready` — Readiness

Answers: **"Is it safe to send enforcement traffic here?"**

- Returns `HTTP 200 { "ready": true }` when the gateway is fully operational.
- Returns `HTTP 503 { "ready": false }` in all other states:
  - During startup (before Redis stores, PostgreSQL, and the consent
    revocation subscriber are all confirmed).
  - When one or more Redis stores failed to initialize or later disconnect.
  - When PostgreSQL is enabled for this deployment (`QODIQA_PG_ENABLED=true`)
    and is unreachable — see **PostgreSQL readiness (READY-50)** below.
  - When the consent revocation subscriber is disconnected — a pod that
    cannot receive revocation events cannot guarantee consent withdrawal is
    enforced, so it must not receive traffic. See **Consent revocation
    subscriber readiness (READY-50)** below.
  - Immediately when shutdown begins (before drain or TCP close).
- Mounted before `requestDrain.middleware` so /ready itself is never drained.

#### PostgreSQL readiness (READY-50)

Reported under the generic `components.persistenceStore` key (see "Security
model" below for why the response never names the backing technology
directly).

- **Only a mandatory dependency when this deployment actually uses
  PostgreSQL** (`QODIQA_PG_ENABLED=true`) — e.g. `QODIQA_AUDIT_ORDERING_MODE=distributed`,
  or any single-node deployment opting into the PostgreSQL mirror/read
  surfaces (compliance reports, transparency log, attestation API, etc.).
  When PostgreSQL is not enabled, `persistenceStore` always reports healthy —
  there is no dependency to gate on.
- Health is refreshed by a **bounded background probe**
  (`src/infra/postgres/pool.js`), not by a query issued inline from GET
  /ready — the readiness handler only ever reads a cached boolean, so probe
  frequency has zero effect on database load. Cadence and per-probe timeout
  are configurable: `QODIQA_PG_READY_CHECK_INTERVAL_MS` (default 5000),
  `QODIQA_PG_READY_TIMEOUT_MS` (default 2000). A stalled connection is
  bounded by the timeout and marks the pool not-ready without blocking the
  monitor loop.

#### Consent revocation subscriber readiness (READY-50)

Reported under `components.consentSubscriber`. Always a mandatory,
unconditional dependency — see `src/core/consent/revocation/RevocationSubscriber.js`.
`isReady()` is maintained reactively by the subscriber's own Redis client
event handlers (connect/ready/error/reconnecting), so this check is also
zero-I/O from GET /ready's perspective. The node must already have this
subscriber connected before it is allowed to start accepting traffic at all
— `consentSubscriber.start()` is awaited during startup and treated as fatal
(`process.exit(1)`) if it cannot connect; this readiness check covers the
runtime case where a previously-healthy subscriber later disconnects.

---

## Security model

`/health` and `/ready` are **unauthenticated by default**, unlike every other
operational endpoint (`/metrics`, `/diagnostics`, `/audit`, `/rbac`, etc.),
which require the `QODIQA_OPS_TOKEN` bearer credential or a per-user RBAC key.

This is deliberate, not an oversight: Kubernetes `httpGet` probes and Docker's
`HEALTHCHECK` have no mechanism to attach a rotating bearer token to their
requests. Mounting these two endpoints behind the same authentication gate as
`/metrics`/`/diagnostics` causes every probe to fail with `401`, which
prevents the pod from ever passing `startupProbe` — it is killed and
restarted in a loop, or is permanently excluded from Service endpoints.

**Why this is safe:** `/health` and `/ready` are contractually restricted to
minimal, non-sensitive output —

```json
// GET /health
{ "status": "ok", "uptime": 42.7 }

// GET /ready
{
  "ready": true,
  "components": {
    "nonceStore":         true,
    "anomalyStore":       true,
    "rateLimitStore":     true,
    "persistenceStore":   true,
    "consentSubscriber":  true
  }
}
```

Neither response ever includes a version number, process ID, Node.js
version, stack trace, configuration value, environment variable, provider
identity, or cryptographic material — that level of detail is exclusively
available from `/diagnostics`, which remains fully authenticated,
IP-allowlisted, and gated behind the diagnostics kill-switch, unchanged by
this design. This is also why the PostgreSQL dependency added by READY-50 is
reported under the generic name `persistenceStore` rather than `postgres` or
`database` — /ready must never disclose which specific backing technology is
in use. A regression test
(`src/middleware/__tests__/healthContentSafety.test.js`) fails the build if
either route's response body ever grows a disallowed key.

**Defense in depth applied regardless of authentication settings:**

- **No rate limiting on probe routes** — `/health`, `/ready` and
  `/health/redis` are deliberately NOT rate-limited. The Redis-backed limiter that
  previously fronted them fails closed when Redis is unavailable, which turned every
  probe into `429 RATE_LIMITED` during exactly the outage class `/ready` exists to
  report — masking the documented 503 + `components` readiness body above. The probe
  handlers are near-zero-cost cached reads (see the zero-I/O notes earlier in this
  document), so an unlimited probe path is not a meaningful amplification vector, and
  the IP allowlist below remains available for network-level restriction.
  `QODIQA_HEALTH_RATE_LIMIT_MAX` / `QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS` are no longer
  consumed. Rate limiting on every enforcement route is unchanged and stays
  fail-closed.
- **IP allowlist** — if you already run with `QODIQA_OPS_IP_ALLOWLIST_ENABLED=true`, the
  same allowlist applies to `/health` and `/ready` (e.g. restrict to your cluster's pod
  CIDR). Off by default, same as for every other operational endpoint.
- **Structured audit logging** — every auth/loopback rejection (when the optional
  hardening below is enabled) emits a structured log event
  (`HEALTH_PROBE_NON_LOOPBACK_BLOCKED`, `OPS_AUTH_MISSING_CREDENTIALS`, etc.).

**Optional hardening (opt-in, off by default):**

| Env var | Default | Effect |
|---|---|---|
| `QODIQA_HEALTH_PROBE_AUTH_REQUIRED` | `false` | Requires the same `QODIQA_OPS_TOKEN`/RBAC credential as `/metrics`. If enabled, you **must** configure your probe to send it (see below) or your deployment will break exactly as this document describes above. |
| `QODIQA_HEALTH_REQUIRE_LOOPBACK` | `false` | Additionally rejects any request whose raw TCP socket address is not loopback. **Do not enable for Kubernetes** — kubelet never connects via loopback. Intended for Docker/Compose/bare-metal only, where `HEALTHCHECK` always executes inside the container. This check reads the raw socket address and cannot be bypassed via `X-Forwarded-For`/`X-Real-IP`. |

If you enable `QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true`, configure the matching
header on every probe:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 3000
    httpHeaders:
      - name: X-Ops-Token
        value: <QODIQA_OPS_TOKEN — inject via Helm/kustomize from the Secret, never a literal>
  # ...same for readinessProbe and startupProbe
```

See `docs/configuration/reference.md` for the full list of `/health`/`/ready`
configuration knobs.

---

## Kubernetes Configuration

### Liveness Probe

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
  timeoutSeconds: 2
```

**Purpose:** Restart the container if the process is hung.

**Tuning notes:**
- `initialDelaySeconds`: set to at least as long as it takes the process to
  begin listening. 5 seconds is conservative for a Node.js process.
- `failureThreshold: 3` gives 30 seconds of tolerance before a restart is
  triggered (3 × 10 s). Increase if Redis initialization takes longer.
- Do not set `initialDelaySeconds` lower than your Redis initialization time
  or Kubernetes may kill the pod during a valid slow-start.

---

### Readiness Probe

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 1
  successThreshold: 1
  timeoutSeconds: 2
```

**Purpose:** Remove the pod from the load balancer when it cannot safely serve
enforcement traffic.

**Tuning notes:**
- `failureThreshold: 1` ensures the pod is removed from rotation on the first
  503. QODIQA enforces fail-closed semantics — sending traffic to a pod with
  no Redis connection would block all requests anyway, so early removal is safe.
- `periodSeconds: 5` gives fast detection of runtime Redis failures without
  excessive probe traffic.
- During shutdown, `/ready` returns 503 immediately (before drain completes).
  Kubernetes will remove the pod from the Service endpoints within one probe
  cycle. Keep `periodSeconds` low so traffic is redirected quickly.

---

## Startup Probe (optional, for slow Redis initialization)

If Redis initialization consistently takes more than 10–15 seconds (e.g., due
to cold-start provisioning), add a startup probe to give the process more time
before liveness checks begin:

```yaml
startupProbe:
  httpGet:
    path: /ready
    port: 3000
  initialDelaySeconds: 2
  periodSeconds: 3
  failureThreshold: 20
  timeoutSeconds: 2
```

This allows up to 62 seconds of initialization time (2 s delay + 20 × 3 s)
before Kubernetes declares the container failed. Once the startup probe
succeeds, the liveness and readiness probes take over.

---

## Shutdown Behaviour

The shutdown sequence is:

1. `readinessState.setReady(false)` — `/ready` returns 503 immediately.
2. `requestDrain.beginShutdown()` — new requests receive `503 SERVICE_SHUTTING_DOWN`.
3. `httpServer.close()` — stop accepting new TCP connections.
4. Wait for in-flight requests to drain.
5. Close Redis connections (including the consent revocation subscriber) and
   the PostgreSQL pool — `pgPool.shutdown()` also stops the background
   readiness probe interval added by READY-50, so no probe fires against a
   closing/closed pool.
6. Exit(0).

Step 1 happens before Step 2 so that `/ready` returns 503 before the drain
middleware fires. This ensures Kubernetes load balancers see a 503 on `/ready`
and stop routing traffic within one probe cycle — before any enforcement
requests are blocked by the drain.

`/health` continues to return `200 { "status": "ok" }` throughout shutdown
because it is mounted before `requestDrain.middleware` and has no readiness
dependency.

---

## Full Pod Spec Example

> Illustrative probe wiring only. The production manifest is the single-node **StatefulSet** with
> `replicas: 1` (`deploy/kubernetes/overlays/single-node/statefulset.yaml`) — use it, not this Deployment with
> `replicas: 2`: a second single-node writer sharing PostgreSQL violates the single-writer invariant (and is refused at boot when declared via `QODIQA_REPLICA_COUNT`), and the distributed overlay is
> refused at production boot.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qodiqa
spec:
  replicas: 2
  selector:
    matchLabels:
      app: qodiqa
  template:
    metadata:
      labels:
        app: qodiqa
    spec:
      terminationGracePeriodSeconds: 60
      containers:
      - name: qodiqa
        image: qodiqa:latest
        ports:
        - containerPort: 3000
        env:
        # Required for replicas > 1 (and recommended for replicas: 1 too) —
        # see "Audit chain ordering mode" above. Without this, QODIQA refuses
        # to start under Kubernetes in the default single-node mode.
        - name: QODIQA_DEPLOYMENT_MODE
          value: distributed
        # ...plus QODIQA_PG_* connection settings (host/port/database/credentials)
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 10
          failureThreshold: 3
          timeoutSeconds: 2
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
          failureThreshold: 1
          successThreshold: 1
          timeoutSeconds: 2
```

**`terminationGracePeriodSeconds`** must be longer than `SHUTDOWN_TIMEOUT_MS`
(default 30 000 ms = 30 s). 60 seconds provides a safe margin. If you increase
`SHUTDOWN_TIMEOUT_MS`, increase this value proportionally.

---

## Anti-patterns

| Anti-pattern | Problem |
|---|---|
| Using `/health` as the readiness probe | `/health` always returns 200 — it will never remove a degraded pod from rotation. |
| Using `/ready` as the liveness probe | `/ready` returns 503 during shutdown; Kubernetes would restart a pod that is shutting down cleanly. |
| Setting `failureThreshold` > 1 for readiness | Delays removal of a degraded pod from the load balancer; traffic continues to a pod that will block all requests. |
| `terminationGracePeriodSeconds` < `SHUTDOWN_TIMEOUT_MS / 1000` | Kubernetes SIGKILL arrives before the graceful shutdown sequence completes; in-flight requests are aborted. |

---

See `docs/deployment/ntp-clock-requirements.md` for clock accuracy requirements that affect
artifact timestamp validation and replay protection TTLs.
