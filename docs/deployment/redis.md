# REDIS DEPLOYMENT

This document covers the three-store Redis architecture, connection configuration, persistence requirements, security hardening, and failure modes for QODIQA production deployments.

---

## Why three stores

QODIQA uses three independent Redis client connections, each serving a distinct enforcement function:

| Store | Key prefix | Purpose | Data structure |
|---|---|---|---|
| Nonce store | `qodiqa:req:v2:` | Replay prevention — registers each `requestId` exactly once | String (SET NX PX) |
| Anomaly store | `anomaly:v2:` | Sliding-window burst detection — per-key max 100/min, global max 5000/min | Sorted set + sequence counter |
| Rate limit store | `ratelimit:v1:` | Policy-driven per-userId or per-IP rate limits | String (INCR + EXPIRE) |

Each store has its own Redis client. A failure in any one store is independently observable and independently degrading. All three must initialize successfully for `/ready` to return 200.

---

## Connection configuration

All three stores build their Redis client options from `src/infra/redis/clientConfig.js`. The shared configuration controls:

**Authentication**

Credential precedence: `REDIS_USERNAME` / `REDIS_PASSWORD` environment variables take precedence over credentials embedded in `REDIS_URL`. If both are set, the environment variables win.

Authentication errors are detected by pattern match against the client error message: `/WRONGPASS|NOAUTH|ERR invalid password|AUTHFAILED/i`.

**TLS**

TLS is enabled when `REDIS_URL` uses the `rediss://` scheme OR when `REDIS_TLS=true` is set. Optional files:

| Variable | Purpose |
|---|---|
| `REDIS_TLS_CA` | CA certificate for server verification |
| `REDIS_TLS_CERT` | Client certificate (mTLS) |
| `REDIS_TLS_KEY` | Client private key (mTLS) |

`REDIS_TLS_CERT` and `REDIS_TLS_KEY` must both be set or both absent. A client certificate without a matching key, or vice versa, is a startup error.

`REDIS_TLS_REJECT_UNAUTHORIZED=false` disables certificate verification. This is a warning in all environments and a fatal startup error in production (`NODE_ENV=production`).

TLS errors are detected by pattern match: `/SSL|certificate|handshake|TLS/i`.

URLs containing credentials are redacted in log output (`[REDACTED]` replaces the userinfo component).

---

## Nonce store

**File**: `src/validation/nonceStore.js`

**Registration command**: `SET qodiqa:req:v2:<requestId> 1 NX PX <ttlMs>`

The TTL is derived from the artifact expiry timestamp. The key expires atomically with the artifact — no separate cleanup is required.

`SET NX` guarantees atomicity. If the key already exists, the command returns null and the middleware returns `REPLAY_DETECTED`.

**Connection parameters**:
- Reconnection: exponential backoff capped at 30 s, no attempt limit
- `CONNECT_TIMEOUT`: `REDIS_CONNECT_TIMEOUT_MS` or 5000 ms
- Reconnect backoff: `min(100 × 2^retries, 2000)` ms
- Flap detection: more than 3 reconnect events within 60 seconds

**Startup probe sequence** (run once during `init()`):

1. `PING`
2. `SET <probe-key> 1 PX 5000`
3. `GET <probe-key>`
4. `DEL <probe-key>`

Emits on success:
- `REDIS_CONNECTIVITY_VALIDATED`
- `REDIS_NAMESPACE_READY`
- `REDIS_AUTH_VALIDATED` (when authentication is configured)
- `REDIS_TLS_VALIDATED` (when TLS is configured)

---

## Anomaly store

**File**: `src/validation/anomalyStore.js`

**Algorithm**: Lua-based sliding window using Redis sorted sets.

For each tracked key, the Lua script (`SLIDE_SCRIPT`) executes atomically:

```
ZREMRANGEBYSCORE key 0 (now - window)
INCR key:seq
ZADD key now (now:seq)
PEXPIRE key (window + 1000)
PEXPIRE key:seq (window + 1000)
return ZCARD key
```

Each tracked key creates **two Redis keys**: the sorted set (`anomaly:v2:key:<id>`) and a sequence counter (`anomaly:v2:key:<id>:seq`). Both expire at `window + 1000` ms.

**Thresholds** (from `src/validation/checkAnomaly.js`):
- `WINDOW_MS`: 60,000 ms
- `PER_KEY_MAX`: 100 requests per window
- `GLOBAL_MAX`: 5,000 requests per window

**Check order**: per-key check runs first (`key:<publicKeyId>`), global check runs second (`global`). Either exceeding its threshold returns `{ block: true, reason: 'ANOMALY_DETECTED' }` with type `SIGNATURE_BURST` (per-key) or `RATE_BURST` (global).

A read-only `PEEK_SCRIPT` (`ZCOUNT`) is available for diagnostics without modifying window state.

**Connection parameters**: same as nonce store — backoff `min(100 × 2^retries, 30000)` ms with jitter, no attempt limit, flap threshold 3/60s.

---

## Rate limit store

**File**: `services/policy/store.js`

**Algorithm**: Lua-based tumbling window.

```
INCR key
if count == 1 then EXPIRE key windowSeconds
return count
```

The window size is policy-driven (`config.windowSeconds` on each `RATE_LIMIT` policy). `EXPIRE` is set only on the first write — the window is fixed from first hit, not sliding.

**Key format**: `ratelimit:v1:<windowSeconds>:<userId-or-ip>`

**Fail-closed behavior**:
- `store.getCount()` throws → count treated as `Infinity` → request blocked
- `store.increment()` throws → error silently ignored (decision is already `EXECUTE` at that point)

`createRedisStore()` is the production factory. `createStore()` (in-memory) is for tests only.

**Connection parameters**: no reconnection limit, `REDIS_CONNECT_TIMEOUT_MS` or 5000 ms, same backoff and flap detection.

---

## Startup initialization

All three stores initialize concurrently via `Promise.allSettled`:

```js
Promise.allSettled([nonceStore.init(), anomalyStore.init(), rateLimitStore.init()])
```

Results are evaluated individually. A store that fails startup is marked as not ready. `_allReady` is `nonceReady && anomalyReady && rlReady`. `setReady(_allReady)` is called after `app.listen` — if any store failed, `/ready` returns 503 and the load balancer must not route traffic.

There is no partial-ready mode. All three stores must be up for the gateway to accept execution requests.

---

## Redis persistence requirements

QODIQA requires Redis AOF persistence to guarantee replay protection across Redis restarts. Without durability, a Redis restart clears the nonce store — previously registered request IDs are forgotten and replay attacks succeed.

**Safe configurations**:

| `appendonly` | `appendfsync` | Risk | Assessment |
|---|---|---|---|
| `yes` | `always` | None — every write synced | Safe |
| `yes` | `everysec` | Up to 1 second of writes lost | Safe |
| `yes` | `no` | Up to ~30 seconds lost | Unsafe |
| `no` | — | Full window replayable | Unsafe |

The production Docker Compose configuration uses `--appendonly yes --appendfsync everysec`.

**Persistence check at startup**

QODIQA checks Redis persistence state during startup via `src/infra/redis/persistenceCheck.js`. The check queries:
- `CONFIG GET appendonly`
- `CONFIG GET appendfsync`
- `INFO persistence`

This check requires `CONFIG GET` permission in the Redis ACL. If `CONFIG GET` is blocked, the persistence state is unknown and treated as unsafe.

**`STRICT_REPLAY_PROTECTION`**

This variable **defaults to `true`** — it is only `false` if explicitly set to the literal string `false`. Whenever it evaluates to `true` (the default, or an explicit `true`), startup aborts (`process.exit(1)`) if the persistence check does not confirm a safe AOF configuration. Only when it is explicitly set to `false` does an unsafe result emit a warning instead and let startup continue.

Leave `STRICT_REPLAY_PROTECTION` at its default (or set it to `true` explicitly for clarity) for all production deployments where replay protection is a hard requirement. Setting it to `false` is a deliberate opt-out and should be reserved for development/staging environments without durable Redis.

---

## Runtime monitoring

QODIQA subscribes to events from all three store emitters during startup. Events flow through `_setupRuntimeMonitoring()` in `server.js`.

**Store-level events** (emitted by each store's EventEmitter):

| Event | Meaning |
|---|---|
| `ready` | Store reconnected and operational |
| `degraded` | Store disconnected or failed |

**Gateway-level log events** (emitted when store events are received):

| Event | Trigger |
|---|---|
| `REDIS_READINESS_TRUE` | Store emits `ready` |
| `REDIS_READINESS_FALSE` | Store emits `degraded` |
| `REDIS_RECONNECT_FLAPPING` | Flap threshold exceeded (>3 reconnects in 60s) |
| `REPLAY_PROTECTION_DEGRADED` | Nonce store emits `degraded` |
| `ANOMALY_PROTECTION_DEGRADED` | Anomaly store emits `degraded` |
| `POLICY_RATE_LIMIT_DEGRADED` | Rate limit store emits `degraded` |
| `GATEWAY_RUNTIME_DEGRADED` | Any store degrades after initial ready |
| `GATEWAY_RUNTIME_RECOVERED` | All stores recover |

All three stores are fail-closed. When any store is degraded, all execution requests to `POST /ai/chat` are blocked. There is no in-memory fallback and no fail-open path.

---

## Failure modes and recovery

### Startup failure — one or more stores fail to initialize

`/ready` returns 503. The load balancer must not route traffic. The pod will not receive requests. Investigate the Redis connection, authentication, and TLS configuration in logs.

### Runtime disconnect — store loses connection after startup

The store emits `degraded`. All execution requests are blocked (fail-closed). The store client attempts reconnection with exponential backoff (`min(100 × 2^retries, 2000)` ms) up to `MAX_RECONNECTS` (5) attempts.

If reconnection succeeds before MAX_RECONNECTS is exhausted, the store emits `ready` and the gateway emits `GATEWAY_RUNTIME_RECOVERED`. Execution resumes.

### No exhausted state

Reconnection continues indefinitely (exponential backoff capped at 30 s). A restart only forces an immediate fresh attempt. Pod health probes (`/health`) continue to answer; `/ready` stays 503 until the store is back.

### Reconnect flapping

More than 3 reconnect events within 60 seconds triggers `REDIS_RECONNECT_FLAPPING`. This indicates an unstable network or Redis instance. Investigate the Redis host, network path, and connection limits before the flap escalates to MAX_RECONNECTS exhaustion.

### AOF-disabled Redis restart

If Redis is running without AOF and restarts, all three key namespaces are cleared. Nonce store data is lost — previously seen `requestId` values are no longer registered. Replay attacks are possible until artifacts from before the restart expire.

Mitigation: enable AOF persistence (`appendonly yes appendfsync everysec`) on all Redis instances used in production. `STRICT_REPLAY_PROTECTION` gates startup on a confirmed safe configuration by default — do not override it to `false` in production.

---

## Production Docker Compose topology

`deploy/docker/docker-compose.prod.yml` is the reference single-node production
deployment: QODIQA, Redis, and PostgreSQL as three services on one Docker host. It is
intentionally single-node — there is no replication or clustering in this file for any
of the three services. There is no multi-node or HA production topology for the gateway: the Kubernetes
production overlay (`deploy/kubernetes/overlays/single-node/`) also runs exactly one replica, and the distributed overlay
is refused at production boot. Redis/PostgreSQL HA can be provided by managed services; it protects the
dependencies only. (Previously said to use `deploy/kubernetes/` for clustering.)

**PostgreSQL service**: `postgres:16-alpine` (pinned major version), backing the Runtime
Consent Registry plus the audit-chain dual-write, transparency log, evidence chain,
compliance, certification, and attestation subsystems — see the "POSTGRESQL / CONSENT
REGISTRY" section of `deploy/env/production.env.example` for what each subsystem needs it for.
`QODIQA_PG_USER`, `QODIQA_PG_PASSWORD`, and `QODIQA_PG_DATABASE` (from `.env.prod`) seed
both the `postgres` service's own `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB`
environment and the `qodiqa` service's connection variables, so credentials are defined
once and reused — no duplicate configuration. `QODIQA_PG_HOST` is hardcoded to the
Compose service name `postgres` (not read from `.env.prod`), the same pattern already
used for `REDIS_URL` pointing at the `redis` service. Both Redis and PostgreSQL ports are
published only on the internal `backend` network (`internal: true`), never on the host.

**In-transit encryption**: unlike Redis, the PostgreSQL connection in this topology runs
without TLS (`QODIQA_PG_SSL=false`). Both services share the same internal-only Docker
network, so this is a deliberate, documented simplification for the single-node reference
deployment rather than an oversight — revisit if the deployment model changes (e.g.
alongside).

**Persistent storage**: the `postgres-data` named volume is mounted at PostgreSQL's data
directory and, like `qodiqa-data`, `qodiqa-logs`, and `redis-data`, must be backed by
durable storage (see the "Named volumes" comment block in the Compose file). Data
survives container recreation, `qodiqa` restarts, and `docker compose restart` — nothing
is stored in an anonymous volume or in container-local storage.

**Startup sequence**: `qodiqa` declares `depends_on: postgres: condition: service_healthy`
(alongside the existing `redis: condition: service_healthy`), so it does not start until
PostgreSQL reports healthy via `pg_isready`, not merely until the container has started.
The health check retries 5 times at a 10s interval with a 20s `start_period`, giving
PostgreSQL room for first-boot initialization before failures count.

**Launching the stack**:

```bash
cp deploy/env/production.env.example .env.prod   # fill in real values, including QODIQA_PG_USER/PASSWORD/DATABASE
docker compose -f deploy/docker/docker-compose.prod.yml --env-file .env.prod up -d
```

**Schema migrations**: the Compose file provisions the PostgreSQL server and database
but does not run schema migrations automatically. After first startup, apply them once
(same command documented in [docs/guides/quickstart.md](../guides/quickstart.md#provision-consent-postgresql)
for local development):

```bash
docker compose -f deploy/docker/docker-compose.prod.yml exec qodiqa node src/infra/postgres/migrate.js
```

---

## Kubernetes deployment notes

**Shared Redis requirement**: all QODIQA pods in a deployment must connect to the same Redis instance or cluster. Separate Redis instances per pod break nonce deduplication — a replay attack succeeds against any pod that has not seen the original request.

**Init container**: both reference Kubernetes manifests (`deploy/kubernetes/overlays/single-node/statefulset.yaml` and `deploy/kubernetes/overlays/distributed/deployment.yaml`) include an init container (`wait-for-redis`) that blocks pod startup until Redis is reachable. This prevents the QODIQA process from starting before the Redis dependency is available.

**Anti-affinity**: `topologySpreadConstraints` with `maxSkew: 1` on `kubernetes.io/hostname` spreads pods across nodes. This is set in both overlays' workload manifests.

**Secrets**: `REDIS_PASSWORD` is injected via `secretKeyRef` from a Kubernetes Secret. The password is never present in the ConfigMap or deployment manifest.
