# Redis Persistence and Replay Protection

## Why persistence matters for replay protection

QODIQA enforces replay protection by storing a nonce key in Redis for every
accepted artifact.  Redis is the single source of truth: any process —
regardless of how many instances are running — sees the same nonce state.

The security invariant is:

> A nonce registered by a successful request must remain registered until its
> TTL expires, even across Redis restarts, crashes, and container recreation.

If Redis loses nonce state, nonces that were previously accepted become
unregistered again.  An attacker holding a valid captured artifact can
re-submit it and it will be accepted — a deterministic replay attack.

---

## Required Redis configuration

```
appendonly    yes
appendfsync   everysec
```

Add these lines to `redis.conf` (or pass them as `--appendonly yes
--appendfsync everysec` command-line flags).

### appendfsync modes and their risk windows

| Mode       | Flush cadence              | Max nonce loss on crash | Recommended |
|------------|---------------------------|------------------------|-------------|
| `always`   | Every write, synchronously | 0 seconds              | High-security deployments |
| `everysec` | Once per second            | ≤ 1 second             | **Default production recommendation** |
| `no`       | OS decides (~30s)          | Up to ~30 seconds      | Not acceptable |
| AOF off    | Never                      | Entire nonce store     | Never acceptable |

`everysec` is the recommended baseline.  It limits the replay attack window
to at most one second of nonce loss, which is acceptable given the artifact
TTL is 60 seconds — an attacker would need to capture and re-submit a nonce
within that narrow window before its original TTL expires anyway.

`always` eliminates the window entirely at the cost of write throughput.  Use
it if your threat model requires zero replay risk under any crash scenario.

---

## If Redis loses nonce state

### What happens

Previously used nonces become unregistered.  Any artifact whose original TTL
has not yet elapsed can be re-submitted and will pass replay protection.

The nonce TTL is exactly the artifact's remaining validity window (≤ 60
seconds).  So the worst-case replay window is: all nonces registered in the
60 seconds before the Redis restart.

### What does not change

- Signature verification is unaffected — Ed25519 keys are stored in
  `data/keys.json`, not Redis.
- Request binding verification is unaffected — it is stateless.
- Policy enforcement is unaffected — rate-limit state is in-memory per
  process, not Redis.

### Operational response

1. If Redis restarts unexpectedly: treat all requests in the 60 seconds
   before the restart as potentially replayable until their original
   timestamps expire.
2. Alert on `REDIS_PERSISTENCE_WARNING` log events.
3. Alert on `REPLAY_PROTECTION_DEGRADED` log events.
4. Review audit logs for duplicate nonces or unusual request patterns in
   the affected window.

---

## Startup validation

QODIQA runs Redis persistence diagnostics at startup and emits structured
log events:

| Event                         | Level | Meaning |
|-------------------------------|-------|---------|
| `REDIS_PERSISTENCE_STATUS`    | INFO  | AOF enabled, appendfsync mode confirmed safe |
| `REDIS_PERSISTENCE_STATUS`    | WARN  | Persistence configuration is unsafe |
| `REDIS_PERSISTENCE_WARNING`   | WARN  | Specific risk description (one per issue) |
| `REPLAY_PROTECTION_DEGRADED`  | WARN  | Summary: replay guarantees are reduced |
| `NONCE_STORE_CONNECT_FAILED`  | ERROR | Redis is unreachable; all guarded requests blocked |

Diagnostics are emitted even if the server proceeds to start.  Wire
`REDIS_PERSISTENCE_WARNING` and `REPLAY_PROTECTION_DEGRADED` to your
alerting system.

---

## Periodic re-validation

The startup check above runs once, at boot. `src/infra/redis/persistenceMonitor.js`
re-runs the identical check on a recurring background interval, against the
same live Redis connection the nonce store already uses, so runtime
configuration drift — an operator or config-management tool flipping
`appendonly` from `yes` to `no` on the live instance, after the process has
already started and passed the startup gate — is no longer invisible until
the next restart.

| Event                                | Level | Meaning |
|---------------------------------------|-------|---------|
| `REDIS_PERSISTENCE_MONITOR_STARTED`   | INFO  | Background validator initialized |
| `REDIS_PERSISTENCE_MONITOR_DISABLED`  | WARN  | Disabled via `QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED=false` |
| `REDIS_PERSISTENCE_DRIFT_DETECTED`    | WARN  | Configuration changed from safe to unsafe after startup |
| `REDIS_PERSISTENCE_RECOVERED`         | INFO  | Configuration changed back to safe |
| `REDIS_PERSISTENCE_MONITOR_DEGRADED`  | WARN  | The periodic check itself could not verify durability (e.g. connection lost) |

Configuration:

```
QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED=true    # default: enabled
QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS=60000 # default: 60s
```

Deliberately **observational, not enforcing**: a drift detected mid-run does
not itself reject in-flight requests or trigger a restart — only the startup
gate (`STRICT_REPLAY_PROTECTION`, above) does that, since turning a live
background check into a live kill-switch risks flapping-induced outages from
a transient `CONFIG GET` failure. `REDIS_PERSISTENCE_DRIFT_DETECTED` routes
through the alerting framework (`src/alerting/detection/OperationalDetector.js`,
severity HIGH) and is exposed at `GET /diagnostics` under `redisPersistence`,
and via the `qodiqa_redis_persistence_safe`/`qodiqa_redis_persistence_drift_total`/
`qodiqa_redis_persistence_check_duration_ms` Prometheus metrics — wire these
into your alerting/dashboards the same way as the startup-time events above.

---

## Strict mode

`STRICT_REPLAY_PROTECTION` refuses startup entirely if Redis persistence
guarantees are insufficient. **This is the default** — the variable defaults
to `true` and only becomes `false` if it is explicitly set to the literal
string `false`. Setting it to `true` yourself is redundant but harmless; it
documents intent explicitly:

```
STRICT_REPLAY_PROTECTION=true
```

Whenever strict mode is active (the default, or an explicit `true`), the
server will:

1. Wait for the Redis connection to complete.
2. Query `CONFIG GET appendonly`, `CONFIG GET appendfsync`, and
   `INFO persistence`.
3. If any of the following are true, emit a `FATAL` log and exit with
   code 1:
   - Redis is unreachable.
   - `appendonly` is `no`.
   - `appendfsync` is `no` or unknown.
   - The CONFIG query itself fails (e.g. ACL restriction).

The exit log includes `aofEnabled`, `appendfsync`, `warnings`, and a
`resolution` field explaining exactly what to fix.

### When to use strict mode

- **Production deployments** where replay integrity is a hard requirement.
- **Regulated environments** where audit trails must be tamper-evident.
- **Multi-tenant deployments** where a replay attack could cross tenant
  boundaries.

### When strict mode is not appropriate

- Local development against an in-memory Redis (no AOF).
- Staging environments where ephemeral Redis is intentional.

In these cases, you must **explicitly set `STRICT_REPLAY_PROTECTION=false`**.
Leaving the variable unset does *not* disable strict mode — the default is
`true`, so an unset variable still refuses to start against a non-durable
Redis. Diagnostics are still emitted as warnings when strict mode is
explicitly disabled; replay protection is still enforced for all nonces that
Redis retains.

---

## Container and ephemeral Redis risks

### Ephemeral Redis (in-memory only, no volume)

All nonce state is lost when the container stops.  This is the default for
most `redis:latest` Docker images with no volume mount and no config file.

**Risk**: full replay window for all nonces from the 60 seconds before
container stop.

**Mitigation**: always mount a persistent volume and configure AOF, or use
strict mode to prevent startup against ephemeral Redis.

### Container recreation (e.g. Kubernetes pod restart)

If the Redis pod is recreated and the data volume is reattached, AOF replay
will restore nonce state on startup.  Without a volume, nonce state is lost.

**Mitigation**: use a `PersistentVolumeClaim` for the Redis data directory
in Kubernetes.

### Process restart (same container, same volume)

AOF replay automatically restores nonce state.  No replay window.  This is
the correct behavior and the reason AOF is required.

---

## Cloud deployment recommendations

### AWS ElastiCache

- Enable AOF by setting the `appendonly` parameter to `yes` in the
  ElastiCache parameter group.
- Set `appendfsync` to `everysec`.
- Enable Multi-AZ with automatic failover to reduce availability gaps.
- Note: ElastiCache does support `CONFIG GET` from application clients.

### Redis Cloud (Redis Enterprise)

- Persistence is configured per-database in the Redis Cloud console.
- Select **AOF – fsync every 1 sec** or **AOF – fsync every write**.
- **Snapshot** persistence alone is not sufficient — it does not guarantee
  nonce recovery between snapshot intervals.

### GCP Memorystore for Redis

- Memorystore supports RDB persistence but not AOF persistence as of the
  current GA release.
- **This means Memorystore is not suitable for strict replay protection.**
- Explicitly set `STRICT_REPLAY_PROTECTION=false` and accept the reduced
  guarantee, or deploy a self-managed Redis instance with AOF enabled.
  Without that explicit override, QODIQA will refuse to start against
  Memorystore by default.
- Monitor Google's release notes for AOF support announcements.

### Azure Cache for Redis

- AOF persistence is available on Premium tier only.
- Standard and Basic tiers do not support AOF — not acceptable for strict
  mode.
- On Premium tier, enable AOF persistence in the Azure Portal under
  **Data persistence**.

---

## Backup and recovery

Nonce TTLs are ≤ 60 seconds.  After 60 seconds, any nonce that was
registered but not persisted is no longer a replay risk because the artifact
it protects has expired by timestamp validation.

This means:

- **Point-in-time nonce recovery is not required.**  AOF is needed only to
  survive the restart window, not for long-term backup.
- **RDB snapshots are not sufficient.**  A snapshot taken every 15 minutes
  leaves a 15-minute window of nonce loss, which is far larger than the
  60-second artifact TTL.  An attacker could replay any artifact from that
  window indefinitely until the snapshot catches up.  Use AOF.

For disaster recovery across data-center failures:
- Redis replication with AOF on the replica provides durability without
  requiring writes to block on replica acknowledgement.
- Redis Cluster with AOF on each shard provides both durability and
  horizontal scale.

---

## Replay safety assumptions

QODIQA's replay protection makes the following assumptions in production:

1. **Redis is durable**: AOF with `everysec` (or `always`) is configured.
2. **Redis is available**: any disconnection causes all replay-guarded
   requests to fail closed (`_assertReady()` throws synchronously).
3. **System clocks are synchronized**: NTP or equivalent keeps artifact
   timestamps within the ±60s window.  Clock skew beyond this value will
   cause legitimate artifacts to fail expiry validation.
4. **Nonce TTLs are respected**: Redis TTL expiry is accurate.  Redis does
   not guarantee sub-millisecond TTL precision, but this is not required
   given the 60-second window.

Violating assumption 1 degrades replay protection to a best-effort basis.
Violating assumption 2 blocks all execution (fail-closed — intentional).
Violating assumptions 3 or 4 may affect legitimate traffic but does not
weaken the security guarantee.
