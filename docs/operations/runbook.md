# OPERATIONAL RUNBOOK

This runbook covers startup verification, health monitoring, routine operations (policy updates, key rotation), incident response, and emergency procedures for QODIQA.

---

## Startup verification

After every deployment, confirm the following before routing production traffic.

### 1. Confirm log sequence

```
SECRET_VALIDATION_OK
ENV_VALIDATION_OK
KEY_MANAGER_READY
POLICIES_LOADED
KEYSTORE_LOADED
GATEWAY_START  { executionIntegrity: "FULL", ready: true }
```

If `executionIntegrity` is `"DEGRADED"` in `GATEWAY_START`, one or more Redis stores failed to initialize. The gateway starts but `/ready` returns 503. The load balancer must not route traffic.

### 2. Verify endpoints

```bash
# Liveness
curl http://localhost:3000/health
# → {"status":"ok","uptime":<seconds>}

# Readiness — must be true before routing traffic
curl http://localhost:3000/ready
# → {"ready":true,"components":{"nonceStore":true,"anomalyStore":true,"rateLimitStore":true}}

# Active public key
curl http://localhost:3000/public-key

# Public key list
curl http://localhost:3000/.well-known/qodiqa/keys

# Enforcement gate — must reject unauthenticated requests
curl -X POST http://localhost:3000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test"}'
# → 200 {"decision":"BLOCK","reason":"MISSING_ARTIFACT"} (default QODIQA_BLOCK_HTTP_MODE=decision; 400 with =status)
```

### 3. Verify Prometheus metrics

```bash
curl -H @"$OPS_AUTH_HEADER_FILE" http://localhost:3000/metrics | grep execution_integrity_full   # ops-authenticated: 0600 file with "Authorization: Bearer <operator API key>"
# → qodiqa_execution_integrity_full{} 1
```

A value of `1` confirms full execution integrity. A value of `0` indicates a degraded Redis store.

---

## Health monitoring

### Probes

| Endpoint | Method | Purpose | Healthy response |
|---|---|---|---|
| `/health` | GET | Liveness | 200 `{"status":"ok","uptime":<s>}` |
| `/ready` | GET | Readiness | 200 `{"ready":true,...}` |
| `/metrics` | GET | Prometheus | 200 text/plain |

`/health` returns 200 as long as the process is running — it does not check Redis state. `/ready` returns 503 when a Redis store, PostgreSQL, the revocation subscriber, admission, the audit backlog, audit persistence or the transparency journal is unhealthy, and during graceful shutdown.

### Key Prometheus metrics

| Metric | Type | Meaning |
|---|---|---|
| `qodiqa_execution_integrity_full{}` | Gauge | 1 = all stores up, 0 = degraded |
| `qodiqa_redis_store_up{store="nonce"}` | Gauge | 1 = nonce store up, 0 = down |
| `qodiqa_redis_store_up{store="anomaly"}` | Gauge | 1 = anomaly store up, 0 = down |
| `qodiqa_redis_store_up{store="rate_limit"}` | Gauge | 1 = rate limit store up, 0 = down |
| `qodiqa_requests_total` | Counter | Total AI execution requests by decision |
| `qodiqa_blocks_total` | Counter | Blocked requests by reason code |
| `qodiqa_security_events_total` | Counter | Security events by category |
| `qodiqa_request_duration_ms` | Histogram | AI execution latency |

### Log events to monitor in production

| Event | Level | Meaning |
|---|---|---|
| `GATEWAY_START` | INFO | Server started; check `executionIntegrity` field |
| `REPLAY_PROTECTION_DEGRADED` | WARN | Nonce store lost; all execution blocked |
| `ANOMALY_PROTECTION_DEGRADED` | WARN | Anomaly store lost; all execution blocked |
| `POLICY_RATE_LIMIT_DEGRADED` | WARN | Rate limit store lost; all execution blocked |
| `GATEWAY_RUNTIME_DEGRADED` | WARN | All Redis stores unavailable |
| `GATEWAY_RUNTIME_RECOVERED` | INFO | All stores back online |
| `KEY_EXPIRING_SOON` | WARN | Active key within 30 days of expiry; rotate immediately |
| `KEY_ROTATION_OVERDUE` | WARN | Active key past 90-day rotation deadline |
| `POLICY_RELOAD_FAILED` | ERROR | SIGHUP policy reload failed; previous policy set retained |
| `REDIS_RECONNECT_FLAPPING` | WARN | >3 reconnects in 60 s; investigate Redis stability |
| `SHUTDOWN_TIMEOUT` | WARN | Graceful shutdown exceeded timeout; force exit(1) |

---

## Policy updates

Change policy through the policy API (governance workflow). The enforced set lives in the PostgreSQL control plane; `policies.json` is import-only. SIGHUP re-reads the enforced set from the control plane without restarting the server; the reload is atomic — the previous policy set is retained if the reload fails.

```bash
# Docker
docker exec <container-name> kill -HUP 1

# Kubernetes
kubectl exec -n qodiqa <pod-name> -- kill -HUP 1

# systemd
kill -HUP <pid>
```

On success: `POLICIES_RELOADED` is emitted with the new policy count.

On failure: `POLICY_RELOAD_FAILED` is emitted with the error. The previous policy set remains active. Fix the cause (for example control-plane connectivity) and re-send SIGHUP.

SIGHUP reloads policies only. It does not reload the key store, Redis connections, or any other runtime state.

---

## RBAC administrator bootstrap

RBAC authorization is always enforced (see `docs/security/RBAC_MODEL.md`) —
every `/rbac`, `/key-admin`, `/v1/admin/*`, `/consent`, and other permission-gated
endpoint requires a real, explicit RBAC user record. There is no
HTTP-reachable path that creates the first one; provision it out-of-band on
first deployment:

```bash
# Docker
docker exec <container-name> node scripts/rbac-bootstrap-key.js

# Kubernetes
kubectl exec -n qodiqa <pod-name> -- node scripts/rbac-bootstrap-key.js

# systemd / bare metal
npm run rbac:bootstrap-key
```

This prints a plaintext API key **exactly once** — store it in your secrets
manager immediately. Use it to provision individually-attributed operator
accounts via `POST /rbac/users` and `POST /rbac/users/:id/api-key`, then
consider rotating or disabling the bootstrap account itself. Re-running the
command when a key already exists reports `ALREADY_PROVISIONED` and takes no
action; pass `--rotate` to force-reissue.

---

## Key rotation

By default, keys rotate automatically — see "Automatic rotation" below. Manual
rotation is still available and is required when:
- A security incident warrants immediate key replacement — this is manual
  rotation's **emergency mode**, and `opts.mode` must be given explicitly (see below); no
  separate revoke step is needed
- `QODIQA_KEY_ROTATION_ENABLED=false` (automatic rotation disabled) and
  `KEY_ROTATION_OVERDUE` is emitted (past 90-day rotation deadline) — this is
  routine maintenance, not incident response; use graceful mode (see below)
  so artifacts signed by the outgoing key keep verifying

```bash
# 1a. Run EMERGENCY rotation (default — for a suspected key compromise; with
#     required env vars set). The outgoing key is REVOKED, not deprecated —
#     it loses signing AND verification capability in this one call. No
#     follow-up revoke() call is needed:
node -e "require('./services/artifact/keyManager').rotate(process.env.QODIQA_CLIENT_ID, { mode: 'emergency' })"

# 1b. Run GRACEFUL rotation instead (routine maintenance only — never for a
#     suspected compromise). The outgoing key is deprecated: it stops
#     signing but remains verifiable for the rest of its 180-day artifact
#     lifetime:
node -e "require('./services/artifact/keyManager').rotateGracefully(process.env.QODIQA_CLIENT_ID)"

# 2. Confirm log events:
#    KEY_REVOKED     — emergency mode: previous key is now revoked
#                      (revocationTrigger: 'ROTATION' distinguishes this from
#                      an explicit /revoke call)
#    KEY_DEPRECATED  — graceful mode only: previous key is now deprecated
#    KEY_ROTATED     — new key ID and version (either mode)

# 3. If QODIQA_KEY_ROTATION_ENABLED=true (default), no further action is
#    needed — every instance reloads keys.json on its own cadence
#    (QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS, default 5 minutes).
#    If automatic rotation is disabled, perform a rolling restart instead —
#    SIGHUP does not reload the key store.
```

**Kubernetes rolling restart (only needed with automatic rotation disabled):**
```bash
kubectl rollout restart statefulset/qodiqa -n qodiqa
kubectl rollout status statefulset/qodiqa -n qodiqa
```

(The production single-node overlay is a StatefulSet with one replica, so this "rolling" restart is a brief full outage;
`deployment/qodiqa` exists only in the non-production distributed overlay.)

**Deprecated keys only ever exist after an explicit graceful-mode rotation** (step 1b above, or the automatic scheduler — see "Automatic rotation"). They remain in the store for the full 180-day artifact lifetime, and artifacts signed with them continue to verify until they expire — no client disruption during a *planned* rotation window. Emergency-mode rotation (step 1a, the default) has no such window: verification of the outgoing key stops immediately.

### Automatic rotation

The rotation scheduler (`services/artifact/rotationScheduler.js`) is enabled by default and rotates every known client's key when it reaches the configured age (`QODIQA_KEY_ROTATION_SCHEDULE`, default `monthly`). In multi-instance deployments, a Redis distributed lock ensures exactly one instance performs a given rotation; all instances then pick up the change via their own periodic reload — no coordination is required from the operator. The scheduler always uses **graceful** mode (outgoing key deprecated, not revoked) — calendar-driven due-ness carries no compromise signal, so it must never fall back to emergency rotation's revoke-on-default behavior. A suspected compromise always requires the operator to run manual (emergency) rotation above.

```bash
# Check scheduler status: running state, configured interval, last/next run,
# and cumulative rotation/error/skip counters.
curl https://<host>/key-admin/rotation-scheduler/status \
  -H "Authorization: Bearer <operator API key>"
```

To disable automatic rotation entirely (falling back to fully manual rotation as described above):
```bash
QODIQA_KEY_ROTATION_ENABLED=false
```

See `docs/security/key-management.md` — "Automatic rotation scheduler" for configuration, KMS-provider behavior, and failure-mode details.

---

## Incident response

### Redis store unavailable

**Symptoms**: `REPLAY_PROTECTION_DEGRADED`, `ANOMALY_PROTECTION_DEGRADED`, or `POLICY_RATE_LIMIT_DEGRADED` log events; `/ready` returns 503; `qodiqa_execution_integrity_full{} 0`.

**Impact**: all `POST /ai/chat` requests are blocked fail-closed. No AI execution while any Redis store is unavailable.

**Resolution**:
1. Check Redis connectivity: network path, authentication, TLS configuration.
2. If Redis is down, restore it. The store client reconnects automatically (exponential backoff capped at 30 s, no attempt limit).
3. On successful reconnection: `GATEWAY_RUNTIME_RECOVERED` is emitted and `/ready` returns 200.
4. There is no exhausted state: reconnection continues indefinitely and `/ready` keeps returning 503 until it succeeds. The liveness probe (`/health`) does not reflect Redis state; a restart is optional.

### Redis reconnect flapping

**Symptoms**: `REDIS_RECONNECT_FLAPPING` — more than 3 reconnect events in 60 seconds.

**Resolution**: investigate Redis host stability, connection limits, and network reliability before flapping degrades enforcement further. A flapping connection degrades enforcement reliability even if individual reconnects succeed.

### Active key expiring

**Symptoms**: `KEY_EXPIRING_SOON` in startup logs (fewer than 30 days remaining) or `KEY_ROTATION_OVERDUE` (past 90-day deadline).

**Resolution**: rotate the key (see [Key rotation](#key-rotation)). If the key is past its 180-day `expiresAt`, the server will not start — rotate before the expiry deadline.

### Active key expired at startup

**Symptoms**: `KEY_EXPIRED_STARTUP` log event; server exits with `KEY_MANAGER_STARTUP_FAILED`.

**Resolution**: the server will not start with an expired active key. Rotate the key using the one-liner (requires only env vars, not a running server), then restart.

```bash
node -e "require('./services/artifact/keyManager').rotate(process.env.QODIQA_CLIENT_ID, { mode: 'emergency' })"
```

### Policy load failure

**Symptoms**: `POLICY_LOAD_FAILED` at startup (fatal); `POLICY_RELOAD_FAILED` at runtime (non-fatal).

**Startup failure**: server exits. Fix `policies.json` — it must include at least one enabled `REQUIRE_CONSENT` policy, must be valid JSON, must not exceed 1 MB, and must not exceed 100 policies. Restart after fixing.

**Runtime failure** (after SIGHUP): previous policy set is retained. The gateway continues operating under the old policy. SIGHUP re-reads the control plane, not `policies.json` (import-only): fix the cause (for example control-plane connectivity) and re-send SIGHUP.

### Key store corrupted or unreadable

**Symptoms**: server exits at startup with "KeyStore: FATAL — key file cannot be loaded".

**Resolution**: a corrupted `keys.json` is a fatal error — QODIQA will not start with an unreadable key store. Restore from backup. If no backup exists and the file is truly unrecoverable, provision a new key with a new KEK (all previously signed artifacts will be unverifiable).

### Audit chain corruption

**Symptoms**: `AUDIT_CHAIN_CORRUPTED` log event from `GET /audit/:artifactId` or `GET /audit/chain/integrity`.

**Investigation**: both endpoints are operator-protected — requests require a per-operator RBAC API key with `READ_AUDIT` (`Authorization: Bearer <operator key>`); a missing credential gives 401, and the shared `QODIQA_OPS_TOKEN` alone gives 403 FORBIDDEN.
```bash
curl http://localhost:3000/$1$OPERATOR_API_KEY"
```

Returns `chainValid: false` with `integrityFailures` and `tamperingDetected`. The audit chain is append-only and hash-chained — corruption indicates either disk error, truncation, or tampering. Preserve the audit log file and investigate the cause before modifying or rotating it.

### Multi-instance startup guard triggered

**Symptoms**: process exits with code `1` immediately at startup, before `/health`/`/ready` ever come up. A synchronous `FATAL` line is written to stderr with one of: `AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN`, `AUDIT_CHAIN_KUBERNETES_TOPOLOGY_UNVERIFIED`, `AUDIT_CHAIN_DISTRIBUTED_PG_REQUIRED`, `AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE`, or `AUDIT_CHAIN_ILLEGAL_TOPOLOGY` (PostgreSQL enabled, single-node ordering and a declared `QODIQA_REPLICA_COUNT` above 1 — `assertNoIllegalTopology()`; in production set `replicas: 1` / `QODIQA_REPLICA_COUNT=1`, since distributed mode is refused until) — this stderr line is the always-reliable signal (`src/core/audit/multiInstanceGuard.js`, `src/runtime/rawStderrDiagnostic.js`). A best-effort CRITICAL webhook notification (`src/runtime/earlyCriticalNotify.js`, ) is also fired to `ALERT_WEBHOOK_URL` if configured, but is fire-and-forget and not guaranteed to land before the process exits — do not rely on it as the sole detection path. This guard runs before the audit chain, alerting pipeline, or PG pool are initialized, so the normal `src/alerting` event-map pipeline never sees this failure; process-supervisor/orchestrator-level monitoring (exit code 1 + the FATAL stderr line) is the intended detection method.

**Impact**: the instance never starts serving traffic. No partial or divergent audit chain is written.

**Resolution**: read the FATAL line's `reason`/`action` fields — they name the exact cause (PM2 cluster worker, Node `cluster.fork()`, unacknowledged Kubernetes multi-replica topology, or a missing/unreachable `audit_chain_head` table in distributed mode) and the exact remediation. Do not attempt to force-start multiple single-node instances against the same audit log — see docs/protocol/AUDIT-SCHEMA-V8.md for why this is fail-closed by design.

---

## Graceful shutdown

QODIQA handles SIGTERM and SIGINT. The shutdown sequence executes exactly once regardless of how many signals are received.

**Shutdown sequence:**
1. Mark service NOT READY (`/ready` → 503); reject new requests with 503
2. Stop accepting new TCP connections (`httpServer.close`)
3. Wait for in-flight requests to drain
4. Disconnect all Redis stores (`Promise.allSettled` — a failing disconnect does not block shutdown; `REDIS_SHUTDOWN_FAILED` is emitted per failure)
5. Confirm audit log is durable (fsync per write — no flush required)
6. Exit cleanly (`exit(0)`)

If shutdown does not complete within `SHUTDOWN_TIMEOUT_MS` (default 30,000 ms), the force-exit timer fires `SHUTDOWN_TIMEOUT` and calls `exit(1)`.

**Log events during shutdown:**
```
SHUTDOWN_SIGNAL_RECEIVED  { signal: "SIGTERM" }
SHUTDOWN_STARTED
SHUTDOWN_READY_FALSE
SHUTDOWN_HTTP_CLOSE_STARTED
SHUTDOWN_HTTP_CLOSED
SHUTDOWN_DRAIN_STARTED
SHUTDOWN_DRAIN_COMPLETE
REDIS_SHUTDOWN_STARTED
REDIS_SHUTDOWN_COMPLETED  (per store)
SHUTDOWN_AUDIT_FLUSH_STARTED
SHUTDOWN_AUDIT_FLUSH_COMPLETE
SHUTDOWN_COMPLETE
```

**Kubernetes**: `terminationGracePeriodSeconds: 60` is set in the reference manifest — this must exceed `SHUTDOWN_TIMEOUT_MS / 1000 + 15 seconds`.

---

## Emergency key revocation

Use revocation when private key material is confirmed compromised. Revocation permanently blocks verification for all artifacts signed with the revoked key.

**If the compromised key is the current active key, use emergency rotation instead (see "Key rotation" above) — a single `keyManager.rotate(clientId, { mode: 'emergency' })` call (or `POST /key-admin/:clientId/rotate`) now provisions a new active key AND revokes the old one atomically.** There is no longer a "rotate, then remember to also revoke" two-step procedure for this case, and no window in between where the compromised key remains verifiable.

Use the standalone revoke call below only to block a **specific non-active key** — e.g. a key already deprecated under a prior graceful rotation, or any key by ID without provisioning a replacement:

```bash
# 1. Revoke by key ID:
node -e "require('./services/artifact/keyManager').revoke('<clientId>:key_v<n>')"

# Example:
node -e "require('./services/artifact/keyManager').revoke('acmecorp-prod:key_v1')"
```

`KEY_REVOKED` is emitted (with no `revocationTrigger` field — this distinguishes an explicit revoke from the `revocationTrigger: 'ROTATION'` emitted by emergency-mode rotation). After revocation, all artifacts signed with the revoked key are BLOCKed — `KEY_REVOKED` while the key still resolves, `INVALID_SIGNATURE` once it does not; `KEY_NOT_FOUND` is never emitted. The response is HTTP 200 `{decision:"BLOCK"}` by default (403 with `QODIQA_BLOCK_HTTP_MODE=status`). Perform a rolling restart to propagate the revocation to all instances.

**Note**: revoking the only active key leaves the deployment unable to sign new artifacts — recover via `POST /key-admin/:clientId/recover`. Never use graceful rotation (`rotateGracefully()` / `POST /key-admin/:clientId/rotate-graceful`) in a suspected-compromise scenario — it deliberately preserves the outgoing key's verification capability and exists only for planned, non-incident maintenance.

---

## Audit investigation

Audit entries can be looked up by artifact ID. Both endpoints require operator authentication — `Authorization: Bearer <QODIQA_OPS_TOKEN>` (or a per-operator RBAC API key) — and return `401 UNAUTHORIZED` without it.

```bash
# Look up a specific artifact's enforcement history
curl http://localhost:3000/audit/<artifact-uuid> \
  -H "Authorization: Bearer $QODIQA_OPS_TOKEN"

# Full chain integrity walk (rate-limited: 30/min)
curl http://localhost:3000/$1$OPERATOR_API_KEY"
```

`GET /audit/:artifactId` requires a UUID v4 format. Returns the execution decision, verification result, policy outcome, consent outcome, and replay history for that artifact.

`GET /audit/chain/integrity` walks the entire audit chain and returns `chainValid`, `tamperingDetected`, and a count of integrity failures.

---

## External verification tools

Artifacts can be verified independently of the running gateway using the bundled verifiers:

```bash
# Node.js (exit 0 = valid, 1 = invalid, 2 = error)
node tools/verify/verify.external.js https://qodiqa.example.com '<artifact_json>' '<request_json>'

# Python (stdlib only — no external dependencies)
python tools/verify/verify_external.py https://qodiqa.example.com '<artifact_json>' '<request_json>'
```

### Offline verification

The commands above are the **online** mode (the unchanged default): the verifier fetches the live key list from `GET /keys` before checking the signature. This means the audited server must be reachable at verification time, and it must still be running years later for a long-lived artifact to remain independently checkable — an architectural gap for anyone whose job is to verify QODIQA's own claims from the outside (an auditor, a regulator, opposing counsel in a dispute).

Both verifiers also support a fully **offline** mode: `--offline --key-file <path>`, optionally with `--bundle <path>` carrying the artifact and request. Once `--offline` is selected, neither verifier makes any network call, under any circumstance — there is no hidden fallback to the live server.

**Corrected 2026-10-09:** keys inside a `--bundle` are never trusted on their own — a bundle without `--key-file` (alias `--trusted-keys`) is refused with `TRUST_ANCHOR_REQUIRED`, and a bundle key must match the trusted key with the same id byte for byte. Artifacts live at most 60 s, so the default mode reports an archived artifact as `EXPIRED`; use `--historical` to verify it as of its own signing time (signature, request binding and key validity at signing time, against the trusted keys). Online mode requires `https://` (plain `http://` only for localhost).

**Archiving trust material while the server is still reachable.** Do this once, at (or soon after) sign time, while `GET /keys` is still reachable — not retroactively after the deployment is gone:

```bash
# Fetch and save the key list this artifact was signed under. Prefer
# /.well-known/qodiqa/keys over /keys — it additionally reports each key's
# status (active/deprecated), which /keys omits.
curl -s https://qodiqa.example.com/.well-known/qodiqa/keys -o keys.json
```

**Offline verification with a separately-archived key file:**

```bash
node   tools/verify/verify.external.js --offline --key-file keys.json '<artifact_json>' '<request_json>'
python tools/verify/verify_external.py --offline --key-file keys.json '<artifact_json>' '<request_json>'
```

**Offline verification from a single self-contained bundle.** For long-term archival, combine the artifact, the request it was bound to, and the key list into one file — this is the recommended format for a durable evidence archive, since it removes any risk of the artifact and its trust material becoming separated over time:

```bash
node -e "
  const fs = require('fs');
  const artifact = JSON.parse(fs.readFileSync('artifact.json', 'utf8'));
  const request  = JSON.parse(fs.readFileSync('request.json', 'utf8'));
  const keys     = JSON.parse(fs.readFileSync('keys.json', 'utf8')).keys;
  fs.writeFileSync('bundle.json', JSON.stringify({ artifact, request, keys }));
"

node   tools/verify/verify.external.js --offline --bundle bundle.json
python tools/verify/verify_external.py --offline --bundle bundle.json
```

The `keys.json` / bundle `keys` array uses the exact same shape the server returns from `GET /keys` or `GET /.well-known/qodiqa/keys` (`{ "keys": [ { "keyId", "publicKey", "status"? } ] }`), or a bare `[...]` array of the same entries.

**Offline mode performs identical cryptographic verification to online mode** — Ed25519 signature, canonical-JSON envelope hash, request-hash binding, expiry/timestamp bounds, and caller-attribution reporting are all unchanged; only the source of the key list differs.

**Failure modes are explicit, never a silent network fallback:**

| Condition | Reason / exit behavior |
|---|---|
| `--offline` given with neither `--key-file` nor `--bundle` | `OFFLINE_MISSING_TRUST_MATERIAL` — exit 1, no network attempted |
| `--key-file` / `--bundle` path does not exist or is unreadable | `KEY_BUNDLE_UNAVAILABLE` / `TRUST_BUNDLE_NOT_FOUND` — exit 1 |
| Key file/bundle is valid JSON but has no `"keys"` array | Clear "does not contain a `keys` array" error — exit 1 |
| `publicKeyId` not present in the supplied key list | `KEY_NOT_FOUND` — same reason code as online mode |
| Programmatic use (`require('./tools/verify/verify.external.js')` / `import verify_external`) with `offline: true` / `offline=True` and no key data supplied | `{ valid: false, reason: 'OFFLINE_TRUST_MATERIAL_MISSING' }` returned — never throws, never fetches |

This is purely additive: every existing invocation with no flags (the syntax shown at the top of this section) behaves exactly as before, and every existing script, CI pipeline, or integration that calls these verifiers online continues to work unmodified. See [](the project history) for the full remediation writeup.
