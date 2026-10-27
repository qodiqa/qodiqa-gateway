# Deployment Lifecycle

This document describes the complete operational lifecycle of a QODIQA
deployment: first deployment, upgrades, rollbacks, policy updates, restarts,
failover, and recovery.  All guidance reflects the current runtime behavior.

---

## Prerequisites for any deployment

Before the QODIQA process can start, the following must be true:

| Prerequisite | Verified by |
|---|---|
| `QODIQA_KEY_ENCRYPTION_KEY` is set to a 64-hex-char value | `SECRET_VALIDATION_OK` log event at startup |
| `OPENAI_API_KEY` is set to a real API key | `SECRET_VALIDATION_OK` |
| `QODIQA_CLIENT_ID` is set to a meaningful identifier | `SECRET_VALIDATION_OK` |
| At least one active signing key exists in `data/keys.json` | `KEY_MANAGER_READY` with `activeKeys ≥ 1` |
| `policies.json` parses successfully | `POLICIES_LOADED` |
| `NODE_ENV=production` is set | Env var present in deployment config |

If any prerequisite fails, the process exits with code 1 and a `FATAL` log event.
The container or task will restart.  Fix the configuration before redeploying.

Two secrets are required for correct operation but are **not** boot prerequisites — the
process starts without them, only specific requests fail:
- `QODIQA_EXECUTION_INVARIANT_SECRET`: not startup-gated; the `/ai/chat` EXECUTE path
  fails the first time it's reached without it.
- A provisioned signing identity: there is no `QODIQA_SIGN_TOKEN` shared secret to check
  at startup. The process starts fine with zero signing identities and `POST /sign`
  correctly returns `401 UNAUTHORIZED` until at least one identity is provisioned — see
  `docs/configuration/reference.md`.

---

## First deployment

### Step 1 — Provision the key store

The key store must be initialized before the first start.  The `rotate()`
function creates the first Ed25519 signing key pair, encrypts the private key
with the KEK, and writes `data/keys.json`.

<!-- "provisioning host" below means a real repository checkout (with
     `npm install` already run) — a CI runner, bastion host, or operator
     workstation with the code cloned. It does NOT mean `docker run` against
     the built/deployed qodiqa image. Reproduced directly: `services/` (used
     by the command below and by "Provision the consent-signer key" further
     down) IS shipped in the production image, so running it via
     `docker run --entrypoint node qodiqa:<tag> -e "..."` happens to also
     work — but `scripts/` (used by the equivalent, idempotent
     `scripts/provision-consent-signer.js` and
     `scripts/provision-signing-identity.js` documented in docs/guides/quickstart.md) is
     entirely excluded from the built image by `.dockerignore` (deliberate
     image-hygiene, not a defect) and throws `Cannot find module` if invoked
     the same way. Confirmed: the same script succeeds immediately when run
     from a real checkout instead. If you reach for one of the `scripts/*.js`
     utilities referenced elsewhere in this repository's docs, run it from a
     checkout, not against the container image. -->

```bash
# On a provisioning host with QODIQA_KEY_ENCRYPTION_KEY set:
QODIQA_KEY_ENCRYPTION_KEY=<64-hex-char-kek> \
QODIQA_KEYS_PATH=/opt/qodiqa/data/keys.json \
  node -e "require('./services/artifact/keyManager').rotateAsync('<your-client-id>').then(() => process.exit(0), (e) => { console.error(e.message); process.exit(1); })"
```

<!--: the earlier one-liner `...rotate('<id>')` created the key but never exited in a
     PostgreSQL-enabled environment. Loading the key store starts control-plane clients that keep the event loop alive;
     reproduced with the release image, exit 137 after a manual stop. `rotateAsync` also waits until the new key-status
     timeline is in the control plane, so the explicit exit cannot drop it. The rotation mode is the same as
     `rotate` (emergency default), which is the correct mode for a first key. -->

<!-- corrected from the previous `.rotateKey(...)` example, which does
     not exist on this module's exports (keyManager.js exports `rotate`, not
     `rotateKey` — `rotateKey` is the separate lower-level function it wraps
     internally from services/artifact/keyStore.js). Reproduced independently
     by running the previous example verbatim against a fresh key-store
     volume: it threw `TypeError: require(...).rotateKey is not a function`
     and left the process unable to complete the documented first-boot
     sequence. Verified the corrected command above against the same fresh
     volume: it succeeds and QODIQA subsequently boots past the
     KEYSTORE_EMPTY fatal check. -->

The resulting `data/keys.json` must be placed on the persistent volume before
QODIQA starts.  In Kubernetes, copy it to the PVC after provisioning.  In ECS
with EFS, write it to the EFS access point.

**Key store provisioning is a one-time operation per deployment.**  Subsequent
key rotations are performed with the server running (see Key Rotation below).

### Step 2 — Apply database migrations

**Required before the first start whenever `QODIQA_DEPLOYMENT_MODE=distributed`
(this repository's Docker Compose and Kubernetes reference topologies both use
it) — do not rely on `QODIQA_PG_AUTO_MIGRATE=true` alone for a genuinely fresh
database.** The production evidence-durability gate (
`server/startup.js`, "Production evidence-durability gate") runs *before* the
distributed-mode auto-migration check, by design — it is deliberately the
first gate in `startServer()` so a misconfigured deployment fails in the
cheapest possible way. The consequence: on a database that has never had any
migration applied, that gate always fails closed with FATAL
`EVIDENCE_DURABILITY_VIOLATION` (`consent_records` / `transparency_log_entries`
/ `evidence_chain_records` do not exist yet) before the code path that would
auto-apply migrations is ever reached. `QODIQA_PG_AUTO_MIGRATE=true` still
works for routine *upgrades* against an already-migrated database (see
"Docker Compose Production Deployment" in
`docs/operations/deployment-runbook.md`) — it just cannot bootstrap the very
first migration by itself.

Apply migrations explicitly instead, against a real superuser for this one
first run (`migrate.js` normally connects as the dedicated `qodiqa_mig` role,
which migration 002 itself creates — it does not exist yet on a virgin
database):

```bash
QODIQA_PG_HOST=<host> QODIQA_PG_PORT=5432 QODIQA_PG_DATABASE=<database> \
QODIQA_PG_MIG_USER=<a superuser, e.g. the database's own bootstrap admin> \
QODIQA_PG_MIG_PASSWORD=<that superuser's password> \
  node src/infra/postgres/migrate.js
```

Subsequent runs (upgrades) may omit `QODIQA_PG_MIG_USER`/`QODIQA_PG_MIG_PASSWORD`
and rely on the default `qodiqa_mig` identity migration 002 created, or on
`QODIQA_PG_AUTO_MIGRATE=true` at startup as already documented above.

<!-- this step did not previously exist in this document. Discovered
     and independently reproduced by rehearsing a genuinely fresh-volume
     provisioning (a scenario no prior task in this series had exercised,
     since every earlier local test stack reused an already-migrated
     volume): QODIQA_PG_AUTO_MIGRATE=true alone left the database with zero
     tables and the application permanently crash-looping on
     EVIDENCE_DURABILITY_VIOLATION. Root-caused via server/startup.js's own
     ordering (the evidence gate is explicitly commented as running first).
     Verified the fix: running the command above against the same fresh
     database applied all 57 pending migrations, and QODIQA subsequently
     booted past the evidence-durability gate on the next start. -->

### Step 3 — Configure secrets

Inject all required environment variables via your secret management service.
Never use a plain `.env` file in production.

```bash
# AWS Secrets Manager example
aws secretsmanager put-secret-value \
    --secret-id /qodiqa/prod/kek \
    --secret-string "$(openssl rand -hex 32)"
```

### Step 4 — Start the service

Deploy the container.  Observe the startup log sequence:

```
ENV_VALIDATION_OK
SECRET_VALIDATION_OK
KEY_MANAGER_READY           { activeKeys: 1 }
POLICIES_LOADED             { count: N }
STARTUP_DIAGNOSTICS
CLOCK_DIAGNOSTICS
REDIS_AUTH_CONFIGURED
REDIS_TLS_ENABLED           { tlsVerified: true }
NONCE_STORE_READY
ANOMALY_STORE_READY
RATE_LIMIT_STORE_READY
REDIS_PERSISTENCE_VALIDATED
REDIS_AUTH_VALIDATED
GATEWAY_RUNTIME_READY       { executionIntegrity: "FULL" }
GATEWAY_STATE_READY
GATEWAY_START               { port: 3000, ready: true }
```

The service is ready to receive traffic only after `GATEWAY_START` with
`ready: true`.  The load balancer's readiness probe (`GET /ready → 200`) gates
traffic automatically.

### Step 5 — Verify the deployment

```bash
# Liveness
curl http://qodiqa:3000/health
# → { "status": "ok", "uptime": N }

# Readiness
curl http://qodiqa:3000/ready
# → { "ready": true, "components": { "nonceStore": true, ... } }

# Public key availability
curl http://qodiqa:3000/public-key
# → { "keyId": "...", "publicKey": "..." }
```

<!-- `/public-key` (src/api/routes/public-key.js) is hardcoded to resolve
     the fixed identity `consent-signer`, not `QODIQA_CLIENT_ID`'s value —
     Step 1 above only provisions `<your-client-id>`. On a genuinely fresh
     deployment that follows Step 1 as written, this command returns
     `{"status":"error","error":{"code":"KEY_UNAVAILABLE", ...}}`, not the
     shape shown above. Reproduced directly against a fresh key store.
     `consent-signer` must be provisioned as a SEPARATE identity before this
     check can pass: -->

```bash
# Required before Step 5's /public-key check will succeed — a separate
# identity from <your-client-id>, used specifically for consent-record
# signing (src/api/routes/public-key.js):
QODIQA_KEY_ENCRYPTION_KEY=<64-hex-char-kek> \
QODIQA_KEYS_PATH=/opt/qodiqa/data/keys.json \
  node -e "require('./services/artifact/keyManager').rotateAsync('consent-signer').then(() => process.exit(0), (e) => { console.error(e.message); process.exit(1); })"
```

---

## Upgrade deployment

QODIQA supports zero-downtime upgrades via rolling replacement, subject to the
constraints.

> **Not in production today.** Production runs the single-node StatefulSet with `replicas: 1`
> (`deploy/kubernetes/overlays/single-node/statefulset.yaml`); the distributed overlay is refused at production boot
> until (`src/infra/config/bootValidator.js`). With one replica the old pod stops before the new one starts, so
> an upgrade is a brief full outage. The multi-pod sequences below (rolling, canary, ECS) apply to non-production
> multi-instance evaluation only.

### Rolling upgrade sequence (Kubernetes)

1. Update the image tag in the Deployment manifest.
2. Apply the change: `kubectl apply -f deploy/kubernetes/overlays/distributed/deployment.yaml` (or `overlays/single-node/statefulset.yaml`, whichever topology is deployed)
3. Kubernetes starts a new pod with the new image.
4. The new pod runs through the full startup sequence.
5. The new pod's readiness probe (`/ready`) must return 200 before Kubernetes
   routes traffic to it.
6. Kubernetes sends `SIGTERM` to one old pod.
7. The old pod sets readiness to false (removed from Service endpoints), drains
   in-flight requests, closes Redis connections, and exits cleanly.
8. Kubernetes repeats until all old pods are replaced.

**Key store compatibility**: the encrypted key store format has not changed
between versions.  A running instance and a new instance can share the same
`keys.json` PVC safely — both instances read the same keys but neither writes
during normal operation (key rotation is an admin operation).

**Audit log during upgrade**: if multiple instances share a persistent volume
(Topology B — single instance), there is no concurrent write issue.  If
instances have separate audit logs (Topology C/D), each instance manages its
own log independently. for the audit log single-writer
constraint.

This entire paragraph describes `QODIQA_AUDIT_ORDERING_MODE=single-node`
(the default, `deploy/kubernetes/overlays/single-node/`). In `distributed` mode
(`deploy/kubernetes/overlays/distributed/deployment.yaml`),
audit ordering has no per-instance state to worry about during a rolling
upgrade — PostgreSQL's `audit_chain_head` row lock serializes appends across
whichever replicas happen to be running at any point in the rollout. "Decision Update" section.

**Redis state during upgrade**: Redis state (nonces, anomaly counters, rate
limits) is preserved across pod restarts.  No nonce state is lost.

### Rolling upgrade sequence (ECS)

1. Register a new task definition with the updated image.
2. Update the ECS service: `aws ecs update-service --task-definition qodiqa:NEW`.
3. ECS launches new tasks, waits for ALB health check (`/ready → 200`).
4. ECS drains old tasks: sends `SIGTERM`, waits `stopTimeout`, then deregisters.

### Canary upgrades

For higher-risk changes, deploy one pod at a time:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 0
    maxSurge: 1      # One new pod at a time
```

Watch the startup log sequence and `/ready` state of the new pod before
allowing the rollout to proceed.

---

## Rollback

### Kubernetes rollback

```bash
# Production: the single-node StatefulSet (the distributed overlay's deployment/qodiqa is non-production only)
kubectl rollout undo statefulset/qodiqa -n qodiqa

# Roll back to a specific revision
kubectl rollout history statefulset/qodiqa -n qodiqa
kubectl rollout undo statefulset/qodiqa --to-revision=N -n qodiqa
```

The old image is used for new pods.  Kubernetes does not roll back automatically: a rollout whose pod never becomes
ready stalls and must be undone as above. A rollback never undoes applied database migrations (additive only) —
see `docs/operations/rollback-runbook.md`. (previously targeted `deployment/qodiqa` and described an
automatic "deployment circuit breaker".)

### ECS rollback

```bash
# Revert to the previous task definition revision
aws ecs update-service \
    --cluster qodiqa-cluster \
    --service qodiqa \
    --task-definition qodiqa:PREVIOUS_REVISION
```

Enable `deploymentCircuitBreaker.rollback: true` in the ECS service to trigger
automatic rollback when new tasks fail to reach a healthy state.

### Rollback constraints

- **Key store**: rollbacks do not affect the key store.  Keys provisioned by
  a newer version remain valid after rollback.
- **Audit log**: entries written by the newer version remain in the audit log
  after rollback.  The chain is not affected — the older version reads and
  continues from the existing chain tail.
- **Redis nonces**: nonces registered by the newer version remain registered
  after rollback.  Replay protection is continuous across version boundaries.

---

## Policy-only update (no restart required)

 policy is changed through the policy API (governance workflow,
`docs/guides/policy-governance.md`); the enforced set lives in the control plane and `policies.json` is
import-only — editing it changes nothing. SIGHUP forces an immediate re-read of the control plane
(`server/startup.js` SIGHUP handler):

```bash
# Kubernetes (production: the single-node StatefulSet, pod qodiqa-0)
kubectl exec -n qodiqa qodiqa-0 -- kill -HUP 1
```

After SIGHUP, the log emits `POLICIES_RELOADED` (`source: "control-plane"`).  If the re-read fails, it emits
`POLICY_RELOAD_FAILED` and continues using the previous policy set.  No downtime occurs.

**Multi-instance policy updates**: in deployments with multiple instances,
SIGHUP must be sent to each instance individually, or a rolling restart must
be performed.  There is a brief window where different instances run different
policy versions.

---

## Restart scenarios

### Planned restart (e.g. configuration change)

1. Send `SIGTERM` to the process (Kubernetes rollout, `docker restart`,
   ECS task stop).
2. The process executes the ordered shutdown sequence (see
   `docs/deployment/startup-and-probes.md`).
3. In-flight requests complete.  Redis connections close cleanly.
4. Process exits with code 0.
5. Orchestrator starts a new instance.
6. New instance runs the full startup sequence.

**Impact**: requests in flight at the moment of SIGTERM complete normally.
New requests after SIGTERM receive 503 `SERVICE_SHUTTING_DOWN`.  The load
balancer removes the pod from rotation as soon as `/ready` returns 503
(typically within one probe interval — 5 seconds in the reference config).

### Unplanned restart (OOM kill, SIGKILL, node failure)

1. The process terminates immediately without cleanup.
2. In-flight requests are interrupted at the OS level.
3. Redis connections are dropped — Redis will detect TCP reset and clean up
   client state.
4. Audit log: any entry being written at the moment of the kill is protected by
   the WAL.  On restart, the WAL recovery mechanism replays the entry if it was
   not committed to the main log before the kill.
5. Orchestrator restarts the container.

**Audit log WAL safety**: `audit-log.js` writes to `audit.log.wal` before
writing to `audit.log`.  On startup, the WAL is replayed if not already
committed.  No entry is lost to an unplanned kill between the WAL write and the
main-log append.

**Redis nonce state**: nonces registered before the kill remain registered in
Redis.  No replay window is opened by an unplanned restart of QODIQA.

---

## Failover scenarios

### Redis unavailable

QODIQA detects Redis unavailability within `REDIS_CONNECT_TIMEOUT_MS` (default
5s).  Behavior:

- `/ready` returns 503 — load balancer removes the pod from rotation.
- `/ai/chat` returns `BLOCK` (`NONCE_STORE_ERROR`) — fail-closed, no execution.
- `/verify/v2` and `/sign` continue to function (no Redis dependency).
- QODIQA attempts reconnection with bounded exponential backoff (up to 5 retries).
- After successful reconnect, `/ready` returns 200 and the load balancer
  reintroduces the pod.

**Operator action**: monitor `REPLAY_PROTECTION_DEGRADED` log events.  If Redis
failover is expected to take more than a few seconds, scale down QODIQA to zero
replicas or configure the load balancer to route away from all pods until Redis
recovers.

### Redis primary failover (Sentinel/Cluster)

Redis Sentinel promotes a replica to primary.  During the promotion window
(typically < 10 seconds), Redis is unavailable.  QODIQA behavior is identical
to Redis unavailable above.

After promotion, QODIQA reconnects to the new primary.  The connection URL
must resolve to the new primary — use a Redis Sentinel-aware client URL or a
DNS name that updates on failover.

### Node/host failure (Kubernetes pod eviction)

The pod is evicted.  The orchestrator starts a replacement pod on another node.
The replacement pod runs the full startup sequence.  The key store and audit log
PVCs reattach to the new pod (subject to the access mode and storage class).

---

## Key rotation

Key rotation creates a new active signing key pair. What happens to the
previous key depends on the mode, which the caller must always pass
explicitly (see the note below) — the `/key-admin/:clientId/rotate`
HTTP endpoint (see the [Key Compromise Runbook](../operations/key-compromise-runbook.md))
hardcodes `mode: 'emergency'`, matching the guidance below that emergency is
the operator's usual intent; a caller of the lower-level `keyManager.rotate()`
function directly (as in the two commands below) must supply the same mode
itself.

<!-- `rotate(clientId)` with no second argument only works for the
     FIRST-EVER key for a client (Step 1 above, `_provisionFirstKey`'s code
     path). Once a key already exists, `keyManager.rotate()` passes `opts`
     straight through, unmodified, to `keyStore.js`'s `rotateKey()`, whose
     `_resolveRotationMode()` throws `TypeError: rotateKey: opts.mode is
     required ... There is no default mode` if `opts.mode` is
     missing — it does NOT default to 'emergency' despite this module's own
     header comment on `rotate()` claiming it does (that comment is itself
     corrected in the same change as this doc fix). Reproduced directly:
     the command below without `{ mode: 'emergency' }` throws on any
     already-provisioned client. -->

```bash
# With QODIQA running, trigger EMERGENCY rotation (for a suspected key
# compromise; the previous key is REVOKED within QODIQA, losing signing
# AND verification capability in this one call). The mode must be passed
# explicitly — there is no default:
QODIQA_KEY_ENCRYPTION_KEY=<kek> \
QODIQA_KEYS_PATH=/opt/qodiqa/data/keys.json \
  node -e "Promise.resolve(require('./services/artifact/keyManager').rotate('<client-id>', { mode: 'emergency' })).then(() => process.exit(0), (e) => { console.error(e.message); process.exit(1); })"

# Trigger GRACEFUL rotation instead (planned maintenance only — never for a
# suspected compromise; the previous key is deprecated, not revoked, and
# stays verifiable for the rest of its 180-day artifact lifetime):
QODIQA_KEY_ENCRYPTION_KEY=<kek> \
QODIQA_KEYS_PATH=/opt/qodiqa/data/keys.json \
  node -e "Promise.resolve(require('./services/artifact/keyManager').rotateGracefully('<client-id>')).then(() => process.exit(0), (e) => { console.error(e.message); process.exit(1); })"
```

After **emergency** (`{ mode: 'emergency' }`, the operator's usual choice — see above) rotation:
- The new key is used for all subsequent `/sign` requests immediately.
- The old key is now `revoked` — QODIQA can no longer sign or verify with it. **For a Vault Transit / HSM-backed key, this QODIQA-side guarantee does not by itself confirm the key is also disabled at the external provider** — see `docs/security/key-management.md`'s "External Key Providers (Vault Transit / HSM / KMS)" section and the [Key Compromise Runbook](../operations/key-compromise-runbook.md) for the required provider-side step.

After **graceful** (explicit opt-in) rotation:
- The new key is used for all subsequent `/sign` requests immediately.
- The old key is kept as `deprecated` and continues to verify artifacts.

In both modes: an out-of-process rotation (the script above) is picked up by the
rotation scheduler's periodic `keys.json` reload (default every 5 min —
`QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS`, see docs/security/key-management.md) or immediately by
a restart. SIGHUP does **not** reload the key store.

**Coordination requirement**: key rotation writes to `keys.json`.  If multiple
instances share the same `keys.json` path (Topology B), rotation must be a
single sequential operation.  Do not run concurrent rotations.

---

## Maintenance windows

QODIQA supports maintenance without downtime for most operations:

| Operation | Downtime | Method |
|---|---|---|
| Image upgrade | Brief full outage in production (one replica); none only in non-production multi-pod evaluation | Rolling update |
| Policy update | None | Policy API (control plane); SIGHUP forces an immediate re-read |
| Key rotation | None | `/key-admin` or the scheduler (in-process, immediate); admin script picked up by the periodic key reload — SIGHUP does not reload keys |
| Signing identity rotation | None | Issue a new API key via `POST /signing-identities/:id/api-key`; revoke or disable the old identity — no restart needed, resolved per-request from the store |
| Secret rotation (EXECUTION_INVARIANT_SECRET) | Brief (rolling restart) | Update secret, rolling restart |
| Secret rotation (KEK) | Requires re-encryption | Key store migration; full restart |
| Redis upgrade | Brief (Redis restart) | QODIQA blocks fail-closed during Redis unavailability |
| TLS certificate rotation | None (rolling restart) | Update certs, rolling restart |
| Provider model catalog refresh | None (env var) or rolling restart (code change) | See "Provider model catalog maintenance" below |

Secret rotation for `QODIQA_EXECUTION_INVARIANT_SECRET` requires a rolling restart
because `services/secrets/secretsProvider.js`'s `getExecutionInvariantSecret()` caches
the loaded value for the process lifetime after its first call. Update the secret in
your secret manager and perform a rolling restart.

There is no `QODIQA_SIGN_TOKEN` to rotate — `POST /sign` authenticates callers via
individually-issued signing identities instead (see the row above).

---

## Provider model catalog maintenance

Run this checklist at every release, and whenever a provider announces a model catalog
change (new model, deprecation, or retirement). Provider model allowlists and default
models are defined in `services/providers/config.js` — see that file's module doc
comment and `docs/guides/providers.md` §6 "Model allowlist extensibility and default model" for
the full mechanism this checklist exercises.

1. **Review each enabled provider's live model catalog** against
   `services/providers/config.js`'s built-in `allowedModels` for that provider (openai,
   anthropic, gemini, mistral — llama/local are deployment-specific and intentionally
   unrestricted, see below). Check the provider's own documentation/changelog for models
   added, deprecated, or retired since the last review.
2. **For a newly-introduced model your deployment needs immediately, without waiting for
   a code change**: set `PROVIDER_ALLOWED_MODELS_EXTRA_<PROVIDER_NAME>` (comma-separated)
   to add it — no restart-blocking code review required, and the built-in baseline is
   never weakened (additive only). Land the equivalent code change (add it to
   `config.js`'s built-in Set) at the next convenient release so the env var override
   becomes unnecessary going forward.
3. **For a model your deployment will never use, or one the provider has retired**: leave
   it in `config.js`'s built-in Set unless you are certain no in-flight or cached client
   integration references it — removing a built-in entry is a code change with its own
   review, not something this checklist automates. There is no env-var mechanism to
   remove a built-in entry, so retirement is always a
   deliberate `config.js` edit.
4. **Verify the environment/policy additive extension, if any is configured**: confirm
   `PROVIDER_ALLOWED_MODELS_EXTRA_<PROVIDER_NAME>` (if set in this deployment's
   environment) still names models the provider actually serves — an entry for a model
   the provider has since retired is harmless (it simply never matches a real response)
   but is worth cleaning up.
5. **Review the configured default model, if one remains** — currently only `openai` ships
   a non-null built-in default (`gpt-3.5-turbo`); confirm it is still a model you want
   silently selected for a request that omits `model`, or override it via
   `PROVIDER_DEFAULT_MODEL_OPENAI`. If any other provider has an operator-configured
   default (`PROVIDER_DEFAULT_MODEL_<PROVIDER_NAME>`), confirm it too is still current.
   **This step is partially self-enforcing**: `config.js` fails the whole module load at
   startup if a configured default is not a member of its own provider's effective
   allowlist, so a default that silently went stale relative to an allowlist edit is
   caught at boot, not discovered later as a confusing per-request failure — but the
   *choice* of default (is `gpt-3.5-turbo` still the right one?) is a judgment call this
   checklist item exists to prompt, not something the assertion can decide for you.
6. **Run the provider validation test suite** — at minimum
   `npx jest services/providers/__tests__/config.test.js services/providers/__tests__/modelValidation.test.js`
   plus each provider's own dedicated suite
   (`services/providers/__tests__/{openai,anthropic,gemini,mistral,llama,local}.test.js`
   and their `.stream.test.js` counterparts) — before shipping any `config.js` change.
7. **Update `docs/guides/providers.md` (§7–§12 per-provider tables) and `docs/api/overview.md`**
   (the `POST /ai/chat` request-body `model` field description) whenever the public model
   catalog or default-model behavior changes — both documents list every provider's exact
   built-in allowlist and default, and go stale exactly like the code they describe if
   left unedited.
