# Persistence Guidance

This document describes every persistent state store used by QODIQA, the
operational consequences of losing each store, and backup and recovery
procedures for each.

---

> **** This document was last
> substantively changed on 2026-07-30 and its inventory below omitted **PostgreSQL**
> entirely and four Redis namespaces. Both are added below (§"PostgreSQL" and the extended
> Redis table); the original text is kept. Backup/DR status is **not production-grade**
> (due-diligence…: the shipped JSON DR archive is unencrypted and its restore
> does not re-establish the chain-head pointers) — see
> before relying
> on any procedure here.

## Persistent state inventory

| Store | File / location | Backed up? | Recoverable without backup? |
|---|---|---|---|
| Key store | `data/keys.json` (`QODIQA_KEYS_PATH`) | Must be backed up | No |
| Audit log | `audit.log` (`QODIQA_AUDIT_LOG`) | Should be backed up | Partial (entries survive pod restarts; permanent loss on volume loss) |
| Audit WAL | `audit.log.wal` | Not backed up separately | Replayed automatically on restart |
| Audit checksum | `audit.log.sum` | Backed up with audit log | Rebuilt automatically from chain if absent |
| Redis nonce store | Redis key prefix `qodiqa:req:v2:` | Redis persistence (AOF) | Keys re-expire naturally; brief replay window if lost |
| Redis anomaly store | Redis key prefix `anomaly:v2:` | Redis persistence (AOF) | Counters reset on loss; brief enforcement gap |
| Redis rate limit store | Redis key prefix `ratelimit:v1:` | Redis persistence (AOF) | Counters reset on loss; brief enforcement gap |
| **PostgreSQL** | Database named by `QODIQA_PG_DATABASE`, migrations `src/infra/postgres/migrations/` 001–083 and 096–108 (96 files) | **Must be backed up** (mandatory store in production) | **No** — see [PostgreSQL] |
| Redis surface rate limiter | `rl:v2:` | Redis persistence (AOF) | Counters reset on loss |
| Redis auth lockout | `authlock:v1:` | Redis persistence (AOF) | Lockout state resets on loss |
| Redis consent cache | `qodiqa:consent:` | Not required (cache) | Yes — rebuilt from PostgreSQL on miss |
| Redis key-rotation lock | `qodiqa:key-rotation-lock:` | Not required (lock) | Yes — re-acquired |

---

## Key store (`data/keys.json`)

### What it contains

AES-256-GCM encrypted Ed25519 signing key pairs.  Each record contains the
encrypted private key (`encryptedPrivDer`), the cleartext public key
(`pubDer`), key metadata (`keyId`, `clientId`, `status`, `createdAt`,
`expiresAt`, `rotationDeadline`), and a self-test result.

### Consequence of loss

**Permanent loss of the private key means all existing signed artifacts
become unverifiable.**  QODIQA can generate new keys, but artifacts signed
with the lost key cannot be re-signed retroactively.  The `/verify/v2`
endpoint will reject any artifact referencing a key ID that is no longer in
the key store.

QODIQA will not start if `keys.json` is absent or contains no active key
(`validateStartup()` exits with code 1 and `KEY_MANAGER_READY` will not fire).

### Backup procedure

1. Back up `keys.json` to an encrypted, access-controlled location after
   every key rotation.
2. Protect the backup with the same access controls as the KEK — anyone with
   both the backup and the KEK can derive the private signing key.
3. Store the KEK (`QODIQA_KEY_ENCRYPTION_KEY`) separately from the key store
   backup.  Losing both the KEK and the key store together is irreversible.

```bash
# Example: copy to encrypted S3 with server-side encryption
aws s3 cp /opt/qodiqa/data/keys.json \
    s3://qodiqa-backups/keys/keys-$(date +%Y%m%d%H%M%S).json \
    --sse aws:kms --sse-kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY_ID
```

### Recovery procedure

1. Restore `keys.json` from backup to the persistent volume.
2. Ensure `QODIQA_KEY_ENCRYPTION_KEY` is set to the KEK that encrypted the
   restored key store.
3. Start QODIQA normally.  The startup sequence will validate the restored key
   store.

If the backup is also lost and a new key store must be created from scratch:

1. Provision a new key store: `node -e "require('./services/artifact/keyManager').rotateAsync('<client-id>').then(() => process.exit(0), (e) => { console.error(e.message); process.exit(1); })"`.
2. Update the `QODIQA_CLIENT_ID` in all artifact-issuing systems to match the
   new key.
3. Accept that all artifacts signed with the old key cannot be verified.
   Depending on your compliance requirements, this may require re-signing or
   revoking existing artifacts out-of-band.

---

## Audit log (`audit.log`)

**This section describes `QODIQA_AUDIT_ORDERING_MODE=single-node` (the
default), where the file below is authoritative.** In `distributed` mode,
PostgreSQL's `audit_chain` table (ordered by `audit_chain_head`'s row lock — "Decision Update"; the head row also carries
`tail_schema_version`, so a writer on an older audit schema is refused —
`invalid_schema_downgrade` — once the head is on a newer one, migration 098) is
authoritative instead, per-request local file writes are disabled, and
backup uses periodic `scripts/export-audit-chain-snapshot.js` snapshots
(same NDJSON + `.sum` format as below) rather than the always-on write path
described here.

### What it contains

A newline-delimited JSON file.  Each line is a cryptographically chained
enforcement decision record:

```json
{
  "timestamp": "...",
  "artifactId": "...",
  "decision": "ALLOW|BLOCK",
  "inputHash": "...",
  "signature": "...",
  "prevHash": "...",
  "hash": "..."
}
```

The `prevHash` of each entry equals the `hash` of the preceding entry
(GENESIS for the first).  The chain is verified by `/audit` endpoints and by
`verifyAuditChain()`.

A companion `.sum` file records `{ count, tailHash }` as an anti-deletion
checksum.  A companion `.wal` file is the write-ahead log — it contains at
most one in-flight entry and is automatically replayed on restart.

### Consequence of loss

- **Log truncation**: the `.sum` checksum will detect on next startup that
  `chain.length < cs.count` and throw `AUDIT_INTEGRITY_VIOLATION`.  QODIQA
  will not start.
- **Complete volume loss**: QODIQA starts with an empty chain.  All prior
  enforcement history is gone.  Compliance obligations may be breached.
- **Partial write at crash**: the WAL recovers the in-flight entry automatically
  on restart.  No entry is lost to an unplanned kill.

### Backup procedure

The audit log is append-only.  Backup strategies:

**Option 1 — Continuous streaming** (recommended for compliance):

Configure a log aggregation agent (Fluent Bit, Fluentd, the Datadog agent) to
stream the structured JSON lines to an immutable destination (S3 Object Lock,
Azure Immutable Blob Storage, Google Cloud Storage with retention policy) as
they are written.  The `.sum` file should be included.

**Option 2 — Periodic snapshot**:

```bash
# Snapshot audit log and checksum together
tar -czf audit-$(date +%Y%m%d%H%M%S).tar.gz \
    /opt/qodiqa/logs/audit.log \
    /opt/qodiqa/logs/audit.log.sum
aws s3 cp audit-*.tar.gz s3://qodiqa-backups/audit/
```

Back up both `audit.log` and `audit.log.sum` together.  Restoring only the
log without the checksum will cause QODIQA to rebuild the checksum from the
chain (safe, but loses the anti-deletion guarantee until the next entry is
written).

### Recovery procedure

1. Restore `audit.log` and `audit.log.sum` to the persistent volume.
2. Start QODIQA.  The startup IIFE in `audit-log.js` will:
   - Replay the WAL if present (safe even on a restored log).
   - Validate the chain from the beginning.
   - Verify the checksum.
3. If checksum validation fails with `AUDIT_INTEGRITY_VIOLATION`, do not start
   QODIQA against the restored log without investigation.  The failure
   indicates the log was truncated or tampered between the last backup and the
   backup point.

If the audit log is lost and cannot be recovered, the only option is to start
with an empty log.  Remove both `audit.log` and `audit.log.sum` from the
volume before starting QODIQA.  QODIQA will start with a new empty chain.

### Live integrity verification

A fourth artifact, `audit.log.verify.json`, is written next to `audit.log`
in single-node mode by the live audit chain verifier
(`src/core/audit/verifier/verifierState.js`) — a small JSON sidecar holding
the verifier's watermark (last verified position and hash), letting periodic
verification re-check only the delta since the last run instead of the
whole chain. It is a convenience cursor, never a source of truth: a missing
or corrupted `audit.log.verify.json` is not an integrity violation —  the
verifier simply re-seeds from the current, already-validated chain state on
its next run. It does not need to be included in backups, and does not need
special recovery handling; the startup watermark-continuity gate
(`src/core/audit/verifierStartupGate.js`) treats its absence the same as a
first-ever run. "Decision
Update: Live Audit Chain Integrity Verifier" and
`docs/operations/audit-chain-integrity-verification.md` for the full detail
of what this continuously verifies beyond the startup-only checks above.

In PG-authoritative (distributed) mode, the equivalent watermark lives in
the `audit_chain_verifier_state` table (migration 031) instead of a file
sidecar — no additional filesystem artifact to back up.

---

## PostgreSQL

PostgreSQL is a **primary, mandatory** persistent store, not an optional add-on:

- **Production requires it.** With `NODE_ENV=production`, a boot without PostgreSQL (or with
  an unreachable evidence store) exits with `EVIDENCE_DURABILITY_VIOLATION`.
- **Consent registry** (authoritative; Redis is only a cache). With the default policy set
  (`POL-001: REQUIRE_CONSENT`), every execution request fails closed with
  `CONSENT_STORE_UNAVAILABLE` when PostgreSQL is unavailable.
- **Audit mirror** (`audit_chain`) of the file audit chain, plus the reconcilers that compare
  them; the **transparency log** (`transparency_log_entries`, the single
  `transparency_log_head` row), **signed checkpoints**, the **evidence chain**
  (`evidence_chain_records`), **request trails**, compliance / certification / attestation
  records.
- **Control plane**: RBAC operators and API-key hashes, signing
  identities, the enforced policy set, tenants and organizations. `POLICY_FILE` /
  `policies.json` is import-only.
- **Persistence Recovery Queue** (`persistence_recovery_queue`, migration 032), with a local
  filesystem journal as its fallback.
- **Roles and isolation:** least-privilege application role `qodiqa_app` plus migration,
  retention, system, reporting and control roles created by the migrations; row-level
  security on tenant tables. RLS is keyed on a session variable the application role can
  set, so it is **not** a hard per-tenant isolation boundary against the application itself
  (due-diligence).
- **Schema level:** the repository chain ends at migration **108** (001–083 and 096–108; it was 078 when this section was written); a database at an older level
  (for example one held at 057 pending approval) lacks the PG-side evidence schema
  (v7 entries, signed checkpoints, append-only guards).
- **Growth:** about **32 KiB of PostgreSQL storage per executed request** (2026-10-09
  measurement); plan disk and retention
  accordingly.

**Consequence of loss.** Consent records, the control plane (operators, signing identities,
policies, tenants), the transparency log and the evidence chain are lost; serving stops
(consent fails closed). The file audit chain survives on its own volume, but the PostgreSQL
side of the evidence model does not.

**Backup / recovery.** Use PostgreSQL-native backups (`pg_dump` / base backups) taken with
an identity that can read every table, stored encrypted and off-site, and test a restore.
No production-grade, restore-tested backup path ships with the repository:
the JSON DR export's restore does not re-establish chain-head pointers, so
an append after such a restore would fork the evidence chains. See
`docs/operations/backup-runbook.md` and `docs/operations/restore-runbook.md`, read together.

---

## Redis stores

### What they contain

> **** The three-store table below is incomplete. The full set of Redis key
> namespaces in current source is:
>
> | Prefix | Store | Failure mode |
> |---|---|---|
> | `qodiqa:req:v2:` | Nonce / replay (`src/validation/nonceStore.js`) | Fail closed; no in-memory fallback. A restart barrier refuses artifacts issued before Redis started (`REPLAY_STATE_UNPROVABLE`) |
> | `anomaly:v2:` | Anomaly windows (`src/validation/anomalyStore.js`) | Fail closed |
> | `ratelimit:v1:` | Policy `RATE_LIMIT` (`services/policy/store.js`) | Fail closed |
> | `rl:v2:` | Surface rate limiter (`src/core/rateLimit/storage.js`) | Fail closed; public read surfaces degrade to a per-process limiter with a CRITICAL alert |
> | `authlock:v1:` | Auth lockout (`src/core/authLockout/storage.js`) | Fail closed |
> | `qodiqa:consent:` | Consent cache (`src/core/consent/ConsentCache.js`) | Optional; a miss falls through to PostgreSQL |
> | `qodiqa:key-rotation-lock:` | Key-rotation lock with fencing token (`src/infra/keys/rotationLock.js`) | Fail closed |
>
> Idempotency, the org-status store and the revocation / org-status pub/sub channels also use
> Redis. Redis Sentinel / Cluster failover has never been exercised.

Three logical stores share the same Redis instance (or cluster):

| Store | Key prefix | Data type | TTL |
|---|---|---|---|
| Nonce store | `qodiqa:req:v2:<requestId>` | String (SET NX PX) | Derived from artifact expiry |
| Anomaly store | `anomaly:v2:key:<keyId>`, `anomaly:v2:global` | Sorted set | Window duration + 1s |
| Rate limit store | `ratelimit:v1:<key>` | String (INCR) | Window duration |

All keys carry TTLs and self-prune.  Redis holds no permanent state — all
content is time-bounded enforcement context.
(2026-10-09: the authoritative permanent state is in the key store, the audit log and
**PostgreSQL** — see above.)

### Consequence of loss

**Nonce store loss**: nonces registered before the loss are gone.  Any
attacker who captured a request before the Redis loss can replay it
successfully after the loss.  The replay window is bounded by the artifact's
expiry time.

**Anomaly store loss**: per-key and global anomaly counters reset.  Anomaly
detection resumes from zero — a burst that was in progress before the loss
will not be blocked until the counter is rebuilt over the sliding window.

**Rate limit store loss**: rate limit counters reset.  Clients whose windows
were partially consumed start fresh.

None of these losses affect the audit log or key store.  QODIQA will
continue operating but with a brief enforcement gap.

### Redis persistence requirements

QODIQA validates Redis persistence at startup under `STRICT_REPLAY_PROTECTION`,
which **defaults to `true`** (it is only `false` if explicitly set to the
literal string `false`). By default, an unsafe or unconfirmed persistence
result refuses startup (`process.exit(1)`) rather than merely warning.
The required configuration is AOF with `appendfsync everysec` (or `always`).

```
appendonly yes
appendfsync everysec
```

This limits the nonce replay window on Redis failure to at most one second of
registrations.

RDB-only persistence (`save N M` without AOF) is not sufficient.  The last
RDB snapshot may be minutes old, meaning a failure opens a multi-minute replay
window.

**ElastiCache limitation**: ElastiCache does not support `CONFIG GET` — QODIQA
cannot verify AOF at startup, and a failed `CONFIG GET` is treated as unsafe.
Since `STRICT_REPLAY_PROTECTION` defaults to `true`, this means QODIQA will
refuse to start against ElastiCache by default unless you have confirmed AOF
is active in the parameter group and explicitly set
`STRICT_REPLAY_PROTECTION=false` to bypass the unverifiable check. See
`docs/deployment/redis-persistence.md`.

### Backup procedure

Redis persistence (AOF file) is the primary durability mechanism.  Back up
the AOF file if you need point-in-time recovery beyond what AOF replay
provides:

```bash
# Trigger a background AOF rewrite to compact the file before backup
redis-cli BGREWRITEAOF

# Copy the compacted AOF file
aws s3 cp /var/lib/redis/appendonly.aof \
    s3://qodiqa-backups/redis/appendonly-$(date +%Y%m%d%H%M%S).aof
```

For Sentinel or Cluster deployments, replicas provide continuous durability.

### Recovery procedure

**Short interruption (< artifact expiry)**:

1. Restart Redis with the existing AOF file.  QODIQA reconnects automatically
   with bounded exponential backoff (up to 5 retries).
2. The AOF replay recreates the nonce, anomaly, and rate limit state as of
   the last fsync.

**Redis volume loss**:

1. Start Redis with an empty data directory.
2. QODIQA reconnects.  All stores start empty.
3. Accept the nonce replay window for the duration of the oldest live
   artifact's remaining expiry period.
4. After all pre-failure artifacts have expired, the system returns to full
   replay protection.

---

## Persistence architecture summary

```
┌─────────────────────────────────────────────────────┐
│  Persistent volume (per QODIQA instance)            │
│                                                     │
│  data/keys.json          ← signing key store        │
│  logs/audit.log          ← enforcement audit chain  │
│  logs/audit.log.sum      ← anti-deletion checksum   │
│  logs/audit.log.wal      ← write-ahead log (transient) │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  Redis (shared across all QODIQA instances)         │
│                                                     │
│  qodiqa:req:v2:*         ← nonce store (TTL-bound)  │
│  anomaly:v2:*            ← anomaly counters (TTL)   │
│  ratelimit:v1:*          ← rate limits (TTL)        │
└─────────────────────────────────────────────────────┘
```

The key store and audit log must survive pod restarts.  Mount them on
persistent storage in every deployment topology.  Losing either without a
backup is irrecoverable.
