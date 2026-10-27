# QODIQA Key Management

This document is the authoritative reference for the QODIQA key lifecycle. It covers active key identification, rotation, archival, emergency revocation, ownership, and the deterministic key selection model. All procedures described here are implemented in the codebase; where a section carries a dated status or an open tracker note, that note is the current state.

This document is scoped to the Ed25519 signing key lifecycle. The underlying KEK — and every other encrypted-at-rest secret class that shares it, including webhook signing secrets — is covered in [`docs/security/secrets-management.md`](secrets-management.md#key-encryption-key-kek-lifecycle).

---

## Key Inventory

### Live keystore

| File | Purpose |
|---|---|
| `data/keys.json` (default) | Live key store — all active, deprecated, and revoked keys |
| `data/key-archive.json` (default) | Immutable archive of purged key metadata |

Both paths are overridable via environment variables:

```
QODIQA_KEYS_PATH=<absolute-path-to-keys.json>
QODIQA_KEYS_ARCHIVE_PATH=<absolute-path-to-key-archive.json>
```

In production these paths must resolve outside the application directory (enforced at startup when `NODE_ENV=production`).

### Key schema

Every key record in `keys.json` carries the following fields:

| Field | Active | Deprecated | Revoked |
|---|---|---|---|
| `clientId` | ✓ | ✓ | ✓ |
| `keyId` | ✓ | ✓ | ✓ |
| `version` | ✓ | ✓ | ✓ |
| `algorithm` | `ed25519` | `ed25519` | `ed25519` |
| `publicKeyDer` | ✓ | ✓ | ✓ |
| `status` | `active` | `deprecated` | `revoked` |
| `createdAt` | ✓ | ✓ | ✓ |
| `retiredAt` | — | ✓ (set only by graceful-mode rotation) | — |
| `rotationDeadline` | ✓ | — | — |
| `expiresAt` | ✓ | — | — |
| `encryptedPrivateKeyDer` | ✓ (AES-256-GCM) | never | never |

Private key material is present in memory only for `active` keys. On rotation or revocation, private material is discarded immediately.

**Authenticated records.** Every save also writes a file-level
`recordSeal` marker and a per-record `recordMac` (HMAC-SHA256 under an HKDF subkey of the KEK, over the record's
public fields, its client bucket and map key, the trust domain and a digest of its encrypted private key), and
encrypts the active private key with AES-GCM AAD = the record identity (`encryptedPrivateKeyDer.aad`). The same applies
to `transparency-keys.json` and `checkpoint-keys.json`. A sealed file with a missing or invalid MAC is refused
(CRITICAL `KEY_RECORD_MAC_REFUSED`; FATAL at boot, live store kept at reload); a legacy file is sealed once at boot
(WARN `KEY_RECORDS_SEALED`, trust on first use) unless `QODIQA_KEYSTORE_REQUIRE_SEALED=true`. Editing a key file by
hand therefore requires the KEK (`sealFileData()` in `src/infra/crypto/keyRecordSeal.js`). Rolling back to code older
than K1 after the first sealed save cannot decrypt the AAD-bound private keys (fail closed) — roll forward instead.
See docs/security/cryptography.md §3.2a.

---

## Key Classification

Every key in the system is assigned exactly one classification:

| Classification | Criteria | Signing | Verification |
|---|---|---|---|
| `ACTIVE` | `status === 'active'` and not expired | Yes | Yes |
| `DEPRECATED` | `status === 'deprecated'` and within retention window | No | Yes |
| `PURGE_ELIGIBLE` | `status === 'deprecated'` and past retention window | No | No (artifacts expired) |
| `REVOKED` | `status === 'revoked'` | No | No |

`DEPRECATED` is a verifiable-but-non-signing status that exists **only** for an explicit, planned migration — see [`rotateKeyGracefully()`](#rotation-procedure) below. It is never the result of ordinary rotation. An operator's default `POST /key-admin/:clientId/rotate` call moves the outgoing key straight to `REVOKED` — see "Rotation Procedure."

To retrieve the live classified inventory:

```
GET /key-admin/inventory
```

No key may remain unclassified. The `getInventory()` function in `keyStore.js` classifies every key in the live store at query time.

---

## Active Key Identification

### One active key per client

The system enforces a structural invariant: **exactly one active key per client**. This is checked at startup by `validateKeyStore()` and enforced by `rotateKey()`. Violating this invariant causes startup to abort.

### How the runtime selects the active key

The signing path calls `keyManager.getSigningKey(clientId)` → `keyStore.getActiveKey(clientId)`. This function:

1. Validates `clientId` format.
2. Iterates all key records for the client.
3. Selects the record with `status === 'active'`.
4. Throws `KEY_EXPIRED` if the active key's `expiresAt` is in the past.
5. Returns `{ keyId, privDer, pubDer, clientId }`.

The `clientId` for signing operations is taken from `QODIQA_CLIENT_ID` (set at deployment time). The runtime never selects keys by ordering, pattern, or implicit fallback.

### Clients with no active key

Clients that have existing key history but no active key (all deprecated or revoked) are in a `CRITICAL` state. Startup will auto-recover via `ensureActiveKey()` → `rotateKey()`, which now handles the no-active-key case by provisioning a new key at `max(existing_version) + 1`.

Operators can also recover manually:

```
POST /key-admin/:clientId/recover
```

This call is idempotent-safe: it rejects with `409 ALREADY_HAS_ACTIVE_KEY` if the client already has an active key.

---

## Key Ownership

Key ownership is encoded in the `keyId` and `clientId` fields. The `keyId` format is:

```
<clientId>:key_v<version>
```

For example: `default:key_v54`, `tenantA:key_v3`.

The prefix of every `keyId` must match the `clientId` of the client bucket it is stored under. This constraint is validated by `_validateClientOwnership()` on all read and write operations, and by `validateKeyStore()` at startup.

**Owner = client ID.** Each client is responsible for its own key lifecycle. Multi-tenant operations are coordinated by `tenantKeyManager`, which operates per-client.

---

## Key Lifecycle

```
                              (rotateKeyGracefully() / { mode: 'graceful' } — explicit ONLY)
                   ┌──► DEPRECATED ──► PURGE_ELIGIBLE ──► ARCHIVED
                   │
PROVISIONING ──► ACTIVE
                   │
                   └──► REVOKED (immediate, any time)
                          ▲
                          └── rotateKey()/rotateKeyAsync() with { mode: 'emergency' } explicit
                              and of revokeKey()/revokeKeyAsync()
```

rotation has two distinct, non-interchangeable modes. `'emergency'` moves the outgoing key straight to `REVOKED`: it loses signing **and** verification capability in the same call, exactly as if `revokeKey()` had been called on it directly. `'graceful'` is the deprecate-and-keep-verifiable behavior. Both are requested explicitly — via `rotateKeyGracefully()` / `rotateKeyGracefullyAsync()` (or `POST /key-admin/:clientId/rotate-graceful`) for graceful, or via `{ mode: 'emergency' }` (or `POST /key-admin/:clientId/rotate`) for emergency.

**mode is mandatory, there is no default.** Earlier, an omitted `opts.mode` silently resolved to `'emergency'`. That implicit default is now removed: `rotateKey()` / `rotateKeyAsync()` **throw a `TypeError` immediately** whenever `opts.mode` is omitted, `null`, `undefined`, an empty string, or any value other than exactly `'graceful'` or `'emergency'` — for every call that rotates an **existing active key**. (First-time provisioning and no-active-key recovery never reach this check — see "Rotation Procedure" below — because there is no outgoing key for a mode to apply to.) The caller must say which outcome it wants; "rotate the key" can no longer silently mean "assume this is an incident" or "assume this is routine maintenance" depending on whether a code path remembered to pass `opts.mode`.

### Lifecycle constants

| Constant | Value | Meaning |
|---|---|---|
| `ROTATION_DAYS` | 90 | Active key should be rotated within this many days of creation |
| `EXPIRY_DAYS` | 180 | Active key expires (cannot sign) after this many days |
| `EXPIRY_WARNING_DAYS` | 30 | Warn when fewer than this many days remain until expiry |

These constants are defined in `services/artifact/keyStore.js` and exported for use by `tenantKeyManager` and `keyAdmin`.

---

## Rotation Procedure

Rotation always creates a new active key. What happens to the **outgoing** key depends on the mode — the mode is **mandatory, never implicit**:

| Mode | Outgoing key status | Signing | Verification | How to invoke | Used by |
|---|---|---|---|---|---|
| `emergency` | `revoked` | No | **No** | `rotateKey()` / `rotateKeyAsync()` with `{ mode: 'emergency' }` explicit, or `POST /key-admin/:clientId/rotate` | Operator-triggered incident-response rotation |
| `graceful` | `deprecated` | No | Yes (until purge-eligible) | `rotateKeyGracefully()` / `rotateKeyGracefullyAsync()`, or `{ mode: 'graceful' }` explicit, or `POST /key-admin/:clientId/rotate-graceful` | The automatic rotation scheduler and startup auto-rotation of an aged-out (not suspected-compromised) key |

**Omitting `opts.mode` (or passing `null`/`undefined`/`''`/an unrecognized string) throws a `TypeError` immediately** for any rotation of an existing active key — see "Mandatory mode" below.

**Why graceful vs. emergency:** "rotate the key" is an operator's most intuitive response to a suspected key compromise. Before the remediation, rotation always moved the outgoing key to `deprecated`, which remains fully verifiable — so an operator who rotated in response to a compromise, believing they had invalidated the old key, had in fact done no such thing: the compromised key could still be used to forge signatures that would pass verification as "historical" artifacts. Only a separate, easy-to-forget `POST /key-admin/:clientId/revoke` call actually blocked verification. `emergency` mode produces the same outcome as an explicit revoke, closing that gap without requiring operators to remember a second step — **use `emergency` only when there is an actual reason to suspect the outgoing key is compromised.**

`graceful` mode exists for planned, non-incident maintenance where preserving verification of artifacts signed just before the rotation is a deliberate goal — see "Which callers use graceful mode" below. **`graceful` is the correct default assumption for routine, unattended, calendar-driven rotation** (the scheduler, startup auto-rotation) precisely because a scheduled or aged-out rotation carries no signal of compromise whatsoever; defaulting *that* class of rotation to immediate revocation would make every artifact signed shortly before a scheduled rotation unverifiable the instant it runs, for zero security benefit. This is why the scheduler (see below) always explicitly passes `{ mode: 'graceful' }` — it is not, and must never become, an implicit fallback baked into `rotateKey()`/`rotateKeyAsync()` themselves.

### Mandatory mode

Every caller that rotates an **existing active key** — i.e. every call to `rotateKey()`/`rotateKeyAsync()` that is not the very first key for a client, or recovery of a client with no active key — must supply `opts.mode` as exactly `'graceful'` or `'emergency'`. The following all throw a `TypeError` synchronously (or reject, for the async form), with **no key-store mutation whatsoever**:

- `opts` omitted entirely, or `opts.mode` absent
- `opts.mode` is `null` or `undefined`
- `opts.mode` is an empty string
- `opts.mode` is any string other than exactly `'graceful'` or `'emergency'` (including case mismatches like `'Emergency'`)
- `opts.mode` is a non-string value (number, boolean, object)

`rotateKeyGracefully()` / `rotateKeyGracefullyAsync()` are unaffected by this requirement from the caller's point of view — they always supply `{ mode: 'graceful' }` internally, so existing callers of those two functions need no code change. Every direct caller of `rotateKey()`/`rotateKeyAsync()` (or `keyManager.rotate()`/`rotateAsync()`) that performs a genuine rotation must be updated to pass `mode` explicitly; see "Migration implications" below.

**First-time provisioning and no-active-key recovery are unaffected.** `rotateKey('some-new-client')` with no `opts` at all still succeeds — there is no outgoing key in either of those cases, so no mode decision is meaningful and the mandatory-mode check never runs.

**Effect on historical artifact verification:** this change is purely about which mode a caller must specify — it does not alter what either mode DOES to the outgoing key. An artifact signed by a key that is later rotated `graceful` remains verifiable exactly as before; one signed by a key later rotated `emergency` becomes unverifiable exactly as before (see "Signing and verification capability after rotation" below). Mandatory mode selection changes nothing about verification outcomes for keys that were already rotated before this remediation shipped.

**Caller responsibilities:** any code that calls `rotateKey()`/`rotateKeyAsync()`/`keyManager.rotate()`/`keyManager.rotateAsync()` directly (not through the `*Gracefully*` helpers) must decide, at the call site, whether the rotation is incident response (`'emergency'`) or planned maintenance (`'graceful'`) and pass that decision explicitly. There is no safe way to omit this decision going forward.

**Migration implications:** deployments or internal tooling that called `rotateKey()`/`rotateKeyAsync()` without `opts.mode` and relied on the previous implicit `'emergency'` default must add `{ mode: 'emergency' }` explicitly to preserve identical behavior. `POST /key-admin/:clientId/rotate` (the admin API) requires no operator-facing change — the route itself was updated to pass `{ mode: 'emergency' }` internally, so its HTTP contract, request body, and response shape are unchanged.

### Standard (emergency) rotation

```
POST /key-admin/:clientId/rotate
```

**What happens:**
1. The manual admin route acquires the same Redis-backed distributed rotation lock (`src/infra/keys/rotationLock.js`) the automatic scheduler uses, keyed by `clientId`. If another rotation (manual or scheduled) already holds it, this call is refused immediately with `409 ROTATION_IN_PROGRESS` — it never proceeds unlocked.
2. The current active key is converted to `revoked` status. Private key material is discarded. This is the same transition `POST /:clientId/revoke` performs, applied automatically to the outgoing key — see "Signing and verification capability after rotation" below.
3. A new Ed25519 key pair is generated and stored as `active` with a fresh 90-day `rotationDeadline` and 180-day `expiresAt`. A SHA-256 fingerprint of the new public key is computed and included in the response and in the `KEY_ROTATED` event.
4. The key store is written atomically to disk.
5. The lock is released.
6. Events emitted: `KEY_REVOKED` (with `revocationTrigger: 'ROTATION'`, distinguishing it from an explicit `/revoke` call), `KEY_ROTATED`.

**Response** now names the outgoing key and its new status explicitly, so this is never silent:
```json
{
  "keyId": "<clientId>:key_v<n+1>", "version": <n+1>, "clientId": "<clientId>",
  "mode": "emergency", "previousKeyId": "<clientId>:key_v<n>", "previousKeyStatus": "revoked",
  "requestId": "<id>"
}
```

### Planned (graceful) rotation

```
POST /key-admin/:clientId/rotate-graceful
```

Deliberately a **separate endpoint**, not a body flag on `/rotate` — a compromise-response rotation must never be silently downgradeable to the weaker semantics by a stray or misremembered request body. Use this only when there is no reason to suspect compromise and continued verification of artifacts signed by the outgoing key is a deliberate, planned goal (e.g. routine housekeeping rotation triggered manually ahead of the scheduler).

**What happens:** identical to standard rotation above, except step 2 converts the current active key to `deprecated` (not `revoked`) and records `retiredAt`; events emitted are `KEY_DEPRECATED` and `KEY_ROTATED`. Response shape is identical with `"mode": "graceful"` and `"previousKeyStatus": "deprecated"`.

### Which callers use graceful mode

Graceful mode is opt-in and only two internal callers use it — both are planned, unattended maintenance with no compromise signal, never incident response:

- **The automatic rotation scheduler** (`services/artifact/rotationScheduler.js`) — keys become due purely by calendar age (`QODIQA_KEY_ROTATION_SCHEDULE`), which carries no information about compromise. Defaulting scheduled rotation to immediate revocation would make every artifact signed shortly before a scheduled rotation unverifiable the instant that rotation runs, for zero security benefit.
- **Startup auto-rotation of an expired active key** (`services/artifact/tenantKeyManager.js` `ensureActiveKey()`) — a key past its `expiresAt` is a maintenance condition, not a compromise signal.

Every operator-facing path — `POST /key-admin/:clientId/rotate`, and any direct call to `keyManager.rotate()`/`rotateAsync()` with `{ mode: 'emergency' }` explicit — produces the emergency outcome. An operator who has an actual, deliberate reason to keep the outgoing key verifiable must opt into `/rotate-graceful` (or `{ mode: 'graceful' }`) explicitly.

#### Signing and verification capability after rotation

Both modes discard private key material from the outgoing record in the same call — that guarantee is unchanged from before this remediation. What differs is **verification**:

- **Emergency:** the outgoing record is rebuilt as `revoked`. `getPublicKey()`/`getKey()` reject it immediately (`status` is not in `VERIFIABLE_STATUSES`) — see "Emergency Revocation Procedure" below, which this mode reuses in full, including the attempt to propagate revocation to a native signing provider (Vault Transit / HSM) when one is configured. That propagation attempt is best-effort at the provider boundary — see "External Key Providers (Vault Transit / HSM / KMS)" below for what happens when it fails.
- **Graceful (explicit only):** the outgoing record is rebuilt as `deprecated` and remains resolvable by `getPublicKey()`/`getKey()` (status is in `VERIFIABLE_STATUSES`) until it becomes purge-eligible.
- **Local Ed25519 keys:** in both modes, the outgoing record never carries `_privDer` — it is stripped at the exact moment of the state transition, not lazily at some later cleanup. There is no private key material left anywhere in the process to sign with.
- **Vault Transit / HSM:** emergency mode calls the provider's `revokeKey()` at its strongest supported method. Graceful mode calls `provider.deprecateKey()`, which advances Vault's `min_encryption_version` past the outgoing key's version (refusing new `sign` calls) while leaving `min_decryption_version` untouched so historical verification keeps working. In both modes, if the provider-side call fails, the whole rotation aborts **before** any local state changes — the previous key remains the sole active key both locally and at the provider (fail-closed).
- **Every path:** `getActiveKey()` / `nativeSignLocked()` only ever select a key whose persisted `status` is `'active'` — never inferred from recency or creation order — and enforce exactly one active key per client (`activeKeys.length > 1` is a startup-fatal structural violation). A revoked or deprecated key is therefore unreachable from the signing path by construction, regardless of mode.

#### Concurrency

Before this fix, `POST /:clientId/rotate` and `POST /:clientId/recover` called the synchronous, unlocked `keyManager.rotate()` directly — only the *automatic* scheduler acquired `rotationLock`. In a multi-instance deployment sharing `keys.json` (single PVC/EFS mount), a manual rotation could race the scheduler's own rotation for the same client, or two manual calls (two operators, or a retried request) could race each other, risking a lost update or a transient two-active-keys/zero-active-keys observation across instances until the next reload. All three routes — `/rotate`, `/rotate-graceful`, and `/recover` — run their mutation inside `_withRotationLock()` (`src/api/routes/keyAdmin.js`), which acquires/releases the identical lock the scheduler uses:
- Lock held elsewhere → `409 ROTATION_IN_PROGRESS` (safe to retry).
- Lock backend (Redis) unreachable → `503 LOCK_UNAVAILABLE` — fail-closed, never rotates without the lock.
- For `/recover`, the "does this client already have an active key?" check and the provisioning it gates both run *inside* the same critical section, so two concurrent recovery calls can never both observe "no active key" and both provision.

**Response:**
```json
{ "keyId": "<clientId>:key_v<n+1>", "version": <n+1>, "clientId": "<clientId>", "fingerprint": "<sha256-hex>" }
```

### Auto-rotation at startup

`tenantKeyManager.validateAllTenantsAtStartup()` calls `ensureActiveKey()` for every known client. If a client's active key is expired, it is automatically rotated and `KEY_ROTATION_AUTO` is emitted. Startup continues after auto-rotation succeeds. This is a one-time, startup-only check — it is independent of the automatic rotation scheduler described below, which rotates keys continuously while the process runs.

### Automatic rotation scheduler

QODIQA also runs a background scheduler (`services/artifact/rotationScheduler.js`) that rotates each client's signing key on a configurable cadence, without operator intervention.

**Interval configuration** — the rotation cadence is configuration-driven, not hardcoded:

| Variable | Purpose | Default |
|---|---|---|
| `QODIQA_KEY_ROTATION_ENABLED` | Master on/off switch for automatic **rotation** only — never affects reload | `true` |
| `QODIQA_KEY_RELOAD_ENABLED` | Master on/off switch for trust-store **reload** only — independent of rotation. Not recommended to disable outside a single-instance deployment | `true` |
| `QODIQA_KEY_ROTATION_SCHEDULE` | Preset: `daily` \| `weekly` \| `monthly` \| `disabled` | `monthly` |
| `QODIQA_KEY_ROTATION_INTERVAL_MS` | Explicit override in milliseconds (highest precedence) | — |
| `QODIQA_KEY_ROTATION_INTERVAL_DAYS` | Explicit override in days | — |
| `QODIQA_KEY_ROTATION_CHECK_INTERVAL_MS` | How often the scheduler scans for due clients | `3600000` (1h) |
| `QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS` | How often **every** instance reloads `keys.json` — the deterministic upper bound on revocation/replacement propagation time fleet-wide | `300000` (5m) |
| `QODIQA_KEY_ROTATION_LOCK_TTL_MS` | Distributed rotation lock TTL | `30000` |
| `QODIQA_KEY_ROTATION_MAX_RETRIES` / `_RETRY_DELAY_MS` | Retry policy on transient rotation failure | `3` / `5000` |
| `QODIQA_KEY_ROTATION_CLIENT_IDS` | Optional comma-separated allowlist | all known clients |

A key becomes due when its age (`now − createdAt` of the active key) reaches the configured interval. This is independent of the fixed 90-day `ROTATION_DAYS` constant used elsewhere for `KEY_ROTATION_OVERDUE` warnings — that constant is unaffected by this scheduler's configuration.

**Cluster safety.** Every instance in a deployment runs the scheduler and evaluates the same due-ness condition. Before rotating a given client, an instance must first acquire a Redis-backed distributed lock (`src/infra/keys/rotationLock.js` — `SET NX PX`, one key per clientId). Only the lock holder rotates; every other instance observes the lock as held and skips that client for the current cycle. This replaces the previously manual operational rule in `docs/deployment/topology.md` ("key rotation coordination: must be serialised") with a structural guarantee — concurrent automatic rotation across pods sharing the same `keys.json` is no longer possible.

**Rotation and reload are independent.** `QODIQA_KEY_ROTATION_ENABLED=false` (or `QODIQA_KEY_ROTATION_SCHEDULE=disabled`) turns off automatic rotation ticking only. Trust-store reload — the mechanism that propagates revocations, externally replaced keys, and metadata updates to this instance — keeps running on its own cadence (`QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS`) regardless. Previously both were gated by the same rotation-enabled check, meaning a fleet running with automatic rotation turned off (e.g. rotation performed manually/out-of-band) would never see revocations propagate at all, with no bounded-time guarantee. `GET /key-admin/rotation-scheduler/status` exposes `rotationActive` and `reloadActive` as separate booleans so operators can see each concern's actual state.

**Fleet-wide visibility without a restart.** Whichever instance wins the lock has the new key in memory immediately. Every running instance — whether or not it performs rotation itself — periodically reloads `keys.json` from disk (`keyManager.reload()`), so instances that did not perform the rotation, or that never rotate at all, pick up the new active key, revoked keys, and replaced keys for verification — without an operator-triggered rolling restart. Reload is fail-closed: a read, parse, or decrypt failure leaves the in-memory store completely untouched and is reported via `KEY_ROTATION_SCHEDULER_RELOAD_FAILED`. Reload is also fully synchronous and swaps the trust store with a single assignment, so concurrent verification requests always observe either the fully-old or fully-new store, never a partial one.

**Restart-safety and idempotency.** Due-ness is derived from the active key's own `createdAt` — already durably persisted — rather than from separate scheduler state. A rotated key's age resets to zero, so the same key is never rotated twice for the same interval regardless of process restarts or how many instances are evaluating it concurrently.

**KMS compatibility.** Rotation is performed via `keyManager.rotateAsync()` / `keyStore.rotateKeyAsync()`. For the default local provider this is identical to standard rotation above. When `QODIQA_KMS_PROVIDER` is `vault-transit` or `hsm`, the new key pair is generated **inside** the external provider (`provider.generateKeyPair()`) and the old key is deprecated inside the provider too (`provider.deprecateKey()`) — private key material never enters the QODIQA process. A remote self-test (sign with the provider, verify locally) runs before the new key is activated; if it fails, or if the provider-side deprecate call fails, the rotation aborts before any local state changes — the previous key remains the sole active key both locally and in the provider.

**Manual trigger and observability:**
```
GET /key-admin/rotation-scheduler/status
```
Returns the scheduler's running state, configured interval, last/next run timestamps, and cumulative rotation/error/skip counters. Prometheus metrics are exposed under the `qodiqa_key_rotation_scheduler_*` and `qodiqa_key_active_age_seconds` / `qodiqa_key_rotation_lock_contention_total` names — see `docs/configuration/reference.md`.

Setting `QODIQA_KEY_ROTATION_ENABLED=false` or `QODIQA_KEY_ROTATION_SCHEDULE=disabled` disables automatic rotation entirely; manual rotation via `POST /key-admin/:clientId/rotate` remains available either way. It does **not** disable trust-store reload — see `QODIQA_KEY_RELOAD_ENABLED` above.

### Recovery rotation (no active key)

When a client has existing key history but no active key, `rotateKey()` takes the recovery path:
- Finds the highest existing version number using `_nextVersion()`.
- Creates a new active key at `max_version + 1`.
- No deprecated key is created (there is no active key to deprecate).
- Emits `KEY_PROVISIONED_RECOVERY`.

Via the admin API:
```
POST /key-admin/:clientId/recover
```
Lock-protected identically to standard rotation — the active-key check and the provisioning are one atomic critical section.

### Transparency and audit-checkpoint keys

The transparency and checkpoint Ed25519 stores have one active key each, a 90-day rotation deadline and a 180-day
expiry; an expired active key makes the next boot FATAL (`TRANSPARENCY_SIGNER_STARTUP_FAILED` /
`CHECKPOINT_KEY_STARTUP_FAILED`). There is no admin route for them; the supported, operator-run path is:

```
node scripts/keys/rotate-offline.js --store transparency --mode graceful --operator <id> --reason "<text>"            # dry run (exit 2)
node scripts/keys/rotate-offline.js --store transparency --mode graceful --operator <id> --reason "<text>" \
     --confirm-offline-recovery [--no-lock]
node scripts/keys/rotate-offline.js --store checkpoint   ...same flags...
```

- Run it with the gateway's own environment (`QODIQA_KEY_ENCRYPTION_KEY` or the KMS settings,
  `QODIQA_TRANSPARENCY_KEYS_PATH`, `QODIQA_CHECKPOINT_KEYS_PATH`). It works on an expired key (the recovery case) and on
  a current one (planned rotation at day 90).
- `--mode graceful`: the outgoing key becomes `deprecated` with `retiredAt` = now; it keeps verifying every root /
  checkpoint it signed before retirement and never signs again. `--mode emergency`: it is revoked — what it signed
  stops verifying (suspected compromise only).
- Lock: the fleet rotation lock `ed25519-store:<store>` through `REDIS_URL`, or `--no-lock` after stopping every
  instance sharing the file. Running instances adopt the new key on their next key-reload tick.
- Exit codes: 0 rotated · 1 failed · 2 dry run · 3 no active key · 4 lock refused · 64 usage. Events:
  `KEY_OFFLINE_RECOVERY_{UNLOCKED,STARTED,COMPLETED,FAILED}` with `store`, `operator`, `reason`.
- The periodic expiry monitor (`KEY_EXPIRING_SOON` / `KEY_ROTATION_OVERDUE` / `KEY_EXPIRED` with `store`) and the
  stores' expired-key errors carry this command (`rotateCommand`).

---

## Archive Procedure

Deprecated keys are retained in the live store until all artifacts signed with them have expired. Once the retention window passes, keys are eligible for purging to the archive.

### Retention window

**When `retiredAt` is known** (keys deprecated after this field was introduced): eligible when `now − retiredAt > 180 days`.

**When `retiredAt` is absent** (keys deprecated before retirement tracking was added): eligible when `now − createdAt > 360 days` (conservative: assumes the key was deprecated at the latest possible time — its full 180-day lifetime).

### Purge procedure

```
POST /key-admin/purge-expired
```

Optional body: `{ "clientId": "<clientId>" }` to restrict to a single client. Omit for global purge.

**What happens:**
1. All purge-eligible deprecated keys are identified.
2. Their metadata (without private key material — it was already discarded at rotation) is appended to `data/key-archive.json`. Archive write is atomic.
3. Archive persistence is confirmed before touching the live store. If archive write fails, the purge aborts (fail-closed).
4. Eligible keys are removed from the in-memory store.
5. The live key store is written atomically to disk.
6. Event emitted: `KEYS_PURGED` with count and keyIds.

**Response:**
```json
{ "purged": <count>, "archived": [ { ...metadata } ] }
```

### Archive file

`data/key-archive.json` is append-only. Entries are never modified or deleted. Each entry contains:

| Field | Description |
|---|---|
| `keyId` | Full key identifier |
| `clientId` | Owning client |
| `purpose` | Always `ed25519-artifact-signing` |
| `owner` | Same as `clientId` |
| `version` | Version number within client sequence |
| `algorithm` | Always `ed25519` |
| `publicKeyB64` | SPKI DER public key, base64 (retained for audit) |
| `createdAt` | When the key was originally created |
| `retiredAt` | When the key was deprecated (null if pre-dating retirement tracking) |
| `purgedAt` | When the entry was written to archive |
| `retirementReason` | Always `RETENTION_PERIOD_EXPIRED` for automatic purges |
| `retentionDays` | The retention policy in effect (`180`) |
| `replacedBy` | The key that succeeded this one |
| `auditNotes` | Human-readable note explaining the purge decision |

Only `deprecated` keys are ever archived — `purgeExpiredDeprecated()` never touches a `revoked` key (see the purge loop in `services/artifact/keyStore.js`). This is what makes the archived-verification tier below safe by construction: every archived entry was verifiable the instant before it was archived, and revocation always bypasses the archive entirely (see "Archived Key Verification" below).

---

## Archived Key Verification

**Product decision: for QODIQA, long-term cryptographic verifiability is a core capability.** Before this remediation, verification had no path back to `data/key-archive.json` — once `purgeExpiredDeprecated()` removed a deprecated key from the live store, any artifact it had signed became permanently unverifiable. This created an undocumented verification ceiling of roughly 180-360 days (depending on whether `retiredAt` was known at purge time), silently conflicting with QODIQA's positioning as a provider of durable execution evidence. This section describes the fix: `getPublicKey()` now falls back to the archive, and a dedicated discovery endpoint exposes archived keys to SDK consumers.

### Lookup order

```
getPublicKey(keyId)
  1. Live keystore  (unchanged fast path — cost and behavior identical to before)
  2. Archived keystore  (consulted ONLY when the live lookup finds no record at all)
```

**The archive is never consulted for a live record that exists but is `revoked`** — revocation always wins, and in any case a revoked key is never written to the archive (see "Archive file" above), so there is nothing for the archive to resurrect. The only case that falls through to the archive is a keyId with **no live record whatsoever** — i.e. a key that was `deprecated` and has since been purged.

A successful archive-tier resolution returns the same `{ pubDer, status, clientId }` shape `getPublicKey()` always has, plus `source: 'archived'` (live resolutions carry `source: 'live'`). `status` is normalized to `'deprecated'` — the real lifecycle status the key held immediately before being purged — never the wire-only `'archived'` marker used by the discovery endpoint's JSON response. **`source` is diagnostic metadata only; it never affects whether a key is treated as valid.** This is what makes `src/validation/resolveKey.js` — and the full `validateArtifact()` verification pipeline behind it — pick up archived-key verification with zero code changes: it already just calls `getPublicKey()` and trusts whatever it returns.

### Archive index cache

The archive is read into an in-memory `Map<keyId, entry>` on first archive-tier lookup and reused for `QODIQA_KEY_ARCHIVE_CACHE_TTL_MS` (default **5 minutes**) before being rebuilt from disk — avoiding a disk read + full JSON parse of a monotonically-growing file on every miss. `purgeExpiredDeprecated()` invalidates this cache immediately after a successful purge, so a just-purged key is verifiable right away rather than waiting out the TTL. Live-key lookups never touch this cache or the archive file at all.

**Multi-instance propagation delay.** In a deployment where multiple instances share `keys.json`/`key-archive.json` (see "Fleet-wide visibility without a restart" under Automatic rotation scheduler above), the archive index cache is **per-instance and uncoordinated** — it runs on its own independent `QODIQA_KEY_ARCHIVE_CACHE_TTL_MS` timer, separate from (and not synchronized with) each instance's own `keys.json` reload cadence (`QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS`). This can produce a narrow, bounded window on a "trailing" instance: once that instance reloads `keys.json` and observes a key as purged (no longer live), its own archive cache may still be up to `QODIQA_KEY_ARCHIVE_CACHE_TTL_MS` stale, during which `getPublicKey()` for that key returns "unknown" rather than falling through to the (already-updated-on-disk) archive. This is architecturally the same class of tradeoff as the existing `keys.json` reload propagation delay above — bounded, self-healing (the next cache rebuild picks it up), and **fails closed** (a verification incorrectly reports "unknown key," never incorrectly succeeds) — it never weakens the revocation guarantee or resurrects an invalid key. No operator action is required; the window closes on its own within one archive cache TTL.

### Defensive parsing

Every archive entry is validated before it can influence a verification outcome — a hand-edited or corrupted `key-archive.json` degrades to "entry skipped" (with a `KEY_ARCHIVE_ENTRY_INVALID` warning), never to a crash or to fabricated key material:

- `keyId` must match the canonical `<clientId>:key_v<n>` format.
- `clientId` must be a valid client identifier, **and its prefix of `keyId` must match it exactly** (ownership consistency, mirroring `_validateClientOwnership()` for the live store).
- `algorithm` and `publicKeyB64` must be non-empty strings, and `publicKeyB64` must decode to a non-empty buffer.

A missing archive file, or one that is empty (zero bytes or whitespace-only), is treated identically to "no archived keys" — never a fail-closed error. A structurally corrupt file (invalid top-level JSON, wrong `version`, missing `entries` array) still fails closed for the archive tier only: the error is caught, logged as `KEY_ARCHIVE_LOOKUP_FAILED`, and treated as "not found in the archive" — it never breaks ordinary live-key verification for callers who never needed the archive in the first place.

### Archived discovery endpoint

```
GET /.well-known/qodiqa/keys/archived
```

The discovery-endpoint counterpart to the `getPublicKey()` fallback above — lets SDK consumers (and any other verifier) resolve a keyId that no longer appears in the live `/.well-known/qodiqa/keys` list, without out-of-band access to `data/key-archive.json`. Same response envelope as the live endpoint:

```json
{
  "keys": [
    { "keyId": "<clientId>:key_v<n>", "algorithm": "ed25519", "publicKey": "<base64 SPKI DER>", "status": "archived", "source": "archived" }
  ],
  "requestId": "<id>"
}
```

`status` and `source` are always `"archived"` here — unlike the live endpoint's active/deprecated distinction, every entry in the archive is equally "purged and no longer live." Read-only, public material only: `publicKey` is the only key-material field, since the archive never contains private key material in the first place (stripped at rotation time, long before a key is ever purge-eligible).

Registered **before** `/.well-known/qodiqa/keys/{keyId}` in `src/api/routes/well-known.js` — Express matches routes in registration order, and `archived` would otherwise be consumed as a (non-matching, 404-producing) `{keyId}` value first. **`GET /.well-known/qodiqa/keys/{keyId}` itself is unchanged and remains live-only** — it is not the endpoint the archived tier was added to, precisely so its existing behavior (404 for a purged key) stays exactly as documented; only the new dedicated endpoint above and the `getPublicKey()` fallback inside the real verification pipeline gained archived-tier awareness.

**Rate limiting:** independently and more strictly limited than the live discovery endpoint, via the `well_known_archived` rate-limit surface (default **20 requests / 60 seconds**, vs. `well_known`'s 120/60 — see `src/core/rateLimit/config.js`). Configurable via `RL_WELL_KNOWN_ARCHIVED_MAX` / `RL_WELL_KNOWN_ARCHIVED_WINDOW`, independently of `RL_WELL_KNOWN_MAX` / `RL_WELL_KNOWN_WINDOW`. This tier is expected to see far less traffic than live discovery — only verifiers checking artifacts old enough to have outlived the live keystore — and the lower budget reflects that while limiting the cost of repeatedly rebuilding/serving the archive index.

### SDK fallback (JavaScript and Python)

Both SDKs' `RemoteKeyProvider` (and Python's `AsyncRemoteKeyProvider`) transparently retry against the archived endpoint when a keyId is absent from the live list, but the live fetch itself succeeded:

```
getPublicKey(keyId)
  1. GET /.well-known/qodiqa/keys        (cached, same as before)
  2. GET /.well-known/qodiqa/keys/archived   (only on a miss above; cached independently, same TTL)
```

If the primary (live) request itself fails (network error, non-2xx), the fallback is **not** attempted — that failure resolves to `null` exactly as before this remediation; only a *successful* primary fetch that doesn't contain the key triggers the archived-tier request. The archived-tier URL defaults to `<discoveryUrl>/archived` when `discoveryUrl` ends with `/qodiqa/keys` (i.e. only for the artifact-signing discovery endpoint — never derived for `/qodiqa/transparency-keys`, which has no archived tier). See [docs/sdk/javascript/configuration.md](../sdk/javascript/configuration.md#key-provider-configuration) and [docs/sdk/python/configuration.md](../sdk/python/configuration.md#key-provider-configuration) for full configuration details. No SDK consumer code changes are required to benefit from this — the same `RemoteKeyProvider` construction call used before this remediation now transparently verifies artifacts signed by since-purged keys too.

### Operational expectations

- Existing `data/key-archive.json` files require **no migration** — the schema is unchanged; this remediation only adds a *reader*.
- Live-key verification latency and cache behavior are **completely unaffected** — the archive is consulted strictly on the live-miss path, never before or in place of the live lookup.
- No existing endpoint's behavior changes: `/.well-known/qodiqa/keys`, `/.well-known/qodiqa/keys/{keyId}`, and every key-rotation/revocation route above are unchanged; only new capability (the archived endpoint, the `getPublicKey()` fallback, and the SDK fallback) was added.
- Log events introduced: `KEY_ARCHIVE_ENTRY_INVALID` (WARN — a malformed archive entry was skipped) and `KEY_ARCHIVE_LOOKUP_FAILED` (ERROR — the archive file itself could not be read/parsed; the affected lookup falls through to "not found," it never crashes or blocks live-key verification).

---

## Emergency Revocation Procedure

Revocation permanently blocks a key from being selected by QODIQA for signing or verification. It cannot be undone. **For local Ed25519 keys, this is a complete revocation** — no private key material exists anywhere outside QODIQA's own encrypted store, so there is no other place a signature could come from. **For Vault Transit, HSM, or KMS-backed keys, QODIQA's revocation is not on its own a guarantee that the external provider will refuse to produce new signatures with that key** — see "External Key Providers (Vault Transit / HSM / KMS)" below before relying on this procedure as a complete compromise response.

### Revoke a specific key

```
POST /key-admin/:clientId/revoke
Body: { "keyId": "<clientId>:key_v<n>" }
```

**What happens:**
1. The key record is converted to `revoked` status. Private key material is discarded.
2. The live store is written atomically to disk.
3. Event emitted: `KEY_REVOKED`.
4. The revoked key is immediately rejected by `getPublicKey()` and `getKey()` — QODIQA can no longer verify artifacts against it, and will never again select it for signing.
5. If a native signing provider (Vault Transit / HSM) is configured, `revokeKeyAsync()` also attempts to revoke the key at the provider — see the warning below. If that provider-side call fails, the key remains revoked locally (steps 1–4 above still hold) but the call throws `NATIVE_REVOCATION_FAILED` so the operator is explicitly told the provider boundary was not confirmed closed.

### External Key Providers (Vault Transit / HSM / KMS)

**Revoking a key within QODIQA updates the application's trust state but does not by itself guarantee that an external HSM, Vault Transit engine, or KMS has stopped honoring signing requests for that key.**

- QODIQA's own signing and verification paths (`getActiveKey()`, `getPublicKey()`, `getKey()`) never select or resolve a revoked key again — that guarantee is unconditional and does not depend on the external provider.
- When a native signing provider is configured (`QODIQA_KMS_PROVIDER=vault-transit` or `hsm`), `revokeKeyAsync()` (`services/artifact/keyStore.js`) additionally calls the provider's own `revokeKey()` at the strongest method the provider advertises via `getRevocationCapabilities()` — this is the propagation path. `src/infra/keys/providers/base.js` defines five methods in strongest-to-weakest order: `destroy` (irreversible key-material deletion), `schedule_deletion` (deletion queued, subject to a provider waiting period), `disable` (key retained but marked unusable for new operations), `archive` (moved out of the active keyring, operator-recoverable), and `deprecate` (**weakest — blocks new signing but the provider still considers the key valid for existing purposes**). Not every provider supports the strongest methods (IAM policy may forbid `destroy`, for example), so a *successful* provider-side call does not always mean the same thing: **if the provider's strongest available method is `archive` or `deprecate`, a "success" response leaves the key in a weaker state than full destruction/disablement.**
- **This provider-side call can also fail outright** (network partition, insufficient provider-side permissions, provider outage). When it fails, `revokeKeyAsync()` throws `NATIVE_REVOCATION_FAILED` and the error message states explicitly that the key may still be able to produce valid signatures at the provider boundary. QODIQA does not — and cannot — force the external provider into a disabled state from its own process if the provider itself does not cooperate.
- **Operators must treat a `NATIVE_REVOCATION_FAILED` error, or any suspected-compromise scenario involving a native-signing key, as requiring the provider-specific emergency procedure in addition to QODIQA's own revocation call**: disable, revoke, or destroy the key directly in Vault Transit / the HSM console / the KMS, following that provider's own incident procedure, independent of what QODIQA reports.
- Revocation of a key held in an external provider depends on that provider: QODIQA cannot force the provider to stop signing with it.

**Do not assume a `POST /key-admin/:clientId/revoke` call alone has fully neutralized a compromised Vault Transit / HSM / KMS key.** Confirm the provider-side state directly (e.g. `vault read transit/keys/<name>` and check `min_encryption_version`/`deletion_allowed`, or the equivalent HSM/KMS console/API) before declaring the incident contained.

**If the revoked key was the sole active key:** the client enters `NO_ACTIVE_KEY` state. Initiate a recovery rotation immediately:

```
POST /key-admin/:clientId/recover
```

### Emergency rotation (revoke + replace in one call)

**As of the remediation, this is a single call.** If the active key is compromised, use standard rotation — it revokes the outgoing key:

```
POST /key-admin/:clientId/rotate
```

This provisions a new active key and immediately blocks verification of artifacts signed with the compromised key, in one atomic, lock-protected operation. There is no longer a two-step "rotate, then remember to also revoke" procedure, and no window in between where the compromised key remains verifiable.

If you only need to block a specific non-active key (e.g. a key already deprecated under a prior graceful rotation, or any key by ID without replacing the current active key), use the standalone revoke call instead:

```
POST /key-admin/:clientId/revoke  { "keyId": "<key-id>" }
```

**Do not use** `POST /key-admin/:clientId/rotate-graceful` in a suspected-compromise scenario — it deliberately preserves the outgoing key's verification capability and is reserved for planned, non-incident maintenance (see "Rotation Procedure" above).

---

## Startup Validation

The server performs the following key-related checks on every startup, in order:

1. **Plaintext scan** (`validateStartup` step 0): Scans `keys.json` on disk for any entry with a `privateKeyDer` field (legacy plaintext format). Any finding is FATAL — startup aborts.

2. **KEK validation** (step 1): Verifies that `QODIQA_KEY_ENCRYPTION_KEY` is present and produces a 32-byte Buffer. FATAL if absent or malformed.

3. **Structural integrity** (step 2): `validateKeyStore()` checks for ownership violations, duplicate versions, and multiple-active-key invariant violations. FATAL if any violation found.

4. **Expired active keys** (step 3): Any active key whose `expiresAt` is in the past causes startup to abort. Rotate before starting.

5. **Expiring/overdue warnings** (step 4): Active keys within 30 days of expiry or past their 90-day rotation deadline emit `WARN` events. Startup continues.

6. **Tenant key provisioning** (step 5): `tenantKeyManager.validateAllTenantsAtStartup()` auto-provisions or auto-rotates as needed for all known clients. FATAL if any provisioning attempt fails.

---

## Deterministic Key Selection Model

| Property | Implementation |
|---|---|
| One active key per client | Enforced structurally by `rotateKey()` and `validateKeyStore()` |
| Active key never selected by ordering | `getActiveKey()` iterates all records and selects the unique `status === 'active'` entry |
| No implicit fallback client | `clientId` is always required; empty or default values are rejected |
| No key guessing | All key lookups are by explicit `keyId` or explicit `clientId` |
| Fail-closed on expiry | Expired active keys cause `getActiveKey()` to throw, not silently fall back |
| Deterministic multi-active fallback | If a structural violation leaves multiple active keys (caught by startup validation), `tenantKeyManager` selects by most-recent `createdAt` and emits `MULTIPLE_ACTIVE_KEYS_DETECTED` |

---

## Admin API Reference

All routes are protected by `opsAuth` middleware (applied in `server.js`).

| Method | Path | Description |
|---|---|---|
| `GET` | `/key-admin/health` | Aggregate health across all tenants |
| `GET` | `/key-admin/inventory` | Full classified key inventory |
| `GET` | `/key-admin/rotation-scheduler/status` | Automatic rotation scheduler status and counters |
| `POST` | `/key-admin/purge-expired` | Archive and remove expired deprecated keys |
| `GET` | `/key-admin/:clientId/status` | Per-tenant key health |
| `POST` | `/key-admin/:clientId/rotate` | Rotate active key — **emergency mode**: outgoing key is revoked |
| `POST` | `/key-admin/:clientId/rotate-graceful` | Rotate active key — **planned mode**: outgoing key is deprecated (stays verifiable) |
| `POST` | `/key-admin/:clientId/revoke` | Revoke a specific key (`keyId` in body) |
| `POST` | `/key-admin/:clientId/recover` | Provision new active key for no-key clients |

---

## Log Events

| Event | Level | Trigger |
|---|---|---|
| `KEY_CREATED` | INFO | First key provisioned for a new client |
| `KEY_ROTATED` | INFO | Rotation completed; new active key ready. Carries `mode` (`'emergency'`\|`'graceful'`) |
| `KEY_DEPRECATED` | INFO | Previous active key deprecated — **graceful-mode rotation only**; never emitted by default/emergency rotation |
| `KEY_PROVISIONED_RECOVERY` | INFO | New active key provisioned for a no-active-key client |
| `KEY_REVOKED` | INFO | Key permanently revoked — via explicit `/revoke`, **or** as the outcome of an explicit `{ mode: 'emergency' }` rotation (distinguish via `revocationTrigger: 'ROTATION'` vs. absent for an explicit revoke) |
| `KEYS_PURGED` | INFO | Expired deprecated keys archived and removed |
| `KEY_ARCHIVE_ENTRY_INVALID` | WARN | A malformed `key-archive.json` entry was skipped while building the archive lookup index |
| `KEY_ARCHIVE_LOOKUP_FAILED` | ERROR | Archive file could not be read/parsed for a `getPublicKey()` fallback lookup — treated as "not found in the archive," never breaks live-key verification |
| `KEY_EXPIRED_STARTUP` | ERROR | Active key found to be expired at startup (FATAL) |
| `KEY_SIGNING_BLOCKED` | WARN | Signing blocked because active key is expired |
| `KEY_EXPIRING_SOON` | WARN | Active key within 30 days of expiry |
| `KEY_ROTATION_OVERDUE` | WARN | Active key past 90-day rotation deadline |
| `KEY_STORE_VIOLATION` | ERROR | Structural invariant violation at startup (FATAL) |
| `KEY_PLAINTEXT_DETECTED` | CRITICAL | Unencrypted private key found on disk (FATAL) |
| `KEY_MIGRATION_STARTED` | INFO | Legacy key format migration started |
| `KEY_MIGRATION_COMPLETED` | INFO | Migration completed; all keys encrypted |
| `KEY_MIGRATION_FAILED` | CRITICAL | Migration failed (FATAL) |
| `TENANT_KEY_MISSING` | WARN | Client has no active key; auto-provisioning |
| `TENANT_KEY_EXPIRED_ACTIVE` | CRITICAL | Client active key expired; auto-rotating |
| `MULTIPLE_ACTIVE_KEYS_DETECTED` | WARN | Structural violation: multiple active keys for one client |
| `KEYSTORE_RELOADED` | INFO | `keys.json` re-read from disk; in-memory store refreshed (includes `revoked`/`activeKeyChanges` counts) |
| `KEYSTORE_RELOAD_FAILED` | ERROR | Reload aborted — in-memory store retained unchanged |
| `KEY_REVOCATION_PROPAGATED` | WARN | A reload observed a key transition to `revoked` that this instance didn't already know about |
| `KEY_ACTIVE_KEY_CHANGED` | INFO | A reload observed a client's active key change (rotation/replacement propagated) |
| `KEY_ROTATION_PROVIDER_DEPRECATE_FAILED` | ERROR | Native signing provider failed to deprecate the old key during **graceful-mode** rotation; rotation aborted |
| `KEY_ROTATION_PROVIDER_REVOKE_FAILED` | ERROR | Native signing provider failed to revoke the old key during **explicit emergency-mode** rotation; rotation aborted — old key remains sole active key both locally and at the provider |
| `KEY_ROTATION_SCHEDULER_STARTED` / `_STOPPED` | INFO | Automatic rotation ticking lifecycle (not the whole scheduler wrapper — see below) |
| `KEY_ROTATION_SCHEDULER_DISABLED` | INFO | Rotation ticking not started — disabled via configuration. Reload is a **separate** concern and, unless also explicitly disabled via `QODIQA_KEY_RELOAD_ENABLED`, keeps running — see `KEY_RELOAD_SCHEDULER_DISABLED` |
| `KEY_RELOAD_SCHEDULER_DISABLED` | INFO | Trust-store reload explicitly turned off via `QODIQA_KEY_RELOAD_ENABLED=false` — not recommended outside a single-instance deployment |
| `KEY_ROTATION_SCHEDULER_TICK_STARTED` / `_TICK_COMPLETED` | INFO | One scheduler evaluation cycle across all known clients |
| `KEY_ROTATION_SCHEDULER_ROTATED` | INFO | Scheduler successfully rotated a client's key |
| `KEY_ROTATION_SCHEDULER_SKIPPED` | INFO/WARN | Client not due, lock held elsewhere, or Redis unavailable |
| `KEY_ROTATION_SCHEDULER_RETRY` | WARN | Retrying a failed rotation attempt |
| `KEY_ROTATION_SCHEDULER_FAILED` | ERROR | Rotation failed after exhausting all retries |
| `KEY_ROTATION_SCHEDULER_RELOAD_FAILED` | WARN | Reload-from-disk attempt failed (runs on every instance, independent of rotation) |
| `KEY_ROTATION_SCHEDULE_INVALID` | WARN | `QODIQA_KEY_ROTATION_SCHEDULE` value not recognized; fell back to `monthly` |
