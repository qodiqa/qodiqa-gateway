#!/usr/bin/env node
'use strict';

/**
 * supported OFFLINE recovery for an EXPIRED artifact signing key.
 *
 * Why this exists: an active artifact key past its expiresAt makes server/startup.js FATAL
 * (keyManager.validateStartup(), KEY_EXPIRED_STARTUP), so the online path (POST /key-admin/:clientId/rotate) is
 * unreachable exactly when it is needed, and tenantKeyManager's KEY_EXPIRED auto-rotate branch never runs at boot.
 * This CLI performs ONE logged rotation of that client's expired key, against the same key file, KEK and KMS
 * provider the server uses, and nothing else. It is never wired into boot.
 *
 * Fail-closed by default — it writes nothing unless every one of these holds:
 *   --client <id>              the client whose ACTIVE key has EXPIRED (refused if the key is not expired, or the
 *                              client has no active key: use POST /key-admin/:clientId/rotate on a running instance)
 * --mode graceful|emergency mandatory, no default. graceful = the expired key becomes deprecated and keeps
 *                              verifying what it signed; emergency = it is revoked (suspected compromise).
 *   --operator <id>            who performs the recovery (recorded in every event)
 *   --reason "<text>"          why (recorded in every event)
 *   --confirm-offline-recovery without it the run is a DRY RUN: it reports the plan and exits 2
 *   and the fleet rotation lock: taken through Redis when REDIS_URL is set (refused if busy or unreachable), or
 *   --no-lock, an explicit operator assertion that every gateway instance sharing this key file is stopped.
 *
 * Usage (the server's own environment: QODIQA_KEYS_PATH, QODIQA_KEY_ENCRYPTION_KEY or the KMS provider settings):
 *   node scripts/keys/rotate-offline.js --client acme --mode graceful --operator alice --reason "INC-123 expired key"
 *   node scripts/keys/rotate-offline.js --client acme --mode graceful --operator alice --reason "INC-123 expired key" \
 *        --confirm-offline-recovery --no-lock
 *
 * Exit codes: 0 rotated · 1 failed (nothing or a consistent store written — see the events) · 2 dry run (nothing
 * written) · 3 refused: nothing to recover · 4 refused: lock unavailable / not asserted · 64 usage error.
 * Output: one JSON report on stdout. Events (KEY_OFFLINE_RECOVERY_*, plus the key store's own KEY_DEPRECATED /
 * KEY_REVOKED / KEY_ROTATED carrying reason + triggeredBy) go through services/logger. Never prints key material.
 * This script never loads .env: run it with the deployment's real environment.
 *
 * K1 — the TRANSPARENCY and AUDIT-CHECKPOINT Ed25519 stores:
 *   --store transparency|checkpoint   (default: artifact, the behaviour above, unchanged)
 * Their active key expires at day 180 and the next boot is then FATAL (TRANSPARENCY_SIGNER_STARTUP_FAILED /
 * CHECKPOINT_KEY_STARTUP_FAILED); there is no online rotation route for them. This is the supported path: ONE logged
 * rotation of the store's single active key, expired or not (planned rotation is due at day 90), under the same
 * mandatory --mode / --operator / --reason / --confirm-offline-recovery / lock-or---no-lock rules. --client is refused.
 *   graceful  = the outgoing key becomes 'deprecated' with retiredAt = now: it keeps verifying every root/checkpoint
 * it signed before retirement (checkpoint.js) and signs nothing again (its private bytes are
 *               zeroised and no longer persisted); the new key is active with fresh 90/180-day deadlines.
 *   emergency = the outgoing key is revoked (suspected compromise): what it signed STOPS verifying.
 * The lock is the fleet rotation lock under the id "ed25519-store:<store>". Running instances pick the new key up on
 * their next key reload tick (keyManager.reload() reloads both stores); a stopped fleet simply boots on it.
 * Paths: QODIQA_TRANSPARENCY_KEYS_PATH; QODIQA_CHECKPOINT_KEYS_PATH (default: beside the transparency file).
 * node scripts/keys/rotate-offline.js --store transparency --mode graceful --operator alice --reason "day-180" \
 *        --confirm-offline-recovery --no-lock
 * Exit codes as above; 3 = the store has no active key (the next boot provisions one).
 */

const CLIENT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MODES = new Set(['graceful', 'emergency']);
const STORES = new Set(['artifact', 'transparency', 'checkpoint']); // K1
const LOCK_TTL_MS = 60_000;

function parseArgs(argv) {
  const out = { confirm: false, noLock: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--confirm-offline-recovery') out.confirm = true;
    else if (a === '--no-lock') out.noLock = true;
    else if (['--client', '--mode', '--operator', '--reason', '--store'].includes(a)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) return { error: `${a} needs a value` };
      out[a.slice(2)] = v; i++;
    } else return { error: `unknown argument ${JSON.stringify(a)}` };
  }
  out.store = out.store === undefined ? 'artifact' : out.store;
  if (!STORES.has(out.store)) return { error: "--store must be exactly 'artifact', 'transparency' or 'checkpoint'" };
  if (out.store !== 'artifact') {
    if (out.client !== undefined) return { error: `--client does not apply to --store ${out.store} (one active key per store)` };
  } else if (!out.client || !CLIENT_ID_RE.test(out.client)) return { error: '--client <id> is required ([A-Za-z0-9_-]{1,64})' };
  if (!MODES.has(out.mode)) return { error: "--mode must be exactly 'graceful' or 'emergency' (no default)" };
  if (!out.operator || !out.operator.trim()) return { error: '--operator <id> is required' };
  if (!out.reason || out.reason.trim().length < 3) return { error: '--reason "<text>" is required' };
  return { args: out };
}

/**
 * @param {string[]} argv  arguments after the script name
 * @param {{ keyStore, kpf, rotationLock, env, emit }} deps
 * @returns {Promise<{ exitCode: number, report: object }>}
 */
async function run(argv, deps) {
  const { keyStore, kpf, rotationLock, env, emit } = deps;
  const p = parseArgs(argv);
  if (p.error) return { exitCode: 64, report: { status: 'USAGE_ERROR', error: p.error } };
  if (p.args.store !== 'artifact') return runEd25519Store(p.args, deps);
  const { client, mode, operator, reason, confirm, noLock } = p.args;
  const ctx = { clientId: client, mode, operator, reason };

  try {
    await kpf.initialize();
    await kpf.wireIntoSecretsProvider();
  } catch (err) {
    emit('ERROR', 'KEY_OFFLINE_RECOVERY_FAILED', { ...ctx, stage: 'kms-init', error: err.message });
    return { exitCode: 1, report: { status: 'FAILED', stage: 'kms-init', error: err.message } };
  }

  let ks;
  try { ks = keyStore.validateKeyStore(); } catch (err) {
    emit('ERROR', 'KEY_OFFLINE_RECOVERY_FAILED', { ...ctx, stage: 'load', error: err.message });
    return { exitCode: 1, report: { status: 'FAILED', stage: 'load', error: err.message } };
  }
  const expired = ks.expiredKeys.filter((k) => k.clientId === client);
  if (expired.length === 0) {
    const hasActive = !!(ks.clients[client] && ks.clients[client].active > 0);
    const why = hasActive
      ? 'the active key is not expired — rotate it online: POST /key-admin/:clientId/rotate'
      : 'the client has no active key — nothing to recover (provision it through /key-admin on a running instance)';
    return { exitCode: 3, report: { status: 'REFUSED', clientId: client, detail: why } };
  }
  const target = expired[0];
  const plan = { clientId: client, expiredKeyId: target.keyId, expiresAt: target.expiresAt, mode,
    outgoingKeyBecomes: mode === 'graceful' ? 'deprecated (still verifies what it signed)' : 'revoked (stops verifying)' };

  if (!confirm) {
    return { exitCode: 2, report: { status: 'DRY_RUN', plan, detail: 'nothing written — re-run with --confirm-offline-recovery' } };
  }

  let lock = null;
  if (noLock) {
    emit('WARN', 'KEY_OFFLINE_RECOVERY_UNLOCKED', { ...ctx, message: 'operator asserted every gateway instance is stopped (--no-lock)' });
  } else if (!env.REDIS_URL) {
    return { exitCode: 4, report: { status: 'REFUSED', plan, detail: 'REDIS_URL is not set: set it to take the fleet rotation lock, or pass --no-lock after stopping every gateway instance that shares this key file' } };
  } else {
    try {
      lock = await rotationLock.acquire(client, LOCK_TTL_MS);
    } catch (err) {
      return { exitCode: 4, report: { status: 'REFUSED', plan, detail: `rotation lock unavailable (fail-closed): ${err.message}` } };
    }
    if (!lock.acquired) return { exitCode: 4, report: { status: 'REFUSED', plan, detail: 'another rotation holds the lock for this client' } };
  }

  emit('WARN', 'KEY_OFFLINE_RECOVERY_STARTED', { ...ctx, keyId: target.keyId, expiresAt: target.expiresAt, locked: !!lock });
  try {
    const result = await keyStore.rotateKeyAsync(client, { mode, reason, triggeredBy: `offline-recovery-cli:${operator}` });
    const active = keyStore.getActiveKey(client); // throws if the new key were unusable
    emit('WARN', 'KEY_OFFLINE_RECOVERY_COMPLETED', { ...ctx, previousKeyId: target.keyId, keyId: result.keyId,
      previousKeyStatus: result.previousKeyStatus });
    return { exitCode: 0, report: { status: 'ROTATED', plan, keyId: active.keyId, version: result.version,
      previousKeyId: result.previousKeyId, previousKeyStatus: result.previousKeyStatus } };
  } catch (err) {
    emit('ERROR', 'KEY_OFFLINE_RECOVERY_FAILED', { ...ctx, stage: 'rotate', keyId: target.keyId, error: err.message, code: err.code || null });
    return { exitCode: 1, report: { status: 'FAILED', stage: 'rotate', plan, error: err.message } };
  } finally {
    if (lock && lock.acquired) { try { await rotationLock.release(client, lock.token); } catch { /* the lock TTL frees it */ } }
  }
}

/**
 * K1: rotate the single active key of the transparency or audit-checkpoint Ed25519 store.
 * deps.ed25519Store(name) returns the store module.
 */
async function runEd25519Store(args, deps) {
  const { kpf, rotationLock, env, emit } = deps;
  const { store, mode, operator, reason, confirm, noLock } = args;
  const ctx = { store, mode, operator, reason };
  const lockId = `ed25519-store:${store}`;

  try {
    await kpf.initialize();
    await kpf.wireIntoSecretsProvider();
  } catch (err) {
    emit('ERROR', 'KEY_OFFLINE_RECOVERY_FAILED', { ...ctx, stage: 'kms-init', error: err.message });
    return { exitCode: 1, report: { status: 'FAILED', stage: 'kms-init', error: err.message } };
  }

  let ks; let active;
  let keyStore;
  try {
    keyStore = deps.ed25519Store(store);
    ks = keyStore.validateKeyStore(); // bootstraps (an expired active key loads; only signing with it is refused)
    active = keyStore.listKeys().find((k) => k.status === 'active') || null;
  } catch (err) {
    emit('ERROR', 'KEY_OFFLINE_RECOVERY_FAILED', { ...ctx, stage: 'load', error: err.message });
    return { exitCode: 1, report: { status: 'FAILED', stage: 'load', error: err.message } };
  }
  if (!active) {
    return { exitCode: 3, report: { status: 'REFUSED', store, detail: `the ${store} store has no active key — nothing to rotate (the next boot provisions one)` } };
  }
  const expired = ks.expiredKeys.some((k) => k.keyId === active.keyId);
  const expiring = ks.expiringKeys.some((k) => k.keyId === active.keyId);
  const plan = { store, file: keyStore.DATA_PATH, activeKeyId: active.keyId, expiresAt: active.expiresAt,
    keyState: expired ? 'expired' : (expiring ? 'expiring' : 'current'), mode,
    outgoingKeyBecomes: mode === 'graceful' ? 'deprecated (still verifies what it signed before retirement)' : 'revoked (stops verifying)',
    violations: ks.violations };

  if (!confirm) {
    return { exitCode: 2, report: { status: 'DRY_RUN', plan, detail: 'nothing written — re-run with --confirm-offline-recovery' } };
  }

  let lock = null;
  if (noLock) {
    emit('WARN', 'KEY_OFFLINE_RECOVERY_UNLOCKED', { ...ctx, message: 'operator asserted every gateway instance is stopped (--no-lock)' });
  } else if (!env.REDIS_URL) {
    return { exitCode: 4, report: { status: 'REFUSED', plan, detail: 'REDIS_URL is not set: set it to take the fleet rotation lock, or pass --no-lock after stopping every gateway instance that shares this key file' } };
  } else {
    try {
      lock = await rotationLock.acquire(lockId, LOCK_TTL_MS);
    } catch (err) {
      return { exitCode: 4, report: { status: 'REFUSED', plan, detail: `rotation lock unavailable (fail-closed): ${err.message}` } };
    }
    if (!lock.acquired) return { exitCode: 4, report: { status: 'REFUSED', plan, detail: `another rotation holds the lock for the ${store} store` } };
  }

  emit('WARN', 'KEY_OFFLINE_RECOVERY_STARTED', { ...ctx, keyId: active.keyId, expiresAt: active.expiresAt, keyState: plan.keyState, locked: !!lock });
  try {
    const result = keyStore.rotateKey({ mode });
    const now = keyStore.getActiveKey(); // throws if the new key were unusable
    const post = keyStore.validateKeyStore();
    if (post.expiredKeys.length > 0 || post.violations.length > 0) {
      const e = new Error(`post-rotation validation failed: ${JSON.stringify({ expiredKeys: post.expiredKeys, violations: post.violations })}`);
      e.code = 'POST_ROTATION_INVALID';
      throw e;
    }
    emit('WARN', 'KEY_OFFLINE_RECOVERY_COMPLETED', { ...ctx, previousKeyId: active.keyId, keyId: result.keyId,
      previousKeyStatus: result.previousKeyStatus });
    return { exitCode: 0, report: { status: 'ROTATED', plan, keyId: now.keyId, version: result.version,
      previousKeyId: result.previousKeyId, previousKeyStatus: result.previousKeyStatus } };
  } catch (err) {
    emit('ERROR', 'KEY_OFFLINE_RECOVERY_FAILED', { ...ctx, stage: 'rotate', keyId: active.keyId, error: err.message, code: err.code || null });
    return { exitCode: 1, report: { status: 'FAILED', stage: 'rotate', plan, error: err.message } };
  } finally {
    if (lock && lock.acquired) { try { await rotationLock.release(lockId, lock.token); } catch { /* the lock TTL frees it */ } }
  }
}

const ED25519_STORE_MODULES = {
  transparency: '../../src/core/transparency/transparencyKeyStore',
  checkpoint: '../../src/core/audit/checkpoint/checkpointKeyStore',
};

async function main() {
  const deps = {
    ed25519Store: (name) => require(ED25519_STORE_MODULES[name]),
    keyStore: require('../../services/artifact/keyStore'),
    kpf: require('../../src/infra/keys/keyProviderFactory'),
    rotationLock: require('../../src/infra/keys/rotationLock'),
    env: process.env,
    emit: require('../../services/logger').emit,
  };
  let res;
  try {
    res = await run(process.argv.slice(2), deps);
  } finally {
    try { await deps.kpf.shutdown(); } catch { /* best effort */ }
    try { if (process.env.REDIS_URL) await deps.rotationLock.disconnect(); } catch { /* best effort */ }
  }
  process.stdout.write(JSON.stringify(res.report, null, 2) + '\n');
  process.exitCode = res.exitCode;
}

module.exports = { run, parseArgs, runEd25519Store, ED25519_STORE_MODULES };

if (require.main === module) {
  main().catch((err) => { process.stderr.write(`rotate-offline: ${err.message}\n`); process.exitCode = 1; });
}
