#!/usr/bin/env node
'use strict';

/**
 * OA-RC-2 — the OFFLINE seal step for the key stores.
 *
 * Production now requires sealed (authenticated) key files by default (src/infra/crypto/keyRecordSeal.sealRequired):
 * a key file written before record sealing existed is refused at boot instead of being sealed on first use. This
 * command performs that one-time seal deliberately, while the gateway is STOPPED, with the deployment's own key-
 * encryption key (QODIQA_KEY_ENCRYPTION_KEY and the same QODIQA_*_KEYS_PATH variables the gateway uses):
 *
 *   1. reports, per store (artifact keys, transparency keys, checkpoint keys): path, sha256, sealed or not, key ids and
 *      SHA-256 fingerprints of their PUBLIC keys — compare these with the published /.well-known/qodiqa/* key sets
 *      BEFORE sealing: sealing makes whatever is on disk authoritative (it is trust-on-first-use, run on purpose);
 *   2. with --seal: loads each store through its own bootstrap (decrypting every key with the KEK — a wrong KEK fails
 *      here and nothing is written), which seals and rewrites an unsealed file atomically;
 *   3. verifies in a SEPARATE process with QODIQA_KEYSTORE_REQUIRE_SEALED=true that every store now loads sealed and
 *      validates with zero violations, and prints the sha256 after.
 *
 * usage:  node scripts/keys/seal-keystore.js                       (report only)
 *         node scripts/keys/seal-keystore.js --seal --confirm-gateway-stopped
 * exit:   0 = every store sealed and verified (or report only) · 1 = a store failed to seal/verify · 2 = usage error
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const STORES = [
  { name: 'artifact', module: 'services/artifact/keyStore' },
  { name: 'transparency', module: 'src/core/transparency/transparencyKeyStore' },
  { name: 'checkpoint', module: 'src/core/audit/checkpoint/checkpointKeyStore' },
];

function storePath(name) {   // the same resolution the stores use (services/artifact/keyStore.js, transparencyKeyStore.js, checkpointKeyStore.js)
  const env = process.env;
  if (name === 'artifact') return path.resolve(env.QODIQA_KEYS_PATH || path.join(ROOT, 'data', 'keys.json'));
  if (name === 'transparency') return path.resolve(env.QODIQA_TRANSPARENCY_KEYS_PATH || path.join(ROOT, 'data', 'transparency-keys.json'));
  return path.resolve(env.QODIQA_CHECKPOINT_KEYS_PATH
    || (env.QODIQA_TRANSPARENCY_KEYS_PATH ? path.join(path.dirname(path.resolve(env.QODIQA_TRANSPARENCY_KEYS_PATH)), 'checkpoint-keys.json') : path.join(ROOT, 'data', 'checkpoint-keys.json')));
}

function inspect(name) {
  const p = storePath(name);
  if (!fs.existsSync(p)) return { store: name, path: p, exists: false };
  const raw = fs.readFileSync(p);
  let data = null; try { data = JSON.parse(raw.toString('utf8')); } catch { /* reported below */ }
  const seal = require(path.join(ROOT, 'src/infra/crypto/keyRecordSeal'));
  const keys = [];
  const add = (keyId, e) => { const pk = e && (e.publicKeyDer || e.publicKeyB64 || e.publicKey); if (pk) keys.push({ keyId, status: e.status || null, publicKeySha256: crypto.createHash('sha256').update(Buffer.from(String(pk), 'base64')).digest('hex') }); };
  if (data && data.clients) for (const cd of Object.values(data.clients)) for (const [k, e] of Object.entries(cd || {})) add(k, e);
  if (data && data.keys) for (const [k, e] of Object.entries(data.keys)) add(k, e);
  return { store: name, path: p, exists: true, sha256: crypto.createHash('sha256').update(raw).digest('hex'), parsed: !!data,
    sealed: data ? seal.isSealedFile(data) : false, keys };
}

// Runs in a child process: bootstrap one store (sealing it when allowed) and validate it.
function childLoad(name, requireSealed) {
  const store = STORES.find((s) => s.name === name);
  const js = `
    const s = require(${JSON.stringify(path.join(ROOT, store.module))});
    try { s.listKeys(); const v = s.validateKeyStore(); const violations = Array.isArray(v) ? v : (v && v.violations) || [];
      console.log('RESULT ' + JSON.stringify({ ok: violations.length === 0, violations: violations.map((x) => x.type || x) }));
    } catch (e) { console.log('RESULT ' + JSON.stringify({ ok: false, error: e.message })); }`;
  // no `cwd`: the shipped seccomp profile denies chdir (the gateway never needs it) — spawn with cwd fails EPERM in the
  // container; the requires above are absolute, so the inherited working directory is irrelevant
  const r = spawnSync(process.execPath, ['-e', js], { encoding: 'utf8',
    env: { ...process.env, QODIQA_KEYSTORE_REQUIRE_SEALED: requireSealed ? 'true' : 'false' } });
  const line = (r.stdout || '').split('\n').find((l) => l.startsWith('RESULT '));
  return line ? JSON.parse(line.slice(7)) : { ok: false, error: (r.error && (r.error.code || r.error.message)) || (r.stderr || '').trim().split('\n').slice(-1)[0] || `exit ${r.status} signal ${r.signal}` };
}

function main(argv) {
  const seal = argv.includes('--seal');
  if (seal && !argv.includes('--confirm-gateway-stopped')) {
    console.error('usage error: --seal rewrites the key files; stop the gateway first and pass --confirm-gateway-stopped');
    return 2;
  }
  if (argv.some((a) => !['--seal', '--confirm-gateway-stopped'].includes(a))) { console.error('usage error: unknown argument'); return 2; }
  const before = STORES.map((s) => inspect(s.name));
  console.log(JSON.stringify({ step: 'before', stores: before }, null, 1));
  if (!seal) return 0;
  let ok = true;
  for (const b of before) {
    if (!b.exists) { console.log(JSON.stringify({ step: 'seal', store: b.store, skipped: 'no key file (created sealed on first use)' })); continue; }
    if (!b.sealed) {
      const r = childLoad(b.store, false);
      console.log(JSON.stringify({ step: 'seal', store: b.store, ...r }));
      if (r.error) { ok = false; continue; }
    }
    const v = childLoad(b.store, true);
    const after = inspect(b.store);
    console.log(JSON.stringify({ step: 'verify', store: b.store, requireSealed: true, ...v, sealed: after.sealed, sha256Before: b.sha256, sha256After: after.sha256 }));
    if (!v.ok || !after.sealed) ok = false;
  }
  console.log(ok ? 'SEAL_OK: every key store loads sealed with QODIQA_KEYSTORE_REQUIRE_SEALED=true' : 'SEAL_FAILED: see the lines above; nothing was changed for a store that failed to load');
  return ok ? 0 : 1;
}

if (require.main === module) process.exit(main(process.argv.slice(2)));
module.exports = { main, inspect, storePath };
