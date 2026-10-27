'use strict';

/**
 * perf-tooling isolation — mirrors test/support/jest.setup.js exactly, so
 * benchmark/load/stress/soak runs never touch production data/keys.json,
 * the production audit.log, or the production transparency keystore.
 * Must be required before any module that transitively loads keyStore.js
 * (DATA_PATH there is evaluated at require() time from these env vars).
 */

const os = require('os');
const fs = require('fs');
const path = require('path');

// Must run before any module that reads provider config at require-time
// (services/providers/config.js builds its CONFIGS object from
// process.env.* once, at first require) — without this, real-provider
// benchmarks would silently see every provider as disabled.
const _explicitBeforeDotenv = new Set(Object.keys(process.env));
require('dotenv').config();
// 2026-10-06 (test-isolation sweep): .env is loaded for PROVIDER settings only. On the dev machine it also names
// the PostgreSQL cluster hosting LIVE (127.0.0.1:5432) and the live dev Redis (6379); a perf/soak run must never inherit
// those as targets. Outside CI, every PostgreSQL/Redis TARGET key that only .env supplied is blanked — a run that needs a
// database or Redis must pass an explicit disposable target in its own environment (e.g. via
//).
if (process.env.CI !== 'true') {
  for (const k of ['QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_URL', 'QODIQA_PG_DATABASE', 'DATABASE_URL', 'PGHOST', 'PGPORT', 'REDIS_URL', 'REDIS_HOST', 'REDIS_PORT']) {
    if (!_explicitBeforeDotenv.has(k) && process.env[k] !== undefined) process.env[k] = '';
  }
}

// ── PostgreSQL mirror isolation (FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md §8,
// prevention layer 2) ───────────────────────────────────────────────────────
// Mirrors test/support/jest.setup.js's identical guard: benchmark.js/memoryProfile.js and
// friends call appendMandatory() directly against whatever QODIQA_PG_DATABASE
// is ambient in .env — that report identified this as carrying the same
// structural risk as the test suite that actually caused the recurring
// audit-mirror divergence (writing real, permanent rows with no file-side
// counterpart), just not yet exercised. Force PG off for local runs unless
// explicitly opted in; CI is unaffected (CI=true is set automatically by the
// runner, and no perf script currently runs in CI).
if (
  process.env.QODIQA_PG_ENABLED === 'true' &&
  process.env.CI !== 'true' &&
  process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS !== 'true'
) {
  // eslint-disable-next-line no-console
  console.warn(
    '[setupEnv] QODIQA_PG_ENABLED=true ambient from .env, but this is a local, non-CI run ' +
    'with no QODIQA_ALLOW_PG_INTEGRATION_TESTS=true opt-in — forcing QODIQA_PG_ENABLED=false ' +
    'for this run (see FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md). Set ' +
    'QODIQA_ALLOW_PG_INTEGRATION_TESTS=true to opt in.'
  );
  process.env.QODIQA_PG_ENABLED = 'false';
}

if (!process.env.QODIQA_KEY_ENCRYPTION_KEY) {
  process.env.QODIQA_KEY_ENCRYPTION_KEY =
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
}

// ── Temp-dir teardown (B1) ──────────────────────────────────────────────────
// Every mkdtempSync below previously had no matching cleanup, so each perf
// script run left its keystore/audit/transparency scratch dirs behind in
// os.tmpdir() permanently (qodiqa-perf-* accumulation). Track every dir THIS
// process creates and remove it on exit; set QODIQA_PERF_KEEP_TEMP=true to
// opt out (e.g. to inspect a run's generated keys.json/audit.log afterward).
const KEEP_TEMP = process.env.QODIQA_PERF_KEEP_TEMP === 'true';
const createdTempDirs = [];
process.on('exit', () => {
  if (KEEP_TEMP) return;
  for (const dir of createdTempDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_) { /* best-effort — process is already exiting */ }
  }
});

try {
  if (!process.env.QODIQA_KEYS_PATH) {
    const ksDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-perf-ks-'));
    createdTempDirs.push(ksDir);
    process.env.QODIQA_KEYS_PATH = path.join(ksDir, 'keys.json');
  }
  if (!process.env.QODIQA_AUDIT_LOG) {
    const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-perf-audit-'));
    createdTempDirs.push(auditDir);
    process.env.QODIQA_AUDIT_LOG = path.join(auditDir, 'audit.log');
  }
  // eslint-disable-next-line global-require
  const { ensureActiveKey } = require('../../lib/keyStoreProvisioning');
  ensureActiveKey('default');
} catch (_) { /* handled per-script if keyStore is unavailable */ }

try {
  if (!process.env.QODIQA_TRANSPARENCY_KEYS_PATH) {
    const tsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-perf-ts-'));
    createdTempDirs.push(tsDir);
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = path.join(tsDir, 'transparency-keys.json');
  }
  // eslint-disable-next-line global-require
  const { ensureActiveTransparencyKey } = require('../../lib/keyStoreProvisioning');
  ensureActiveTransparencyKey();
} catch (_) { /* not needed by most perf scripts */ }

module.exports = {};
