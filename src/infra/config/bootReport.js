'use strict';

/**
 * BOOT_REPORT — one truthful, secret-free statement of what THIS process is
 * actually running with.
 *
 * Emitted once as INFO BOOT_REPORT right after GATEWAY_START, and written to
 * the path in QODIQA_BOOT_REPORT_PATH when that variable is set (used to
 * produce<profile>.json).
 *
 * "Truthful" is the contract, so every field is OBSERVED from the running
 * process, never inferred from what the configuration intended:
 *   - PostgreSQL TLS is read from pg_stat_ssl for the app pool's own backend;
 *   - migrations are read from qodiqa_migrations over that same connection;
 *   - signing keys come from the loaded keystore (ids and status only);
 *   - providers are the ones the provider config actually ENABLED;
 *   - rate limiting reports the limiter's enablement AND its storage
 * readiness separately (they differ, and the earlier logs conflated them);
 *   - the semantic fingerprint hashes the EFFECTIVE (post-env) configuration
 *     the classifier booted with — read-only; nothing here changes it.
 * A probe that fails is reported as { observed: false, error } — never
 * silently replaced by the configured intent.
 *
 * Never contains secret values: config vars appear only inside
 * configFingerprint (secret-like names hashed as <set>/<unset>), key material
 * is never read beyond the key id, and URLs are redacted.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const SCHEMA_VERSION = 1;

function sha256(value) {
  return crypto.createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
}

// Stable JSON: object keys sorted recursively, so a fingerprint never depends
// on property insertion order.
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k])]));
  }
  return value;
}

async function observe(fn) {
  try {
    return { observed: true, ...(await fn()) };
  } catch (err) {
    return { observed: false, error: err.code ? `${err.code}: ${err.message}` : err.message };
  }
}

/** PostgreSQL facts over the app pool's own connection. */
async function postgresFacts({ pg, pgSslConfigured }) {
  if (!pg.isEnabled()) return { enabled: false };
  // client = this process's socket; server = pg_stat_ssl for the same backend.
  // With TLS terminated by a proxy in front of PostgreSQL, client.tls is true
  // and server.ssl is false — both are reported, neither is inferred.
  const tls = await observe(async () => ({ configured: pgSslConfigured, ...(await pg.connectionSecurity()) }));
  if (!tls.observed) tls.configured = pgSslConfigured;
  const migrations = await observe(async () => {
    const { rows } = await pg.query(
      'SELECT version, name FROM qodiqa_migrations ORDER BY version DESC');
    const onDisk = listMigrationFiles();
    return {
      applied: rows.length,
      latest:  rows[0] ? { version: rows[0].version, name: rows[0].name } : null,
      onDisk:  onDisk.length,
      pending: onDisk.length - rows.length,
    };
  });
  return { enabled: true, tls, migrations };
}

function listMigrationFiles() {
  const dir = path.join(__dirname, '..', 'postgres', 'migrations');
  return fs.readdirSync(dir).filter((f) => /^\d+.*\.sql$/.test(f));
}

function keyFacts(listKeys) {
  const keys = listKeys();
  return {
    count:  keys.length,
    active: keys.filter((k) => k.status === 'active').map((k) => k.keyId).sort(),
    byStatus: keys.reduce((acc, k) => { acc[k.status] = (acc[k.status] || 0) + 1; return acc; }, {}),
  };
}

function semanticFacts(semanticConfig, semanticStatus) {
  const effective = canonical({
    thresholds: {
      similarity:  semanticConfig.SIMILARITY_THRESHOLD,
      family:      semanticConfig.FAMILY_SIMILARITY_THRESHOLDS,
      head:        semanticConfig.HEAD_SCORE_THRESHOLD,
      v9:          semanticConfig.V9_SCORE_THRESHOLD,
      v5:          semanticConfig.V5_SCORE_THRESHOLD,
      ft2BandBLo:  semanticConfig.FT2_BAND_B_LO,
      ft2Family:   semanticConfig.FT2_FAMILY_THRESHOLDS,
      ft3BandBLo:  semanticConfig.FT3_BAND_B_LO,
      ft3Family:   semanticConfig.FT3_FAMILY_THRESHOLDS,
    },
    flags: {
      ft2:         semanticConfig.FT2_ENABLED,
      ft3:         semanticConfig.FT3_ENABLED,
      normalize:   semanticConfig.NORMALIZE_ENABLED,
      normalizeV2: semanticConfig.NORMALIZE_V2_ENABLED,
      tailWindow:  semanticConfig.TAIL_WINDOW_ENABLED,
      intentGate:  semanticConfig.INTENT_GATE_ENABLED,
    },
  });
  const deviations = semanticConfig.getDeviations();
  return {
    model:        semanticStatus.model,
    bootStatus:   semanticStatus.status,
    anchorCount:  semanticStatus.anchorCount,
    flags:        effective.flags,
    deviatesFromPinnedDefaults: deviations.length > 0,
    deviations:   deviations.map((dev) => dev.key),
    fingerprint:  sha256(effective),
    pinnedDefaultsFingerprint: sha256(canonical(semanticConfig.PINNED_DEFAULTS)),
  };
}

/**
 * @param {object} facts   what startup.js already observed during boot
 * @param {object} deps    module accessors. `listKeys` (→ the loaded keystore's
 *                         listing function) and `providers` (→ enabled provider
 *                         names) are REQUIRED and supplied by server/startup.js:
 *                         infra must not import services (arch rule
 *                         no-infra-to-services). The rest default to infra/core
 *                         modules and are injectable for tests.
 */
async function buildBootReport(facts, deps = {}) {
  for (const k of ['listKeys', 'providers']) {
    if (typeof deps[k] !== 'function') throw new TypeError(`buildBootReport: deps.${k} is required`);
  }
  const d = {
    validation:     () => require('./bootValidator').getLastBootValidation(),
    pg:             () => require('../postgres/pool'),
    pgSsl:          () => require('../postgres/pgSsl').resolvePgSslOptions(process.env) !== false,
    redisSummary:   () => require('../redis/clientConfig').getConfigSummary(),
    semanticConfig: () => require('../../core/semantic/embeddingSimilarity/config'),
    semanticStatus: () => require('../../core/semantic/embeddingSimilarity').getStatus(),
    opsConfig:      () => facts.opsConfig,
    ...deps,
  };
  const validation = d.validation() || {};
  const ops = d.opsConfig() || {};
  const redis = d.redisSummary();
  const anyRedisStoreReady = !!(facts.nonceReady || facts.anomalyReady || facts.rlReady);

  const report = {
    schemaVersion: SCHEMA_VERSION,
    generatedAt:   new Date().toISOString(),
    pid:           process.pid,
    node:          process.version,
    profile:       validation.profile ?? null,
    nodeEnv:       validation.nodeEnv ?? process.env.NODE_ENV ?? null,
    config: {
      fingerprint:  validation.fingerprint ?? null,
      warnings:     (validation.warnings || []).map((w) => w.variable),
    },
    postgres: await postgresFacts({ pg: d.pg(), pgSslConfigured: d.pgSsl() }),
    redis: {
      url:           redis.urlRedacted,
      tlsConfigured: redis.tlsEnabled,
      tlsVerified:   redis.tlsVerified,
      authConfigured: redis.authConfigured,
      // A TLS-configured client cannot speak plaintext, so a READY store over
      // a TLS configuration means TLS was established.
      tlsEstablished: redis.tlsEnabled && anyRedisStoreReady,
      stores: { nonce: !!facts.nonceReady, anomaly: !!facts.anomalyReady, policyRateLimit: !!facts.rlReady },
    },
    keys:      await observe(async () => keyFacts(d.listKeys())),
    providers: d.providers(),
    rateLimit: {
      requestLimiterEnabled:  !!facts.requestRateLimitEnabled,
      requestLimiterStorageReady: !!facts.requestRateLimitStorageReady,
      protectionActive:       !!facts.requestRateLimitEnabled && !!facts.requestRateLimitStorageReady,
      policyRateLimitStoreReady: !!facts.rlReady,
      // the real state, in words. 'off' only via RL_ENABLED=false.
      mode: !facts.requestRateLimitEnabled ? 'off (RL_ENABLED=false)'
        : facts.requestRateLimitStorageReady ? 'on (Redis)'
          : 'on, backend not ready: failMode=closed buckets return 429, failMode=degrade buckets use the per-process fallback',
      failModes: facts.requestRateLimitFailModes ?? null,
    },
    planes: {
      admin:       ops.adminEnabled === true,
      diagnostics: ops.diagnosticsEnabled === true,
      profiling:   ops.profilingDiagnosticsEnabled === true,
      opsTokenConfigured: !!ops.token,
    },
    semantic: await observe(async () => semanticFacts(d.semanticConfig(), d.semanticStatus())),
    executionIntegrity: facts.executionIntegrity ?? null,
    // audit store — group commit on/off (rollback switch) and any boot WAL recovery / torn-tail repair.
    auditStorage: facts.auditStorage ?? null,
  };
  return report;
}

/**
 * Build, emit and (optionally) persist the report. Never throws: a failure is
 * emitted as BOOT_REPORT_FAILED, because a reporting fault must not take down
 * a gateway that has already started.
 */
async function emitBootReport(facts, { emit, env = process.env, deps } = {}) {
  try {
    const report = await buildBootReport(facts, deps);
    emit('INFO', 'BOOT_REPORT', { report });
    if (env.QODIQA_BOOT_REPORT_PATH) {
      fs.writeFileSync(env.QODIQA_BOOT_REPORT_PATH, JSON.stringify(report, null, 2) + '\n');
    }
    return report;
  } catch (err) {
    emit('ERROR', 'BOOT_REPORT_FAILED', { error: err.message });
    return null;
  }
}

module.exports = { buildBootReport, emitBootReport, canonical, SCHEMA_VERSION };
