'use strict';

/**
 * Pure environment-variable builders for acceptance tests that spawn
 * server.js DIRECTLY (not via scripts/bootstrap-dev.js) and therefore need
 * full, explicit control over which QODIQA_* variables exist — e.g. AT-001
 * (env-var fail-closed sequencing) and AT-009 (empty key store).
 *
 * Unlike scripts/lib/devEnvironment.js, nothing here ever mutates
 * process.env of the calling process. The acceptance runner is a single
 * long-lived Node process executing ~100 tests in sequence; mutating its own
 * process.env (or relying on modules that cache a path read from it at
 * require() time, like services/artifact/keyStore.js) would leak state
 * between tests. Every function here returns a plain env object to hand to
 * child_process.spawn's `env` option instead.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function generateKek() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Fresh isolated on-disk paths for one test. Never inside data/, config/, or
 * the repository root.
 */
function createIsolatedPaths(tempPrefix = 'qodiqa-acceptance-') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), tempPrefix));
  return {
    root,
    keysPath: path.join(root, 'keys.json'),
    transparencyKeysPath: path.join(root, 'transparency-keys.json'),
    auditLogPath: path.join(root, 'audit.log'),
    signingStorePath: path.join(root, 'signing-identities.json'),
  };
}

/**
 * Provisions a single dev-scoped signing identity directly into an isolated
 * store file, and returns its plaintext signing API key — the acceptance
 * suite's own out-of-band equivalent of scripts/provision-signing-identity.js
 * (TRUST-1 remediation: there is no more shared QODIQA_SIGN_TOKEN to generate).
 *
 * signingIdentityStore.js re-reads QODIQA_SIGNING_STORE_PATH from
 * process.env on every _loadFromDisk() call following a _reset() — never
 * caches the path at require() time — so this function can safely target an
 * arbitrary path without mutating this (long-lived, shared-across-tests)
 * process's env: it sets the var, does its writes, then restores whatever
 * was there before, exactly bracketing the store's own module-level cache
 * reset so no state leaks to whichever test runs next in this same process.
 */
function provisionSigningIdentity({ signingStorePath, tenantId, environment = 'development', allowedProviders = null }) {
  // eslint-disable-next-line global-require
  const store = require('../../src/core/signing/signingIdentityStore');
  const prevPath = process.env.QODIQA_SIGNING_STORE_PATH;
  process.env.QODIQA_SIGNING_STORE_PATH = signingStorePath;
  store._reset();
  try {
    const identity = store.createSigningIdentity({
      name:        `${tenantId}-acceptance`,
      tenantId,
      environment,
      allowedProviders,
      permissions: ['SIGN_ARTIFACT'],
      createdBy:   'ACCEPTANCE_TEST',
    });
    const { plaintext } = store.issueSigningKey(identity.id, { issuedBy: 'ACCEPTANCE_TEST' });
    // REL-01: the store writes only to the in-memory control plane — the legacy file is import-only.
    // A raw-spawned server in memory mode seeds from that file, so hand the identity over through it, exactly as
    // scripts/lib/devEnvironment.js does (exportSeedFixture → QODIQA_SIGNING_STORE_PATH, still set here).
    store.exportSeedFixture();
    return plaintext;
  } finally {
    store._reset();
    if (prevPath === undefined) delete process.env.QODIQA_SIGNING_STORE_PATH;
    else process.env.QODIQA_SIGNING_STORE_PATH = prevPath;
  }
}

function removePaths(paths) {
  if (paths && paths.root && fs.existsSync(paths.root)) {
    fs.rmSync(paths.root, { recursive: true, force: true });
  }
}

/**
 * A minimal, functional base environment (PATH/SystemRoot/TEMP/etc. that
 * Node itself needs to run and resolve child processes) without inheriting
 * any ambient QODIQA_ / REDIS_URL / AI-provider variables that might happen
 * to be set in the runner's own shell — every acceptance test should start from
 * a known-clean slate and opt in to exactly the variables it needs.
 */
const OS_PASSTHROUGH_KEYS = [
  'PATH', 'Path', 'SystemRoot', 'SystemDrive', 'TEMP', 'TMP', 'windir',
  'ComSpec', 'PATHEXT', 'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
  'APPDATA', 'LOCALAPPDATA', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE',
];

function baseOsEnv() {
  const env = {};
  for (const key of OS_PASSTHROUGH_KEYS) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  // phase 17: every directly-spawned child preloads the LIVE-endpoint socket guard (CI exempt), so a product
  // default (localhost:5432, redis://localhost:6379) can never reach the LIVE services on the development machine.
  // eslint-disable-next-line global-require
  const guard = require('../helpers/liveEndpointGuard');
  if (!guard.isExempt(process.env)) env.NODE_OPTIONS = guard.withPreload(process.env.NODE_OPTIONS);
  return env;
}

/**
 * Builds a complete, explicit env object for a directly-spawned server.js,
 * with every QODIQA_* variable the caller does NOT specify simply absent
 * (not defaulted) — so tests like AT-001 can add exactly one variable at a
 * time and observe the next fail-closed check fire.
 *
 * "Absent" has one loophole: server/startup.js calls dotenv.config() at
 * boot, and dotenv BACKFILLS any variable missing from the child's env from
 * the repo's .env file (it never overrides one that exists — even as an
 * empty string). On a dev machine whose .env carries provider keys and
 * QODIQA_PG_* config, a raw-spawned server therefore silently inherited all
 * of it: AT-001's "no provider configured" spawn booted with .env's
 * providers, PG enabled against the shared database, and died on the
 * audit-mirror consistency check instead of the check under test
 *. To make "absent" mean absent, every
 * key the repo .env file defines is pre-blocked with an explicit empty
 * string — the value QODIQA's fail-closed checks already treat as
 * unconfigured — unless the caller's overrides set it.
 *
 * @param {object} [overrides] variables to set/override on top of the OS-passthrough base
 */
function dotenvKeyBlock() {
  const envPath = path.join(__dirname, '..', '..', '.env');
  if (!fs.existsSync(envPath)) return {};
  let parsed;
  try {
    // eslint-disable-next-line global-require
    parsed = require('dotenv').parse(fs.readFileSync(envPath, 'utf8'));
  } catch {
    return {};
  }
  const block = {};
  for (const key of Object.keys(parsed)) block[key] = '';
  return block;
}

// QODIQA_PG_USER / _PASSWORD and every QODIQA_PG_<ROLE>_USER / _PASSWORD (below).
const PG_CREDENTIAL_KEY = /^QODIQA_PG_(?:[A-Z]+_)?(?:USER|PASSWORD)$/;

function buildRawEnv(overrides = {}) {
  const block = dotenvKeyBlock();
  // A raw case that explicitly opts into PostgreSQL (sets QODIQA_PG_ENABLED
  // or QODIQA_PG_DATABASE) needs the QODIQA_PG_* credential family it does
  // NOT override to keep backfilling from .env — the retention-role startup
  // gate (server/startup.js → retentionPrivilegeCheck) connects with
  // QODIQA_PG_RETENTION_PASSWORD, which no case passes explicitly. Blocking
  // those to '' turns a deliberate PG opt-in into a 28P01 boot fatal.
  //
  // phase 17: credentials only — never the connection TARGET. Un-blocking QODIQA_PG_HOST/PORT/URL let a case
  // that named only QODIQA_PG_DATABASE back-fill .env's cluster (on the development machine the one hosting LIVE,
  // 127.0.0.1:5432). Every PG case passes its host/port explicitly (from helpers/postgres.js), so the target keys stay
  // blocked unless the case overrides them.
  //
  // Credentials only from THIS process's explicit env (the test environment / CI), never from .env.
  // Un-blocking the credential keys let the child's dotenv back-fill hand it .env's role passwords — on the development
  // machine the LIVE cluster's rotated qodiqa_system / qodiqa_reporting / … passwords — which then failed (28P01)
  // against the disposable acceptance cluster and boot-fataled AT-045/079/081/097/098. A credential key .env defines but
  // this process does not stays blocked ('' = unconfigured); every other non-target QODIQA_PG_* key keeps the old rule.
  if (overrides.QODIQA_PG_ENABLED === 'true' || overrides.QODIQA_PG_DATABASE) {
    // eslint-disable-next-line global-require
    const { TARGET_KEYS } = require('../helpers/liveEndpointGuard');
    for (const key of Object.keys(block)) {
      if (key.startsWith('QODIQA_PG_') && !TARGET_KEYS.includes(key) && !PG_CREDENTIAL_KEY.test(key)) delete block[key];
    }
    for (const key of Object.keys(process.env)) {
      if (PG_CREDENTIAL_KEY.test(key)) block[key] = process.env[key];
    }
  }
  return { ...baseOsEnv(), ...block, ...overrides };
}

/**
 * Builds a fully isolated, working env object (KEK, signing identity store,
 * client id, fresh key/audit/transparency paths, an AI provider default) —
 * everything server.js needs to start successfully — for tests that spawn
 * server.js directly but still want it to actually reach GATEWAY_START (e.g.
 * AT-009, which only wants the key STORE empty, everything else healthy).
 *
 * TRUST-1 remediation: there is no more shared QODIQA_SIGN_TOKEN for the
 * spawned server to read. Instead, a single dev-scoped signing identity is
 * provisioned directly into paths.signingStorePath (see
 * provisionSigningIdentity() above), and its plaintext API key is returned
 * as env.QODIQA_SIGN_TOKEN for backward compatibility with existing
 * acceptance scripts that read `fixedEnv.QODIQA_SIGN_TOKEN` and pass it to
 * ctx.artifacts.callSign() — that field name is legacy but its value is now
 * a real per-identity credential, not a shared secret; server.js itself
 * never reads this env var.
 *
 * @param {object} [opts]
 * @param {string} [opts.clientId='acceptance-test']
 * @param {string} [opts.tempPrefix='qodiqa-acceptance-']
 * @param {object} [opts.overrides] applied last, can override any generated value
 * @param {boolean} [opts.emptyKeyStore=false] when true, keysPath points at a
 *   file that is never created (KEYSTORE_EMPTY at startup)
 */
function buildWorkingEnv(opts = {}) {
  const clientId = opts.clientId || 'acceptance-test';
  const paths = createIsolatedPaths(opts.tempPrefix || 'qodiqa-acceptance-');

  const signingKey = provisionSigningIdentity({
    signingStorePath: paths.signingStorePath,
    tenantId:         clientId,
    environment:      'development',
  });

  const env = buildRawEnv({
    NODE_ENV: 'development',
    QODIQA_KEY_ENCRYPTION_KEY: generateKek(),
    // The EXECUTE path's provider dispatch HMAC-binds the execution
    // invariant context with this 64-hex secret (services/
    // executionInvariantToken.js via secretsProvider.js). Raw servers used
    // to inherit it silently from .env via dotenv backfill; with backfill
    // blocked (see dotenvKeyBlock) a working env must provision its own,
    // exactly like the KEK above.
    QODIQA_EXECUTION_INVARIANT_SECRET: generateKek(),
    QODIQA_SIGN_TOKEN: signingKey, // legacy field name — see doc comment above
    QODIQA_CLIENT_ID: clientId,
    QODIQA_KEYS_PATH: paths.keysPath,
    QODIQA_AUDIT_LOG: paths.auditLogPath,
    QODIQA_TRANSPARENCY_KEYS_PATH: paths.transparencyKeysPath,
    QODIQA_SIGNING_STORE_PATH: paths.signingStorePath,
    LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1',
    // the local provider no longer falls back to an OpenAI model name; requests that omit
    // `model` use PROVIDER_DEFAULT_MODEL_LOCAL (the model the project's real-runtime e2e evidence used).
    PROVIDER_DEFAULT_MODEL_LOCAL: 'llama3.2:1b',
    STRICT_REPLAY_PROTECTION: 'false',
    // REL-01: an isolated tenant seed (see below) — never the repository's data/tenants.json.
    TENANT_STORE_PATH: path.join(paths.root, 'tenants.json'),
    ...opts.overrides,
  });

  // REL-01: the tenant registry writes only to the in-memory control plane, so registering the tenant
  // in a provisioning process never reached a raw-spawned server, and every signed request BLOCKed TENANT_UNKNOWN.
  // Hand it over through the (isolated) seed file, exactly as scripts/lib/devEnvironment.js does.
  // Memory mode only (PostgreSQL mode reads the control plane, never the seed file — devEnvironment.js's same guard).
  if (env.NODE_ENV === 'production' || env.QODIQA_CONTROL_PLANE_BACKEND === 'pg') return { env, paths };
  const reg = spawnSync(process.execPath, ['-e',
    "const r = require('./src/core/tenancy/tenantRegistry'); " +
    "try { r.registerTenant(process.env.QODIQA_CLIENT_ID); } catch (e) { if (!/already/i.test(e.message)) throw e; } " +
    'r.exportSeedFixture();',
  ], { cwd: path.join(__dirname, '..', '..'), env, encoding: 'utf8' });
  if (reg.status !== 0) throw new Error(`tenant seed provisioning failed: ${reg.stderr || reg.stdout}`);

  return { env, paths };
}

module.exports = {
  generateKek,
  provisionSigningIdentity,
  createIsolatedPaths,
  removePaths,
  baseOsEnv,
  buildRawEnv,
  buildWorkingEnv,
};
