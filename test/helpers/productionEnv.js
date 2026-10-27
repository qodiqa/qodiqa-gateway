'use strict';

// build a child-process environment that PASSES every production boot rule
// so a test can change exactly one thing and assert
// the refusal — or success — it cares about.
//
//  - Starts from SYSTEM variables only (PATH, SystemRoot, TEMP, …): nothing
//    QODIQA-scoped leaks from the Jest worker (test/support/jest.setup.js deliberately sets
//    test-only toggles such as QODIQA_SEM_FT3_ENABLED=false and an all-F KEK,
//    which production correctly refuses).
//  - Every variable name the local .env defines is set explicitly (to our value
//    or to ''), so the child's own dotenv load (server/startup.js) cannot
//    backfill it. PostgreSQL connection settings/passwords are taken from .env
//    only when the test enables PG; they are passed through, never logged.
//  - Secrets are fresh random values; the provider is a loopback URL.
//  - validProductionEnv() self-checks with the real validator and throws if the
//    result would not pass — so a test failure always means the rule under test.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { secretProblems } = require('../../src/infra/config/credentialRules');

const REPO_ROOT = path.join(__dirname, '..', '..');
const SCOPED = /^(QODIQA_|OPENAI_|ANTHROPIC_|GEMINI_|MISTRAL_|LLAMA_|LOCAL_|REDIS_|RL_|POLICY_FILE$|NODE_ENV$|STRICT_REPLAY_PROTECTION$|REVOCATION_|ORG_STATUS_|ALERT_|VAULT_|HF_TOKEN$|PROVIDER_|PORT$|AI_CHAT_TIMEOUT_MS$|LOCAL_TIMEOUT_MS$)/;
// QODIQA_PG_MIG_USER / QODIQA_PG_MIG_PASSWORD are deliberately NOT forwarded — the gateway never
// uses the migration credential and a production boot refuses it; they are blanked below (never backfilled from .env).
const PG_CONN = ['QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PG_RETENTION_PASSWORD',
  // the dedicated cross-tenant role pools (migration 060, rolePools.js).
  'QODIQA_PG_SYSTEM_PASSWORD', 'QODIQA_PG_REPORTING_PASSWORD',
  // the control-plane role (migration 065) — production always runs the PostgreSQL control plane.
  'QODIQA_PG_CONTROL_PASSWORD'];

const rand = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

function dotenvParsed() {
  const f = path.join(REPO_ROOT, '.env');
  return fs.existsSync(f) ? require('dotenv').parse(fs.readFileSync(f)) : {};
}

function systemEnv() {
  return Object.fromEntries(Object.entries(process.env).filter(([k]) => !SCOPED.test(k)));
}

/**
 * @param {object} o
 * @param {string} o.keysPath      keystore path OUTSIDE the repository (e.g. a temp dir)
 * @param {boolean} [o.pg=false]   enable PostgreSQL (connection settings from .env)
 * @param {object} [o.overrides]   applied last; a value of undefined deletes the variable
 */
function validProductionEnv({ keysPath, pg = false, overrides = {} } = {}) {
  if (!keysPath) throw new Error('productionEnv: keysPath (outside the repository) is required');
  const parsed = dotenvParsed();
  const env = { ...systemEnv() };
  for (const name of Object.keys(parsed)) env[name] = ''; // block dotenv backfill of every .env name
  Object.assign(env, {
    NODE_ENV: 'production',
    QODIQA_KEY_ENCRYPTION_KEY: rand(),
    QODIQA_EXECUTION_INVARIANT_SECRET: rand(),
    QODIQA_CLIENT_ID: 'w2-production-client',
    QODIQA_KEYS_PATH: keysPath,
    // production now refuses an unset (or in-repo) transparency key path; beside the
    // keystore, outside the repository. A test may still override it.
    QODIQA_TRANSPARENCY_KEYS_PATH: path.join(path.dirname(keysPath), 'transparency-keys.json'),
    POLICY_FILE: path.join(REPO_ROOT, 'deploy/env/production.policies.example'),
    QODIQA_DSR_PSEUDONYM_PEPPER: rand(),
    // REVOCATION_/ORG_STATUS_SIGNING_KEY are no longer read; the keyring
    // is provisioned below with the SAME KEK the child process will use.
    RL_ENABLED: 'true',
    REDIS_URL: 'rediss://127.0.0.1:6380',
    LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1',
    QODIQA_PG_ENABLED: pg ? 'true' : 'false',
  });
  // a CI runner or clean checkout has no .env file. ER 2026-10-06: an explicitly set process value WINS over .env
  // (the reverse order could point the spawned server at the .env cluster — which hosts LIVE on the dev machine — while
  // the suite itself targeted another cluster). Locally unchanged when nothing is set explicitly.
  // phase 17: explicit process values ONLY — .env is never a source of the PostgreSQL target or credentials
  // (it names the cluster hosting LIVE on the dev machine). A local opted-in run must name its cluster explicitly
  // (test/support/jest.setup.js refuses it otherwise); an un-opted run that asks for pg gets an empty target the guard refuses.
  if (pg) for (const k of PG_CONN) { const v = process.env[k]; if (v !== undefined) env[k] = v; }
  env.QODIQA_PG_MIG_USER = ''; env.QODIQA_PG_MIG_PASSWORD = ''; // never handed to a gateway (empty = blocks dotenv backfill)
  // (hosted-CI rehearsal): a fresh cluster's role passwords ARE the published migration placeholders, which
  // production refuses. A test that needs a VALID production env gets a strong stand-in instead (suites that
  // must really connect — productionBootProfile — pass the passwords they hardened the disposable cluster to).
  // ER 2026-10-06: the stand-in now replaces ANY value the production validator itself would reject — judged by the
  // validator's own predicate (credentialRules.secretProblems, the same minLength 16 as bootValidator's
  // secret.pg_passwords rule), not just literal placeholders. CI's explicit weak `qodiqa` migration password (and any
  // other weak explicit value) used to reach the child and fail the self-check — locally it was masked only because
  // .env won the precedence. The validator is unchanged and still refuses such values in a real boot.
  if (pg) for (const k of PG_CONN) if (/PASSWORD$/.test(k) && typeof env[k] === 'string' && secretProblems(env[k], { minLength: 16 }).length) env[k] = rand(16);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete env[k]; else env[k] = v;
  }
  // phase 17: the spawned production child carries the LIVE-endpoint socket guard (CI exempt) — its product
  // defaults (localhost:5432) must never reach the LIVE cluster on the dev machine.
  if (!require('./liveEndpointGuard').isExempt(env)) env.NODE_OPTIONS = require('./liveEndpointGuard').withPreload(env.NODE_OPTIONS);
  provisionMacKeyring(env);
  provisionAuditWitness(env);
  return env;
}

/**
 * production requires a provisioned MAC keyring encrypted under the
 * KEK the child process will use. Provisioned with the operator CLI itself
 * (scripts/security/macKeyring.js init), in a file named after a fingerprint of
 * that KEK so a reused keystore directory never hands a child a keyring it
 * cannot decrypt. Skipped when a test sets QODIQA_MAC_KEYS_PATH itself or when
 * there is no keystore path / KEK to provision under.
 */
function provisionMacKeyring(env) {
  if (env.QODIQA_MAC_KEYS_PATH !== undefined || !env.QODIQA_KEYS_PATH || !env.QODIQA_KEY_ENCRYPTION_KEY) return;
  const kekTag = crypto.createHash('sha256').update(env.QODIQA_KEY_ENCRYPTION_KEY).digest('hex').slice(0, 12);
  env.QODIQA_MAC_KEYS_PATH = path.join(path.dirname(env.QODIQA_KEYS_PATH), `mac-keys-${kekTag}.json`);
  if (fs.existsSync(env.QODIQA_MAC_KEYS_PATH)) return;
  const r = require('child_process').spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts/security/macKeyring.js'), 'init'],
    { cwd: REPO_ROOT, env, encoding: 'utf8', timeout: 30000 });
  if (r.status !== 0) throw new Error(`productionEnv: MAC keyring provisioning failed: ${(r.stderr || r.stdout || '').slice(0, 300)}`);
}

/**
 * production requires audit anchoring. Provisions a local witness exactly as the shipped k8s overlay
 * documents (scripts/anchor/witness-cosign.js --public-key creates the key and prints its public trust record), in a
 * temp directory OUTSIDE the key store's directory, and points the anchor export at it. Skipped when a test sets
 * QODIQA_WITNESS_MODE itself (including to undefined via overrides, which deletes).
 */
function provisionAuditWitness(env) {
  if (env.QODIQA_WITNESS_MODE !== undefined || env.NODE_ENV !== 'production') return;
  const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'qodiqa-w2-witness-'));
  const keyPath = path.join(dir, 'witness-key.json');
  const r = require('child_process').spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts/anchor/witness-cosign.js'), '--public-key'],
    { cwd: REPO_ROOT, encoding: 'utf8', timeout: 30000, env: { ...systemEnv(), WITNESS_ID: 'w2-witness', WITNESS_KEY_PATH: keyPath, WITNESS_LOG_PATH: path.join(dir, 'unused.jsonl') } });
  if (r.status !== 0) throw new Error(`productionEnv: audit witness provisioning failed: ${(r.stderr || r.stdout || '').slice(0, 300)}`);
  fs.writeFileSync(path.join(dir, 'witness-public-keys.json'), JSON.stringify([JSON.parse(r.stdout)]));
  Object.assign(env, {
    QODIQA_WITNESS_MODE: 'local', QODIQA_WITNESS_ID: 'w2-witness', QODIQA_WITNESS_KEY_PATH: keyPath,
    QODIQA_WITNESS_LOG_PATH: path.join(dir, 'witness-log.jsonl'),
    QODIQA_WITNESS_PUBLIC_KEYS: path.join(dir, 'witness-public-keys.json'),
    QODIQA_ANCHOR_EXPORT_PATH: path.join(dir, 'anchors.jsonl'),
  });
}

/** Assert (with the real validator) that env has no fatal violation; returns the result. */
function assertBootValid(env) {
  const { validateBoot } = require(path.join(REPO_ROOT, 'src/infra/config/bootValidator'));
  const r = validateBoot(env);
  if (r.fatal.length) throw new Error('productionEnv self-check: unexpected fatal violations: ' + r.fatal.map((f) => f.variable).join(', '));
  return r;
}

// Variables prepareIsolatedEnvironment() sets that a spawned child must keep: the
// isolated store paths, and the KEK/client id its keystore was provisioned under.
const ISOLATION_VARS = [
  'QODIQA_KEYS_PATH', 'QODIQA_AUDIT_LOG', 'QODIQA_TRANSPARENCY_KEYS_PATH', 'QODIQA_SIGNING_STORE_PATH',
  'ORG_STORE_PATH', 'TENANT_STORE_PATH', 'QODIQA_POLICY_STORE', 'QODIQA_RBAC_STORE_PATH',
  'QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH', 'QODIQA_PORTAL_USER_STORE_PATH',
  'QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_CLIENT_ID',
];
function pickIsolation(env = process.env) {
  return Object.fromEntries(ISOLATION_VARS.filter((k) => env[k] !== undefined).map((k) => [k, env[k]]));
}

module.exports = { validProductionEnv, assertBootValid, systemEnv, dotenvParsed, rand, pickIsolation, provisionMacKeyring, ISOLATION_VARS, REPO_ROOT };
