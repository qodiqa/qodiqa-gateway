'use strict';

/**
 * Shared isolated-development-environment preparation.
 *
 * Extracted so that scripts/bootstrap-dev.js (the `npm run dev` entry
 * point) and test/serverStartupSmoke.test.js (the permanent regression
 * test that boots the real server.js) prepare an isolated environment in
 * exactly the same way — one implementation, not two that can drift apart.
 *
 * This module only prepares process.env and isolated on-disk paths. It
 * never spawns or requires server.js itself, and it never decides what to
 * do about Redis reachability (fail fast vs. skip a test) — that decision
 * is caller-specific and is left to the caller via the returned
 * `redisReachable` flag.
 */

const crypto = require('crypto');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const { ensureActiveKey, ensureActiveTransparencyKey } = require('./keyStoreProvisioning');
const { probeRedisReachable } = require('./redisProbe');

const PROVIDER_ENV_VARS = [
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'GEMINI_API_KEY',
  'MISTRAL_API_KEY',
  'LLAMA_BASE_URL',
  'LOCAL_BASE_URL',
];

// ── Isolated temp storage ──────────────────────────────────────────────────
// Fresh for every call. Never inside data/, config/, or the repository root.
function createIsolatedPaths(tempPrefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), tempPrefix));
  return {
    root,
    keysPath:             path.join(root, 'keys.json'),
    transparencyKeysPath: path.join(root, 'transparency-keys.json'),
    auditLogPath:         path.join(root, 'audit.log'),
    signingStorePath:     path.join(root, 'signing-identities.json'),
    // the file-backed stores whose defaults live under data/.
    orgStorePath:            path.join(root, 'organizations.json'),
    tenantStorePath:         path.join(root, 'tenants.json'),
    policyStorePath:         path.join(root, 'policy-store.json'),
    rbacStorePath:           path.join(root, 'rbac-users.json'),
    rbacCustomRoleStorePath: path.join(root, 'rbac-custom-roles.json'),
    portalUserStorePath:     path.join(root, 'tenant-portal-users.json'),
    // two more runtime WRITE paths whose defaults live under data/. Unisolated, the persistence-recovery
    // journal of one dev/test boot (written whenever PG is saturated or down) landed in the repository's
    // data/prq-journal and was REPLAYED into the next boot's own database — foreign evidence rows, and data/
    // mutated by a harness run. investigations.json is written when an investigation is opened.
    prqJournalDir:           path.join(root, 'prq-journal'),
    investigationsPath:      path.join(root, 'investigations.json'),
  };
}

// store env var → key in createIsolatedPaths(). Set only when the
// caller has not chosen a path itself (e.g. the acceptance RBAC helper passes
// its own QODIQA_RBAC_STORE_PATH); .env defines none of these.
const STORE_ENV = {
  ORG_STORE_PATH:                     'orgStorePath',
  TENANT_STORE_PATH:                  'tenantStorePath',
  QODIQA_POLICY_STORE:                'policyStorePath',
  QODIQA_RBAC_STORE_PATH:             'rbacStorePath',
  QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH: 'rbacCustomRoleStorePath',
  QODIQA_PORTAL_USER_STORE_PATH:      'portalUserStorePath',
  QODIQA_PRQ_JOURNAL_DIR:             'prqJournalDir',      //
  QODIQA_INVESTIGATIONS_PATH:         'investigationsPath', //
};

// ── Cryptographically random secrets ───────────────────────────────────────
// Same primitive production key material generation uses
// (services/secrets/secretsProvider.js expects 64 hex chars / 32 bytes).
function generateKek() {
  return crypto.randomBytes(32).toString('hex');
}

function hasAnyProviderConfigured() {
  return PROVIDER_ENV_VARS.some((name) => !!process.env[name]);
}

/**
 * Prepares a fully isolated QODIQA runtime environment by mutating
 * process.env directly (matching how server.js itself reads configuration
 * — from process.env at require/startup time, not via a config object
 * threaded through the call stack).
 *
 * Callers are responsible for deciding what to do with the returned
 * `redisReachable` flag (bootstrap-dev.js fails fast and never spawns the
 * server; the smoke test skips itself) and for restoring/cleaning up
 * process.env and the returned temp directory afterward if they need to
 * avoid leaking state into later work in the same process.
 *
 * @param {object}   [opts]
 * @param {string}   [opts.clientId='dev-local']
 * @param {string}   [opts.tempPrefix='qodiqa-dev-']
 * @param {(msg: string) => void} [opts.log]   informational logger (no-op by default)
 * @param {(msg: string) => void} [opts.warn]  warning logger (no-op by default)
 * @returns {Promise<{ paths: object, redisUrl: string, redisReachable: boolean }>}
 */
async function prepareIsolatedEnvironment(opts = {}) {
  const clientId   = opts.clientId   || 'dev-local';
  const tempPrefix = opts.tempPrefix || 'qodiqa-dev-';
  const log  = opts.log  || (() => {});
  const warn = opts.warn || (() => {});

  const paths = createIsolatedPaths(tempPrefix);
  log(`Isolated storage: ${paths.root}`);

  // These always override whatever is ambient — dev/test environments must
  // never inherit or use production secrets, even by accident.
  process.env.NODE_ENV                      = 'development';
  process.env.QODIQA_KEY_ENCRYPTION_KEY     = generateKek();
  // boot validation requires a 64-hex execution invariant secret in EVERY
  // profile (BOOT-RULES.md §1), so the isolated environment provisions its own
  // exactly like the KEK — never inherited from an ambient/.env value.
  process.env.QODIQA_EXECUTION_INVARIANT_SECRET = generateKek();
  process.env.QODIQA_CLIENT_ID              = clientId;
  process.env.QODIQA_KEYS_PATH              = paths.keysPath;
  process.env.QODIQA_AUDIT_LOG              = paths.auditLogPath;
  process.env.QODIQA_TRANSPARENCY_KEYS_PATH = paths.transparencyKeysPath;
  process.env.QODIQA_SIGNING_STORE_PATH     = paths.signingStorePath;
  // before this, org/tenant/policy/RBAC/portal stores fell back to
  // the repository's data/ files, so every isolated dev/test boot read and
  // wrote the real data/organizations.json, data/tenants.json, etc.
  for (const [name, key] of Object.entries(STORE_ENV)) {
    if (!process.env[name]) process.env[name] = paths[key];
  }
  log(`Isolated stores: ${Object.keys(STORE_ENV).join(', ')} (unless already set by the caller).`);

  // TRUST-1 remediation: there is no more QODIQA_SIGN_TOKEN shared secret.
  // Every caller of POST /sign needs its own signing identity — provision
  // one dev-scoped identity here, in the same isolated store the freshly
  // spawned server.js will read (QODIQA_SIGNING_STORE_PATH above), and issue
  // it a real per-identity API key.
  // the store is the control plane. PostgreSQL-backed, the spawned
  // server reads the identity from PostgreSQL; in dev/test memory mode it is
  // handed over through the (isolated) seed fixture instead.
  const { createSigningIdentity, issueSigningKey, exportSeedFixture } = require('./../../src/core/signing/signingIdentityStore');
  const controlPlane = require('./../../src/core/controlPlane');
  await controlPlane.start({ notifier: false });
  const devIdentity = await createSigningIdentity({
    name:        `${clientId}-dev`,
    tenantId:    clientId,
    environment: 'development',
    permissions: ['SIGN_ARTIFACT'],
    createdBy:   'DEV_BOOTSTRAP',
  });
  const { plaintext: devSigningKey } = await issueSigningKey(devIdentity.id, { issuedBy: 'DEV_BOOTSTRAP' });
  if (!controlPlane.isPg()) exportSeedFixture();

  // Development-only usability aid: the key above is random per invocation
  // and otherwise never surfaces anywhere, which makes manually exercising
  // POST /sign with curl/Postman impossible. Print it once, via plain
  // console.log (never the structured logger), and only when NODE_ENV is
  // "development" — this never runs for `npm start` / production and does
  // not change the generated value.
  if (process.env.NODE_ENV === 'development') {
    console.log(
      '\n' +
      '--------------------------------------------------------\n' +
      'QODIQA Development Environment\n' +
      '\n' +
      'Client ID:\n' +
      `${clientId}\n` +
      '\n' +
      'Signing API Key (identity: ' + devIdentity.name + '):\n' +
      `${devSigningKey}\n` +
      '\n' +
      'Use this header when calling POST /sign:\n' +
      `Authorization: Bearer ${devSigningKey}\n` +
      '--------------------------------------------------------\n',
    );
  }

  ensureActiveKey(clientId);
  // provisioning the key registers the dev tenant as a
  // side effect (keyStore._registerTenantQuietly) — in THIS process. the tenant registry
  // wrote tenants.json and the spawned server read it; memory mode nothing is written at
  // runtime, so the hand-off must be explicit, exactly as for the signing identity above. Without
  // it the spawned server never learned the tenant and every signed request BLOCKed TENANT_UNKNOWN.
  if (!controlPlane.isPg()) require('./../../src/core/tenancy/tenantRegistry').exportSeedFixture();
  log(`Provisioned isolated signing key for client "${clientId}".`);

  // GET /public-key serves this specific, reserved 'consent-signer'
  // identity (src/api/routes/public-key.js) — structurally separate from
  // any tenant's own signing key above. Nothing previously provisioned it
  // for dev/test boots (scripts/provision-consent-signer.js exists but was
  // never called from here), so every isolated dev/test server this project
  // has ever booted has had /public-key permanently 500 KEY_UNAVAILABLE,
  // unnoticed until specifically exercised it. Depends on's
  // fix to ensureActiveKey() above — without it, this call would silently
  // no-op once clientId's own key already exists in the same store.
  ensureActiveKey('consent-signer');
  log('Provisioned isolated consent-signer key (serves GET /public-key).');

  ensureActiveTransparencyKey();
  log('Provisioned isolated transparency signing key.');

  if (!hasAnyProviderConfigured()) {
    // A real, production-supported provider type (self-hosted OpenAI-
    // compatible runtime), never a mock — see scripts/bootstrap-dev.js.
    process.env.LOCAL_BASE_URL = process.env.LOCAL_BASE_URL || 'http://127.0.0.1:11434/v1';
    warn(`No AI provider configured — defaulting LOCAL_BASE_URL=${process.env.LOCAL_BASE_URL}.`);
  } else {
    log('AI provider configuration detected in environment — using it as-is.');
  }
  // the local provider no longer falls back to an OpenAI model name. For this DEVELOPMENT bootstrap
  // only, a configured local provider (the fallback above, or an explicit LOCAL_BASE_URL such as an acceptance stub)
  // without PROVIDER_DEFAULT_MODEL_LOCAL gets an explicit local default; production never receives one implicitly.
  if (process.env.LOCAL_BASE_URL && !process.env.PROVIDER_DEFAULT_MODEL_LOCAL) {
    process.env.PROVIDER_DEFAULT_MODEL_LOCAL = 'llama3.2:1b';
    warn(`LOCAL_BASE_URL set without PROVIDER_DEFAULT_MODEL_LOCAL — development default ${process.env.PROVIDER_DEFAULT_MODEL_LOCAL} (override it, or send \`model\`).`);
  }

  const redisUrl       = process.env.REDIS_URL || 'redis://localhost:6379';
  const redisReachable = await probeRedisReachable(redisUrl);

  if (redisReachable && process.env.STRICT_REPLAY_PROTECTION === undefined) {
    // See docs/guides/installation.md "Why STRICT_REPLAY_PROTECTION is relaxed by default in
    // development" — a plain TCP probe can't verify AOF persistence, and
    // this does not disable per-request fail-closed behavior.
    process.env.STRICT_REPLAY_PROTECTION = 'false';
    warn('STRICT_REPLAY_PROTECTION=false (Redis reachable, AOF durability unverifiable by probe).');
  }

  return { paths, redisUrl, redisReachable };
}

module.exports = {
  prepareIsolatedEnvironment,
  createIsolatedPaths,
  STORE_ENV,
  generateKek,
  hasAnyProviderConfigured,
};
