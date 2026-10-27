'use strict';

/**
 * Out-of-band signing identity provisioning (TRUST-1 remediation).
 *
 * Unlike the old QODIQA_SIGN_TOKEN shared secret (a single env var every
 * caller used identically), every caller of POST /sign now needs its own
 * signing identity — scoped to a tenant, an environment, and optionally a
 * restricted provider set (see src/core/signing/signingIdentityStore.js).
 *
 * Provisioning can happen two ways:
 *   1. An already-bootstrapped RBAC admin calls POST /signing-identities
 *      (see src/api/routes/admin/signingIdentities.js) over HTTP.
 *   2. This script, run out-of-band with direct filesystem access to the
 *      same store the server reads (QODIQA_SIGNING_STORE_PATH) — useful for
 *      CI provisioning, local development, and initial bootstrap before any
 *      RBAC admin exists yet. It calls the exact same store functions the
 *      HTTP admin API uses; it does not duplicate or bypass any validation.
 *
 * Usage:
 *   node scripts/provision-signing-identity.js \
 *     --name ci-pipeline --tenant-id default --environment production \
 *     [--providers openai,anthropic] [--max-ttl-ms 300000] [--rotate]
 *
 * The plaintext key is printed exactly once and is never stored in plaintext
 * anywhere — store it securely (e.g. your secrets manager) immediately.
 */

const {
  createSigningIdentity, listSigningIdentities, issueSigningKey,
} = require('../src/core/signing/signingIdentityStore');
const { flush: _flushLogger } = require('../services/logger');

function _parseArgs(argv) {
  const out = { rotate: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--rotate') { out.rotate = true; continue; }
    if (arg === '--name')          { out.name = argv[++i]; continue; }
    if (arg === '--tenant-id')     { out.tenantId = argv[++i]; continue; }
    if (arg === '--environment')   { out.environment = argv[++i]; continue; }
    if (arg === '--providers')     { out.providers = argv[++i]; continue; }
    if (arg === '--max-ttl-ms')    { out.maxTtlMs = Number(argv[++i]); continue; }
  }
  return out;
}

function _fail(message) {
  _flushLogger();
  console.error(JSON.stringify({ status: 'ERROR', message }, null, 2));
  process.exit(1);
}

const args = _parseArgs(process.argv.slice(2));

if (!args.name || !args.tenantId || !args.environment) {
  _fail(
    'Usage: node scripts/provision-signing-identity.js --name <name> ' +
    '--tenant-id <tenantId> --environment <development|test|ci|staging|production> ' +
    '[--providers p1,p2] [--max-ttl-ms <ms>] [--rotate]',
  );
}

const allowedProviders = args.providers
  ? args.providers.split(',').map((s) => s.trim()).filter(Boolean)
  : null;

// the store lives in the control plane — PostgreSQL in production
// (the row is written there, versioned); dev/test memory mode hands the result
// to the next server boot through the seed fixture.
const cp = require('../src/core/controlPlane');
const { exportSeedFixture } = require('../src/core/signing/signingIdentityStore');

async function _done(code) {
  if (!cp.isPg()) { try { exportSeedFixture(); } catch (e) { _fail(e.message); } }
  await cp.stop().catch(() => {});
  await require('../src/infra/postgres/rolePools').shutdownAll().catch(() => {});
  process.exit(code);
}

async function main() {
  await cp.start({ notifier: false });
  let identity = listSigningIdentities().find((i) => i.name === args.name);

  if (identity && !args.rotate) {
    _flushLogger();
    console.log(JSON.stringify({
      status:      'ALREADY_PROVISIONED',
      identityId:  identity.id,
      name:        identity.name,
      tenantId:    identity.tenantId,
      environment: identity.environment,
      hasApiKey:   !!identity.apiKeyHash,
      message:     'A signing identity with this name already exists. Re-run with --rotate ' +
                   'to issue a new key (the existing key keeps working until its grace window ends, ' +
                   'QODIQA_API_KEY_ROTATION_GRACE_HOURS, default 24 h; revoke it to end it at once).',
    }, null, 2));
    return _done(0);
  }

  try {
    if (!identity) {
      identity = await createSigningIdentity({
        name:        args.name,
        tenantId:    args.tenantId,
        environment: args.environment,
        allowedProviders,
        permissions: ['SIGN_ARTIFACT'],
        maxTtlMs:    Number.isFinite(args.maxTtlMs) ? args.maxTtlMs : null,
        createdBy:   'CLI_BOOTSTRAP',
      });
    }

    const { plaintext, issuedAt } = await issueSigningKey(identity.id, { issuedBy: 'CLI_BOOTSTRAP' });

    _flushLogger();
    console.log(JSON.stringify({
      status:      args.rotate ? 'ROTATED' : 'PROVISIONED',
      identityId:  identity.id,
      name:        identity.name,
      tenantId:    identity.tenantId,
      environment: identity.environment,
      allowedProviders,
      issuedAt,
      apiKey:      plaintext,
      message:     'Store this signing API key securely now — it will never be displayed again. ' +
                   'Use it as "Authorization: Bearer <apiKey>" against POST /sign.',
    }, null, 2));
    return _done(0);
  } catch (err) {
    _fail(err.message);
  }

}

main().catch((err) => _fail(err.message));
