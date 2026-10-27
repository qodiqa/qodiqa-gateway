'use strict';

/**
 * RBAC bootstrap API key provisioning.
 *
 * Every RBAC-gated HTTP endpoint (POST /rbac/users/:id/api-key included)
 * requires an authenticated req.rbacUser, which requires a resolvable
 * per-operator API key. That is a deliberate chicken-and-egg: there is no
 * HTTP-reachable path that issues the very first key, because any such path
 * would be an unauthenticated (or shared-secret-gated) route capable of
 * minting administrative access — exactly the fail-open pattern this
 * project's RBAC model is designed to prevent (see docs/security/RBAC_MODEL.md).
 *
 * This script closes that gap the only way that does not reopen it: by
 * running out-of-band, against the same control-plane RBAC store
 * the server reads (PostgreSQL; dev/test memory mode: the seed file), using the exact same
 * bootstrapAdmin() / issueApiKey() functions the HTTP admin API uses. It
 * requires operational access to the runtime environment (kubectl exec,
 * docker exec, SSH, or direct host access) — never a network-reachable
 * credential.
 *
 * Usage:
 *   node scripts/rbac-bootstrap-key.js            # issue only if no key exists yet
 *   node scripts/rbac-bootstrap-key.js --rotate    # force-rotate (invalidates old key)
 *   node scripts/rbac-bootstrap-key.js --user <username> [--rotate]
 *issue the key of an EXISTING operator out of band. The HTTP admin API
 *       no longer hands one admin a working key for a peer or superior (403 PEER_CREDENTIAL_FORBIDDEN): that would
 *       let one person act as two in maker-checker. Host access is the second factor of this path.
 *
 * The plaintext key is printed exactly once and is never stored in plaintext
 * anywhere — store it securely (e.g. your secrets manager) immediately.
 */

const { bootstrapAdmin, getUser, getUserByUsername, issueApiKey, exportSeedFixture } = require('../src/core/rbac/store');
// the store lives in the control plane — PostgreSQL in production
// (this script writes the row there, versioned, exactly like the HTTP admin
// API), or dev/test memory mode, where the result is handed to the next
// server boot through the seed fixture (the only file this path ever writes).
const cp = require('../src/core/controlPlane');
// THROUGHPUT-12: services/logger.js batches INFO/WARN/ERROR stdout writes and
// flushes them asynchronously (see that file's header comment) — necessary
// for server throughput, but this script's own final console.log/error below
// is parsed positionally by callers (operators, tests), so any not-yet-
// flushed structured log line must be drained BEFORE that print, or it could
// land after it on the stream. flush() does its actual work synchronously
// (the returned Promise is for callers that want to await it); calling it
// bare, un-awaited, still drains in-line before the next statement runs.
const { flush: _flushLogger } = require('../services/logger');

const FORCE_ROTATE = process.argv.includes('--rotate');
const _ui = process.argv.indexOf('--user');
const TARGET_USERNAME = _ui >= 0 ? process.argv[_ui + 1] : null;

async function _finish(code) {
  await cp.stop().catch(() => {});
  await require('../src/infra/postgres/rolePools').shutdownAll().catch(() => {});
  process.exit(code);
}

async function main() {
  await cp.start({ notifier: false });

  let admin;
  if (TARGET_USERNAME) {
    admin = getUserByUsername(TARGET_USERNAME);
    if (!admin) {
      _flushLogger();
      console.error(JSON.stringify({ status: 'ERROR', message: `Operator "${TARGET_USERNAME}" not found (create it first via POST /rbac/users).` }, null, 2));
      return _finish(1);
    }
  } else {
    const created = await bootstrapAdmin();
    const adminId = process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_ID || 'bootstrap-admin';
    admin = created || getUser(adminId);
  }

  if (!admin) {
    _flushLogger();
    console.error(JSON.stringify({
      status:  'ERROR',
      message: 'Bootstrap admin user could not be found or created.',
    }, null, 2));
    return _finish(1);
  }

  if (admin.apiKeyHash && !FORCE_ROTATE) {
    if (!cp.isPg()) exportSeedFixture();
    _flushLogger();
    console.log(JSON.stringify({
      status:   'ALREADY_PROVISIONED',
      userId:   admin.id,
      username: admin.username,
      role:     admin.role,
      issuedAt: admin.apiKeyIssuedAt,
      message:  'An API key already exists for this user. Re-run with --rotate to ' +
                'issue a new one (this immediately invalidates the existing key).',
    }, null, 2));
    return _finish(0);
  }

  const { plaintext, issuedAt } = await issueApiKey(admin.id, { issuedBy: 'CLI_BOOTSTRAP' });
  if (!cp.isPg()) exportSeedFixture();

  _flushLogger();
  console.log(JSON.stringify({
    status:   FORCE_ROTATE && admin.apiKeyHash ? 'ROTATED' : 'PROVISIONED',
    userId:   admin.id,
    username: admin.username,
    role:     admin.role,
    issuedAt,
    apiKey:   plaintext,
    message:  'Store this API key securely now — it will never be displayed again. ' +
              'Use it as "Authorization: Bearer <apiKey>" against /rbac to create ' +
              'additional operator accounts, then consider disabling this account ' +
              'or rotating its key on a regular schedule.',
  }, null, 2));
  return _finish(0);
}

main().catch((err) => {
  _flushLogger();
  console.error(JSON.stringify({ status: 'ERROR', message: err.message, code: err.code || null }, null, 2));
  _finish(1);
});
