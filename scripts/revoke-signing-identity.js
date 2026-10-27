'use strict';
/**
 * Out-of-band signing-key REVOCATION.
 *
 * The counterpart of scripts/provision-signing-identity.js. A public deployment runs with the admin plane OFF
 * (QODIQA_ADMIN_ENABLED=false), so DELETE /signing-identities/:id/api-key is not reachable there; an operator with host
 * access (docker compose exec / kubectl exec) must still be able to revoke a leaked developer key immediately. This
 * calls the exact store function the HTTP admin route uses (revokeSigningKey): the key stops resolving at once, the
 * previous key's rotation grace ends too, and /ai/chat re-checks revocation, so artifacts already minted are refused.
 *
 * Usage:
 *   node scripts/revoke-signing-identity.js (--name <name> | --id <identityId>) --reason "<why>" [--by <operator>]
 *
 * Output: one JSON object (status REVOKED | NOT_FOUND | NO_API_KEY | ERROR); exit 0 only for REVOKED.
 */

const { listSigningIdentities, getSigningIdentity, revokeSigningKey } = require('../src/core/signing/signingIdentityStore');
const { flush: _flushLogger } = require('../services/logger');

function _parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--name')   { out.name = argv[++i]; continue; }
    if (arg === '--id')     { out.id = argv[++i]; continue; }
    if (arg === '--reason') { out.reason = argv[++i]; continue; }
    if (arg === '--by')     { out.by = argv[++i]; continue; }
  }
  return out;
}

const cp = require('../src/core/controlPlane');
const { exportSeedFixture } = require('../src/core/signing/signingIdentityStore');

async function _done(code, body) {
  if (body) { _flushLogger(); console.log(JSON.stringify(body, null, 2)); }
  if (code === 0 && !cp.isPg()) { try { exportSeedFixture(); } catch (e) { console.error(e.message); code = 1; } }
  await cp.stop().catch(() => {});
  await require('../src/infra/postgres/rolePools').shutdownAll().catch(() => {});
  process.exit(code);
}

async function main() {
  const args = _parseArgs(process.argv.slice(2));
  if ((!args.name && !args.id) || (args.name && args.id) || !args.reason || !String(args.reason).trim()) {
    _flushLogger();
    console.error(JSON.stringify({ status: 'ERROR', message: 'Usage: node scripts/revoke-signing-identity.js (--name <name> | --id <identityId>) --reason "<why>" [--by <operator>]' }, null, 2));
    process.exit(1);
  }
  await cp.start({ notifier: false });
  const identity = args.id ? getSigningIdentity(args.id) : listSigningIdentities().find((i) => i.name === args.name);
  if (!identity) return _done(1, { status: 'NOT_FOUND', name: args.name || null, identityId: args.id || null });
  if (!identity.apiKeyHash) return _done(1, { status: 'NO_API_KEY', identityId: identity.id, name: identity.name });
  try {
    await revokeSigningKey(identity.id, { revokedBy: args.by || 'CLI_OPERATOR', reason: String(args.reason).trim() });
  } catch (e) {
    return _done(1, { status: e.code === 'NO_API_KEY' ? 'NO_API_KEY' : 'ERROR', identityId: identity.id, message: e.message });
  }
  const after = getSigningIdentity(identity.id);
  return _done(0, { status: 'REVOKED', identityId: identity.id, name: identity.name, tenantId: identity.tenantId,
    environment: identity.environment, revokedAt: after && after.revokedAt, revokedBy: args.by || 'CLI_OPERATOR' });
}

main().catch((e) => _done(1, { status: 'ERROR', message: e.message }));
