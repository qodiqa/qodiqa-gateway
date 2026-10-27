'use strict';

/**
 * Launch plan R-08: revocation of a signing identity's key — the demo's emergency stop — had no dedicated test at the
 * store layer (only replica-propagation suites). These pin the store contract the HTTP admin route
 * (DELETE /signing-identities/:id/api-key) and scripts/revoke-signing-identity.js both call.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');

// Not one of test/support/jest.dataIsolation.js's six stores: point it at this file's isolation dir (same pattern as
// src/core/security/__tests__/apiKeyLifecycle.test.js).
const dir = path.dirname(process.env.QODIQA_RBAC_STORE_PATH || fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-stores-')));
process.env.QODIQA_SIGNING_STORE_PATH = path.join(dir, 'signing-identities-revocation.json');
const sis = require('../signingIdentityStore');

let n = 0;
async function fresh() {
  const id = (await sis.createSigningIdentity({ name: `rev-${Date.now()}-${++n}`, tenantId: 'demo', environment: 'development', permissions: ['SIGN_ARTIFACT'], allowedProviders: ['local'] })).id;
  const { plaintext } = await sis.issueSigningKey(id);
  return { id, key: plaintext };
}

describe('signing identity revocation (R-08)', () => {
  test('a revoked key stops resolving at once and the record is marked revoked with who/why', async () => {
    const { id, key } = await fresh();
    expect(sis.resolveSigningIdentity(key)).toMatchObject({ id });
    await sis.revokeSigningKey(id, { revokedBy: 'ops-test', reason: 'demo emergency stop' });
    expect(sis.resolveSigningIdentity(key)).toBeNull();
    expect(sis.resolveSigningIdentityDetailed(key)).toBeNull();
    expect(sis.getSigningIdentity(id)).toMatchObject({ revoked: true, revokedBy: 'ops-test', revokedReason: 'demo emergency stop', apiKeyHash: null });
    expect(sis.getSigningIdentity(id).revokedAt).toEqual(expect.any(String));
  });

  test('revocation also ends the previous key\'s rotation grace (no key of that identity survives)', async () => {
    const { id, key: k1 } = await fresh();
    const k2 = (await sis.issueSigningKey(id)).plaintext;
    expect(sis.resolveSigningIdentityDetailed(k1)).toMatchObject({ status: 'grace', via: 'previous' });
    await sis.revokeSigningKey(id, { revokedBy: 'ops-test', reason: 'rotate+revoke' });
    expect(sis.resolveSigningIdentity(k1)).toBeNull();
    expect(sis.resolveSigningIdentity(k2)).toBeNull();
  });

  test('revoking twice → NO_API_KEY; unknown identity → NOT_FOUND (the CLI maps these to exit 1)', async () => {
    const { id } = await fresh();
    await sis.revokeSigningKey(id, { revokedBy: 'ops-test' });
    expect(() => sis.revokeSigningKey(id, { revokedBy: 'ops-test' })).toThrow(expect.objectContaining({ code: 'NO_API_KEY' }));
    expect(() => sis.revokeSigningKey('00000000-0000-4000-8000-000000000000')).toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
  });

  test('re-issuing after revocation yields a working new key; the revoked key never comes back', async () => {
    const { id, key: old } = await fresh();
    await sis.revokeSigningKey(id, { revokedBy: 'ops-test' });
    const next = (await sis.issueSigningKey(id)).plaintext;
    expect(sis.resolveSigningIdentity(next)).toMatchObject({ id });
    expect(sis.resolveSigningIdentity(old)).toBeNull();
    expect(sis.getSigningIdentity(id)).toMatchObject({ revoked: false, revokedAt: null });
  });

  test('revoking one identity leaves the others untouched (per-scenario demo identities are independent)', async () => {
    const a = await fresh();
    const b = await fresh();
    await sis.revokeSigningKey(a.id, { revokedBy: 'ops-test' });
    expect(sis.resolveSigningIdentity(a.key)).toBeNull();
    expect(sis.resolveSigningIdentity(b.key)).toMatchObject({ id: b.id });
  });
});
