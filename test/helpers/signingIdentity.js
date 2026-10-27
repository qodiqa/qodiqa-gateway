'use strict';

/**
 * Shared Jest test helper for provisioning a signing identity — TRUST-1
 * remediation. Replaces the old pattern of every /sign-touching test file
 * setting a literal `process.env.QODIQA_SIGN_TOKEN` value and sending it via
 * the (now-removed) `x-qodiqa-sign-token` header.
 *
 * Call this BEFORE the first request that needs to authenticate against
 * /sign in a given test file. Each Jest test file gets its own fresh module
 * registry by default, so signingIdentityStore's in-memory cache does not
 * need an explicit reset here the way the long-lived acceptance-suite
 * process does (see test/harness/environment.js).
 *
 * @param {object} [opts]
 * @param {string} [opts.tenantId='default']   must match QODIQA_CLIENT_ID /
 *   whatever clientId the test's key store expects
 * @param {string} [opts.environment='test']   must match resolveServerEnvironment()
 *   — Jest sets NODE_ENV=test, so 'test' is correct unless the test overrides
 *   QODIQA_ENVIRONMENT
 * @param {string[]|null} [opts.allowedProviders=null]
 * @param {string} [opts.storeDir] directory to hold the isolated store file;
 *   defaults to a fresh os.tmpdir() mkdtemp
 * @returns {{ apiKey: string, identityId: string, storePath: string }}
 */
function provisionTestSigningIdentity(opts = {}) {
  const fs   = require('fs');
  const os   = require('os');
  const path = require('path');

  if (!process.env.QODIQA_SIGNING_STORE_PATH) {
    const dir = opts.storeDir || fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-signing-'));
    process.env.QODIQA_SIGNING_STORE_PATH = path.join(dir, 'signing-identities.json');
  }

  const store = require('../../src/core/signing/signingIdentityStore');

  const identity = store.createSigningIdentity({
    name:             `${opts.tenantId || 'default'}-test`,
    tenantId:         opts.tenantId || 'default',
    environment:      opts.environment || 'test',
    allowedProviders: opts.allowedProviders ?? null,
    permissions:      ['SIGN_ARTIFACT'],
    createdBy:        'JEST_TEST',
  });
  const { plaintext } = store.issueSigningKey(identity.id, { issuedBy: 'JEST_TEST' });
  // the store never writes its file any more; a suite that re-requires
  // modules finds the identity again through the seed fixture.
  store.exportSeedFixture();

  return {
    apiKey:     plaintext,
    identityId: identity.id,
    storePath:  process.env.QODIQA_SIGNING_STORE_PATH,
  };
}

module.exports = { provisionTestSigningIdentity };
