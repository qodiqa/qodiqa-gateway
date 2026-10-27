'use strict';

// (API-8 remediation): single, shared implementation for "list public
// signing keys" — consumed by both /public-keys (canonical) and /keys
// (deprecated legacy alias, see keys.js). Before this module existed, each
// router independently filtered keyManager.listPublicKeys() and built its own
// response shape; the two had silently diverged (one hardcoded `algorithm`,
// the other omitted it entirely). One filtering function, one serialization
// function — both routers call this and nothing else.

const keyManager = require('../../../../services/artifact/keyManager');
const { keyDates } = require('./publicKeyDates');

// Revoked keys are excluded: exposing them leaks information about key
// compromise without serving any legitimate verification purpose.
function listPublicKeysForApi() {
  return keyManager.listPublicKeys()
    .filter(k => k.status !== 'revoked')
    .map(k => ({
      keyId:     k.keyId,
      publicKey: k.publicKeyB64,
      // Sourced from the real key record rather than a hardcoded literal —
      // see API-8-REMEDIATION-REPORT.md for why the old /keys value
      // ('Ed25519', hardcoded) never actually reflected k.algorithm.
      algorithm: k.algorithm,
      status:    k.status,
      ...keyDates(k),
    }));
}

module.exports = { listPublicKeysForApi };
