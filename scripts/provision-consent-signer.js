'use strict';

const { getActiveKey, rotateKey } = require('../services/artifact/keyStore');

const CLIENT_ID = 'consent-signer';

let existing;
try {
  existing = getActiveKey(CLIENT_ID);
} catch (err) {
  if (err.message && err.message.includes('no active key')) {
    existing = null;
  } else {
    // unexpected error — rotateKey will handle provisioning
    existing = null;
  }
}

if (existing) {
  console.log(JSON.stringify({
    status:   'ALREADY_EXISTS',
    clientId: CLIENT_ID,
    keyId:    existing.keyId,
    message:  'consent-signer key already active — no action taken',
  }, null, 2));
  process.exit(0);
}

const result = rotateKey(CLIENT_ID);

const verification = getActiveKey(CLIENT_ID);

console.log(JSON.stringify({
  status:    'PROVISIONED',
  clientId:  result.clientId,
  keyId:     result.keyId,
  version:   result.version,
  verified:  verification.keyId === result.keyId,
  pubDerB64: verification.pubDer.toString('base64'),
  message:   'consent-signer key provisioned',
}, null, 2));
// (K7-D2/D3): requiring the key store starts control-plane clients that keep the event loop alive in a
// PostgreSQL-enabled environment, so without an explicit exit this script never returns (reproduced in K7).
process.exit(0);
