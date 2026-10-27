#!/usr/bin/env node
'use strict';
/**
 * operator CLI for the keystore MAC keyring
 * (src/core/security/macKeyring.js).
 *
 *   node scripts/security/macKeyring.js init     create the keyring if absent (never overwrites)
 *   node scripts/security/macKeyring.js status   active kid + verifiable kids (no key material)
 *   node scripts/security/macKeyring.js rotate   new active key; previous stays verifiable
 *
 * Uses the process's own QODIQA_KEY_ENCRYPTION_KEY (the KEK every node shares)
 * and QODIQA_MAC_KEYS_PATH / QODIQA_KEYS_PATH, exactly as the server resolves
 * them. Production never generates a keyring on its own; run `init` once per
 * deployment and share the file with every node, like the signing keystore.
 * Output never contains key material.
 */
const cmd = process.argv[2];
const ring = require('../../src/core/security/macKeyring');
const logger = require('../../services/logger'); logger.emit = () => {};

try {
  if (cmd === 'init') console.log(JSON.stringify(ring.init()));
  else if (cmd === 'status') console.log(JSON.stringify(ring.status()));
  else if (cmd === 'rotate') console.log(JSON.stringify(ring.rotate({ by: process.env.USER || process.env.USERNAME || 'cli' })));
  else { console.error('usage: macKeyring.js init|status|rotate'); process.exit(2); }
} catch (e) {
  console.error(`macKeyring ${cmd} failed: ${e.code || ''} ${e.message}`);
  process.exit(1);
}
