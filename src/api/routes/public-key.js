'use strict';

const { Router } = require('express');
const { success, failure } = require('../response.js');
const keyManager = require('../../../services/artifact/keyManager.js');
const { createRateLimitMiddleware } = require('../../core/rateLimit');

const router = Router();

// the one public route that had no limiter — same bucket as /public-keys.
router.get('/', createRateLimitMiddleware('public_keys', { envelope: 'legacyFailure' }), (req, res) => {
  let consentKey;
  try {
    // getActivePublicKey never returns private key material.
    consentKey = keyManager.getActivePublicKey('consent-signer');
  } catch {
    return failure(res, 'KEY_UNAVAILABLE', 'Signing key is unavailable', 500);
  }

  return success(res, {
    keys: [
      {
        kid:       consentKey.keyId,
        use:       'consent_artifact',
        algorithm: 'Ed25519',
        format:    'base64',
        publicKey: consentKey.publicKeyB64,
        // CRYPTO-7/KEY-13: getActivePublicKey() always resolves the current
        // active key (it throws otherwise) — 'active' is therefore accurate
        // by construction, not a guess.
        status:    'active',
      },
    ],
  });
});

router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

module.exports = router;
