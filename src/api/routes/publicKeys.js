'use strict';

const { Router }          = require('express');
const { listPublicKeysForApi } = require('./shared/publicKeyListing');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { success, failure } = require('../response');

// Rate limit matches the /keys endpoint (120 requests per 60-second window).
const keysRateLimit = createRateLimitMiddleware('public_keys', { envelope: 'legacyFailure' });

const router = Router();

// GET /public-keys — canonical endpoint. Lists active and deprecated
// (non-revoked) public keys. Status is included (active vs deprecated) so
// callers can identify the current signing key and distinguish it from
// legacy keys still valid for verification.
//
// /keys is a deprecated alias of this exact handler (see keys.js) — both
// share listPublicKeysForApi() so there is
// exactly one filtering function and one serialization path between them.
router.get('/', keysRateLimit, (req, res) => {
  try {
    return success(res, { keys: listPublicKeysForApi() });
  } catch {
    return success(res, { keys: [] });
  }
});

router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

module.exports = router;
