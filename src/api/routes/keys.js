'use strict';

const { Router }          = require('express');
const { listPublicKeysForApi } = require('./shared/publicKeyListing');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { success, failure } = require('../response');
const { sendDeprecationHeaders } = require('../../middleware/deprecation');

const keysRateLimit = createRateLimitMiddleware('keys', { envelope: 'legacyFailure' });

const router = Router();

// GET /keys — DEPRECATED legacy alias of GET /public-keys (/ API-8
// remediation). Both routes call the identical listPublicKeysForApi()
// (see ./shared/publicKeyListing.js) and therefore always produce identical
// `data.keys` output — see src/api/routes/__tests__/keysPublicKeysParity.test.js.
// Kept for backward compatibility only; new integrations should use
// /public-keys. Emits Deprecation/Link response headers and a warning log
// event on every call via the shared src/middleware/deprecation.js helper
// (API-7 remediation), mirroring the existing legacy-alias pattern in
// src/api/routes/consent.js (CONSENT_DELETE_ACTOR_DEPRECATED_USED).
router.get('/', keysRateLimit, (req, res) => {
  sendDeprecationHeaders(res, {
    successorLink: '/public-keys',
    warnEvent:     'KEYS_LEGACY_ENDPOINT_USED',
    warnDetails: {
      path:      req.path,
      requestId: req.requestId ?? res.locals?.requestId ?? null,
      message:   'GET /keys is deprecated: identical to GET /public-keys, kept for backward compatibility. Use /public-keys instead.',
    },
  });

  try {
    return success(res, { keys: listPublicKeysForApi() });
  } catch {
    return success(res, { keys: [] });
  }
});

router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

module.exports = router;
