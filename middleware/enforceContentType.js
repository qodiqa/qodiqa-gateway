'use strict';

/**
 * enforceContentType — middleware that rejects POST/PUT/PATCH requests whose
 * Content-Type is not application/json.
 *
 * Returns HTTP 415 Unsupported Media Type so callers can distinguish a content-
 * type rejection from a validation rejection (400) or enforcement block (403).
 *
 * Safe for GET/HEAD/DELETE: those methods carry no body so the check is skipped.
 */
function enforceContentType(req, res, next) {
  const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);
  if (!BODY_METHODS.has(req.method)) return next();

  const ct = req.get('content-type') || '';
  if (!ct.includes('application/json')) {
    return res.status(415).json({
      decision:  'BLOCK',
      reason:    'UNSUPPORTED_MEDIA_TYPE',
      details:   {},
      requestId: req.requestId ?? null,
    });
  }
  next();
}

module.exports = enforceContentType;
