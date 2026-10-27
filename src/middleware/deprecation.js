'use strict';

/**
 * Shared Deprecation/Sunset header helper (API-7 remediation).
 *
 * Extracted from two independent, near-identical implementations that
 * previously lived in src/api/routes/consent.js (the legacy
 * DELETE /consent/actor/:actorId route) and src/api/routes/keys.js (the
 * legacy GET /keys route) — both set the same RFC 8594 Deprecation/Sunset/
 * Link headers and emitted a WARN log event on every call to a
 * superseded route. This is now the single place that logic lives; any
 * future route deprecation should call this instead of hand-rolling the
 * header set again.
 */

const { emit } = require('../../services/logger');

/**
 * Sets Deprecation/Sunset/Link response headers and emits a WARN log event
 * for a call to a deprecated route.
 *
 * @param {import('express').Response} res
 * @param {{
 *   sunset?: string,          // RFC 8594 Sunset date (e.g. an RFC 7231 HTTP date) — omit for an open-ended deprecation with no planned removal date
 *   successorLink?: string,   // path of the replacement route, e.g. '/public-keys'
 *   warnEvent?: string,       // log event name emitted via services/logger
 *   warnDetails?: object,     // structured details merged into the log event
 * }} [opts]
 */
function sendDeprecationHeaders(res, opts = {}) {
  const { sunset, successorLink, warnEvent, warnDetails } = opts;

  res.set('Deprecation', 'true');
  if (sunset) res.set('Sunset', sunset);
  if (successorLink) res.set('Link', `<${successorLink}>; rel="successor-version"`);

  if (warnEvent) {
    emit('WARN', warnEvent, warnDetails || {});
  }
}

module.exports = { sendDeprecationHeaders };
