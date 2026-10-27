'use strict';

/**
 * Legacy field-casing normalization.
 *
 * Generic helper for accepting a deprecated field name alongside its
 * canonical replacement without duplicating this logic per-route. Used
 * first by src/api/routes/consent.js, whose request schemas historically
 * used snake_case (`actor_id`, `granted_by`, ...) while the rest of the
 * management API uses camelCase (`actorId`, `tenantId`, ...) — see
 * finding API-5.
 *
 * Call this BEFORE handing the body to a `.strict()` Zod schema — the
 * schema itself only ever needs to know about the canonical camelCase
 * field names; this function does the legacy→canonical translation ahead
 * of parsing so `.strict()` never sees (and never has to special-case) the
 * deprecated key.
 */

/**
 * @param {object} body Raw, unvalidated request body (or query object).
 * @param {Record<string,string>} aliasMap Maps a deprecated legacy key to
 *   its canonical replacement key, e.g. `{ actor_id: 'actorId' }`.
 * @returns {{ body: object, usedLegacyKeys: string[] }}
 *   `body` — a shallow copy with every legacy key present in `aliasMap`
 *   translated to its canonical form (canonical values win if both the
 *   legacy and canonical key are present in the input).
 *   `usedLegacyKeys` — the legacy key names that were actually present in
 *   the input, empty if none were used.
 */
function normalizeLegacyBody(body, aliasMap) {
  const source = (body && typeof body === 'object') ? body : {};
  const out = { ...source };
  const usedLegacyKeys = [];

  for (const [legacyKey, canonicalKey] of Object.entries(aliasMap)) {
    if (!Object.prototype.hasOwnProperty.call(out, legacyKey)) continue;
    usedLegacyKeys.push(legacyKey);
    if (!Object.prototype.hasOwnProperty.call(out, canonicalKey)) {
      out[canonicalKey] = out[legacyKey];
    }
    delete out[legacyKey];
  }

  return { body: out, usedLegacyKeys };
}

module.exports = { normalizeLegacyBody };
