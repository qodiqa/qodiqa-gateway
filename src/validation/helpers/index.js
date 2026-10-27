'use strict';

/**
 * Shared validation helper utilities.
 *
 * These functions are used both by Zod schema refinements and by route handlers
 * that need structural checks Zod cannot express natively (recursive depth,
 * serialised byte size).  Centralised here so the logic is not duplicated
 * across route files.
 */

/**
 * Recursively checks whether an object exceeds the maximum allowed nesting depth.
 * Arrays count as one nesting level.  Used to prevent DoS via deeply nested payloads.
 *
 * @param {unknown} val
 * @param {number}  maxDepth
 * @param {number}  [current=0]
 * @returns {boolean}
 */
function exceedsDepth(val, maxDepth, current = 0) {
  if (val === null || typeof val !== 'object') return false;
  if (current >= maxDepth) return true;
  const values = Array.isArray(val) ? val : Object.values(val);
  for (const v of values) {
    if (typeof v === 'object' && v !== null && exceedsDepth(v, maxDepth, current + 1)) return true;
  }
  return false;
}

/**
 * Returns an approximate serialised byte size of an object.
 * Returns Infinity if the object cannot be serialised (circular reference, etc.).
 *
 * @param {unknown} obj
 * @returns {number}
 */
function roughSize(obj) {
  try { return JSON.stringify(obj).length; } catch { return Infinity; }
}

/**
 * Extract the first QODIQA-specific reason code embedded in a Zod parse error
 * via `params: { qodiqaReason }` in a `.superRefine()` call.
 *
 * Falls back to `defaultReason` when no custom code is found.
 *
 * @param {import('zod').ZodError} zodError
 * @param {string} [defaultReason='INVALID_REQUEST']
 * @returns {string}
 */
function firstQodiqaReason(zodError, defaultReason = 'INVALID_REQUEST') {
  for (const issue of zodError.issues) {
    if (/** @type {any} */ (issue).params?.qodiqaReason) return /** @type {any} */ (issue).params.qodiqaReason;
  }
  return defaultReason;
}

/**
 * Format a ZodError into the platform-standard validation detail array.
 * Each entry contains the dot-separated field path and the human-readable message.
 *
 * Deliberately omits actual field VALUES to avoid logging sensitive data.
 *
 * @param {import('zod').ZodError} zodError
 * @returns {{ field: string, message: string }[]}
 */
function formatZodDetails(zodError) {
  return zodError.issues.map(issue => ({
    field:   issue.path.length > 0 ? issue.path.join('.') : '(root)',
    message: issue.message,
  }));
}

module.exports = { exceedsDepth, roughSize, firstQodiqaReason, formatZodDetails };
