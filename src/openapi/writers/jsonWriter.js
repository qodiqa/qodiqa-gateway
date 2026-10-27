'use strict';

/**
 * JSON Writer — OpenAPI Component #42
 *
 * Serialises the OpenAPI specification object to a JSON string.
 * Pure function — no I/O, no state.
 */

/**
 * Serialise the spec to a JSON string.
 *
 * @param {object}  spec
 * @param {object}  [options]
 * @param {boolean} [options.pretty]  — use 2-space indentation (default true)
 * @returns {string}
 */
function writeJson(spec, options) {
  if (!spec || typeof spec !== 'object') {
    throw new TypeError('writeJson: spec must be a non-null object');
  }

  const pretty = !options || options.pretty !== false;
  return pretty ? JSON.stringify(spec, null, 2) : JSON.stringify(spec);
}

module.exports = { writeJson };
