'use strict';

/**
 * YAML Writer — OpenAPI Component #42
 *
 * Pure-JS YAML serialiser for JSON-compatible data structures.
 * No external dependencies — uses only Node.js built-ins.
 *
 * Handles the full subset of YAML required by OpenAPI 3.1:
 *   - Objects (block mappings)
 *   - Arrays (block sequences)
 *   - Strings (with correct quoting for special characters)
 *   - Numbers, booleans, null
 *   - Multiline strings (literal block scalar |)
 *   - Proper indentation (2 spaces per level)
 *
 * Limitations (acceptable for OpenAPI specs):
 *   - No anchors/aliases
 *   - No flow style (always uses block style)
 *   - No custom YAML tags
 *   - Circular references will cause a RangeError (stack overflow)
 */

// ── YAML string quoting ───────────────────────────────────────────────────────

// Characters that require quoting when they appear at the start of a scalar.
const _FLOW_INDICATORS = new Set(['{', '}', '[', ']', ',', '#', '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`', "'", '"']);

// Words that YAML interprets as booleans or null (YAML 1.1 + 1.2 compat).
const _YAML_KEYWORDS = new Set(['true', 'false', 'null', 'yes', 'no', 'on', 'off', 'True', 'False', 'Null', 'YES', 'NO', 'ON', 'OFF', 'TRUE', 'FALSE', 'NULL', '~']);

function _needsDoubleQuoting(str) {
  if (str.length === 0) return true;
  if (_YAML_KEYWORDS.has(str)) return true;
  // Looks like a number (integer, float, hex, octal, inf, nan)
  if (/^[-+]?(\d+\.?\d*([eE][-+]?\d+)?|0x[0-9a-fA-F]+|0o[0-7]+|\.inf|\.nan)$/i.test(str)) return true;
  // Starts with a flow indicator or colon
  if (_FLOW_INDICATORS.has(str[0])) return true;
  if (str[0] === ':') return true;
  // Contains ': ' or ' #' which YAML parsers interpret as mapping/comment separators
  if (str.includes(': ') || str.includes(' #')) return true;
  // Starts or ends with whitespace
  if (str !== str.trim()) return true;
  return false;
}

function _yamlString(str, indent) {
  if (str.includes('\n')) {
    // Literal block scalar
    const lines = str.split('\n');
    const prefix = ' '.repeat(indent + 2);
    return '|\n' + lines.map(l => prefix + l).join('\n');
  }
  if (_needsDoubleQuoting(str)) {
    // Escape backslashes and double-quotes then wrap
    const escaped = str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return `"${escaped}"`;
  }
  return str;
}

// ── Core serialiser ───────────────────────────────────────────────────────────

/**
 * Recursively serialise a value to a YAML string fragment.
 *
 * @param {*}      value
 * @param {number} indent   — current indent level (in spaces)
 * @param {boolean} inline  — if true, emit inline (value only, no leading newline)
 * @returns {string}
 */
function _toYaml(value, indent, inline) {
  const pad = ' '.repeat(indent);

  if (value === null || value === undefined) {
    return inline ? 'null' : pad + 'null';
  }

  if (typeof value === 'boolean') {
    const s = value ? 'true' : 'false';
    return inline ? s : pad + s;
  }

  if (typeof value === 'number') {
    const s = isFinite(value) ? String(value) : (value > 0 ? '.inf' : '-.inf');
    return inline ? s : pad + s;
  }

  if (typeof value === 'string') {
    const s = _yamlString(value, indent);
    return inline ? s : pad + s;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return inline ? '[]' : pad + '[]';
    const lines = value.map(item => {
      if (item !== null && typeof item === 'object') {
        const inner = _toYaml(item, indent + 2, false);
        // Strip the leading indent from inner since '- ' provides it
        const stripped = inner.slice(indent + 2);
        return pad + '- ' + stripped.trim();
      }
      return pad + '- ' + _toYaml(item, 0, true);
    });
    return (inline ? '' : '') + lines.join('\n');
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return inline ? '{}' : pad + '{}';
    const lines = keys.map(key => {
      const v = value[key];
      // Key must always be quoted if it contains special chars
      const yamlKey = _needsDoubleQuoting(String(key)) ? `"${String(key).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"` : String(key);

      if (v !== null && typeof v === 'object') {
        if (Array.isArray(v)) {
          if (v.length === 0) return pad + yamlKey + ': []';
          return pad + yamlKey + ':\n' + _toYaml(v, indent + 2, false);
        }
        if (Object.keys(v).length === 0) return pad + yamlKey + ': {}';
        return pad + yamlKey + ':\n' + _toYaml(v, indent + 2, false);
      }
      return pad + yamlKey + ': ' + _toYaml(v, 0, true);
    });
    return lines.join('\n');
  }

  // Fallback for unknown types
  return inline ? String(value) : pad + String(value);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Serialise the OpenAPI spec object to a YAML string.
 *
 * @param {object} spec
 * @returns {string}  Valid YAML document
 */
function writeYaml(spec) {
  if (!spec || typeof spec !== 'object') {
    throw new TypeError('writeYaml: spec must be a non-null object');
  }

  return '---\n' + _toYaml(spec, 0, false) + '\n';
}

module.exports = { writeYaml };
