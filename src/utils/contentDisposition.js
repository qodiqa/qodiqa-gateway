'use strict';

/**
 * Canonical Content-Disposition filename sanitizer — INJ-8 remediation.
 *
 * Several export endpoints interpolate a value (a route parameter, or a
 * value ultimately derived from one) directly into a Content-Disposition
 * header without validation. CR/LF characters in an interpolated value could
 * inject additional header lines (HTTP response splitting / header
 * injection); double-quote characters can prematurely terminate the
 * filename="..." parameter and alter how downstream tooling parses the
 * header. This strips both classes of character and applies the standard
 * quoted-string escape for any residual double quote, so every
 * header-interpolated filename in the codebase goes through one sanitizer
 * instead of each call site reimplementing its own — see INJ-8 in
 * for the full finding.
 *
 * safeAttachmentHeader() additionally emits an RFC 6266 `filename*` extended
 * parameter (RFC 5987 percent-encoding) whenever the name contains non-ASCII
 * characters, alongside an ASCII-safe `filename="..."` fallback for clients
 * that don't parse the extended form.
 */

// CR, LF, and NUL — header/line-injection control characters.
const CONTROL_CHARS_RE = /[\r\n\x00]/g;

// Deterministic fallback when the sanitized name is empty (absent input, or
// input consisting solely of stripped control characters).
const DEFAULT_FILENAME = 'download';

// Printable ASCII only — used to decide whether a filename* extended
// parameter is needed, and to build the ASCII fallback name.
const NON_ASCII_RE = /[^\x20-\x7e]/;

// RFC 5987 attr-char: everything outside this set must be percent-encoded
// in the filename* value.
const ATTR_CHAR_RE = /[A-Za-z0-9!#$&+\-.^_`|~]/;

/**
 * @param {unknown} filename
 * @returns {string} A value safe to interpolate inside `filename="..."`.
 */
function sanitizeFilename(filename) {
  const s = String(filename ?? '').replace(CONTROL_CHARS_RE, '');
  return s.replace(/"/g, '\\"');
}

// Non-ASCII bytes are not valid in a legacy quoted-string filename param;
// replace them with '_' and rely on filename* to carry the real value.
function _asciiFallbackName(name) {
  return name.replace(/[^\x20-\x7e]/g, '_');
}

// RFC 5987 percent-encoding of the UTF-8 bytes of `name`.
function _percentEncodeExtValue(name) {
  const bytes = Buffer.from(name, 'utf8');
  let out = '';
  for (const byte of bytes) {
    const ch = String.fromCharCode(byte);
    out += ATTR_CHAR_RE.test(ch) ? ch : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

/**
 * Build a complete, safe, RFC 6266-compliant `Content-Disposition` header
 * value: `attachment; filename="<ascii fallback>"[; filename*=UTF-8''<...>]`.
 *
 * CR, LF, and NUL are always stripped first, so they can never reach the
 * header regardless of input. An empty or absent filename falls back to a
 * fixed default rather than producing an empty or "null"/"undefined" name.
 *
 * @param {unknown} filename
 * @returns {string}
 */
function safeAttachmentHeader(filename) {
  const stripped = String(filename ?? '').replace(CONTROL_CHARS_RE, '').trim();
  const name = stripped.length ? stripped : DEFAULT_FILENAME;

  const asciiName = _asciiFallbackName(name);
  const quoted = asciiName.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const header = `attachment; filename="${quoted}"`;

  if (!NON_ASCII_RE.test(name)) return header;

  return `${header}; filename*=UTF-8''${_percentEncodeExtValue(name)}`;
}

module.exports = { sanitizeFilename, safeAttachmentHeader };
