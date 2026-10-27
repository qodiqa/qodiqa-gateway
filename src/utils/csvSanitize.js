'use strict';

/**
 * Canonical CSV cell sanitizer — INJ-7 remediation.
 *
 * Neutralizes spreadsheet-formula injection (CSV injection / "Formula
 * Injection", OWASP): a cell whose content starts with a character a
 * spreadsheet application (Excel, Google Sheets, LibreOffice) interprets as
 * the start of a formula — `=`, `+`, `-`, `@`, or a leading tab/CR — is
 * prefixed with a single quote so it opens as inert text instead of
 * executing as a formula when the exported file is opened. Every CSV
 * exporter in the codebase should call this instead of reimplementing
 * quote-escaping independently — see INJ-7
 * for the full finding.
 */

// Leading characters spreadsheet applications treat as formula starts.
// Tab (\t) and CR (\r) are included because some parsers strip a leading
// quote-and-whitespace combination before formula sniffing.
const FORMULA_PREFIX_RE = /^[=+\-@\t\r]/;

/**
 * Neutralize formula-injection characters, then apply standard CSV
 * quote-escaping (double any embedded double-quote, wrap in double-quotes).
 *
 * @param {unknown} value
 * @returns {string} A fully quoted, CSV-safe cell — ready to join with commas.
 */
function sanitizeCsvCell(value) {
  if (value === null || value === undefined) return '';
  let s = String(value);
  if (FORMULA_PREFIX_RE.test(s)) {
    s = "'" + s;
  }
  return '"' + s.replace(/"/g, '""') + '"';
}

module.exports = { sanitizeCsvCell, FORMULA_PREFIX_RE };
