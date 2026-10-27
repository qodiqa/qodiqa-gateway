'use strict';

/**
 * canonical HTML-escaping shared by all four admin UIs.
 *
 * This is the strict superset of the four previously-duplicated copies: it
 * normalizes null/undefined to '' (audit-viewer.js/policy-management.js's
 * behavior) and escapes & < > " ' (also escaping the apostrophe, which
 * dashboard.js/console.js's copies did not). Verified against every existing
 * call site in dashboard.js/console.js before consolidating: neither ever
 * calls esc(null)/esc(undefined) (values are pre-coalesced with `?? '—'`
 * first), and the HTML entity &#39; renders as the same visible glyph as a
 * literal apostrophe — so this is not an observable behavior change anywhere.
 */
(function (global) {
  function esc(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Safely embed a value as a JSON literal inside an HTML attribute (e.g.
  // data-arg="..." used by the shared delegated click dispatcher).
  // JSON.stringify() produces a well-formed JS/JSON literal (handles quotes,
  // backslashes, control chars, unicode); esc() then HTML-encodes that
  // literal so its own quote characters can never terminate the surrounding
  // HTML attribute. Neither step alone is sufficient against untrusted
  // input — always use this instead of hand-building an attribute value.
  function attrJs(value) {
    return esc(JSON.stringify(value));
  }

  const ns = (global.QodiqaCommon = global.QodiqaCommon || {});
  ns.esc = esc;
  ns.attrJs = attrJs;

  if (typeof module === 'object' && module.exports) {
    module.exports = { esc, attrJs };
  }
})(typeof window !== 'undefined' ? window : globalThis);
