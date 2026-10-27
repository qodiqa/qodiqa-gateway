'use strict';

/**
 * canonical `<span class="badge ...">` rendering primitive shared
 * by audit-viewer.js and policy-management.js (both already produce exactly
 * this markup shape for their various badge helpers). Each file keeps its
 * own color/label mapping — that is domain logic (what a given decision/
 * signature/policy-status value should look like), not duplicated
 * infrastructure — and calls this shared primitive to render it.
 *
 * dashboard.js's colored `.value` spans and console.js's `verdict-chip`/
 * `state-pill` components are visually and structurally distinct components,
 * not the same badge pattern, and are intentionally left unmigrated (see
 * WP-038-REMEDIATION-REPORT.md, "Documented scope exceptions").
 */
(function (global) {
  const esc = (global.QodiqaCommon && global.QodiqaCommon.esc) ||
    (typeof require === 'function' ? require('./esc').esc : String);

  function badge(text, cls) {
    return `<span class="badge ${cls || ''}">${esc(text)}</span>`;
  }

  const ns = (global.QodiqaCommon = global.QodiqaCommon || {});
  ns.badge = badge;

  if (typeof module === 'object' && module.exports) {
    module.exports = { badge };
  }
})(typeof window !== 'undefined' ? window : globalThis);
