'use strict';

/**
 * canonical delegated click-dispatch listener shared by
 * dashboard.js, audit-viewer.js, and policy-management.js. Supports both
 * pre-existing authoring conventions unchanged, so no action map in any of
 * the three files had to be rewritten:
 *
 *   style: 'args' (default) — audit-viewer.js's original convention, also
 *     used by dashboard.js's migrated pagination dispatch. JSON.parses
 *     data-arg (wrapped as a 1-element array) or data-args (already an
 *     array) and spreads them as call arguments: `fn(...args)`. Actions
 *     listed in `rawElementActions` instead receive the raw element
 *     (audit-viewer.js's toggleCollapse, whose original inline handler was
 *     `onclick="toggleCollapse(this)"`).
 *
 *   style: 'element' — policy-management.js's original convention. Always
 *     calls `fn(el, e)` and lets each action closure read el.dataset itself,
 *     exactly as CLICK_FNS's entries already do.
 *
 * console.js is not migrated onto this dispatcher: it never had one to
 * begin with (see WP-038-REMEDIATION-REPORT.md).
 */
(function (global) {
  function createClickDispatcher(actions, opts) {
    opts = opts || {};
    const style = opts.style || 'args';
    const rawElementActions = opts.rawElementActions || [];

    return function onClick(e) {
      const el = e.target.closest('[data-action]');
      if (!el) return;

      const fn = actions[el.dataset.action];
      if (!fn) return;

      if (style === 'element') {
        fn(el, e);
        return;
      }

      // style === 'args' — matches audit-viewer.js's original semantics,
      // including its defensive (native buttons already block this) disabled
      // check.
      if (el.disabled) return;

      if (rawElementActions.indexOf(el.dataset.action) !== -1) {
        fn(el);
        return;
      }

      const args = el.dataset.args !== undefined ? JSON.parse(el.dataset.args)
                 : el.dataset.arg !== undefined ? [JSON.parse(el.dataset.arg)]
                 : [];
      fn(...args);
    };
  }

  const ns = (global.QodiqaCommon = global.QodiqaCommon || {});
  ns.createClickDispatcher = createClickDispatcher;

  if (typeof module === 'object' && module.exports) {
    module.exports = { createClickDispatcher };
  }
})(typeof window !== 'undefined' ? window : globalThis);
