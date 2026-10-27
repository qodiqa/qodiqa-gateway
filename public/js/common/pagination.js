'use strict';

/**
 * canonical pagination math + button markup shared by the admin UIs
 * whose pagination is JS-generated (dashboard.js, audit-viewer.js).
 *
 * policy-management.js's pagination bar is static HTML with buttons toggled
 * via .disabled/textContent rather than regenerated markup, so it has no use
 * for renderPager() — but it still reuses paginate() for its page-count math
 * (see policy-management.js), eliminating the second copy of the
 * Math.ceil(total / pageSize) boundary computation.
 */
(function (global) {
  const esc = (global.QodiqaCommon && global.QodiqaCommon.esc) ||
    (typeof require === 'function' ? require('./esc').esc : String);
  const attrJs = (global.QodiqaCommon && global.QodiqaCommon.attrJs) ||
    (typeof require === 'function' ? require('./esc').attrJs : JSON.stringify);

  // dashboard.js used `Math.ceil(total / pageSize) || 1`; audit-viewer.js used
  // `Math.max(1, Math.ceil(total / pageSize))`. Both clamp to a minimum of 1
  // page and are equal for every input (including total === 0, where
  // Math.ceil(0/x) === 0, `0 || 1` === 1, and `Math.max(1, 0)` === 1).
  function paginate(total, pageSize, page) {
    const totalPages = Math.max(1, Math.ceil(total / pageSize) || 1);
    return {
      totalPages,
      hasPrev: page > 1,
      hasNext: page < totalPages,
    };
  }

  function pagerInfo(page, totalPages, total, word) {
    return `Page ${page} of ${totalPages} (${total} ${word || 'total'})`;
  }

  // Renders the "◀ Prev  Page X of Y (Z word)  Next ▶" markup using the
  // data-action/data-arg (attrJs-encoded) dispatch scheme shared by
  // dashboard.js and audit-viewer.js. Each caller supplies its own labels/
  // glyphs/word/wrapper-class so the exact visual output of every existing
  // page is preserved unchanged.
  function renderPager(opts) {
    const { total, pageSize, page, actionName, prevLabel, nextLabel, totalWord, infoClass } = opts;
    const { totalPages, hasPrev, hasNext } = paginate(total, pageSize, page);
    const infoAttr = infoClass ? ` class="${esc(infoClass)}"` : '';
    return `<button ${!hasPrev ? 'disabled' : ''} data-action="${esc(actionName)}" data-arg="${attrJs(page - 1)}">${prevLabel}</button>
    <span${infoAttr}>${pagerInfo(page, totalPages, total, totalWord)}</span>
    <button ${!hasNext ? 'disabled' : ''} data-action="${esc(actionName)}" data-arg="${attrJs(page + 1)}">${nextLabel}</button>`;
  }

  const ns = (global.QodiqaCommon = global.QodiqaCommon || {});
  ns.paginate = paginate;
  ns.pagerInfo = pagerInfo;
  ns.renderPager = renderPager;

  if (typeof module === 'object' && module.exports) {
    module.exports = { paginate, pagerInfo, renderPager };
  }
})(typeof window !== 'undefined' ? window : globalThis);
