'use strict';

/**
 * DSR export and restriction read at most one page (200 / 500 rows) and silently stopped there — a
 * data subject with more consent records or history got an INCOMPLETE export (GDPR Art. 20) or an incomplete restriction (Art. 18)
 * with no warning. pageAll() reads every page, in order, before the caller acts on the result.
 *
 * @param {(opts: {limit: number, offset: number}) => Promise<any[]>} fetchPage  returns the rows of ONE page
 * @param {number} pageSize  the largest limit the underlying store honours (its own cap)
 * @param {number} [maxRows] safety bound (default 1,000,000) — exceeding it throws rather than truncating silently
 */
async function pageAll(fetchPage, pageSize, maxRows = 1_000_000) {
  const all = [];
  for (let offset = 0; ; offset += pageSize) {
    const rows = await fetchPage({ limit: pageSize, offset });
    all.push(...rows);
    if (rows.length < pageSize) return all;
    if (all.length >= maxRows) {
      const e = new Error(`DSR_RESULT_TOO_LARGE: more than ${maxRows} rows — refusing to return a silently truncated result`);
      e.code = 'DSR_RESULT_TOO_LARGE';
      throw e;
    }
  }
}

module.exports = { pageAll };
