'use strict';

/**
 * API-4 remediation — pagination drift-prevention test.
 *
 * Mirrors routeParity.test.js's source-text-scan approach: rather than
 * instantiating every router (which needs per-file constructor dependencies —
 * Postgres-backed stores, RBAC permission gates, live policy getters — just
 * to read a query param), this statically scans each route-handler file for
 * raw reads of canonical/legacy pagination parameter names and asserts the
 * file goes through the shared utility (src/utils/pagination.js) instead of
 * reimplementing page/pageSize/limit/offset parsing locally.
 *
 * Before API-4, five files each carried a byte-for-byte copy of the same
 * page/pageSize/sortOrder parser, and several more hand-rolled incompatible
 * limit/offset schemes — this test is what makes the fix self-enforcing
 * going forward: a new collection endpoint added later that reads
 * page/pageSize/limit/offset off req.query without importing the shared
 * utility fails this test immediately, with the offending file named in the
 * failure output.
 */

const fs = require('fs');
const path = require('path');

const ROUTE_DIRS = [
  path.join(__dirname, '..', 'api', 'routes'),
  path.join(__dirname, '..', 'alerting', 'api'),
];

const PAGINATION_UTIL_IMPORT_RE = /require\(\s*['"][^'"]*utils\/pagination['"]\s*\)/;
const PAGINATION_UTIL_CALL_RE = /\b(parsePagination|parseSortOrder|paginateArray|withPaginationMeta|buildPaginationMeta|isPaginationRequested)\s*\(/;

// Any raw read of a canonical or legacy pagination parameter name off a
// query-like object (req.query, a validated zod `parsed.data`, etc.) —
// this is exactly the pattern every ad-hoc parser in the pre-API-4 codebase
// used (e.g. `parseInt(req.query.page, 10)`, `req.query.pageSize`,
// `const { limit, offset } = parsed.data`).
const RAW_QUERY_PAGINATION_RE =
  /\b(?:req\.query|\w*[Qq]uery|parsed\.data|\w+Parsed\.data)\.(page|pageSize|limit|offset)\b/;

function _listJsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '__tests__') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(..._listJsFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.js') && !entry.name.endsWith('.test.js')) {
      out.push(full);
    }
  }
  return out;
}

const REPO_ROOT = path.join(__dirname, '..', '..');
const files = ROUTE_DIRS.flatMap(_listJsFiles);

describe('API-4 — pagination drift prevention', () => {
  test('sanity: scanned a non-trivial number of route files', () => {
    // Guards against the file walker silently finding nothing (e.g. after a
    // directory rename) and this whole suite passing vacuously.
    expect(files.length).toBeGreaterThan(20);
  });

  test.each(files.map(f => [path.relative(REPO_ROOT, f), f]))(
    '%s: any raw page/pageSize/limit/offset query read goes through src/utils/pagination.js',
    (_label, file) => {
      const src = fs.readFileSync(file, 'utf8');

      if (!RAW_QUERY_PAGINATION_RE.test(src)) {
        return; // nothing pagination-shaped in this file — nothing to enforce
      }

      const importsUtil = PAGINATION_UTIL_IMPORT_RE.test(src);
      const usesUtil = PAGINATION_UTIL_CALL_RE.test(src);

      if (!importsUtil || !usesUtil) {
        throw new Error(
          `${path.relative(REPO_ROOT, file)} reads a page/pageSize/limit/offset ` +
          'query parameter but does not both import and call the canonical ' +
          "pagination utility (src/utils/pagination.js). New collection " +
          'endpoints must derive pagination via parsePagination/parseSortOrder/' +
          'paginateArray/withPaginationMeta/buildPaginationMeta/isPaginationRequested ' +
          'rather than reimplementing page/pageSize/limit/offset parsing locally ' +
          '— see API-4-REMEDIATION-REPORT.md.',
        );
      }
    },
  );
});
