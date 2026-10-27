'use strict';

/**
 * Canonical pagination utility — API-4 remediation.
 *
 * Before this module, pagination was independently reimplemented across the
 * route layer: five files (attestation.js, certification.js,
 * verificationPortal.js, transparencyLog.js, evidenceChain.js) each carried a
 * byte-for-byte copy of the same page/pageSize/sortOrder parser, several more
 * used an incompatible limit/offset convention (prqDlq, consent, DSR, policy
 * governance), and response shapes varied (bare `total`, no `totalPages`, no
 * `hasNextPage`/`hasPreviousPage`). Every collection endpoint should now
 * derive its request parameters and response metadata through this module
 * instead of reimplementing the logic locally — see
 * API-4-REMEDIATION-REPORT.md for the full inventory and rationale.
 *
 * Canonical request contract:
 *   - `page`      (1-based, default 1)
 *   - `pageSize`  (default 50, clamped to [1, maxPageSize])
 *   - `sortOrder` ('asc' | 'desc', default 'desc')
 *
 * Deprecated aliases — still accepted, normalized into the canonical model,
 * never removed (backward compatibility is a hard constraint of API-4):
 *   - `limit`           → `pageSize`
 *   - `offset`          → derives `page`; the exact legacy offset is still
 *                         honored for the underlying query even when it does
 *                         not fall on a `pageSize` boundary
 *   - `sort` / `sortDir` (when the value is literally 'asc'/'desc')
 *                       → `sortOrder`
 *
 * Canonical response metadata (`buildPaginationMeta` / `withPaginationMeta`):
 *   `page`, `pageSize`, `totalItems`, `totalPages`, `hasNextPage`,
 *   `hasPreviousPage` — added alongside whatever fields a given endpoint
 *   already returned (e.g. the legacy `total`), never replacing them.
 */

const DEFAULT_MAX_PAGE_SIZE = 500;
const DEFAULT_PAGE_SIZE = 50;

// API-1: safety ceiling for endpoints that otherwise return their full,
// unbounded collection when the caller supplies no pagination params (a
// deliberate backward-compatibility choice — see isPaginationRequested()'s
// own doc). Below this ceiling, "no pagination requested" still means "full
// array" exactly as before; above it, pagination is forced even though the
// caller didn't ask, so a genuinely large dataset can never be returned in
// one unbounded response.
const DEFAULT_UNBOUNDED_CEILING = 5000;

function _toPositiveInt(value) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function _toNonNegativeInt(value) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/**
 * Parse page/pageSize (canonical) or limit/offset (legacy) query params into
 * one normalized shape usable by both page-based and offset-based callers.
 *
 * @param {object} query
 * @param {{defaultPageSize?: number, maxPageSize?: number}} [opts]
 * @returns {{page: number, pageSize: number, limit: number, offset: number}}
 */
function parsePagination(query = {}, opts = {}) {
  const defaultPageSize = opts.defaultPageSize || DEFAULT_PAGE_SIZE;
  const maxPageSize     = opts.maxPageSize     || DEFAULT_MAX_PAGE_SIZE;

  const pageSize = Math.min(
    maxPageSize,
    _toPositiveInt(query.pageSize) || _toPositiveInt(query.limit) || defaultPageSize,
  );

  const explicitOffset = _toNonNegativeInt(query.offset);
  const explicitPage   = _toPositiveInt(query.page);

  let page;
  let offset;
  if (explicitPage === null && explicitOffset !== null) {
    // Legacy offset-based caller: honor the exact offset for the query, and
    // derive `page` (best-effort — legacy offsets need not be page-aligned)
    // purely for response metadata.
    offset = explicitOffset;
    page   = Math.floor(offset / pageSize) + 1;
  } else {
    page   = explicitPage || 1;
    offset = (page - 1) * pageSize;
  }

  return { page, pageSize, limit: pageSize, offset };
}

/**
 * Parse the sort direction, accepting the canonical `sortOrder` plus the
 * `sort` / `sortDir` aliases used by legacy endpoints. Endpoints whose `sort`
 * parameter is a named-field enum (not a bare direction) rather than a
 * direction toggle must NOT use this helper — see API-4 report §"justified
 * exceptions" (e.g. GET /alerts's `sort=risk_score_desc`).
 *
 * @param {object} query
 * @param {{default?: 'asc'|'desc'}} [opts]
 * @returns {'asc'|'desc'}
 */
function parseSortOrder(query = {}, opts = {}) {
  const def = opts.default || 'desc';
  const raw = query.sortOrder ?? query.sortDir ?? query.sort;
  if (raw === 'asc' || raw === 'desc') return raw;
  return def;
}

/**
 * Build the canonical pagination metadata block from a page/pageSize/count.
 *
 * @param {{page: number, pageSize: number, totalItems: number}} args
 */
function buildPaginationMeta({ page, pageSize, totalItems }) {
  const total      = Math.max(0, Number(totalItems) || 0);
  const totalPages = pageSize > 0 ? Math.ceil(total / pageSize) : 0;
  return {
    page,
    pageSize,
    totalItems: total,
    totalPages,
    hasNextPage:     page < totalPages,
    hasPreviousPage: page > 1,
  };
}

/**
 * Merge canonical pagination metadata into an existing result object without
 * removing any field the endpoint already returned (additive-only, per the
 * API-4 backward-compatibility constraint). `totalField` names the key the
 * result already uses for the item count (most stores return `total`).
 *
 * @param {object} result — must already carry `page` and `pageSize`
 * @param {{totalField?: string}} [opts]
 */
function withPaginationMeta(result, opts = {}) {
  const totalField = opts.totalField || 'total';
  const totalItems = result.totalItems ?? result[totalField] ?? 0;
  const meta = buildPaginationMeta({ page: result.page, pageSize: result.pageSize, totalItems });
  return { ...result, ...meta };
}

/**
 * Slice an already-fetched in-memory array and attach canonical pagination
 * metadata. Used for endpoints whose underlying store has no LIMIT/OFFSET
 * support of its own (small in-memory collections) so that opt-in pagination
 * can be added without touching the store layer.
 *
 * @param {Array} items
 * @param {{page: number, pageSize: number}} args
 */
function paginateArray(items, { page, pageSize }) {
  const totalItems = items.length;
  const offset = (page - 1) * pageSize;
  const slice = items.slice(offset, offset + pageSize);
  return { items: slice, ...buildPaginationMeta({ page, pageSize, totalItems }) };
}

/**
 * True if the caller supplied any pagination-related query param — used by
 * previously-unbounded endpoints to decide whether to keep returning the
 * full collection (default, backward-compatible) or switch to sliced +
 * metadata output (opt-in).
 */
function isPaginationRequested(query = {}) {
  return (
    query.page !== undefined ||
    query.pageSize !== undefined ||
    query.limit !== undefined ||
    query.offset !== undefined
  );
}

/**
 * API-1: true if the endpoint should paginate its response — either because
 * the caller explicitly asked (isPaginationRequested()), or because the
 * full, unbounded collection would exceed the safety ceiling. Endpoints that
 * currently return their full array when no pagination is requested (a
 * deliberate backward-compatibility choice) should gate that branch on this
 * instead of isPaginationRequested() alone, so a caller who never opts in
 * still can't trigger truly unbounded enumeration of a large dataset.
 *
 * @param {object} query
 * @param {number} itemCount
 * @param {{ ceiling?: number }} [opts]
 */
function requiresPagination(query = {}, itemCount = 0, { ceiling = DEFAULT_UNBOUNDED_CEILING } = {}) {
  return isPaginationRequested(query) || itemCount > ceiling;
}

module.exports = {
  DEFAULT_MAX_PAGE_SIZE,
  DEFAULT_PAGE_SIZE,
  DEFAULT_UNBOUNDED_CEILING,
  parsePagination,
  parseSortOrder,
  buildPaginationMeta,
  withPaginationMeta,
  paginateArray,
  isPaginationRequested,
  requiresPagination,
};
