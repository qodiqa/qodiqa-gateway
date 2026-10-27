'use strict';

/**
 * API-4 remediation — canonical pagination utility tests.
 *
 * Coverage:
 *   PG-01 … PG-15  parsePagination: canonical params, defaults, clamping
 *   PG-16 … PG-25  parsePagination: legacy limit/offset aliases
 *   PG-26 … PG-33  parseSortOrder: canonical + legacy aliases
 *   PG-34 … PG-44  buildPaginationMeta / withPaginationMeta
 *   PG-45 … PG-50  paginateArray / isPaginationRequested
 */

const {
  DEFAULT_MAX_PAGE_SIZE,
  DEFAULT_PAGE_SIZE,
  parsePagination,
  parseSortOrder,
  buildPaginationMeta,
  withPaginationMeta,
  paginateArray,
  isPaginationRequested,
} = require('./pagination');

describe('PG-01…15 — parsePagination canonical params', () => {
  test('PG-01 defaults to page 1, default page size, offset 0', () => {
    expect(parsePagination({})).toEqual({
      page: 1, pageSize: DEFAULT_PAGE_SIZE, limit: DEFAULT_PAGE_SIZE, offset: 0,
    });
  });

  test('PG-02 honors explicit page/pageSize', () => {
    expect(parsePagination({ page: '3', pageSize: '20' })).toEqual({
      page: 3, pageSize: 20, limit: 20, offset: 40,
    });
  });

  test('PG-03 clamps pageSize to maxPageSize', () => {
    expect(parsePagination({ pageSize: '9999' }).pageSize).toBe(DEFAULT_MAX_PAGE_SIZE);
  });

  test('PG-04 respects a caller-supplied maxPageSize override', () => {
    expect(parsePagination({ pageSize: '9999' }, { maxPageSize: 100 }).pageSize).toBe(100);
  });

  test('PG-05 respects a caller-supplied defaultPageSize', () => {
    expect(parsePagination({}, { defaultPageSize: 25 }).pageSize).toBe(25);
  });

  test('PG-06 non-positive pageSize is treated as absent and falls back to the default (not clamped to 1)', () => {
    expect(parsePagination({ pageSize: '0' }).pageSize).toBe(DEFAULT_PAGE_SIZE);
    expect(parsePagination({ pageSize: '-5' }).pageSize).toBe(DEFAULT_PAGE_SIZE);
  });

  test('PG-07 clamps page below 1 up to 1', () => {
    expect(parsePagination({ page: '0' }).page).toBe(1);
    expect(parsePagination({ page: '-3' }).page).toBe(1);
  });

  test('PG-08 rejects non-numeric page/pageSize, falls back to defaults', () => {
    expect(parsePagination({ page: 'abc', pageSize: 'xyz' })).toEqual({
      page: 1, pageSize: DEFAULT_PAGE_SIZE, limit: DEFAULT_PAGE_SIZE, offset: 0,
    });
  });

  test('PG-09 computes offset from page/pageSize', () => {
    expect(parsePagination({ page: '5', pageSize: '10' }).offset).toBe(40);
  });

  test('PG-10 large page number produces a large offset (empty-page case)', () => {
    const { page, offset } = parsePagination({ page: '1000', pageSize: '50' });
    expect(page).toBe(1000);
    expect(offset).toBe(49950);
  });

  test('PG-11 fractional page/pageSize truncate via parseInt', () => {
    expect(parsePagination({ page: '2.9', pageSize: '10.9' })).toEqual({
      page: 2, pageSize: 10, limit: 10, offset: 10,
    });
  });

  test('PG-12 missing query object defaults safely', () => {
    expect(parsePagination()).toEqual({
      page: 1, pageSize: DEFAULT_PAGE_SIZE, limit: DEFAULT_PAGE_SIZE, offset: 0,
    });
  });

  test('PG-13 page=1 always yields offset 0 regardless of pageSize', () => {
    expect(parsePagination({ page: '1', pageSize: '500' }).offset).toBe(0);
  });

  test('PG-14 exact maxPageSize boundary is accepted unclamped', () => {
    expect(parsePagination({ pageSize: String(DEFAULT_MAX_PAGE_SIZE) }).pageSize)
      .toBe(DEFAULT_MAX_PAGE_SIZE);
  });

  test('PG-15 pageSize one above maxPageSize is clamped down', () => {
    expect(parsePagination({ pageSize: String(DEFAULT_MAX_PAGE_SIZE + 1) }).pageSize)
      .toBe(DEFAULT_MAX_PAGE_SIZE);
  });
});

describe('PG-16…25 — parsePagination legacy limit/offset aliases', () => {
  test('PG-16 limit alias maps to pageSize', () => {
    expect(parsePagination({ limit: '30' }).pageSize).toBe(30);
  });

  test('PG-17 offset alias maps to an exact offset', () => {
    expect(parsePagination({ offset: '17' }).offset).toBe(17);
  });

  test('PG-18 offset derives a best-effort page even when not page-aligned', () => {
    // offset 17 with pageSize 10 falls inside page 2 (items 10-19)
    expect(parsePagination({ offset: '17', limit: '10' }).page).toBe(2);
  });

  test('PG-19 canonical page takes precedence over legacy offset when both given', () => {
    const result = parsePagination({ page: '3', pageSize: '10', offset: '999' });
    expect(result).toEqual({ page: 3, pageSize: 10, limit: 10, offset: 20 });
  });

  test('PG-20 canonical pageSize takes precedence over legacy limit when both given', () => {
    expect(parsePagination({ pageSize: '15', limit: '999' }).pageSize).toBe(15);
  });

  test('PG-21 limit is clamped to maxPageSize identically to pageSize', () => {
    expect(parsePagination({ limit: '9999' }).pageSize).toBe(DEFAULT_MAX_PAGE_SIZE);
  });

  test('PG-22 offset=0 is honored exactly (not treated as falsy/missing)', () => {
    expect(parsePagination({ offset: '0', limit: '10' })).toEqual({
      page: 1, pageSize: 10, limit: 10, offset: 0,
    });
  });

  test('PG-23 negative offset falls back to page-based computation', () => {
    expect(parsePagination({ offset: '-5' }).offset).toBe(0);
  });

  test('PG-24 non-numeric offset is ignored, defaults to page 1', () => {
    expect(parsePagination({ offset: 'nope' })).toEqual({
      page: 1, pageSize: DEFAULT_PAGE_SIZE, limit: DEFAULT_PAGE_SIZE, offset: 0,
    });
  });

  test('PG-25 limit+offset combination round-trips through canonical page/pageSize', () => {
    const result = parsePagination({ limit: '25', offset: '50' });
    expect(result.pageSize).toBe(25);
    expect(result.offset).toBe(50);
    expect(result.page).toBe(3);
  });
});

describe('PG-26…33 — parseSortOrder', () => {
  test('PG-26 defaults to desc', () => {
    expect(parseSortOrder({})).toBe('desc');
  });

  test('PG-27 canonical sortOrder=asc', () => {
    expect(parseSortOrder({ sortOrder: 'asc' })).toBe('asc');
  });

  test('PG-28 canonical sortOrder=desc', () => {
    expect(parseSortOrder({ sortOrder: 'desc' })).toBe('desc');
  });

  test('PG-29 legacy sortDir alias', () => {
    expect(parseSortOrder({ sortDir: 'asc' })).toBe('asc');
  });

  test('PG-30 legacy sort alias (direction-style value)', () => {
    expect(parseSortOrder({ sort: 'asc' })).toBe('asc');
  });

  test('PG-31 sortOrder takes precedence over legacy aliases', () => {
    expect(parseSortOrder({ sortOrder: 'asc', sortDir: 'desc', sort: 'desc' })).toBe('asc');
  });

  test('PG-32 invalid value falls back to default', () => {
    expect(parseSortOrder({ sortOrder: 'sideways' })).toBe('desc');
  });

  test('PG-33 caller-supplied default is honored', () => {
    expect(parseSortOrder({}, { default: 'asc' })).toBe('asc');
  });
});

describe('PG-34…44 — buildPaginationMeta / withPaginationMeta', () => {
  test('PG-34 computes totalPages via ceiling division', () => {
    expect(buildPaginationMeta({ page: 1, pageSize: 10, totalItems: 95 }).totalPages).toBe(10);
  });

  test('PG-35 empty collection yields totalPages 0 and hasNextPage false', () => {
    const meta = buildPaginationMeta({ page: 1, pageSize: 10, totalItems: 0 });
    expect(meta.totalPages).toBe(0);
    expect(meta.hasNextPage).toBe(false);
    expect(meta.hasPreviousPage).toBe(false);
  });

  test('PG-36 first page of multiple has hasPreviousPage false, hasNextPage true', () => {
    const meta = buildPaginationMeta({ page: 1, pageSize: 10, totalItems: 25 });
    expect(meta.hasPreviousPage).toBe(false);
    expect(meta.hasNextPage).toBe(true);
  });

  test('PG-37 last page has hasNextPage false, hasPreviousPage true', () => {
    const meta = buildPaginationMeta({ page: 3, pageSize: 10, totalItems: 25 });
    expect(meta.totalPages).toBe(3);
    expect(meta.hasNextPage).toBe(false);
    expect(meta.hasPreviousPage).toBe(true);
  });

  test('PG-38 middle page has both hasNextPage and hasPreviousPage true', () => {
    const meta = buildPaginationMeta({ page: 2, pageSize: 10, totalItems: 25 });
    expect(meta.hasNextPage).toBe(true);
    expect(meta.hasPreviousPage).toBe(true);
  });

  test('PG-39 exact multiple of pageSize does not add a phantom page', () => {
    expect(buildPaginationMeta({ page: 1, pageSize: 10, totalItems: 20 }).totalPages).toBe(2);
  });

  test('PG-40 negative/garbage totalItems is floored to 0', () => {
    expect(buildPaginationMeta({ page: 1, pageSize: 10, totalItems: -5 }).totalItems).toBe(0);
    expect(buildPaginationMeta({ page: 1, pageSize: 10, totalItems: NaN }).totalItems).toBe(0);
  });

  test('PG-41 withPaginationMeta adds canonical fields without removing legacy `total`', () => {
    const result = withPaginationMeta({ items: [1, 2], page: 1, pageSize: 10, total: 2 });
    expect(result.total).toBe(2);
    expect(result.totalItems).toBe(2);
    expect(result.totalPages).toBe(1);
    expect(result.hasNextPage).toBe(false);
    expect(result.hasPreviousPage).toBe(false);
    expect(result.items).toEqual([1, 2]);
  });

  test('PG-42 withPaginationMeta supports a custom totalField name', () => {
    const result = withPaginationMeta(
      { events: [], page: 2, pageSize: 5, dlqTotal: 12 },
      { totalField: 'dlqTotal' },
    );
    expect(result.dlqTotal).toBe(12);
    expect(result.totalItems).toBe(12);
    expect(result.totalPages).toBe(3);
  });

  test('PG-43 withPaginationMeta is a no-op passthrough for unrelated fields', () => {
    const result = withPaginationMeta({ page: 1, pageSize: 10, total: 0, sortOrder: 'asc' });
    expect(result.sortOrder).toBe('asc');
  });

  test('PG-44 withPaginationMeta prefers an existing totalItems over totalField', () => {
    const result = withPaginationMeta({ page: 1, pageSize: 10, total: 999, totalItems: 3 });
    expect(result.totalItems).toBe(3);
    expect(result.totalPages).toBe(1);
  });
});

describe('PG-45…50 — paginateArray / isPaginationRequested', () => {
  test('PG-45 slices an in-memory array and attaches metadata', () => {
    const items = Array.from({ length: 25 }, (_, i) => i);
    const result = paginateArray(items, { page: 2, pageSize: 10 });
    expect(result.items).toEqual([10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
    expect(result.totalItems).toBe(25);
    expect(result.totalPages).toBe(3);
    expect(result.hasNextPage).toBe(true);
    expect(result.hasPreviousPage).toBe(true);
  });

  test('PG-46 paginateArray returns an empty slice for an out-of-range page', () => {
    const items = [1, 2, 3];
    const result = paginateArray(items, { page: 5, pageSize: 10 });
    expect(result.items).toEqual([]);
    expect(result.hasNextPage).toBe(false);
  });

  test('PG-47 paginateArray on an empty array yields empty items and zero totals', () => {
    const result = paginateArray([], { page: 1, pageSize: 10 });
    expect(result.items).toEqual([]);
    expect(result.totalItems).toBe(0);
    expect(result.totalPages).toBe(0);
  });

  test('PG-48 isPaginationRequested is false when no pagination params given', () => {
    expect(isPaginationRequested({})).toBe(false);
    expect(isPaginationRequested({ status: 'ACTIVE' })).toBe(false);
  });

  test('PG-49 isPaginationRequested is true when any canonical param is present', () => {
    expect(isPaginationRequested({ page: '2' })).toBe(true);
    expect(isPaginationRequested({ pageSize: '10' })).toBe(true);
  });

  test('PG-50 isPaginationRequested is true when any legacy alias is present', () => {
    expect(isPaginationRequested({ limit: '10' })).toBe(true);
    expect(isPaginationRequested({ offset: '0' })).toBe(true);
  });
});
