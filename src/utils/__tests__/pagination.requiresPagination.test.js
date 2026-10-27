'use strict';

/**
 * API-1 remediation — requiresPagination() safety ceiling.
 */

const { requiresPagination, DEFAULT_UNBOUNDED_CEILING } = require('../pagination');

describe('requiresPagination()', () => {
  test('false when no pagination requested and item count is under the ceiling', () => {
    expect(requiresPagination({}, 100)).toBe(false);
  });

  test('true when the caller explicitly requests pagination, regardless of count', () => {
    expect(requiresPagination({ page: '1' }, 5)).toBe(true);
    expect(requiresPagination({ pageSize: '10' }, 5)).toBe(true);
    expect(requiresPagination({ limit: '10' }, 5)).toBe(true);
    expect(requiresPagination({ offset: '0' }, 5)).toBe(true);
  });

  test('true when item count exceeds the default ceiling, even with no pagination requested', () => {
    expect(requiresPagination({}, DEFAULT_UNBOUNDED_CEILING + 1)).toBe(true);
  });

  test('false exactly at the ceiling boundary (ceiling is exceeded, not met, to trigger)', () => {
    expect(requiresPagination({}, DEFAULT_UNBOUNDED_CEILING)).toBe(false);
  });

  test('a custom ceiling can be supplied', () => {
    expect(requiresPagination({}, 11, { ceiling: 10 })).toBe(true);
    expect(requiresPagination({}, 10, { ceiling: 10 })).toBe(false);
  });
});
