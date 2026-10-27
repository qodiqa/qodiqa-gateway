'use strict';

/**
 * Assertion helpers for acceptance-test implementations.
 *
 * A thrown TestAssertionError is caught by helpers/runner.js and reported
 * as FAIL. A thrown NeedsReviewSignal is caught and reported as
 * NEEDS_REVIEW instead — the only two outcomes runner.js distinguishes
 * besides a clean PASS return. Assertions are never retried by the runner
 * (requirement #19): one failed check is one FAIL, full stop.
 */

class TestAssertionError extends Error {
  constructor(message, { expected, actual } = {}) {
    super(message);
    this.name = 'TestAssertionError';
    this.expected = expected;
    this.actual = actual;
  }
}

class NeedsReviewSignal extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'NeedsReviewSignal';
  }
}

function needsReview(reason) {
  throw new NeedsReviewSignal(reason);
}

function fail(message, details) {
  throw new TestAssertionError(message, details);
}

function ok(condition, message) {
  if (!condition) fail(message);
}

function equal(actual, expected, message) {
  if (actual !== expected) {
    fail(message || `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`, { expected, actual });
  }
}

function deepEqual(actual, expected, message) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a !== b) {
    fail(message || `Expected ${b}, got ${a}`, { expected, actual });
  }
}

function hasKeys(obj, keys, message) {
  const missing = keys.filter((k) => !(obj && Object.prototype.hasOwnProperty.call(obj, k)));
  if (missing.length > 0) {
    fail(message || `Missing key(s): ${missing.join(', ')}`, { expected: keys, actual: Object.keys(obj || {}) });
  }
}

function exactKeys(obj, keys, message) {
  const actualKeys = Object.keys(obj || {}).sort();
  const expectedKeys = [...keys].sort();
  deepEqual(actualKeys, expectedKeys, message || `Expected exactly keys [${expectedKeys.join(', ')}], got [${actualKeys.join(', ')}]`);
}

function includes(haystack, needle, message) {
  if (!haystack || !haystack.includes(needle)) {
    fail(message || `Expected to find ${JSON.stringify(needle)}`, { expected: needle, actual: haystack });
  }
}

module.exports = {
  TestAssertionError,
  NeedsReviewSignal,
  needsReview,
  fail,
  ok,
  equal,
  deepEqual,
  hasKeys,
  exactKeys,
  includes,
};
