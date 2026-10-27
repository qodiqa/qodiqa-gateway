'use strict';

const {
  CATEGORIES,
  classifyFailure,
  isRetryableCategory,
  shouldRetry,
  computeBackoffMs,
} = require('../retryPolicy');
const { SigningTimeoutError } = require('../withDeadline');

describe('retryPolicy.classifyFailure — failure classification', () => {
  test('classifies our own deadline errors as TIMEOUT', () => {
    const err = new SigningTimeoutError(3000, { provider: 'vault', operation: 'sign' });
    expect(classifyFailure(err)).toBe(CATEGORIES.TIMEOUT);
  });

  test('classifies connection-reset/refused errors as NETWORK', () => {
    const err = Object.assign(new Error('connect failed'), { code: 'ECONNRESET' });
    expect(classifyFailure(err)).toBe(CATEGORIES.NETWORK);
  });

  test('classifies socket hang up message as NETWORK', () => {
    expect(classifyFailure(new Error('socket hang up'))).toBe(CATEGORIES.NETWORK);
  });

  test('classifies HTTP 503/429/504 as PROVIDER_UNAVAILABLE', () => {
    expect(classifyFailure(Object.assign(new Error('x'), { statusCode: 503 }))).toBe(CATEGORIES.PROVIDER_UNAVAILABLE);
    expect(classifyFailure(Object.assign(new Error('x'), { statusCode: 429 }))).toBe(CATEGORIES.PROVIDER_UNAVAILABLE);
    expect(classifyFailure(Object.assign(new Error('x'), { statusCode: 504 }))).toBe(CATEGORIES.PROVIDER_UNAVAILABLE);
  });

  test('classifies Vault sealed / leader election as PROVIDER_UNAVAILABLE', () => {
    expect(classifyFailure(new Error('Vault is sealed'))).toBe(CATEGORIES.PROVIDER_UNAVAILABLE);
    expect(classifyFailure(new Error('leader election in progress'))).toBe(CATEGORIES.PROVIDER_UNAVAILABLE);
  });

  test('classifies HTTP 401 / auth messages as AUTHENTICATION', () => {
    expect(classifyFailure(Object.assign(new Error('x'), { statusCode: 401 }))).toBe(CATEGORIES.AUTHENTICATION);
    expect(classifyFailure(new Error('AppRole authentication failed'))).toBe(CATEGORIES.AUTHENTICATION);
  });

  test('classifies HTTP 403 / permission denied as AUTHORIZATION', () => {
    expect(classifyFailure(Object.assign(new Error('x'), { statusCode: 403 }))).toBe(CATEGORIES.AUTHORIZATION);
    expect(classifyFailure(new Error('permission denied'))).toBe(CATEGORIES.AUTHORIZATION);
  });

  test('classifies missing SDK / unset env var as CONFIGURATION', () => {
    expect(classifyFailure(new Error('node-vault is not installed'))).toBe(CATEGORIES.CONFIGURATION);
    expect(classifyFailure(new Error('HSM_PKCS11_LIB is not set'))).toBe(CATEGORIES.CONFIGURATION);
  });

  test('classifies self-test / signature failures as CRYPTOGRAPHIC', () => {
    expect(classifyFailure(new Error('FATAL: native signing provider self-test failed'))).toBe(CATEGORIES.CRYPTOGRAPHIC);
  });

  test('classifies revoked/disabled key as PERMANENT_REJECTION', () => {
    expect(classifyFailure(new Error('key has been revoked'))).toBe(CATEGORIES.PERMANENT_REJECTION);
    expect(classifyFailure(Object.assign(new Error('x'), { statusCode: 404 }))).toBe(CATEGORIES.PERMANENT_REJECTION);
  });

  test('classifies malformed request as INVALID_REQUEST', () => {
    expect(classifyFailure(Object.assign(new Error('malformed request body'), { statusCode: 400 }))).toBe(CATEGORIES.INVALID_REQUEST);
  });

  test('falls back to UNKNOWN (fail-closed) for unrecognised errors', () => {
    expect(classifyFailure(new Error('something completely unexpected'))).toBe(CATEGORIES.UNKNOWN);
  });

  test('handles a null/undefined error gracefully', () => {
    expect(classifyFailure(null)).toBe(CATEGORIES.UNKNOWN);
    expect(classifyFailure(undefined)).toBe(CATEGORIES.UNKNOWN);
  });
});

describe('retryPolicy.isRetryableCategory — retry eligibility', () => {
  test('TIMEOUT, NETWORK, PROVIDER_UNAVAILABLE are retryable', () => {
    expect(isRetryableCategory(CATEGORIES.TIMEOUT)).toBe(true);
    expect(isRetryableCategory(CATEGORIES.NETWORK)).toBe(true);
    expect(isRetryableCategory(CATEGORIES.PROVIDER_UNAVAILABLE)).toBe(true);
  });

  test('never retries permission/auth/crypto/permanent/config/unknown failures', () => {
    expect(isRetryableCategory(CATEGORIES.AUTHENTICATION)).toBe(false);
    expect(isRetryableCategory(CATEGORIES.AUTHORIZATION)).toBe(false);
    expect(isRetryableCategory(CATEGORIES.CONFIGURATION)).toBe(false);
    expect(isRetryableCategory(CATEGORIES.CRYPTOGRAPHIC)).toBe(false);
    expect(isRetryableCategory(CATEGORIES.INVALID_REQUEST)).toBe(false);
    expect(isRetryableCategory(CATEGORIES.PERMANENT_REJECTION)).toBe(false);
    expect(isRetryableCategory(CATEGORIES.UNKNOWN)).toBe(false);
  });
});

describe('retryPolicy.shouldRetry', () => {
  test('retries a transient failure below the attempt cap', () => {
    const result = shouldRetry({ error: new Error('ECONNRESET'), attempt: 1, maxAttempts: 3 });
    // "ECONNRESET" as a bare message string still matches the NETWORK regex.
    expect(result.retry).toBe(true);
    expect(result.category).toBe(CATEGORIES.NETWORK);
  });

  test('refuses to retry once maxAttempts is reached, even for a transient category', () => {
    const result = shouldRetry({ error: new Error('socket hang up'), attempt: 3, maxAttempts: 3 });
    expect(result.retry).toBe(false);
    expect(result.reason).toMatch(/maximum/);
  });

  test('never retries permission denied regardless of attempt count', () => {
    const result = shouldRetry({
      error: Object.assign(new Error('permission denied'), { statusCode: 403 }),
      attempt: 1,
      maxAttempts: 5,
    });
    expect(result.retry).toBe(false);
    expect(result.category).toBe(CATEGORIES.AUTHORIZATION);
  });

  test('never retries invalid signature / cryptographic failures', () => {
    const result = shouldRetry({ error: new Error('signature verification failed'), attempt: 1, maxAttempts: 5 });
    expect(result.retry).toBe(false);
    expect(result.category).toBe(CATEGORIES.CRYPTOGRAPHIC);
  });
});

describe('retryPolicy.computeBackoffMs — exponential backoff with jitter', () => {
  const policy = { initialBackoffMs: 100, maxBackoffMs: 2000, retryJitter: false };

  test('grows exponentially without jitter', () => {
    expect(computeBackoffMs(1, policy)).toBe(100);
    expect(computeBackoffMs(2, policy)).toBe(200);
    expect(computeBackoffMs(3, policy)).toBe(400);
    expect(computeBackoffMs(4, policy)).toBe(800);
  });

  test('caps at maxBackoffMs', () => {
    expect(computeBackoffMs(10, policy)).toBe(2000);
  });

  test('applies full jitter: result is uniformly within [0, exponential)', () => {
    const jitterPolicy = { ...policy, retryJitter: true };
    // Deterministic RNG for a reproducible assertion.
    expect(computeBackoffMs(3, jitterPolicy, () => 0)).toBe(0);
    expect(computeBackoffMs(3, jitterPolicy, () => 0.999999)).toBeLessThan(400);
    expect(computeBackoffMs(3, jitterPolicy, () => 0.5)).toBe(200);
  });

  test('never returns a negative delay', () => {
    expect(computeBackoffMs(1, policy, () => -1)).toBeGreaterThanOrEqual(0);
  });
});
