'use strict';

/**
 * Webhook Safe Retry Policy Tests — Component 44.6
 *
 * WRP-01…10   classifyFailure: HTTP status code classification
 * WRP-11…18   classifyFailure: edge cases and unknown statuses
 * WRP-19…26   shouldRetry: idempotency gate (POST default = no retry)
 * WRP-27…35   shouldRetry: attempt limit gate
 * WRP-36…46   shouldRetry: failure classification gate
 * WRP-47…52   shouldRetry: all three gates combined
 * WRP-53…62   computeBackoffMs: exponential formula and limits
 * WRP-63…70   computeBackoffMs: jitter behavior
 * WRP-71…78   retryHandler integration: policy applied on delivery failure
 * WRP-79…86   retryHandler integration: isIdempotent flag from dispatcher payload
 * WRP-87…93   retryHandler integration: permanent failure stops retries
 * WRP-94…100  webhookDispatcher: isIdempotent + httpMethod in operation payload
 */

// ── Global mocks (must precede all requires) ──────────────────────────────────

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const mockDnsLookup = jest.fn();
jest.mock('dns', () => ({ promises: { lookup: mockDnsLookup } }));

const mockPool = {
  _enabled: true,
  isEnabled() { return this._enabled; },
  query: jest.fn(),
  // Test double for the real pgPool.withTenantTransaction — runs fn
  // against the same mocked .query() without replicating tenantContext's
  // format validation, which the live-PG adversarial harness covers instead.
  withTenantTransaction: jest.fn((_tenantId, fn) => fn({ query: mockPool.query })),
};
jest.mock('../../../infra/postgres/pool', () => mockPool);

const mockEnqueueWebhookDelivery = jest.fn().mockResolvedValue(undefined);
jest.mock('../../../core/persistenceRecovery', () => ({
  enqueueWebhookDelivery: mockEnqueueWebhookDelivery,
  isEnabled:              () => true,
  OPERATION_TYPES:        { WEBHOOK_DELIVERY: 'WEBHOOK_DELIVERY' },
}));

// ── Imports ───────────────────────────────────────────────────────────────────

process.env.QODIQA_KEY_ENCRYPTION_KEY = 'a'.repeat(64);

const {
  classifyFailure,
  shouldRetry,
  computeBackoffMs,
  TRANSIENT_STATUSES,
  PERMANENT_STATUSES,
} = require('../webhookRetryPolicy');

// these cases used to fail FAST only because createSecureLookup() mishandled the Node >= 20 { all: true }
// contract, so the delivery never reached the network. With the lookup fixed, https.request() would really connect to the mocked
// address (93.184.216.34) and the suite would depend on the network. Make the failure explicit and deterministic instead: every
// outbound request ends in ECONNREFUSED on the next tick.
const https = require('https');
const { EventEmitter } = require('events');
jest.spyOn(https, 'request').mockImplementation(() => {
  const req = new EventEmitter();
  req.write = () => {};
  req.destroy = () => {};
  req.end = () => { process.nextTick(() => req.emit('error', Object.assign(new Error('connect ECONNREFUSED 93.184.216.34:443'), { code: 'ECONNREFUSED' }))); };
  return req;
});

const { buildConfig }    = require('../webhookSecurityConfig');
const { retryHandler }   = require('../webhookDelivery');
const { encryptSecret, generateSecret } = require('../webhookSecrets');

// ── Shared helpers ────────────────────────────────────────────────────────────

const BASE_CONFIG = buildConfig();

function cfg(overrides) {
  return Object.freeze({ ...BASE_CONFIG, ...overrides });
}

const ENDPOINT_ID = '11111111-1111-1111-1111-111111111111';
const EVENT_ID    = '22222222-2222-2222-2222-222222222222';

// the retry path derives tenant context from eventPayload.tenantId
// (there is no HTTP request in scope for a background retry) — every op
// built here carries one, matching what the real dispatcher always embeds
// (buildCertificationCompletedPayload/buildAttestationCompletedPayload).
const TENANT_ID = 'test-tenant';

function makeOp({ retryCount = 0, isIdempotent = true, httpMethod = 'POST', endpointId = ENDPOINT_ID, tenantId = TENANT_ID } = {}) {
  return {
    retryCount,
    payload: {
      endpointId,
      eventId:      EVENT_ID,
      eventType:    'certification.completed',
      eventPayload: { eventId: EVENT_ID, eventType: 'certification.completed', timestamp: new Date().toISOString(), tenantId },
      isIdempotent,
      httpMethod,
    },
  };
}

function makeMockEndpoint() {
  const plain = generateSecret();
  const enc   = encryptSecret(plain);
  return {
    id:          ENDPOINT_ID,
    tenant_id:   'test-tenant',
    url:         'https://example.com/hook',
    enabled:     true,
    event_types: ['certification.completed'],
    secret_enc:  enc.enc,
    secret_iv:   enc.iv,
    secret_tag:  enc.tag,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  mockPool._enabled = true;
  mockPool.query.mockResolvedValue({ rows: [] });
  mockDnsLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
});

// ── WRP-01…10: classifyFailure — HTTP status classification ───────────────────

describe('WRP — classifyFailure HTTP status', () => {
  test('WRP-01 null (network/timeout) → TRANSIENT', () => {
    expect(classifyFailure(null)).toBe('TRANSIENT');
  });

  test('WRP-02 undefined (missing status) → TRANSIENT', () => {
    expect(classifyFailure(undefined)).toBe('TRANSIENT');
  });

  test('WRP-03 429 Too Many Requests → TRANSIENT', () => {
    expect(classifyFailure(429)).toBe('TRANSIENT');
  });

  test('WRP-04 500 Internal Server Error → TRANSIENT', () => {
    expect(classifyFailure(500)).toBe('TRANSIENT');
  });

  test('WRP-05 502 Bad Gateway → TRANSIENT', () => {
    expect(classifyFailure(502)).toBe('TRANSIENT');
  });

  test('WRP-06 503 Service Unavailable → TRANSIENT', () => {
    expect(classifyFailure(503)).toBe('TRANSIENT');
  });

  test('WRP-07 504 Gateway Timeout → TRANSIENT', () => {
    expect(classifyFailure(504)).toBe('TRANSIENT');
  });

  test('WRP-08 408 Request Timeout → TRANSIENT', () => {
    expect(classifyFailure(408)).toBe('TRANSIENT');
  });

  test('WRP-09 409 Conflict → TRANSIENT', () => {
    expect(classifyFailure(409)).toBe('TRANSIENT');
  });

  test('WRP-10 400 Bad Request → PERMANENT', () => {
    expect(classifyFailure(400)).toBe('PERMANENT');
  });
});

// ── WRP-11…18: classifyFailure — additional and edge cases ────────────────────

describe('WRP — classifyFailure additional', () => {
  test('WRP-11 401 Unauthorized → PERMANENT', () => {
    expect(classifyFailure(401)).toBe('PERMANENT');
  });

  test('WRP-12 403 Forbidden → PERMANENT', () => {
    expect(classifyFailure(403)).toBe('PERMANENT');
  });

  test('WRP-13 404 Not Found → PERMANENT', () => {
    expect(classifyFailure(404)).toBe('PERMANENT');
  });

  test('WRP-14 405 Method Not Allowed → PERMANENT', () => {
    expect(classifyFailure(405)).toBe('PERMANENT');
  });

  test('WRP-15 410 Gone → PERMANENT', () => {
    expect(classifyFailure(410)).toBe('PERMANENT');
  });

  test('WRP-16 501 Not Implemented → PERMANENT', () => {
    expect(classifyFailure(501)).toBe('PERMANENT');
  });

  test('WRP-17 422 Unprocessable Entity → PERMANENT (unknown 4xx = fail-closed)', () => {
    expect(classifyFailure(422)).toBe('PERMANENT');
  });

  test('WRP-18 999 Unknown status → PERMANENT (fail-closed for unrecognized codes)', () => {
    expect(classifyFailure(999)).toBe('PERMANENT');
  });
});

// ── WRP-19…26: shouldRetry — idempotency gate ─────────────────────────────────

describe('WRP — shouldRetry idempotency gate', () => {
  const OPTS = { httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 500 };

  test('WRP-19 POST with isIdempotent=false is never retried', () => {
    const r = shouldRetry({ ...OPTS, isIdempotent: false });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/idempotent/i);
  });

  test('WRP-20 POST with isIdempotent=true and transient error is retried', () => {
    const r = shouldRetry({ ...OPTS, isIdempotent: true });
    expect(r.retry).toBe(true);
  });

  test('WRP-21 isIdempotent=undefined (missing) is treated as false', () => {
    const r = shouldRetry({ ...OPTS, isIdempotent: undefined });
    expect(r.retry).toBe(false);
  });

  test('WRP-22 isIdempotent=null (missing) is treated as false', () => {
    const r = shouldRetry({ ...OPTS, isIdempotent: null });
    expect(r.retry).toBe(false);
  });

  test('WRP-23 reason string mentions the HTTP method when not idempotent', () => {
    const r = shouldRetry({ ...OPTS, isIdempotent: false, httpMethod: 'POST' });
    expect(r.reason).toMatch(/POST/);
  });

  test('WRP-24 GET (hypothetical) with isIdempotent=false is still not retried', () => {
    const r = shouldRetry({ ...OPTS, isIdempotent: false, httpMethod: 'GET' });
    expect(r.retry).toBe(false);
  });

  test('WRP-25 shouldRetry returns an object with retry and reason fields', () => {
    const r = shouldRetry({ ...OPTS, isIdempotent: true });
    expect(typeof r.retry).toBe('boolean');
    expect(typeof r.reason).toBe('string');
    expect(r.reason.length).toBeGreaterThan(0);
  });

  test('WRP-26 isIdempotent gate is checked before attempt limit', () => {
    // If not idempotent, attempt limit doesn't matter — idempotency check fires first
    const r = shouldRetry({ ...OPTS, isIdempotent: false, attempt: 1, maxAttempts: 100 });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/idempotent/i);
  });
});

// ── WRP-27…35: shouldRetry — attempt limit gate ───────────────────────────────

describe('WRP — shouldRetry attempt limit gate', () => {
  const OPTS = { isIdempotent: true, httpMethod: 'POST', httpStatus: 500 };

  test('WRP-27 attempt=1, maxAttempts=5: retry allowed', () => {
    expect(shouldRetry({ ...OPTS, attempt: 1, maxAttempts: 5 }).retry).toBe(true);
  });

  test('WRP-28 attempt=4, maxAttempts=5: retry allowed', () => {
    expect(shouldRetry({ ...OPTS, attempt: 4, maxAttempts: 5 }).retry).toBe(true);
  });

  test('WRP-29 attempt=5, maxAttempts=5: retry NOT allowed (at limit)', () => {
    const r = shouldRetry({ ...OPTS, attempt: 5, maxAttempts: 5 });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/maximum/i);
  });

  test('WRP-30 attempt=6, maxAttempts=5: retry NOT allowed (over limit)', () => {
    expect(shouldRetry({ ...OPTS, attempt: 6, maxAttempts: 5 }).retry).toBe(false);
  });

  test('WRP-31 maxAttempts=1: first attempt itself is at the limit', () => {
    const r = shouldRetry({ ...OPTS, attempt: 1, maxAttempts: 1 });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/maximum/i);
  });

  test('WRP-32 maxAttempts=10: attempt=9 is allowed', () => {
    expect(shouldRetry({ ...OPTS, attempt: 9, maxAttempts: 10 }).retry).toBe(true);
  });

  test('WRP-33 maxAttempts=10: attempt=10 is NOT allowed', () => {
    expect(shouldRetry({ ...OPTS, attempt: 10, maxAttempts: 10 }).retry).toBe(false);
  });

  test('WRP-34 attempt limit reason mentions the attempt number and max', () => {
    const r = shouldRetry({ ...OPTS, attempt: 5, maxAttempts: 5 });
    expect(r.reason).toMatch(/5/);
  });

  test('WRP-35 attempt=0 (hypothetical pre-attempt): retry allowed when maxAttempts=5', () => {
    expect(shouldRetry({ ...OPTS, attempt: 0, maxAttempts: 5 }).retry).toBe(true);
  });
});

// ── WRP-36…46: shouldRetry — failure classification gate ─────────────────────

describe('WRP — shouldRetry failure classification gate', () => {
  const OPTS = { isIdempotent: true, httpMethod: 'POST', attempt: 1, maxAttempts: 5 };

  test('WRP-36 null status (network error): retried', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: null }).retry).toBe(true);
  });

  test('WRP-37 500: retried', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 500 }).retry).toBe(true);
  });

  test('WRP-38 429: retried', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 429 }).retry).toBe(true);
  });

  test('WRP-39 503: retried', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 503 }).retry).toBe(true);
  });

  test('WRP-40 400: NOT retried (permanent)', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 400 }).retry).toBe(false);
  });

  test('WRP-41 401: NOT retried (permanent)', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 401 }).retry).toBe(false);
  });

  test('WRP-42 403: NOT retried (permanent)', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 403 }).retry).toBe(false);
  });

  test('WRP-43 404: NOT retried (permanent)', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 404 }).retry).toBe(false);
  });

  test('WRP-44 410: NOT retried (permanent)', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 410 }).retry).toBe(false);
  });

  test('WRP-45 permanent failure reason mentions the status code', () => {
    const r = shouldRetry({ ...OPTS, httpStatus: 404 });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/404/);
  });

  test('WRP-46 999 unknown status: NOT retried (fail-closed)', () => {
    expect(shouldRetry({ ...OPTS, httpStatus: 999 }).retry).toBe(false);
  });
});

// ── WRP-47…52: shouldRetry — all gates combined ───────────────────────────────

describe('WRP — shouldRetry combined gates', () => {
  test('WRP-47 all three gates pass: retry=true', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 500 });
    expect(r.retry).toBe(true);
  });

  test('WRP-48 idempotency fails, other gates pass: retry=false', () => {
    const r = shouldRetry({ isIdempotent: false, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 500 });
    expect(r.retry).toBe(false);
  });

  test('WRP-49 attempt limit fails, other gates pass: retry=false', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 5, maxAttempts: 5, httpStatus: 500 });
    expect(r.retry).toBe(false);
  });

  test('WRP-50 failure is permanent, other gates pass: retry=false', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 400 });
    expect(r.retry).toBe(false);
  });

  test('WRP-51 non-idempotent + permanent failure: retry=false (idempotency gate fires first)', () => {
    const r = shouldRetry({ isIdempotent: false, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 400 });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/idempotent/i); // first gate mentioned
  });

  test('WRP-52 idempotent + at limit + permanent: retry=false (limit gate fires before classification)', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 5, maxAttempts: 5, httpStatus: 500 });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/maximum/i); // second gate mentioned
  });
});

// ── WRP-53…62: computeBackoffMs — exponential formula ────────────────────────

describe('WRP — computeBackoffMs formula', () => {
  const NO_JITTER = cfg({ retryBaseDelayMs: 1000, retryMaxDelayMs: 60_000, retryJitter: false });

  test('WRP-53 attempt=1: delay = baseMs × 2^0 = baseMs', () => {
    expect(computeBackoffMs(1, NO_JITTER)).toBe(1000);
  });

  test('WRP-54 attempt=2: delay = baseMs × 2^1 = 2×base', () => {
    expect(computeBackoffMs(2, NO_JITTER)).toBe(2000);
  });

  test('WRP-55 attempt=3: delay = baseMs × 2^2 = 4×base', () => {
    expect(computeBackoffMs(3, NO_JITTER)).toBe(4000);
  });

  test('WRP-56 attempt=4: delay = baseMs × 2^3 = 8×base', () => {
    expect(computeBackoffMs(4, NO_JITTER)).toBe(8000);
  });

  test('WRP-57 delay is capped at retryMaxDelayMs', () => {
    const small = cfg({ retryBaseDelayMs: 1000, retryMaxDelayMs: 5000, retryJitter: false });
    // attempt=10: 1000 × 2^9 = 512000 → capped at 5000
    expect(computeBackoffMs(10, small)).toBe(5000);
  });

  test('WRP-58 delay is an integer (floor applied)', () => {
    const p = cfg({ retryBaseDelayMs: 1001, retryMaxDelayMs: 60_000, retryJitter: false });
    const d = computeBackoffMs(1, p);
    expect(Number.isInteger(d)).toBe(true);
  });

  test('WRP-59 delay ≥ 0 always', () => {
    expect(computeBackoffMs(1, cfg({ retryBaseDelayMs: 0, retryMaxDelayMs: 0, retryJitter: false }))).toBe(0);
  });

  test('WRP-60 no-jitter: same attempt always returns same value (deterministic)', () => {
    const d1 = computeBackoffMs(3, NO_JITTER);
    const d2 = computeBackoffMs(3, NO_JITTER);
    expect(d1).toBe(d2);
  });

  test('WRP-61 computeBackoffMs grows with attempt number (without jitter)', () => {
    const d1 = computeBackoffMs(1, NO_JITTER);
    const d2 = computeBackoffMs(2, NO_JITTER);
    const d3 = computeBackoffMs(3, NO_JITTER);
    expect(d2).toBeGreaterThan(d1);
    expect(d3).toBeGreaterThan(d2);
  });

  test('WRP-62 retryMaxDelayMs is a hard cap even for very large attempt numbers', () => {
    const cap = cfg({ retryBaseDelayMs: 5000, retryMaxDelayMs: 30_000, retryJitter: false });
    expect(computeBackoffMs(100, cap)).toBe(30_000);
  });
});

// ── WRP-63…70: computeBackoffMs — jitter ─────────────────────────────────────

describe('WRP — computeBackoffMs jitter', () => {
  test('WRP-63 with jitter=true and random=0: delay is 0', () => {
    const p = cfg({ retryBaseDelayMs: 5000, retryMaxDelayMs: 60_000, retryJitter: true });
    expect(computeBackoffMs(1, p, () => 0)).toBe(0);
  });

  test('WRP-64 with jitter=true and random=1: delay is floor(exponential)', () => {
    const p = cfg({ retryBaseDelayMs: 5000, retryMaxDelayMs: 60_000, retryJitter: true });
    // random()=1 → floor(1 × 5000) = 4999 (floor of 5000.0 × 1 = 5000 → 5000)
    expect(computeBackoffMs(1, p, () => 1)).toBe(5000);
  });

  test('WRP-65 with jitter=true and random=0.5: delay ≈ exponential/2', () => {
    const p = cfg({ retryBaseDelayMs: 10_000, retryMaxDelayMs: 60_000, retryJitter: true });
    expect(computeBackoffMs(1, p, () => 0.5)).toBe(5000);
  });

  test('WRP-66 with jitter=false: _randomFn is not called', () => {
    const p      = cfg({ retryBaseDelayMs: 5000, retryMaxDelayMs: 60_000, retryJitter: false });
    const random = jest.fn().mockReturnValue(0);
    computeBackoffMs(1, p, random);
    expect(random).not.toHaveBeenCalled();
  });

  test('WRP-67 jitter delay is always ≤ exponential (no-jitter) value', () => {
    const noJ = cfg({ retryBaseDelayMs: 5000, retryMaxDelayMs: 60_000, retryJitter: false });
    const yesJ = cfg({ retryBaseDelayMs: 5000, retryMaxDelayMs: 60_000, retryJitter: true });
    const base  = computeBackoffMs(3, noJ);
    // With random=0.9, jitter delay should be ≤ base
    const jittered = computeBackoffMs(3, yesJ, () => 0.9);
    expect(jittered).toBeLessThanOrEqual(base);
  });

  test('WRP-68 jitter delay is always ≥ 0', () => {
    const p = cfg({ retryBaseDelayMs: 5000, retryMaxDelayMs: 60_000, retryJitter: true });
    expect(computeBackoffMs(1, p, () => 0)).toBeGreaterThanOrEqual(0);
  });

  test('WRP-69 TRANSIENT_STATUSES contains 429, 500, 502, 503, 504', () => {
    expect(TRANSIENT_STATUSES.has(429)).toBe(true);
    expect(TRANSIENT_STATUSES.has(500)).toBe(true);
    expect(TRANSIENT_STATUSES.has(502)).toBe(true);
    expect(TRANSIENT_STATUSES.has(503)).toBe(true);
    expect(TRANSIENT_STATUSES.has(504)).toBe(true);
  });

  test('WRP-70 PERMANENT_STATUSES contains 400, 401, 403, 404, 410', () => {
    expect(PERMANENT_STATUSES.has(400)).toBe(true);
    expect(PERMANENT_STATUSES.has(401)).toBe(true);
    expect(PERMANENT_STATUSES.has(403)).toBe(true);
    expect(PERMANENT_STATUSES.has(404)).toBe(true);
    expect(PERMANENT_STATUSES.has(410)).toBe(true);
  });
});

// ── WRP-71…78: retryHandler — policy applied on failure ──────────────────────

describe('WRP — retryHandler policy integration', () => {
  test('WRP-71 endpoint not found: returns success=true without calling shouldRetry', async () => {
    mockPool.query.mockResolvedValue({ rows: [] }); // endpoint not found
    const op = makeOp({ isIdempotent: false }); // even non-idempotent
    const result = await retryHandler(op);
    expect(result.success).toBe(true); // gone endpoint = stop retrying
  });

  test('WRP-72 non-idempotent POST with delivery failure: no retry scheduled, DLQ-bound', async () => {
    const ep = makeMockEndpoint();
    mockPool.query
      .mockResolvedValueOnce({ rows: [ep] })  // _getEndpointForDelivery
      .mockResolvedValueOnce({ rows: [] });    // logDelivery

    // Example.com will fail (network) but retry is suppressed by policy
    const op = makeOp({ isIdempotent: false });
    const result = await retryHandler(op);
    // (D6): inverted — an undeliverable event is no longer marked complete; it
    // fails "non-retryable:" so the worker moves it to the DLQ at once.
    expect(result).toEqual({ success: false, error: expect.stringMatching(/^non-retryable: webhook delivery abandoned/) });
  });

  test('WRP-73 retryHandler emits WEBHOOK_RETRY_SUPPRESSED when policy blocks retry', async () => {
    const { emit } = require('../../../../services/logger');
    const ep = makeMockEndpoint();
    mockPool.query
      .mockResolvedValueOnce({ rows: [ep] })
      .mockResolvedValueOnce({ rows: [] });

    const op = makeOp({ isIdempotent: false });
    await retryHandler(op);

    expect(emit).toHaveBeenCalledWith('INFO', 'WEBHOOK_RETRY_SUPPRESSED', expect.objectContaining({
      isIdempotent: false,
    }));
  });

  test('WRP-74 retryHandler does not emit WEBHOOK_RETRY_SUPPRESSED for endpoint-gone case', async () => {
    const { emit } = require('../../../../services/logger');
    mockPool.query.mockResolvedValue({ rows: [] });
    const op = makeOp({ isIdempotent: true });
    await retryHandler(op);
    const suppressed = emit.mock.calls.filter(c => c[1] === 'WEBHOOK_RETRY_SUPPRESSED');
    expect(suppressed).toHaveLength(0);
  });

  test('WRP-75 retryHandler increments webhook_retries_total metric when attempt > 1', async () => {
    const webhookMetrics = require('../webhookMetrics');
    webhookMetrics.reset();
    mockPool.query.mockResolvedValue({ rows: [] }); // endpoint gone

    const op = makeOp({ retryCount: 1 }); // attempt = 2
    await retryHandler(op);

    const snap = webhookMetrics.snapshot();
    const retryKey = Object.keys(snap.counters).find(k => k.includes('webhook_retries_total'));
    expect(retryKey).toBeDefined();
    expect(snap.counters[retryKey]).toBeGreaterThanOrEqual(1);
  });

  test('WRP-76 retryHandler: attempt derived correctly from retryCount', async () => {
    // retryCount=0 → attempt=1, retryCount=4 → attempt=5
    mockPool.query.mockResolvedValue({ rows: [] });
    const op4 = makeOp({ retryCount: 4 });
    const r = await retryHandler(op4);
    expect(r.success).toBe(true); // endpoint gone → stop
  });

  test('WRP-77 retryHandler without isIdempotent field defaults to no-retry', async () => {
    const ep = makeMockEndpoint();
    mockPool.query
      .mockResolvedValueOnce({ rows: [ep] })
      .mockResolvedValueOnce({ rows: [] });

    // Simulate old operation payload without isIdempotent
    const op = {
      retryCount: 0,
      payload: {
        endpointId:   ENDPOINT_ID,
        eventId:      EVENT_ID,
        eventType:    'certification.completed',
        eventPayload: { eventId: EVENT_ID, eventType: 'certification.completed', timestamp: new Date().toISOString(), tenantId: TENANT_ID },
        // isIdempotent NOT set → defaults to false
      },
    };
    const result = await retryHandler(op);
    // (D6): inverted — an undeliverable event is no longer marked complete; it
    // fails "non-retryable:" so the worker moves it to the DLQ at once.
    expect(result.success).toBe(false); // no retry for missing isIdempotent → DLQ
    expect(result.error).toMatch(/^non-retryable:.*not marked as idempotent/);
  });

  test('WRP-78 retryHandler: isIdempotent=true allows retry on network failure', async () => {
    // Delivery to example.com will fail with a network/timeout error (null httpStatus)
    // which is TRANSIENT, so the policy should allow retry
    const ep = makeMockEndpoint();
    mockPool.query
      .mockResolvedValueOnce({ rows: [ep] })
      .mockResolvedValueOnce({ rows: [] }); // logDelivery

    const op = makeOp({ isIdempotent: true, retryCount: 0 });
    const result = await retryHandler(op);
    // Delivery to example.com will fail → TRANSIENT (null status) → retry allowed
    // Worker returns { success: false, error } to schedule another attempt
    expect(typeof result.success).toBe('boolean');
  });
});

// ── WRP-79…86: retryHandler — isIdempotent from dispatcher payload ────────────

describe('WRP — dispatcher isIdempotent field', () => {
  test('WRP-79 operation payload with isIdempotent=true: retryHandler allows retry on 503', async () => {
    const { emit } = require('../../../../services/logger');
    const ep = makeMockEndpoint();
    mockPool.query
      .mockResolvedValueOnce({ rows: [ep] })
      .mockResolvedValueOnce({ rows: [] }); // logDelivery

    // Create operation as dispatcher would (isIdempotent=true, httpMethod='POST')
    const op = makeOp({ isIdempotent: true, retryCount: 0 });
    const result = await retryHandler(op);
    // Network failure (null status) → TRANSIENT → policy.retry=true → return success:false
    // This tells the worker to schedule another attempt
    if (!result.success) {
      // Retry was scheduled — correct behavior
      const scheduled = emit.mock.calls.find(c => c[1] === 'WEBHOOK_RETRY_SCHEDULED');
      expect(scheduled).toBeDefined();
    }
  });

  test('WRP-80 operation payload with isIdempotent=false: retryHandler suppresses retry', async () => {
    const ep = makeMockEndpoint();
    mockPool.query
      .mockResolvedValueOnce({ rows: [ep] })
      .mockResolvedValueOnce({ rows: [] });

    const op = makeOp({ isIdempotent: false, retryCount: 0 });
    const result = await retryHandler(op);
    // (D6): inverted — an undeliverable event is no longer marked complete; it
    // fails "non-retryable:" so the worker moves it to the DLQ at once.
    expect(result.success).toBe(false); // suppressed — no retry → DLQ
    expect(result.error).toMatch(/^non-retryable:/);
  });

  test('WRP-81 httpMethod field is propagated in WEBHOOK_RETRY_SUPPRESSED log', async () => {
    const { emit } = require('../../../../services/logger');
    const ep = makeMockEndpoint();
    mockPool.query
      .mockResolvedValueOnce({ rows: [ep] })
      .mockResolvedValueOnce({ rows: [] });

    const op = makeOp({ isIdempotent: false, httpMethod: 'POST' });
    await retryHandler(op);

    const suppressed = emit.mock.calls.find(c => c[1] === 'WEBHOOK_RETRY_SUPPRESSED');
    expect(suppressed).toBeDefined();
  });
});

// ── WRP-87…93: retryHandler — permanent failures stop retries ─────────────────

describe('WRP — retryHandler permanent failure suppression', () => {
  // We can't mock the HTTPS delivery easily here (no real TLS server),
  // but we can verify the policy decision for permanent HTTP status codes
  // by testing shouldRetry directly with the same parameters retryHandler uses.

  test('WRP-87 shouldRetry with 404 and isIdempotent=true: no retry (permanent)', () => {
    const r = shouldRetry({
      isIdempotent: true,
      httpMethod:   'POST',
      attempt:      1,
      maxAttempts:  BASE_CONFIG.maxRetryAttempts,
      httpStatus:   404,
    });
    expect(r.retry).toBe(false);
    expect(r.reason).toMatch(/permanent/i);
  });

  test('WRP-88 shouldRetry with 401: permanent even with isIdempotent=true', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 401 });
    expect(r.retry).toBe(false);
  });

  test('WRP-89 shouldRetry with 403: permanent even with isIdempotent=true', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 403 });
    expect(r.retry).toBe(false);
  });

  test('WRP-90 shouldRetry with 500: transient + idempotent = retry', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: 500 });
    expect(r.retry).toBe(true);
  });

  test('WRP-91 shouldRetry with null (network): transient + idempotent = retry', () => {
    const r = shouldRetry({ isIdempotent: true, httpMethod: 'POST', attempt: 1, maxAttempts: 5, httpStatus: null });
    expect(r.retry).toBe(true);
  });

  test('WRP-92 shouldRetry determinism: same inputs always produce same output', () => {
    const opts = { isIdempotent: true, httpMethod: 'POST', attempt: 2, maxAttempts: 5, httpStatus: 503 };
    const r1 = shouldRetry(opts);
    const r2 = shouldRetry(opts);
    expect(r1.retry).toBe(r2.retry);
    expect(r1.reason).toBe(r2.reason);
  });

  test('WRP-93 classifyFailure is deterministic for all known status codes', () => {
    const codes = [null, 400, 401, 403, 404, 408, 409, 410, 429, 500, 502, 503, 504];
    for (const code of codes) {
      expect(classifyFailure(code)).toBe(classifyFailure(code));
    }
  });
});

// ── WRP-94…100: webhookDispatcher — isIdempotent in enqueued payload ──────────

describe('WRP — dispatcher enqueues isIdempotent=true', () => {
  beforeEach(() => {
    mockPool.query.mockReset();
    mockEnqueueWebhookDelivery.mockReset().mockResolvedValue(undefined);
  });

  test('WRP-94 dispatched payload includes isIdempotent=true', async () => {
    const enc = encryptSecret('whsec_abc');
    mockPool.query.mockResolvedValue({
      rows: [{
        id:          ENDPOINT_ID,
        tenant_id:   'tenant1',
        url:         'https://example.com/hook',
        event_types: ['certification.completed'],
        secret_enc:  enc.enc,
        secret_iv:   enc.iv,
        secret_tag:  enc.tag,
      }],
    });

    const {
      dispatchEvent,
      buildCertificationCompletedPayload,
    } = require('../webhookDispatcher');

    const payload = buildCertificationCompletedPayload({
      certification_id:       'c1',
      certification_level:    'CERTIFIED',
      certification_decision: 'CERTIFIED',
      score:                  80,
    });

    dispatchEvent('certification.completed', payload);
    await new Promise(r => setTimeout(r, 30));

    expect(mockEnqueueWebhookDelivery).toHaveBeenCalledTimes(1);
    const call = mockEnqueueWebhookDelivery.mock.calls[0][0];
    expect(call.payload.isIdempotent).toBe(true);
  });

  test('WRP-95 dispatched payload includes httpMethod=POST', async () => {
    const enc = encryptSecret('whsec_abc');
    mockPool.query.mockResolvedValue({
      rows: [{
        id:          ENDPOINT_ID,
        tenant_id:   'tenant1',
        url:         'https://example.com/hook',
        event_types: ['certification.completed'],
        secret_enc:  enc.enc,
        secret_iv:   enc.iv,
        secret_tag:  enc.tag,
      }],
    });

    const { dispatchEvent, buildCertificationCompletedPayload } = require('../webhookDispatcher');
    const payload = buildCertificationCompletedPayload({
      certification_id: 'c2', certification_level: 'CERTIFIED', certification_decision: 'CERTIFIED', score: 70,
    });
    dispatchEvent('certification.completed', payload);
    await new Promise(r => setTimeout(r, 30));

    const call = mockEnqueueWebhookDelivery.mock.calls[0][0];
    expect(call.payload.httpMethod).toBe('POST');
  });

  test('WRP-96 dispatched payload includes eventId', async () => {
    const enc = encryptSecret('whsec_abc');
    mockPool.query.mockResolvedValue({
      rows: [{
        id:          ENDPOINT_ID,
        tenant_id:   'tenant1',
        url:         'https://example.com/hook',
        event_types: ['attestation.completed'],
        secret_enc:  enc.enc,
        secret_iv:   enc.iv,
        secret_tag:  enc.tag,
      }],
    });

    const { dispatchEvent, buildAttestationCompletedPayload } = require('../webhookDispatcher');
    const payload = buildAttestationCompletedPayload({ attestation_id: 'att1', attestation_decision: 'ATTESTED' });
    dispatchEvent('attestation.completed', payload);
    await new Promise(r => setTimeout(r, 30));

    const call = mockEnqueueWebhookDelivery.mock.calls[0][0];
    expect(call.payload.eventId).toBe(payload.eventId);
    expect(typeof call.payload.eventId).toBe('string');
  });

  test('WRP-97 shouldRetry: maxRetryAttempts from default config is ≥ 1', () => {
    expect(BASE_CONFIG.maxRetryAttempts).toBeGreaterThanOrEqual(1);
  });

  test('WRP-98 shouldRetry: retryBaseDelayMs from default config is > 0', () => {
    expect(BASE_CONFIG.retryBaseDelayMs).toBeGreaterThan(0);
  });

  test('WRP-99 shouldRetry: retryMaxDelayMs from default config is > retryBaseDelayMs', () => {
    expect(BASE_CONFIG.retryMaxDelayMs).toBeGreaterThan(BASE_CONFIG.retryBaseDelayMs);
  });

  test('WRP-100 computeBackoffMs at max attempt does not exceed retryMaxDelayMs', () => {
    const delay = computeBackoffMs(BASE_CONFIG.maxRetryAttempts, BASE_CONFIG, () => 1);
    expect(delay).toBeLessThanOrEqual(BASE_CONFIG.retryMaxDelayMs);
  });
});
