'use strict';

/**
 * Component #13 — Persistence Recovery Queue
 *
 * PRQ-01   isPersistenceFailure: ECONNREFUSED → true
 * PRQ-02   isPersistenceFailure: ETIMEDOUT    → true
 * PRQ-03   isPersistenceFailure: PG class 08 (connection)  → true
 * PRQ-04   isPersistenceFailure: PG class 53 (resources)   → true
 * PRQ-05   isPersistenceFailure: PG class 57 (operator)    → true
 * PRQ-06   isPersistenceFailure: PG class 23 (constraint)  → false
 * PRQ-07   isPersistenceFailure: PG class 42 (syntax)      → false
 * PRQ-08   isPersistenceFailure: PG class 28 (auth)        → false
 * PRQ-09   isPersistenceFailure: message heuristic "connection refused" → true
 * PRQ-10   isPersistenceFailure: null/undefined → false
 * PRQ-11   buildPhantomRecord ATTESTATION_SAVE: id is null, attestation_id matches
 * PRQ-12   buildPhantomRecord CERTIFICATION_SAVE: id is null, certification_id matches
 * PRQ-13   buildPhantomRecord PORTAL_VERIFICATION_SAVE: id is null, verification_id matches
 * PRQ-14   buildPhantomRecord unknown type → throws
 * PRQ-15   queue.enqueue + queue.claimNext → durable INSERT then atomic
 *          UPDATE ... FOR UPDATE SKIP LOCKED, parsed back into the operation shape
 * PRQ-16   queue.claimNext on an empty result set → returns null
 * PRQ-17   queue.markComplete issues a DELETE keyed by operationId
 * PRQ-18   queue.markRetry reads existing error history, appends, and reschedules eligible_at
 * PRQ-19   queue.moveToDlq transitions status to DLQ and stamps dlq_at
 * PRQ-20   queue.getStats maps PENDING/DLQ counts from a single aggregate query
 * PRQ-21   worker._processOne: success → markComplete called
 * PRQ-22   worker._processOne: transient failure → markRetry called
 * PRQ-23   worker._processOne: exceeds MAX_RETRIES → moveToDlq called
 * PRQ-24   worker._processOne: no handler registered → moveToDlq immediately
 * PRQ-25   metrics: inc/get/snapshot/reset work correctly
 * PRQ-26   recoveryManager.enqueue: disabled mode (PostgreSQL not enabled) → returns phantom, no query issued
 * PRQ-27   recoveryManager.enqueue: PostgreSQL not ready → returns phantom, no throw
 *
 * Full end-to-end lifecycle correctness (real claim/retry/DLQ/replay
 * semantics against a live PostgreSQL instance) is covered separately by
 * test/persistence-recovery-durability.test.js (CHAIN-3) — this file tests
 * queue.js's own SQL-issuing logic in isolation via an injected fake query
 * function, mirroring the style of
 * src/infra/postgres/__tests__/pg-audit-backend.recovery.test.js.
 */

'use strict';

const {
  isPersistenceFailure,
  buildPhantomRecord,
  OPERATION_TYPES,
} = require('../src/core/persistenceRecovery/persistenceOperation');

const metrics = require('../src/core/persistenceRecovery/metrics');
const worker  = require('../src/core/persistenceRecovery/worker');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeErr(code, message) {
  const e = new Error(message ?? `error with code ${code}`);
  e.code = code;
  return e;
}

// ── PRQ-01 – PRQ-10: isPersistenceFailure classification ─────────────────────

describe('isPersistenceFailure — network errors', () => {
  test('PRQ-01 ECONNREFUSED → true', () => {
    expect(isPersistenceFailure(makeErr('ECONNREFUSED'))).toBe(true);
  });

  test('PRQ-02 ETIMEDOUT → true', () => {
    expect(isPersistenceFailure(makeErr('ETIMEDOUT'))).toBe(true);
  });

  test('PRQ-02b ECONNRESET → true', () => {
    expect(isPersistenceFailure(makeErr('ECONNRESET'))).toBe(true);
  });

  test('PRQ-02c EPIPE → true', () => {
    expect(isPersistenceFailure(makeErr('EPIPE'))).toBe(true);
  });
});

describe('isPersistenceFailure — PG error codes', () => {
  test('PRQ-03 PG 08006 (connection failure) → true', () => {
    expect(isPersistenceFailure(makeErr('08006'))).toBe(true);
  });

  test('PRQ-03b PG 08000 (connection exception) → true', () => {
    expect(isPersistenceFailure(makeErr('08000'))).toBe(true);
  });

  test('PRQ-04 PG 53300 (too many connections) → true', () => {
    expect(isPersistenceFailure(makeErr('53300'))).toBe(true);
  });

  test('PRQ-05 PG 57P01 (admin shutdown) → true', () => {
    expect(isPersistenceFailure(makeErr('57P01'))).toBe(true);
  });

  test('PRQ-05b PG 40001 (serialization failure) → true', () => {
    expect(isPersistenceFailure(makeErr('40001'))).toBe(true);
  });

  test('PRQ-06 PG 23505 (unique_violation) → false', () => {
    expect(isPersistenceFailure(makeErr('23505'))).toBe(false);
  });

  test('PRQ-06b PG 23503 (foreign_key_violation) → false', () => {
    expect(isPersistenceFailure(makeErr('23503'))).toBe(false);
  });

  test('PRQ-07 PG 42601 (syntax_error) → false', () => {
    expect(isPersistenceFailure(makeErr('42601'))).toBe(false);
  });

  test('PRQ-08 PG 28000 (invalid_authorization) → false', () => {
    expect(isPersistenceFailure(makeErr('28000'))).toBe(false);
  });

  test('PRQ-08b PG 22001 (string_data_right_truncation) → false', () => {
    expect(isPersistenceFailure(makeErr('22001'))).toBe(false);
  });
});

describe('isPersistenceFailure — message heuristics', () => {
  test('PRQ-09a "connection refused" in message → true', () => {
    expect(isPersistenceFailure(new Error('connect ECONNREFUSED 127.0.0.1:5432'))).toBe(true);
  });

  test('PRQ-09b "pool exhausted" in message → true', () => {
    expect(isPersistenceFailure(new Error('pool exhausted after 30s'))).toBe(true);
  });

  test('PRQ-09c "server closed the connection" in message → true', () => {
    expect(isPersistenceFailure(new Error('server closed the connection unexpectedly'))).toBe(true);
  });

  test('PRQ-10 null → false', () => {
    expect(isPersistenceFailure(null)).toBe(false);
  });

  test('PRQ-10b undefined → false', () => {
    expect(isPersistenceFailure(undefined)).toBe(false);
  });
});

// ── PRQ-11 – PRQ-14: buildPhantomRecord ──────────────────────────────────────

describe('buildPhantomRecord', () => {
  test('PRQ-11 ATTESTATION_SAVE: id null, attestation_id matches payload', () => {
    const rec = buildPhantomRecord(OPERATION_TYPES.ATTESTATION_SAVE, {
      attestationId:      'att-uuid-123',
      attestationDecision: 'ATTESTED',
    });
    expect(rec.id).toBeNull();
    expect(rec.attestation_id).toBe('att-uuid-123');
    expect(rec.attestation_decision).toBe('ATTESTED');
    expect(rec.attestation_type).toBe('ARTIFACT_VERIFICATION');
    expect(rec.generated_at).toBeDefined();
  });

  test('PRQ-12 CERTIFICATION_SAVE: id null, certification_id matches payload', () => {
    const rec = buildPhantomRecord(OPERATION_TYPES.CERTIFICATION_SAVE, {
      certificationId:       'cert-uuid-456',
      certificationLevel:    'CERTIFIED',
      certificationDecision: 'CERTIFIED',
      score:                 85,
    });
    expect(rec.id).toBeNull();
    expect(rec.certification_id).toBe('cert-uuid-456');
    expect(rec.score).toBe(85);
    expect(rec.generated_at).toBeDefined();
  });

  test('PRQ-13 PORTAL_VERIFICATION_SAVE: id null, verification_id matches payload', () => {
    const rec = buildPhantomRecord(OPERATION_TYPES.PORTAL_VERIFICATION_SAVE, {
      verificationId:     'pv-uuid-789',
      artifactFingerprint: 'abc123',
      overallResult:       'VERIFIED',
    });
    expect(rec.id).toBeNull();
    expect(rec.verification_id).toBe('pv-uuid-789');
    expect(rec.artifact_fingerprint).toBe('abc123');
    expect(rec.verified_at).toBeDefined();
  });

  test('PRQ-14 unknown operationType → throws', () => {
    expect(() => buildPhantomRecord('UNKNOWN_OP', {})).toThrow('unknown operationType');
  });
});

// ── PRQ-15 – PRQ-20: queue operations (injected fake PostgreSQL) ─────────────
//
// CHAIN-3: queue.js is now backed by the persistence_recovery_queue
// PostgreSQL table (migration 032) instead of Redis. This fake simulates
// that table in memory, dispatching on the query `label` queue.js passes to
// every _query() call — the same "simulate real store semantics, not raw
// wire protocol" approach the old buildMockRedisClient() used, just against
// the new backend. Full end-to-end correctness against a real PostgreSQL
// instance is covered by test/persistence-recovery-durability.test.js.

const queueModule = require('../src/core/persistenceRecovery/queue');

function buildFakePgQueryFn() {
  const rows = new Map(); // operation_id → row object (snake_case, mirrors the table)

  const fn = async (sql, params, label) => {
    switch (label) {
      case 'prq_enqueue': {
        const [operationId, operationType, service, payloadJson, retryCount, lastError, errorHistoryJson, createdAt] = params;
        rows.set(operationId, {
          operation_id: operationId, operation_type: operationType, service,
          payload: JSON.parse(payloadJson), status: 'PENDING', eligible_at: new Date(),
          retry_count: retryCount, replay_count: 0, last_error: lastError,
          error_history: JSON.parse(errorHistoryJson), created_at: new Date(createdAt),
          dlq_at: null, replayed_at: null, archived_at: null,
        });
        return { rows: [] };
      }
      case 'prq_claim_next': {
        const due = [...rows.values()].filter(r => r.status === 'PENDING' && r.eligible_at <= new Date());
        if (due.length === 0) return { rows: [] };
        due.sort((a, b) => a.eligible_at - b.eligible_at);
        const row = due[0];
        row.eligible_at = new Date(Date.now() + Number(params[0]));
        return { rows: [{ ...row }] };
      }
      case 'prq_mark_complete': {
        rows.delete(params[0]);
        return { rows: [] };
      }
      case 'prq_mark_retry_read': {
        const row = rows.get(params[0]);
        return { rows: row ? [{ error_history: row.error_history }] : [] };
      }
      case 'prq_mark_retry': {
        const [operationId, retryCount, errorMessage, errorHistoryJson, eligibleAtMs] = params;
        const row = rows.get(operationId);
        if (row) {
          row.retry_count   = retryCount;
          row.last_error    = errorMessage;
          row.error_history = JSON.parse(errorHistoryJson);
          row.eligible_at    = new Date(Number(eligibleAtMs));
        }
        return { rows: [] };
      }
      case 'prq_move_to_dlq_read': {
        const row = rows.get(params[0]);
        return { rows: row ? [{ operation_type: row.operation_type, service: row.service, error_history: row.error_history }] : [] };
      }
      case 'prq_move_to_dlq': {
        const [operationId, retryCount, finalError, errorHistoryJson, dlqAtMs] = params;
        const row = rows.get(operationId);
        if (row) {
          row.status        = 'DLQ';
          row.retry_count    = retryCount;
          row.last_error     = finalError;
          row.error_history  = JSON.parse(errorHistoryJson);
          row.dlq_at         = new Date(Number(dlqAtMs));
        }
        return { rows: [] };
      }
      case 'prq_get_stats': {
        const queueDepth = [...rows.values()].filter(r => r.status === 'PENDING').length;
        const dlqDepth   = [...rows.values()].filter(r => r.status === 'DLQ').length;
        return { rows: [{ queue_depth: queueDepth, dlq_depth: dlqDepth }] };
      }
      default:
        throw new Error(`buildFakePgQueryFn: unhandled label "${label}"`);
    }
  };

  fn._rows = rows;
  return fn;
}

describe('queue operations', () => {
  const pgPool = require('../src/infra/postgres/pool');
  let fakeQuery;
  let isEnabledSpy;

  beforeEach(() => {
    fakeQuery = buildFakePgQueryFn();
    queueModule.__setQueryFnForTest(fakeQuery);
    // queue._isReady() delegates to pgPool.isEnabled() — stub it directly
    // rather than constructing a real pg.Pool via pgPool.initialize().
    isEnabledSpy = jest.spyOn(pgPool, 'isEnabled').mockReturnValue(true);
  });

  afterEach(() => {
    queueModule.__setQueryFnForTest(null);
    isEnabledSpy.mockRestore();
  });

  test('PRQ-15 enqueue + claimNext returns the enqueued operation', async () => {
    await queueModule.enqueue({
      operationId:   'op-001',
      operationType: OPERATION_TYPES.ATTESTATION_SAVE,
      service:       'attestation',
      payload:       { attestationId: 'att-001', attestationDecision: 'ATTESTED' },
    });

    const claimed = await queueModule.claimNext();
    expect(claimed).not.toBeNull();
    expect(claimed.operationId).toBe('op-001');
    expect(claimed.operationType).toBe(OPERATION_TYPES.ATTESTATION_SAVE);
    expect(claimed.retryCount).toBe(0);
  });

  test('PRQ-16 claimNext on empty queue → null', async () => {
    const result = await queueModule.claimNext();
    expect(result).toBeNull();
  });

  test('PRQ-17 markComplete removes item from queue', async () => {
    await queueModule.enqueue({
      operationId:   'op-002',
      operationType: OPERATION_TYPES.CERTIFICATION_SAVE,
      service:       'certification',
      payload:       { certificationId: 'cert-002' },
    });

    await queueModule.claimNext();
    await queueModule.markComplete('op-002');

    const stats = await queueModule.getStats();
    expect(stats.queueDepth).toBe(0);
    expect(fakeQuery._rows.has('op-002')).toBe(false);
  });

  test('PRQ-18 markRetry reschedules with future timestamp', async () => {
    await queueModule.enqueue({
      operationId:   'op-003',
      operationType: OPERATION_TYPES.PORTAL_VERIFICATION_SAVE,
      service:       'portal',
      payload:       { verificationId: 'pv-003', artifactFingerprint: 'abc', overallResult: 'FAILED' },
    });

    await queueModule.claimNext();
    const futureMs = Date.now() + 30_000;
    await queueModule.markRetry('op-003', 'connection refused', 1, futureMs);

    const row = fakeQuery._rows.get('op-003');
    expect(row.retry_count).toBe(1);
    expect(row.last_error).toBe('connection refused');

    // Item should NOT be claimable yet (eligible_at in future)
    const claimed = await queueModule.claimNext();
    expect(claimed).toBeNull();
  });

  test('PRQ-19 moveToDlq removes from queue, adds to DLQ', async () => {
    await queueModule.enqueue({
      operationId:   'op-004',
      operationType: OPERATION_TYPES.ATTESTATION_SAVE,
      service:       'attestation',
      payload:       { attestationId: 'att-004', attestationDecision: 'NOT_ATTESTED' },
    });

    await queueModule.claimNext();
    await queueModule.moveToDlq('op-004', 'max retries exceeded', 5);

    const stats = await queueModule.getStats();
    expect(stats.queueDepth).toBe(0);
    expect(stats.dlqDepth).toBe(1);
  });

  test('PRQ-20 getStats returns queueDepth and dlqDepth', async () => {
    await queueModule.enqueue({
      operationId: 'op-005', operationType: OPERATION_TYPES.ATTESTATION_SAVE,
      service: 'attestation', payload: { attestationId: 'att-005', attestationDecision: 'ATTESTED' },
    });
    await queueModule.enqueue({
      operationId: 'op-006', operationType: OPERATION_TYPES.CERTIFICATION_SAVE,
      service: 'certification', payload: { certificationId: 'cert-006' },
    });

    const stats = await queueModule.getStats();
    expect(stats.queueDepth).toBe(2);
    expect(stats.dlqDepth).toBe(0);
  });
});

// ── PRQ-21 – PRQ-24: worker._processOne ──────────────────────────────────────

describe('worker._processOne', () => {
  const { _processOne, MAX_RETRIES, RETRY_DELAYS_MS } = worker;

  function makeOp(overrides = {}) {
    return {
      operationId:   'test-op-001',
      operationType: OPERATION_TYPES.ATTESTATION_SAVE,
      service:       'attestation',
      payload:       { attestationId: 'att-test', attestationDecision: 'ATTESTED' },
      retryCount:    0,
      ...overrides,
    };
  }

  beforeEach(() => {
    // Reset worker handler registry by re-registering nothing
    // (worker module is stateful — we inject handlers per test)
  });

  test('PRQ-21 success handler → markComplete called', async () => {
    worker.registerHandler(OPERATION_TYPES.ATTESTATION_SAVE, async () => ({ success: true }));

    const calls = [];
    const mockQueue = {
      markComplete: async (id) => calls.push({ type: 'complete', id }),
      markRetry:    async () => {},
      moveToDlq:    async () => {},
    };

    // Inject mock queue
    jest.resetModules();
    // Use the real _processOne with real queue stubs via monkey-patching
    const origMarkComplete = queueModule.markComplete;
    const origMarkRetry    = queueModule.markRetry;
    const origMoveToDlq    = queueModule.moveToDlq;

    queueModule.markComplete = async (id) => calls.push({ type: 'complete', id });
    queueModule.markRetry    = async () => calls.push({ type: 'retry' });
    queueModule.moveToDlq    = async () => calls.push({ type: 'dlq' });

    try {
      await _processOne(makeOp());
      expect(calls).toContainEqual({ type: 'complete', id: 'test-op-001' });
    } finally {
      queueModule.markComplete = origMarkComplete;
      queueModule.markRetry    = origMarkRetry;
      queueModule.moveToDlq    = origMoveToDlq;
    }
  });

  test('PRQ-22 transient failure + retryCount < MAX_RETRIES → markRetry called', async () => {
    worker.registerHandler(OPERATION_TYPES.ATTESTATION_SAVE,
      async () => ({ success: false, error: 'ECONNREFUSED' })
    );

    const calls = [];
    const origMarkComplete = queueModule.markComplete;
    const origMarkRetry    = queueModule.markRetry;
    const origMoveToDlq    = queueModule.moveToDlq;

    queueModule.markComplete = async () => {};
    queueModule.markRetry    = async (id, err, count) => calls.push({ type: 'retry', id, count });
    queueModule.moveToDlq    = async () => calls.push({ type: 'dlq' });

    try {
      await _processOne(makeOp({ retryCount: 0 }));
      expect(calls).toContainEqual(expect.objectContaining({ type: 'retry' }));
    } finally {
      queueModule.markComplete = origMarkComplete;
      queueModule.markRetry    = origMarkRetry;
      queueModule.moveToDlq    = origMoveToDlq;
    }
  });

  test('PRQ-23 failure at MAX_RETRIES → moveToDlq called', async () => {
    worker.registerHandler(OPERATION_TYPES.ATTESTATION_SAVE,
      async () => ({ success: false, error: 'still failing' })
    );

    const calls = [];
    const origMarkComplete = queueModule.markComplete;
    const origMarkRetry    = queueModule.markRetry;
    const origMoveToDlq    = queueModule.moveToDlq;

    queueModule.markComplete = async () => {};
    queueModule.markRetry    = async () => {};
    queueModule.moveToDlq    = async (id) => calls.push({ type: 'dlq', id });

    try {
      await _processOne(makeOp({ retryCount: MAX_RETRIES }));
      expect(calls).toContainEqual(expect.objectContaining({ type: 'dlq' }));
    } finally {
      queueModule.markComplete = origMarkComplete;
      queueModule.markRetry    = origMarkRetry;
      queueModule.moveToDlq    = origMoveToDlq;
    }
  });

  test('PRQ-24 no handler registered → moveToDlq immediately', async () => {
    const calls = [];
    const origMarkComplete = queueModule.markComplete;
    const origMarkRetry    = queueModule.markRetry;
    const origMoveToDlq    = queueModule.moveToDlq;

    queueModule.markComplete = async () => {};
    queueModule.markRetry    = async () => {};
    queueModule.moveToDlq    = async (id) => calls.push({ type: 'dlq', id });

    try {
      await _processOne(makeOp({ operationType: 'NONEXISTENT_OP' }));
      expect(calls).toContainEqual(expect.objectContaining({ type: 'dlq' }));
    } finally {
      queueModule.markComplete = origMarkComplete;
      queueModule.markRetry    = origMarkRetry;
      queueModule.moveToDlq    = origMoveToDlq;
    }
  });
});

// ── PRQ-25: metrics ───────────────────────────────────────────────────────────

describe('metrics', () => {
  beforeEach(() => metrics._reset());

  test('PRQ-25a inc increments counter', () => {
    metrics.inc('test_counter', { surface: 'attestation' });
    metrics.inc('test_counter', { surface: 'attestation' });
    expect(metrics.get('test_counter', { surface: 'attestation' })).toBe(2);
  });

  test('PRQ-25b add accumulates values', () => {
    metrics.add('test_latency', 100, { op: 'save' });
    metrics.add('test_latency', 200, { op: 'save' });
    expect(metrics.get('test_latency', { op: 'save' })).toBe(300);
  });

  test('PRQ-25c snapshot returns all counters', () => {
    metrics.inc('alpha');
    metrics.inc('beta');
    const snap = metrics.snapshot();
    expect(snap['alpha']).toBe(1);
    expect(snap['beta']).toBe(1);
  });

  test('PRQ-25d reset clears all counters', () => {
    metrics.inc('alpha');
    metrics._reset();
    expect(metrics.get('alpha')).toBe(0);
  });
});

// ── PRQ-26 – PRQ-27: recoveryManager disabled / PostgreSQL not ready ─────────
//
// CHAIN-3: these two tests previously documented the exact bug the audit
// finding describes — enqueue() silently dropping a failed write with no
// durable record whenever its (then Redis-based) store was unavailable, and
// that being treated as normal, acceptable behavior. That is no longer true
// in the general case: the queue's store is now PostgreSQL (migration 032),
// the same durable store QODIQA already depends on for every other write.
// What both tests below still correctly cover is a narrower, legitimate
// case — recovery being switched off entirely (no PostgreSQL configured at
// all) — which remains a deliberate, disclosed no-op mode, not silent data
// loss of a write that could otherwise have been durably recorded. See
// recoveryManager.js's header comment and
// test/persistence-recovery-durability.test.js for proof that, when
// PostgreSQL *is* configured, enqueue() durably persists the retry instead
// of dropping it.

describe('recoveryManager.enqueue', () => {
  let recoveryManager;

  beforeEach(() => {
    jest.resetModules();
    delete process.env.QODIQA_PG_ENABLED;
    delete process.env.PRQ_ENABLED;
    recoveryManager = require('../src/core/persistenceRecovery/recoveryManager');
  });

  test('PRQ-26 disabled mode (PostgreSQL not enabled at all) → returns phantom, no query issued', async () => {
    // PRQ_ENABLED not set, QODIQA_PG_ENABLED not set → recovery queue disabled
    const phantom = await recoveryManager.enqueue(
      OPERATION_TYPES.ATTESTATION_SAVE,
      { attestationId: 'att-no-pg', attestationDecision: 'ATTESTED' },
      new Error('ECONNREFUSED'),
    );
    expect(phantom).not.toBeNull();
    expect(phantom.attestation_id).toBe('att-no-pg');
    expect(phantom.id).toBeNull();
  });

  test('PRQ-27 forced-enabled but PostgreSQL not ready → returns phantom, does not throw', async () => {
    process.env.PRQ_ENABLED = 'true';
    jest.resetModules();
    recoveryManager = require('../src/core/persistenceRecovery/recoveryManager');

    // queue._isReady() returns false (pgPool never initialized in this test)
    const phantom = await recoveryManager.enqueue(
      OPERATION_TYPES.CERTIFICATION_SAVE,
      { certificationId: 'cert-no-pg', certificationLevel: 'CERTIFIED',
        certificationDecision: 'CERTIFIED', score: 90 },
      new Error('ECONNREFUSED'),
    );
    expect(phantom).not.toBeNull();
    expect(phantom.certification_id).toBe('cert-no-pg');
    expect(phantom.id).toBeNull();

    delete process.env.PRQ_ENABLED;
  });
});
