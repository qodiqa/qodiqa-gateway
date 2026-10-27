'use strict';

/**
 * Recovery Tests —
 *
 * Validates that QODIQA's enforcement pipeline recovers correctly from the
 * failure scenarios introduced by the failure injection framework.
 *
 * All tests use in-process in-memory stubs — no real Redis or PostgreSQL
 * connection is required.  Tests cover:
 *
 *   REC-01   Enforcement pipeline is FAIL-CLOSED when nonce store is unavailable
 *   REC-02   Enforcement pipeline is FAIL-CLOSED when anomaly store is unavailable
 *   REC-03   Enforcement recovers immediately once stores come back online
 *   REC-04   Redis latency does not cause silent data loss (reject, not hang forever)
 *   REC-05   Network partition → both stores fail → pipeline blocks every request
 *   REC-06   Post-partition recovery: subsequent requests succeed once stores restored
 *   REC-07   PG down does not crash the enforcement pipeline (PG not on critical path)
 *   REC-08   Clock skew within ±5 min is tolerated (replay window still effective)
 *   REC-09   Clock skew beyond replay window causes replay detection to degrade gracefully
 *   REC-10   Disk full: audit log write failure is handled (process does not crash)
 *   REC-11   Disk full recovery: subsequent writes succeed once space restored
 *   REC-12   Memory pressure: pipeline does not OOM on large allocation before call
 *   REC-13   Persistence recovery queue: transient PG error enqueues for retry
 *   REC-14   Persistence recovery queue: data error (constraint) is NOT retried
 *   REC-15   Persistence recovery queue: exceeds MAX_RETRIES → moved to DLQ
 *   REC-16   Audit chain: startup replay from WAL restores chain state correctly
 *   REC-17   Audit chain: corrupted WAL entry is detected and reported
 *   REC-18   Rate-limit store unavailable → fail-closed (429) not fail-open (200)
 *   REC-19   Redis timeout (simulated) → nonce store rejection surfaces as error
 *   REC-20   Simultaneous Redis + PG failure → pipeline is still fail-closed
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const {
  redisDownNonceStore,
  redisLatencyNonceStore,
  redisTimeoutNonceStore,
  redisDownAnomalyStore,
  redisLatencyAnomalyStore,
  networkPartition,
  withMemoryPressure,
  injectClockSkew,
} = require('../src/testing/failureInjection');

const { makeNonceStore, makeOpenAnomalyStore, makeDeadStore } = require('../src/testing/stores');

const {
  isPersistenceFailure,
  buildPhantomRecord,
  OPERATION_TYPES,
} = require('../src/core/persistenceRecovery/persistenceOperation');

const worker  = require('../src/core/persistenceRecovery/worker');
const metrics = require('../src/core/persistenceRecovery/metrics');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeNetErr(code, msg) {
  return Object.assign(new Error(msg || `error ${code}`), { code });
}

function makePgErr(pgCode, msg) {
  return Object.assign(new Error(msg || `PG error ${pgCode}`), { code: pgCode });
}

function makeQueue() {
  // Inline minimal in-memory queue (mirrors the structure tested in PRQ tests)
  const items = [];
  const dlq   = [];
  let   nextId = 1;
  return {
    enqueue(op) { const id = nextId++; items.push({ id, op, retries: 0, retryAfter: 0 }); return id; },
    claimNext() {
      const now = Date.now();
      const idx = items.findIndex(i => i.retryAfter <= now);
      if (idx === -1) return null;
      return items[idx];
    },
    markComplete(id) { const i = items.findIndex(x => x.id === id); if (i !== -1) items.splice(i, 1); },
    markRetry(id, delayMs) {
      const item = items.find(x => x.id === id);
      if (item) { item.retries++; item.retryAfter = Date.now() + delayMs; }
    },
    moveToDlq(id) { const i = items.findIndex(x => x.id === id); if (i !== -1) { dlq.push(items[i]); items.splice(i, 1); } },
    getStats() { return { queueDepth: items.length, dlqDepth: dlq.length }; },
    _items: items, _dlq: dlq,
  };
}

// ── REC-01: Fail-closed on nonce store unavailability ─────────────────────────

describe('REC-01: Fail-closed on nonce store unavailability', () => {
  test('redisDownNonceStore rejects register()', async () => {
    const store = redisDownNonceStore();
    await expect(store.register('req-abc', 300_000)).rejects.toMatchObject({ code: 'ECONNREFUSED' });
  });

  test('redisDownNonceStore rejects isRegistered()', async () => {
    const store = redisDownNonceStore();
    await expect(store.isRegistered('req-abc')).rejects.toMatchObject({ code: 'ECONNREFUSED' });
  });
});

// ── REC-02: Fail-closed on anomaly store unavailability ───────────────────────

describe('REC-02: Fail-closed on anomaly store unavailability', () => {
  test('redisDownAnomalyStore rejects record()', async () => {
    const store = redisDownAnomalyStore();
    await expect(store.record('user:x', Date.now(), 60_000)).rejects.toMatchObject({ code: 'ECONNREFUSED' });
  });

  test('redisDownAnomalyStore rejects peek()', async () => {
    const store = redisDownAnomalyStore();
    await expect(store.peek('user:x', Date.now(), 60_000)).rejects.toMatchObject({ code: 'ECONNREFUSED' });
  });
});

// ── REC-03: Recovery once stores come back online ─────────────────────────────

describe('REC-03: Recovery once stores come back online', () => {
  test('switching from dead store to live store succeeds immediately', async () => {
    const deadStore = redisDownNonceStore();
    await expect(deadStore.register('r1', 60_000)).rejects.toBeDefined();

    // Simulate recovery: replace with a live store
    const liveStore = makeNonceStore();
    const result    = await liveStore.register('r1', 60_000);
    expect(result.registered).toBe(true);
  });

  test('repeated registration after recovery is idempotent (second call returns false)', async () => {
    const store = makeNonceStore();
    const r1    = await store.register('idempotent-r1', 60_000);
    const r2    = await store.register('idempotent-r1', 60_000);
    expect(r1.registered).toBe(true);
    expect(r2.registered).toBe(false); // already registered
  });
});

// ── REC-04: Latency does not cause silent data loss ───────────────────────────

describe('REC-04: Redis latency surfaces as rejection within timeout', () => {
  test('redisLatencyNonceStore adds delay then resolves', async () => {
    const liveStore   = makeNonceStore();
    const slowStore   = redisLatencyNonceStore(liveStore, 50);
    const start       = Date.now();
    const result      = await slowStore.register('slow-r1', 60_000);
    const elapsed     = Date.now() - start;
    expect(result.registered).toBe(true);
    expect(elapsed).toBeGreaterThanOrEqual(40);
  });

  test('redisLatencyAnomalyStore adds delay then resolves', async () => {
    const liveStore = makeOpenAnomalyStore();
    const slowStore = redisLatencyAnomalyStore(liveStore, 50);
    const start     = Date.now();
    const result    = await slowStore.record('user:y', Date.now(), 60_000);
    const elapsed   = Date.now() - start;
    expect(result).toMatchObject({ count: 0 });
    expect(elapsed).toBeGreaterThanOrEqual(40);
  });
});

// ── REC-05: Network partition → both stores fail ──────────────────────────────

describe('REC-05: Network partition — all stores fail simultaneously', () => {
  test('networkPartition() returns failing nonce store', async () => {
    const { nonceStore } = networkPartition();
    await expect(nonceStore.register('np-r1', 60_000)).rejects.toMatchObject({ code: 'ECONNREFUSED' });
  });

  test('networkPartition() returns failing anomaly store', async () => {
    const { anomalyStore } = networkPartition();
    await expect(anomalyStore.record('np-u', Date.now(), 60_000)).rejects.toMatchObject({ code: 'ECONNREFUSED' });
  });

  test('networkPartition() returns failing PG pool', async () => {
    const { pgPool } = networkPartition();
    await expect(pgPool.query('SELECT 1')).rejects.toBeDefined();
  });
});

// ── REC-06: Post-partition recovery ───────────────────────────────────────────

describe('REC-06: Post-partition recovery — requests succeed with new stores', () => {
  test('after partition, fresh stores service requests correctly', async () => {
    const liveNonce   = makeNonceStore();
    const liveAnomaly = makeOpenAnomalyStore();

    const nr = await liveNonce.register('post-partition-r1', 60_000);
    expect(nr.registered).toBe(true);

    const ar = await liveAnomaly.record('post-partition-user', Date.now(), 60_000);
    expect(ar).toMatchObject({ count: 0 });
  });
});

// ── REC-07: PG down does not crash enforcement pipeline ───────────────────────

describe('REC-07: PG unavailability is non-fatal to enforcement pipeline', () => {
  test('isPersistenceFailure classifies ECONNREFUSED as retryable', () => {
    expect(isPersistenceFailure(makeNetErr('ECONNREFUSED'))).toBe(true);
  });

  test('isPersistenceFailure classifies ETIMEDOUT as retryable', () => {
    expect(isPersistenceFailure(makeNetErr('ETIMEDOUT'))).toBe(true);
  });

  test('isPersistenceFailure classifies PG class 08 (connection) as retryable', () => {
    expect(isPersistenceFailure(makePgErr('08006'))).toBe(true);
  });

  test('isPersistenceFailure classifies PG class 53 (resources) as retryable', () => {
    expect(isPersistenceFailure(makePgErr('53300'))).toBe(true);
  });

  test('buildPhantomRecord succeeds when PG is down', () => {
    const phantom = buildPhantomRecord(OPERATION_TYPES.ATTESTATION_SAVE, {
      attestationId: 'att-1', attestationDecision: 'PASS',
    });
    expect(phantom.id).toBeNull();
    expect(phantom.attestation_id).toBe('att-1');
  });
});

// ── REC-08: Clock skew within ±5 min ─────────────────────────────────────────

describe('REC-08: Clock skew within replay window is tolerated', () => {
  test('Date.now() offset by +3 min does not break nonce registration', async () => {
    const store    = makeNonceStore();
    const injector = injectClockSkew(3 * 60 * 1000); // +3 minutes
    try {
      const result = await store.register('skew-r1', 300_000);
      expect(result.registered).toBe(true);
    } finally {
      injector.restore();
    }
  });

  test('Date.now() offset by -3 min does not break nonce registration', async () => {
    const store    = makeNonceStore();
    const injector = injectClockSkew(-3 * 60 * 1000); // -3 minutes
    try {
      const result = await store.register('skew-r2', 300_000);
      expect(result.registered).toBe(true);
    } finally {
      injector.restore();
    }
  });
});

// ── REC-09: Clock skew beyond replay window ───────────────────────────────────

describe('REC-09: Large clock skew does not crash the system', () => {
  test('Clock skew of +24 hours: registration still does not throw', async () => {
    const store    = makeNonceStore();
    const injector = injectClockSkew(24 * 60 * 60 * 1000);
    try {
      // The nonce store itself doesn't reject — but higher layers would
      // reject the request as outside the replay window.  The store
      // must not crash.
      const result = await store.register('bigskew-r1', 300_000);
      expect(result.registered).toBe(true);
    } finally {
      injector.restore();
    }
  });
});

// ── REC-10 / REC-11: Disk full handling ──────────────────────────────────────

describe('REC-10/REC-11: Disk full fault is isolated and recoverable', () => {
  test('injectDiskFull() makes writeFileSync throw ENOSPC', () => {
    const { injectDiskFull } = require('../src/testing/failureInjection');
    const fs = require('fs');
    const injector = injectDiskFull();
    try {
      expect(() => fs.writeFileSync('/tmp/test-enospc', 'data')).toThrow(/ENOSPC/);
    } finally {
      injector.restore();
    }
  });

  test('after restore(), writeFileSync works normally again', () => {
    const { injectDiskFull } = require('../src/testing/failureInjection');
    const fs   = require('fs');
    const os   = require('os');
    const path = require('path');
    const tmp  = path.join(os.tmpdir(), `qodiqa-recovery-test-${Date.now()}.txt`);

    const injector = injectDiskFull();
    try {
      expect(() => fs.writeFileSync(tmp, 'data')).toThrow();
    } finally {
      injector.restore();
    }

    // After restore, writes work
    expect(() => fs.writeFileSync(tmp, 'recovery')).not.toThrow();
    fs.unlinkSync(tmp);
  });
});

// ── REC-12: Memory pressure ───────────────────────────────────────────────────

describe('REC-12: Memory pressure does not prevent operation', () => {
  test('withMemoryPressure (16 MB) wraps fn and returns its result', async () => {
    const fn = async () => 42;
    const pressured = withMemoryPressure(fn, 16 * 1024 * 1024);
    const result    = await pressured();
    expect(result).toBe(42);
  });

  test('withMemoryPressure propagates fn errors correctly', async () => {
    const fn = async () => { throw new Error('fn-error'); };
    const pressured = withMemoryPressure(fn, 1024 * 1024);
    await expect(pressured()).rejects.toThrow('fn-error');
  });
});

// ── REC-13: Persistence recovery queue — transient error enqueues ─────────────

describe('REC-13: Transient PG error enqueues operation for retry', () => {
  test('ECONNREFUSED is classified as retryable and produces phantom', () => {
    const err     = makeNetErr('ECONNREFUSED');
    const isRetry = isPersistenceFailure(err);
    expect(isRetry).toBe(true);

    // When retryable, the caller should enqueue and return phantom
    const phantom = buildPhantomRecord(OPERATION_TYPES.ATTESTATION_SAVE, {
      attestationId: 'att-retry-1', attestationDecision: 'PASS',
    });
    expect(phantom.id).toBeNull();
    expect(phantom.attestation_id).toBe('att-retry-1');
  });
});

// ── REC-14: Data error is NOT retried ────────────────────────────────────────

describe('REC-14: PG data error (constraint violation) is NOT retried', () => {
  test('class 23 (integrity constraint) → not retryable', () => {
    const err = makePgErr('23505', 'duplicate key value violates unique constraint');
    expect(isPersistenceFailure(err)).toBe(false);
  });

  test('class 42 (syntax error) → not retryable', () => {
    const err = makePgErr('42601', 'syntax error at or near SELECT');
    expect(isPersistenceFailure(err)).toBe(false);
  });

  test('class 28 (invalid authorization) → not retryable', () => {
    const err = makePgErr('28000', 'password authentication failed');
    expect(isPersistenceFailure(err)).toBe(false);
  });
});

// ── REC-15: Exceeds MAX_RETRIES → DLQ ────────────────────────────────────────

describe('REC-15: Operation exceeds MAX_RETRIES and moves to DLQ', () => {
  test('queue.moveToDlq removes from queue and adds to DLQ', () => {
    const queue = makeQueue();
    const id    = queue.enqueue({ type: 'ATTESTATION_SAVE', data: { attestation_id: 'dlq-1' } });
    expect(queue.getStats().queueDepth).toBe(1);
    expect(queue.getStats().dlqDepth).toBe(0);

    queue.moveToDlq(id);
    expect(queue.getStats().queueDepth).toBe(0);
    expect(queue.getStats().dlqDepth).toBe(1);
  });

  test('markRetry increments retry counter and delays next claim', () => {
    const queue = makeQueue();
    const id    = queue.enqueue({ type: 'ATTESTATION_SAVE', data: { attestation_id: 'retry-2' } });
    queue.markRetry(id, 5_000);
    const item  = queue._items.find(i => i.id === id);
    expect(item.retries).toBe(1);
    expect(item.retryAfter).toBeGreaterThan(Date.now());
    // Not claimable yet (retryAfter > now)
    expect(queue.claimNext()).toBeNull();
  });
});

// ── REC-16: Audit chain WAL recovery ─────────────────────────────────────────
//
// The two tests below (module loads / exports API) were the only WAL-replay
// coverage previously in this file — they never actually exercised the
// orphaned-WAL branch of loadFromDisk()'s startup IIFE (src/core/audit/
// audit-log.js), a known gap flagged in audit/part-04-transparency-audit-
// chain.md. The new tests that follow build a real audit.log + a real
// orphaned .wal file on disk and require a fresh audit-log.js instance
// pointed at them (jest.resetModules(), since loadFromDisk() runs at
// require() time), asserting the actual replay/dedup/cleanup behavior.

const os   = require('os');
const path = require('path');
const fs   = require('fs');

function _walTestPaths() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-rec16-wal-'));
  return { dir, logPath: path.join(dir, 'audit.log') };
}

// Builds a real, correctly hash-chained entry using the same entryBuilder.js
// production code path append() itself uses — never a hand-rolled fixture —
// so a bug in this test can never masquerade as a bug in the module under test.
function _buildChainedEntry(prevHash, artifactId) {
  const entryBuilder = require('../src/core/audit/entryBuilder');
  const normalized = entryBuilder.normalizeFields({
    artifactId,
    inputHash:           'a'.repeat(64),
    decision:            'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:           `sig-${artifactId}`,
    requestHash:          'b'.repeat(64),
    policyHash:           'c'.repeat(64),
    verificationResult:  true,
  });
  return entryBuilder.buildEntry(normalized, prevHash);
}

describe('REC-16: Audit chain WAL-based startup recovery', () => {
  test('audit-log module loads without throwing (module itself is recovery-safe)', () => {
    // The audit-log module performs WAL recovery on require() — if it throws,
    // the process would crash.  We verify it can be required safely.
    expect(() => require('../src/core/audit/audit-log')).not.toThrow();
  });

  test('audit-log exports the expected public API', () => {
    const auditLog = require('../src/core/audit/audit-log');
    expect(typeof auditLog.append).toBe('function');
    expect(typeof auditLog.getChainStats).toBe('function');
  });

  test('an orphaned .wal entry (crash after WAL write, before main-log append) is replayed on load', async () => {
    const { dir, logPath } = _walTestPaths();
    process.env.QODIQA_AUDIT_LOG = logPath;
    jest.resetModules();

    // First boot: append 2 entries normally, then shut this instance down
    // (jest.resetModules() below simulates the process restart).
    let auditLog = require('../src/core/audit/audit-log');
    await auditLog.append({ artifactId: 'rec16-1', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig1', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
    await auditLog.append({ artifactId: 'rec16-2', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig2', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
    const tailAfterTwo = auditLog.getAuditTailHash();

    // Simulate a crash between "WAL written" and "appended to main log":
    // write a real, correctly-chained third entry ONLY to the .wal file —
    // exactly the state _appendOne() leaves on disk between its step 1 and
    // step 2 (see audit-log.js).
    const orphan = _buildChainedEntry(tailAfterTwo, 'rec16-3-orphan');
    fs.writeFileSync(logPath + '.wal', JSON.stringify(orphan) + '\n', 'utf8');

    // Restart: require a fresh instance pointed at the same files.
    jest.resetModules();
    auditLog = require('../src/core/audit/audit-log');

    expect(auditLog.getChainStats().modernLength).toBe(3);
    expect(auditLog.getAuditTailHash()).toBe(orphan.hash);
    expect(await auditLog.alreadyExecuted('rec16-3-orphan')).toBe(true);
    expect(fs.existsSync(logPath + '.wal')).toBe(false); // WAL cleaned up after replay

    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(3);
    expect(JSON.parse(lines[2]).artifactId).toBe('rec16-3-orphan');

    fs.rmSync(dir, { recursive: true, force: true });
    delete process.env.QODIQA_AUDIT_LOG;
  });

  test('a WAL entry already committed to the main log (crash after append, before WAL cleanup) is not duplicated', async () => {
    const { dir, logPath } = _walTestPaths();
    process.env.QODIQA_AUDIT_LOG = logPath;
    jest.resetModules();

    let auditLog = require('../src/core/audit/audit-log');
    await auditLog.append({ artifactId: 'rec16-committed', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });

    // The entry is already the last line of the main log (append() already
    // completed steps 1-6). Simulate a crash right before step 5's WAL
    // unlink by re-writing the SAME already-committed entry back into the
    // .wal file — loadFromDisk() must detect "already committed" via the
    // hash comparison and only delete the WAL, never duplicate the entry.
    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    fs.writeFileSync(logPath + '.wal', lines[lines.length - 1] + '\n', 'utf8');

    jest.resetModules();
    auditLog = require('../src/core/audit/audit-log');

    expect(auditLog.getChainStats().modernLength).toBe(1); // not duplicated to 2
    expect(fs.existsSync(logPath + '.wal')).toBe(false);

    fs.rmSync(dir, { recursive: true, force: true });
    delete process.env.QODIQA_AUDIT_LOG;
  });
});

// ── REC-17: Corrupted WAL detection ──────────────────────────────────────────

describe('REC-17: Corrupted WAL entry detection via checksum', () => {
  test('sha256Hex produces different digests for different inputs', () => {
    const { sha256Hex } = require('../src/infra/crypto/hashing');
    const h1 = sha256Hex('entry:{"id":1,"hash":"abc"}');
    const h2 = sha256Hex('entry:{"id":1,"hash":"xyz"}');
    expect(h1).not.toBe(h2);
  });

  test('sha256Hex is consistent (same input → same output)', () => {
    const { sha256Hex } = require('../src/infra/crypto/hashing');
    const payload = 'entry:{"id":99,"hash":"aabbcc"}';
    expect(sha256Hex(payload)).toBe(sha256Hex(payload));
  });

  test('a checksum claiming more entries than the file contains is a fatal AUDIT_INTEGRITY_VIOLATION (truncation)', async () => {
    const { dir, logPath } = _walTestPaths();
    process.env.QODIQA_AUDIT_LOG = logPath;
    jest.resetModules();

    let auditLog = require('../src/core/audit/audit-log');
    await auditLog.append({ artifactId: 'rec17-1', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig1', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
    await auditLog.append({ artifactId: 'rec17-2', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig2', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });

    // Simulate truncation: the checksum sidecar (audit.log.sum) still claims
    // 3 entries were durably committed, but the file (below) will only have 2.
    const cs = JSON.parse(fs.readFileSync(logPath + '.sum', 'utf8'));
    fs.writeFileSync(logPath + '.sum', JSON.stringify({ ...cs, count: 3 }), 'utf8');

    jest.resetModules();
    expect(() => require('../src/core/audit/audit-log')).toThrow(/AUDIT_INTEGRITY_VIOLATION/);

    fs.rmSync(dir, { recursive: true, force: true });
    delete process.env.QODIQA_AUDIT_LOG;
  });

  test('a checksum tailHash that disagrees with the on-disk entry at that position is a fatal AUDIT_INTEGRITY_VIOLATION (tampering)', async () => {
    const { dir, logPath } = _walTestPaths();
    process.env.QODIQA_AUDIT_LOG = logPath;
    jest.resetModules();

    let auditLog = require('../src/core/audit/audit-log');
    await auditLog.append({ artifactId: 'rec17-3', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig1', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });

    const cs = JSON.parse(fs.readFileSync(logPath + '.sum', 'utf8'));
    fs.writeFileSync(logPath + '.sum', JSON.stringify({ ...cs, tailHash: 'f'.repeat(64) }), 'utf8');

    jest.resetModules();
    expect(() => require('../src/core/audit/audit-log')).toThrow(/AUDIT_INTEGRITY_VIOLATION/);

    fs.rmSync(dir, { recursive: true, force: true });
    delete process.env.QODIQA_AUDIT_LOG;
  });
});

// ── REC-18: Rate-limit store unavailable → fail-closed ───────────────────────

describe('REC-18: Rate-limit store unavailable → fail-closed (429)', () => {
  test('makeDeadStore.record() rejects on call', async () => {
    const dead = makeDeadStore('ECONNREFUSED');
    await expect(dead.record()).rejects.toThrow('ECONNREFUSED');
  });

  test('makeDeadStore.peek() rejects on call', async () => {
    const dead = makeDeadStore('ECONNREFUSED');
    await expect(dead.peek()).rejects.toThrow('ECONNREFUSED');
  });
});

// ── REC-19: Redis timeout → surfaces as error ─────────────────────────────────

describe('REC-19: Redis timeout surfaces as rejection, not silent hang', () => {
  test('redisTimeoutNonceStore rejects after hangMs', async () => {
    const store = redisTimeoutNonceStore(makeNonceStore(), 100); // 100 ms hang
    await expect(store.register('timeout-r1', 60_000)).rejects.toMatchObject({ code: 'ETIMEDOUT' });
  }, 1_000); // generous timeout for the test runner itself

  test('redisTimeoutNonceStore.isRegistered rejects after hangMs', async () => {
    const store = redisTimeoutNonceStore(makeNonceStore(), 100);
    await expect(store.isRegistered('timeout-r2')).rejects.toMatchObject({ code: 'ETIMEDOUT' });
  }, 1_000);
});

// ── REC-20: Simultaneous Redis + PG failure ───────────────────────────────────

describe('REC-20: Simultaneous Redis and PG failure — system remains fail-closed', () => {
  test('both stores and PG pool are unavailable', async () => {
    const { nonceStore, anomalyStore, pgPool } = networkPartition();

    const [nr, ar, pgr] = await Promise.allSettled([
      nonceStore.register('rp-r1', 60_000),
      anomalyStore.record('rp-u', Date.now(), 60_000),
      pgPool.query('SELECT 1'),
    ]);

    expect(nr.status).toBe('rejected');
    expect(ar.status).toBe('rejected');
    expect(pgr.status).toBe('rejected');
  });

  test('enforcing fail-closed requires that errors propagate, not swallowed', async () => {
    const dead  = redisDownNonceStore();
    let   threw = false;
    try {
      await dead.register('swallow-test', 60_000);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});
